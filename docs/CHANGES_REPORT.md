# Cipher Cracker Toolkit: change report

**Scope:** everything changed since commit `042a372` ("Update README.md"), the starting point of this work.
**Date:** 2026-11-23
**Measurement setup:** all figures were measured on the development machine (Windows 11, 20 logical CPUs, Python 3.15.2; the tests also pass on Python 3.14). Timings vary roughly 1.5–2× between runs on the same machine, so speed-ups are side-by-side comparisons of old and new code run under the same conditions.

The work happened in three stages:
1. A performance audit and bug fixes.
2. Annealing fixes and the new Two-Layer Solver.
3. TUI consistency and a launcher redesign.

---

## 1. Summary

| Area | Result |
|---|---|
| Speed | Core n-gram scoring 6.9× faster. Substitution, transposition and Vigenère annealing 5.6–7.4× faster with identical results. The default 5-gram model loads in ~0.03 s instead of 2.27 s. |
| Correctness | About 25 confirmed bugs fixed (section 4), including two tools that could not start on a machine without numpy and dictionary attacks that discarded the correct key. |
| Annealing | One shared engine and temperature schedule, validated by measured success rates. Five solvers that started at temperatures of 1,000–10,000 (mostly a random walk) were moved onto it. |
| New capability | Two-Layer Solver (menu 37): substitution, transposition and Vigenère-family layers in any two-layer combination, solved jointly. The session keeps the ciphertext so you can try other combinations. |
| TUI | One colour palette and banner style across all 33 tools. Redesigned launcher: two-column layout, a description of the highlighted tool, multi-digit hotkeys, Help and About pages, and errors that no longer close the app. |
| Quality | 20 unit tests (up from 5). Compiled bytecode removed from git, `.gitignore` added, no third-party dependencies. |

---

## 2. Performance

### 2.1 Scoring core (`scripts/ngram_scoring.py`)
- **Rolling n-gram index:** one multiply-add per letter instead of one per n-gram character.
- **Text to letter codes in C:** conversion uses `bytes.translate` instead of a Python character loop.
- **Model cache:** the parsed text-format model is cached as a binary table in `N-grams/.cache/`. The cache is rebuilt automatically if the source file changes, and the folder is git-ignored.
- **Word spacing (`add_spaces`):** now uses back-pointers instead of copying the output string at every step. The output is unchanged.

### 2.2 Measured speed-ups (old vs new, same inputs)

| Operation | Before | After | Speed-up |
|---|---|---|---|
| `score_text`, 208 letters | 65 µs | 9 µs | 6.9× |
| Substitution annealing, per step | 94 µs | 13 µs | 7.4× |
| Transposition annealing, per step | 111 µs | 16 µs | 7.1× |
| Vigenère annealing, per step | 111 µs | 20 µs | 5.6× |
| One default annealing pass (1.06 M steps), substitution / transposition / Vigenère | 99 / 118 / 117 s | 13 / 17 / 21 s | — |
| Permutation solver | — | — | 4.4–7.2× (annealing), 6.4–9.9× (brute force) |
| Columnar dictionary batch (30,000 words) | 0.78 s | 0.22 s | 3.6× |
| Word spacing, 400 / 800 letters | 0.88 / 4.20 s | 0.32 / 2.43 s | 2.8× / 1.7× |
| Loading the default 5-gram model | 2.27 s | ~0.03 s (cached) | — |

### 2.3 How the speed-ups were achieved
- **Substitution and transposition annealing:**
  - **Constant terms computed once.** Letter IoC and entropy cannot change under a substitution key (a bijection) or a transposition (a reordering), so the solvers no longer recompute them on every step.
  - **Fast decryption.** Transposition decrypts with one C-level slice copy per column.
- **Vigenère annealing:** only the key column that changed is re-decrypted on each step.
- **Dictionary attacks:**
  - The word list is cached in memory.
  - Each distinct column order is evaluated only once (46% of dictionary words share an order with an earlier word).
  - Small runs execute in one process, which is faster than starting a process pool.
  - A full 435,723-word Vigenère run takes **8.5 s** on the parallel path and ranks the correct key first.

### 2.4 How equivalence was verified
For every rewritten solver, the original code (taken from git) and the new code were run with the same random seeds, and returned identical keys and scores. Scoring functions, the text-model parser and the transposition decryptors were compared on thousands of random inputs and produced byte-for-byte identical outputs.

---

## 3. Annealing settings and the Two-Layer Solver

### 3.1 What was measured
- **Score scale.** All annealing solvers score candidates with mean n-gram log score × entropy^0.5. Because it is a mean, its scale does not depend on text length.
  - One key change moves the score by a median of 0.5–2 points from a random key.
  - Next to the correct key, one change moves it by 25–40 points.
- **The 20 → 0.1 schedule works.** The existing schedule (geometric cooling from 20 to 0.1) solved every test case at its default 1.06 M steps:

  | Solver | Test cases | Solved |
  |---|---|---|
  | Substitution | 80, 120 and 200 letters | 8/8 each |
  | Transposition | widths 8, 12 and 16 | 8/8 each |
  | Vigenère | periods 7 and 15 | 6/6 each |

  Those three solvers keep their settings.
- **The high-temperature solvers were mostly random walks.** Beaufort, Porta, Gronsfeld, columnar transposition (single and double) and Gromark started at 1,000–10,000. With linear cooling from 1,000, the temperature only drops below ~20 in the last ~2% of the run.

### 3.2 What changed
- **`scripts/annealing.py` (new):** the shared engine. It cools geometrically from 20 to 0.1 over a fixed step budget, finishes with a hill-climbing polish, and Ctrl+C keeps the best result found so far.
- **`scripts/periodic_solver.py` (new):** one fast solver for Vigenère, Beaufort, Porta and Gronsfeld. The Beaufort, Porta and Gronsfeld tools now use it.
- **Columnar transposition and Gromark:** their annealing modes now use the shared engine.
- **Results, compared with the old versions** (the new versions run several independent searches by default):

  | Solver | Old | New |
  |---|---|---|
  | Beaufort | 5/6 | 6/6 |
  | Porta | 6/6 | 6/6 |
  | Gronsfeld | 6/6 | 6/6 |
  | Gromark | 0/8 | 1/8 |

  Gromark remains weak; see section 6.

### 3.3 Two-Layer Solver (menu 37, `scripts/two_layer.py`, `scripts/layered.py`)
- **How it works:**
  - Each layer has its own key: a substitution alphabet, a column order, or a periodic key.
  - One joint annealing search changes one layer's key per step and scores the fully decrypted text.
  - Independent runs execute in parallel across CPU cores, and the tool reports how many reached the same plaintext.
- **Combinations:**
  - Substitution + transposition: either order; they commute, so the order does not matter.
  - Transposition → Vigenère-family.
  - Vigenère-family → transposition.
  - Substitution → Vigenère-family.
  - Vigenère-family → substitution.
  - Double transposition.
  - Substitution + substitution: two simple substitutions compose into one, so this is solved as a single substitution.
- **Built-in test mode:** encrypts a sample text with random keys, so the solver can be checked on a known answer.
- **Session loop (stage 3):** after a search, the tool stays in the module with the ciphertext remembered. From there you can:
  - try another combination or settings;
  - repeat the last search, adding to the results;
  - review or save the results;
  - view the ciphertext statistics;
  - enter a new ciphertext, or make a test ciphertext and switch to it.
- **Measured success per independent run** ("solved" = at least 90% of letters correct; 5 trials per row, 4 for the Vigenère → substitution row):

| Combination | Letters | Steps per run | Solved per run |
|---|---|---|---|
| Substitution + Transposition, width 8 | 300 and 600 | 400,000 | 4/5 each |
| Substitution + Transposition, width 12 | 400 | 1,500,000 | 2/5 |
| Substitution + Transposition, width 16 | 600 | 1,500,000 | 1/5 |
| Transposition (w 8) → Vigenère (period 7) | 300 / 600 | 400,000 | 4/5 / 5/5 |
| Vigenère (period 7) → Transposition (w 8) | 400 | 1,500,000 | 3/5 |
| Substitution → Vigenère (period 5) | 300 and 600 | 400,000 | 5/5 each |
| Vigenère (period 5) → Substitution | 400 | 1,500,000 | 3/4 |
| Transposition (w 5) + Transposition (w 7) | 300 and 600 | 400,000 | 5/5 each |

- **Defaults:** the default budgets are at least the values shown, with 4 independent runs.
- **Rejected idea:** a "solve the transposition first" stage, using trigram coincidence (which substitution cannot change), was tested. It did not improve success, so it was not kept.

---

## 4. Bugs fixed

Each fix was reproduced before the change and re-tested after it.

**Tools that could not run, or returned no or wrong results**
- **Hill and Gromark** could not load on this machine because they need numpy, which is not installed. Both are now standard-library only:
  - Hill uses exact integer matrix arithmetic. Inverses were checked on 3,000 random matrices.
  - Hill's 2×2 brute force previously kept only IoC-window matches in enumeration order, and missed the true key in a test case. It now ranks all keys by n-gram score and puts the true key first.
- **Vigenère, Beaufort and Porta dictionary attacks** discarded candidates outside a narrow IoC window (0.065–0.070). The original returned no result at all for a test text whose plaintext IoC was just over 0.070. These attacks now also keep the best n-gram candidates, and the correct key ranks first. Phrases containing spaces now match.
- **Autoclave:**
  - Frequency mode always returned 0 results: a call passed the wrong number of arguments, and the error was silently ignored.
  - With no crib, every word counted as a match.
- **Gromark:**
  - Spaces shifted the running key.
  - Primers starting with 0 (10% of the space) were never searched.
  - Modes 3 and 4 could never produce a result, and queued about 40 million jobs. They now require a crib and show the search size before starting.
  - The genetic algorithm crashed with 1-letter keywords.
- **Playfair:** J in the key or ciphertext was dropped instead of becoming I. With no crib, every dictionary word was reported as a "phrase match".
- **Gronsfeld:** spaces shifted the key.
- **Scytale:** about half of the valid side counts were skipped.
- **Substitution annealing:**
  - "Pure IoC" mode gave every key the same score, so the search was random. It now switches to Combined mode with an explanation.
  - In Combined mode, an IoC far outside the target range could invert the search.

**Crashes and corrupted output**
- **Running key:** a key shorter than the text crashed; it now shows a clear message.
- **Vigenère auto-solver:** crashed with a division by zero on input with no letters.
- **Permutation solver:** accepted widths of 0 or less, which crashed or produced garbage.
- **Columnar transposition:** highlighting could insert colour codes inside other colour codes.

**Statistics and performance**
- **Kasiski:** used only the first 10 repeated sequences for its statistics. It now uses all of them, with no measured change in accuracy (25/35 top-1 and 35/35 top-3 before and after).
- **Columnar transposition:**
  - The IoC calculation was quadratic.
  - The double-transposition search repeated the inner decryption for every outer key.

---

## 5. TUI and launcher (stage 3)

- **One theme (`scripts/theme.py`).**
  - Every tool and the launcher import their colours from one place.
  - The previous dark grey (colour 238) and dark red (88) were nearly invisible on dark terminals; the new palette was chosen to be readable on both dark and light backgrounds.
  - `NO_COLOR` turns colours off.
  - All 33 tools use the same `banner()` title block and option style.
- **Launcher (`main.py`).**
  - **Layout:** two columns on wide terminals, so every tool fits on one screen; one scrolling column on narrow ones. Rendering was checked from 120×45 down to 50×16.
  - **Description line:** a one-line description of the highlighted tool appears under the menu.
  - **Multi-digit hotkeys:** typing `3` then `7` reaches tool 37. Previously only 0–9 worked.
  - **Help page:** controls, a suggested workflow for an unknown ciphertext, how scoring works, and a description of every tool. **About page:** version, licence and n-gram data source.
  - **Errors:** Ctrl+C inside a tool returns to the menu instead of quitting. A crash in a tool shows its traceback instead of a 2-second flash.
  - **Lazy loading:** tools are imported when opened, so start-up is faster, a broken tool cannot stop the menu from loading, and parallel worker processes are lighter.
  - **Plain-text fallback:** a plain-text menu is used when input is piped.
- **Typo fix:** "Simmulated Annealing" in the menu.

---

## 6. Known limitations and open items

- **Gromark annealing** solves only 1/8 test cases. A neighbouring primer produces an unrelated key, so the search has no gradient. It needs a different attack, for example primer search with a crib.
- **Hard two-layer cases:** wide transpositions (width ≥ 12) under substitution, and texts under about 200 letters, often need several independent runs, and may not be solvable at all.
- **Unguarded number prompts:** several tools still use bare `int(input())` prompts. Gromark, for example, raises an error on non-numeric input. The launcher now catches these, but the prompts themselves were not hardened.
- **Not changed:**
  - The XOR, modular and four-square solvers were not optimised.
  - Modular ADD-SUB's base-1 setting only affects the display.
  - Bifid has no period option.
  - Crib drag, keyword alphabet and Bifid mishandle non-ASCII letters.
  - Six copies of the IoC function remain.

---

## 7. Files

**New**
- `scripts/annealing.py`: the shared annealing engine.
- `scripts/periodic_solver.py`: the periodic-key solver (Vigenère, Beaufort, Porta, Gronsfeld).
- `scripts/layered.py`: the stacked-layer model used by the Two-Layer Solver.
- `scripts/two_layer.py`: the Two-Layer Solver tool.
- `scripts/attack_support.py`: shared dictionary-attack code.
- `scripts/transposition_core.py`: fast transposition decryptors.
- `scripts/theme.py`: the colour palette and banner helpers.
- `tests/test_core.py`, `tests/test_layered.py`, `tests/__init__.py`: tests.
- `.gitignore`, `docs/CHANGES_REPORT.md`.

**Removed from git:** 37 compiled `__pycache__/*.pyc` files. They are regenerated automatically and now ignored.

**Modified:** `main.py`, `README.md`, `utils/utils.py`, and 33 of the 34 existing Python files in `scripts/` (all except the empty `__init__.py`), covering the performance work, bug fixes, solver ports, and theme changes.

**Tests:** run `python -m unittest discover -s tests -t .` from the repository root (20 tests).

---

## 8. Stage 4 (2026-11-27): Unknown Cipher Analyzer and an audit of every tool

**Goal:** a user with an unknown ciphertext and no clues should be guided to the right attack, and each tool on that path should work.

### 8.1 New: Unknown Cipher Analyzer (menu 39)

`scripts/cipher_profile.py` (statistics and rules) and `scripts/cipher_analyzer.py` (screen). The method comes from the K4 workbench's screens: each statistic is compared with references of the same length, rather than with fixed thresholds. The references are 400 English passages, random letters, shuffled English and shuffled copies of the text.

- **Output:** ranked pathways, each with the tools to open, then instant attacks, then optional parallel hill-climbing.
- **Instant attacks:** affine/Caesar, routes, rail fence, every columnar order up to width 7, periodic keys by frequencies, autokey and Hill.
- **Accuracy:** README, "Unknown Cipher Analyzer", has the table.
- **Changes during development, each made after a measured failure:**
  - **Period test.** It is Bonferroni-corrected, because about 30 periods are tested at once. Running-key texts had been flagged as periodic.
  - **Choosing the key length.** A divisor or a multiple of the strongest period is chosen by a measured test. The tool had reported 3 for a period-6 key.
  - **"Letter counts kept" when the letters are English.** Chi-squared alone now puts a text in this branch. A rail fence of a passage with a low IoC had been routed to the polyalphabetic branch.
  - **Borderline IoC.** An IoC within 3 SD of the English mean keeps both branches open. Some Caesar texts had been misrouted.

### 8.2 New: session ciphertext (`scripts/session.py`)

- **Set once:** with `C` in the launcher, or automatically by tool 39.
- **Offered everywhere:** every ciphertext prompt accepts Enter to use it. The prompt matcher was checked against every `input()` prompt in the toolkit.
- **Multi-line paste:** a paste into a ciphertext prompt is collected whole instead of spilling into the next prompts.
  - **Untested:** this paste detection reads the console input buffer, so it cannot be tested with piped input. It was not tested in a real console.

### 8.3 Audit

Three independent read-only audits covered every module, and each reported finding came with a reproduction. Findings fixed (tests in `tests/test_audit_fixes.py`):

| Tool | Problem (reproduced) | Fix | Check after the fix |
|---|---|---|---|
| 22 Rail fence | Kept spaces, so grouped ciphertext decrypted wrongly. A `*` in the text corrupted the output. No ranking or offsets, and a 20-rail cap. | Rewritten. A permutation replaces the marker characters, and every rail count 2-40 × every offset × both directions is ranked by n-grams. | The audit's grouped example ranks first. Round trips pass with offsets and `*`. |
| 23 Matrix Permutation | Refused prime lengths. Mishandled non-A-Z letters. Layout numbers differed from 32/37. One prompt per width and no time estimate. | Any width allowed, letters A-Z only, layouts numbered as in 32/37. One brute-force limit, a time estimate before starting, keys also printed in tool-20 form. | A 397-letter (prime) columnar is solved. |
| 20 Columnar | Exhaustive search kept every result (368 MB at width 9). Keys from 23/32/37/38 could not be entered. Only one layout in direct decrypt. | Workers enumerate their own orders and keep the top 200. `transposition_core.parse_column_key` accepts keywords, digit keys and printed read orders. Direct decrypt offers all four layouts. | Width 9: 9.8 MB in the parent, 5.3 s (parallel), correct key. Every key form gives the same order. |
| 38 Known-plaintext columnar | The recovered key was never shown. A reversed range (`8-2`) crashed. Huge searches started without warning. | Key shown as letters (`?` = not fixed). Ranges accepted in either order. Confirmation above 50 million orders. | Planted key `KEY` is displayed. |
| 21 Scytale | The key was called "sides" but is the number of columns. | Labelled as columns, with the row count shown too. | — |
| Launcher | At 120×30 the menu fell back to one scrolling column: 20 entries visible, "↓ 27 more" (the audit's render). | System entries moved to hotkeys. Two columns from 88 columns wide, three from 132. | All tools visible at 100×30, 120×30 and 140×30 (rendered with a mocked terminal size). |
| 9 Playfair | Every plaintext printed 50 times. No working keyless attack: memetic 9-15% of letters correct. | Print fixed. New `playfair_anneal.py` (square annealing, parallel runs, agreement count) as mode `A`, and as a hill-climb in tool 39. | 304 letters, 1,000,000 steps per run: 2 of 8 runs found the key at start temperature 8, 1 of 8 at 20. Failed runs stall at about half the true key's fitness. 8 runs per setting is too few to rank the two settings. |
| 5 Hill | The known-plaintext attack crashed on a misaligned crib, or printed "Success!" with a wrong key. IoC prompts had no effect. No 3x3 attack without known plaintext. | New ciphertext-only row attack for 2x2 and 3x3 (each key row scored alone by letter frequencies). Known-plaintext attack for any crib, position known or unknown, cross-checked against every crib block. Unusable cribs explained. IoC prompts removed. Encrypt mode. | 3x3 solved from 150 and 300 letters (0.9 s and 1.8 s). Known-plaintext with unknown position finds the key, 7 of 7 blocks confirmed. |
| 4 Autoclave | Dictionary attack discarded the key when the plaintext IoC was outside 0.065-0.070. No direct decrypt. Vigenère plaintext autokey only. | Rewritten. Primer-free attack: ciphertext autokey decrypts directly past the primer, and plaintext autokey splits into chains with 26 choices each. Plaintext and ciphertext autokey, both tableaux, decrypt, encrypt, and an n-gram-ranked dictionary mode. Added to tool 39's instant attacks. | Plaintext autokey: 4 of 4 planted texts fully recovered, 0.8-1.6 s. Ciphertext autokey: right primer length, 92-98% of letters (the misses are primer letters). |
| 6 XOR, 7 Modular | IoC filter discarded the correct key, and results were ranked by IoC. Modular advanced the key on spaces and read a space in the key as a shift. | Keep the top 25 by n-gram cost outside the IoC window and rank by n-gram cost. Key advances on letters only, and non-letters are dropped from the key. | Key LANTERN ranked first in both. `HELLO WORLD` + `AB` = `HFLMO XOSLE`. |
| 3 Gronsfeld | Exhaustive search kept every key's result in memory. The audit measured 81 MB at length 5 and extrapolated about 8 GB at 7. | Workers generate their own key ranges and keep the best 50. | 100,000 keys: 50 kept, 23.8 MB, the planted key ranked first. |
| 30 Vigenère auto-solver | "CRACK SUCCESSFUL" on random text. Periods 1-20 only. | Key length from the corrected column-IoC test. Vigenère and Beaufort. Verdict against same-length English. Maximum period chosen by the user. | Key LIGHTHOUSE recovered. Random letters: "not solved". |
| 34 Crib drag | Vigenère only, and 400+ unranked rows. | Vigenère, Beaufort and Variant Beaufort. Ranked by how English the key fragment looks. Fragments that repeat with a period are listed. | Running key: true position 4th of 1,077. KRYPTOS key: true position first among repeating fragments, period 7. |
| 33 Word pattern | First 15 matches shown alphabetically. No cross-word consistency. | Joint beam search with one-to-one letters, plus 4 substitution-annealer runs, ranked by the share of dictionary words. | 3 of 4 test sentences solved (79/79, 79/81 with DOG/GOD ambiguous, 94/94). The 51-letter sentence failed. |
| 15 Four-square | J was dropped from the ciphertext, shifting every digraph after it. | J → I. | — |
| 36 Friedman, 40 IoC, 41 Frequency | Overconfident advice. Output printed before the empty-input check. | Estimates worded as rough, with measured errors quoted. Input checked first. | Friedman measured: 7-letter key estimated as 9.9 and 12.5, 10-letter key as 7.5 and 15.8. |
| 14 Porta, 13 Beaufort, 3 Gronsfeld, 2 Gromark | Porta asked for a temperature and cooling rate it ignored. A misleading "alphabet" error. Gromark silently accepted a primer that was not 5 digits. | Prompts removed, error message corrected, primer validated. | — |

### 8.4 Not done (open)

- **Four-square annealing speed:** about 3 minutes per run (audit measurement). Not changed.
- **Vigenère (tool 1) annealing:** not seeded with the frequency key. The default budget is about 165 s per key length (audit measurement). Tools 30 and 39 now give the frequency solution instantly.
- **Bifid:** no key search, and no period option.
- **Inputs:** Caesar and affine score texts under 5 letters as "inf". `float(input())` is unguarded in Vigenère and Beaufort mode 2.
- **Matrix Generator:** gives nothing useful on prime lengths.
- **Playfair annealer:** its success rate was measured on one 304-letter text only.

### 8.5 C-engine prompt and the KRYPTOS tableau

- **C-engine notice:** the launcher header says "C engines not built: 45" while they are missing.
- **Build offer:** tools 23, 32 and 38, which have C engines, say so before running in Python and offer to build them on the spot (`B`). The quoted speed-ups are the README's measured ones.
- **KRYPTOS tableau in tool 39:** the instant periodic attack also tries Vigenère and Beaufort on the KRYPTOS-keyed tableau (`cipher_profile.KEYED_ALPHABETS`). On Paradigm CTF PK1, which is Vigenère on the KRYPTOS alphabet, it recovers the key PROVENANCE and the plaintext instantly.

### 8.6 Speed (C) and new solvers

**Profile first.** In a substitution + transposition annealing run, `ngram_total` took 1.76 of 2.36 s (75%); decryption took 0.07 s. So instead of porting every module to C, the n-gram total was ported and is selected automatically by `ngram_scoring` when the library is built. Results are unchanged: a run with the same seed gives the same score with and without C.

| What | Before | After |
|---|---|---|
| `ngram_total`, 300 letters | 16.4 µs | 3.4 µs (about 1 µs of it is the ctypes call) |
| Annealing step, substitution + transposition | 40.1 µs | 10.8 µs |
| Annealing step, Vigenère | 50.4 µs | 17.1 µs |
| Four-square annealing step | 176 µs (audit measurement) | 22 µs |
| Quagmire I-III over 341,591 dictionary alphabets, period 6 | 56 s (first version, one process) | 8.8 s |

**New C kernels** (library version 3, `scripts/native/fast.py`):
- n-gram total;
- keyed-alphabet chi-squared fit;
- Gromark primer screen;
- Bifid/Trifid decryption;
- Four-square decryption.

Each has a Python reference, and `tests/test_new_solvers.py` requires identical results. A library missing a function now counts as "not built" instead of raising.

**New tools:**
- 17 Quagmire (keyword alphabets);
- 18 Bifid / Trifid solver;
- 19 Gromark solver;
- 24 Routes & Irregular, using transposition families ported from the K4 workbench (one change: `tuple(src)` instead of `bytes(src)` for texts over 255 letters).

**Tool 39 (analyzer):**
- With a key length found, its instant attacks now include the dictionary Quagmire search.
- With the C engines, the exhaustive columnar search goes to width 8.

**Measured on planted texts:**

| Solver | Text | Result |
|---|---|---|
| Quagmire | LIGHTHOUSE alphabet, Quagmire I, II and III | All three recovered. |
| Routes & Irregular | Width-12 spiral, TOMATO Myszkowski, BALLOONS AMSCO | All three found. |
| Gromark | 250 and 400 letters | 4 of 4 solved. |
| Gromark | 150 letters | 1 of 2. |
| Four-square | 300 letters, 8 runs of 1,000,000 steps | 2 of 8 runs solved, 48 s in all. |

The Gromark screen alone ranked the true primer only 129th-1,051st of 100,000. That is why the best 3,000 primers are refined: given the right primer, refining recovered 100% of the plaintext.

### 8.7 Tests

`python -m unittest discover -s tests -t .` runs 64 tests: 28 from earlier stages, 12 for the analyzer, 16 for the audit fixes and 8 for the new solvers and C kernels. With the C library built, all 64 run (about 100 s). Without it, the 10 native tests (6 earlier, 4 new) are skipped.

---

## 9. Stage 5 (2026-11-27): every engine in C, compute settings, menu v2.1

Menu numbers in this section are the v2.1 numbers; sections 1-8 use the numbers of their time (the help screen, `H`, has the old-to-new table).

### 9.1 C only, no Python fallback

Every annealing, dictionary and large brute-force search now runs in C. The Python search loops they replaced were deleted, not kept as fallbacks. Small keyspaces still loop in Python around C scoring (Caesar, Affine, crib-drag offsets, the Vigenère Auto-Solver's per-column shift fit). Dead Python code found by a scan for unreferenced functions was deleted too: a pure-Python Vigenère solver in tool 21, `caesar.save_caesar_results` and `transposition_families.segment_sources`. Without the library, the solvers raise `native.NativeUnavailable` with the build instructions; the launcher offers the build at start-up and dims the tools that need it. The library is one file built from every `.c` file in `scripts/native/` (14 engines sharing `cct_common.h`), with `-O3 -march=native -ffp-contract=off`: no fused multiply-add, so C fitness values equal the Python definitions bit for bit.

The port ran in five groups (periodic, layered, digraphic, keystream, screens). Each group's work was checked by an independent verifier and fixed until no serious issue was left. Measured before (the previous Python engine) and after (C), on a 20-thread machine with other jobs running, so the figures are rough:

| Search | Before | After |
|---|---|---|
| Two-Layer Solver (61), substitution + width-8 transposition, 300,000 steps | 2.59 s | 1.23 s |
| Substitution Solver (13), 1,058,000 steps | 5.82 s | 3.34 s |
| Keyed Columnar (45), double annealing [8, 10], 300,000 steps | 4.19 s | 1.58 s |
| Keyed Columnar (45), every order of width 10 | 16.1 s | 1.65 s |
| Keyed Columnar (45), dictionary (390,418 words) | 5.47 s | 2.49 s |
| Double columnar (45), 6x6 exhaustive | 10.1 s | 0.64 s |
| Playfair annealing (51), 100,000 steps | 8.59 s | 0.44 s |
| Playfair dictionary (51), 440,375 keywords | 19.0 s | 1.1-1.3 s |
| Four-Square annealing (52), 200,000 steps | 4.95 s | 0.76 s |
| Bifid period 7 (53), 200,000 steps | 6.50 s | 1.67 s |
| Hill 3x3 row attack (54) | 1.45 s | 0.14 s |
| Autokey (31) with a word list, 40 letters | 8.04 s | 0.11 s |
| Autokey (31) without a word list, 200 letters, primers up to 20 | 5.84 s | 0.15 s |
| Gromark Solver (34), 250 letters, full solve | 295 s | 16 s (10 workers) |
| Word Pattern Attack (14) beam search | 0.07-0.27 s | 0.01-0.07 s |

The periodic annealer (22-25) was already mostly C-scored and kept its speed (Vigenère, period 7, 2,000,000 steps: 1.6 s before and 1.7 s after); what changed is that it now also accepts any alphabet of 1-256 symbols (I/J-merged, with digits, keyed, Spanish) instead of refusing non-A-Z alphabets.

Success rates of the C engines, 16 runs each on one planted 300-letter text: Playfair 6/16 at 1,000,000 steps, Four-Square 11/16 at 1,000,000, Bifid period 7 16/16 at 400,000, **Trifid period 7 0/16** at 400,000 (the former Python Trifid: 0/8; C at 4,000,000 steps: 0/8). Trifid remains unsolved by this toolkit.

**Removed** (superseded, not ported):
- Playfair: the memetic attack (9-15% of letters, section 8.3) and the two duplicate dictionary modes, now one C keyword attack.
- Hill: the exhaustive 2x2 mode (the row attack returns the same keys).
- Gromark (known key) (71): the genetic, annealing, hill-climbing, dictionary and key-length search modes; ciphertext-only attacks are tool 34.
- Former tool 32 (Annealing: Transposition): merged into tool 44, Column-Order Solver, as "Moves: 2 = swap only"; the module `simulated_annealing_transposition.py` is deleted.
- `annealing.anneal` and `annealing.hill_climb`; `annealing.py` keeps the shared definitions (`Fitness`, `Schedule`, `letter_entropy`, defaults).

**Accepted design choices:** several searches run their C calls on threads (ctypes releases the GIL) instead of processes: the Gronsfeld exhaustive search, the shared dictionary attacks (`attack_support`), the Playfair dictionary attack, the Keyed Columnar exhaustive, dictionary and double searches, Autokey's word list, Quagmire and Routes & Irregular. Playfair annealing, Four-Square, Bifid / Trifid, the Two-Layer Solver, Gromark and the analyzer's hill-climb use processes; tool 45's annealing restarts run one after another. Measured on the full period-8 Gronsfeld search: 10 workers, threads 11.5 s and processes 10.9 s; period 7, threads 1.24 s and processes 2.80 s (process start-up dominates small searches).

### 9.2 Compute settings (92, key `P`)

On the first launch the toolkit shows the CPU, threads, free memory and GPUs and asks for a limit on worker processes; later launches show the saved limit in one line (Enter keeps it, `C` changes it and shows the hardware again). Presets: Light (a quarter of the threads), Balanced (half, the default), Heavy (all but two), or any number. Searches run at below-normal priority by default, inherited by worker processes. Every worker count in the toolkit goes through `compute.workers()`. Saved per machine in `cct_settings.json` (git-ignored).

### 9.3 Menu v2.1

Tools are grouped in attack order and numbered by tens (README, Features). After the analyzer runs, its recommended tools are marked with • and `N` steps through them; PgUp/PgDn jump between blocks; the footer shows the selected tool's old number ("was NN") when it fits. The analyzer's columnar hill-climb now starts at width 9, since widths 2-8 are searched exhaustively. The analyzer's pathways name tools by module, so the numbers they show always match the menu.

### 9.4 Fixes

- Menu 91 only said "run python -m pip install ziglang" when zig's compiler was missing from the Python running the toolkit (for example Python 3.14 when ziglang is installed in 3.15 only): it now names that Python and offers to install ziglang into it.
- Rebuilding while a toolkit had the library loaded failed on Windows: the build now waits as `cct_native.dll.new` and is installed at the next start.
- `SetPriorityClass` silently failed (64-bit process handle truncated by ctypes); fixed with explicit argument types and checked in worker processes.

### 9.5 Open

- Trifid: not solved (above).
- Gromark Solver: the alphabet climb stalls in some runs (5 of 7 exact in one review; 2 stopped at the complementary key, 88-93% of letters); short texts such as tool 71's 78-letter test case are not solved.