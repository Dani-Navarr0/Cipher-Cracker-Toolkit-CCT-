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
