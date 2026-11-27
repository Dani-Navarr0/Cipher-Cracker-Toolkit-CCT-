# Cipher Cracker Toolkit (CCT)

A comprehensive, powerful command-line toolkit for classical cryptanalysis, cipher breaking, and automated brute-forcing. Designed for cryptography enthusiasts. 

![License](https://img.shields.io/badge/License-MIT-green.svg)

<img width="1601" height="515" alt="image" src="https://github.com/user-attachments/assets/d773e34b-7c4e-4fa2-bfe6-9c301f5c7533" />

## Features

CCT is divided into four main categories, accessible via an interactive terminal launcher.

### 1. Substitution Ciphers
Tools to encrypt, decrypt, and brute-force substitution ciphers:
* **Caesar Cipher**
* **Vigenère Cipher**
* **Beaufort Cipher**
* **Porta Cipher**
* **Autoclave Cipher** (recovers the primer of plaintext or ciphertext autokey with no word list, Vigenère or Beaufort tableau)
* **Running Key Cipher**
* **Playfair Cipher** (annealing over the key square with no key or word list; dictionary and memetic attacks)
* **Four-Square Cipher**
* **Affine Cipher**
* **Hill Cipher** (ciphertext-only attack on 2x2 and 3x3 keys, known-plaintext attack with the crib position unknown)
* **Gronsfeld Cipher**
* **Gromark Cipher**
* **Polybius Square**
* **Bifid Cipher**
* **XOR Cipher**
* **Modular Add/Sub**

### 2. Transposition Ciphers
Tools for ciphers that rearrange the plaintext without changing the alphabet:
* **Columnar Transposition**
* **Scytale Cipher**
* **Rail Fence Cipher** (every rail count and starting offset, forwards and reversed, ranked by n-gram fitness)
* **Routes & Irregular Transpositions** (menu 24): grid routes (rows, columns, snakes, diagonals, spirals; any width, optionally starting part-way into the first row), rail fence, redefence, K3-style double rotation, and Myszkowski and AMSCO with every dictionary keyword or every key up to width 7, ranked by n-gram fitness. The families are the K4 workbench's.

### New solvers (stage 4)
* **Quagmire / Keyword Alphabets** (menu 17): a periodic key on keyword-mixed alphabets (Quagmire I: keyed plaintext alphabet; II: keyed cipher alphabet; III: both keyed, as on Kryptos), with every dictionary word tried as the alphabet keyword. Each column's shift is fitted by letter frequencies, so only the alphabet is searched; a C kernel scores all 341,591 distinct dictionary alphabets in about 9 s on 20 cores.
* **Bifid / Trifid Solver** (menu 18): annealing over the 5x5 square or 3x3x3 cube for each period (or the whole text as one block), with decryption in C.
* **Gromark Solver** (menu 19): ciphertext only. Every primer is screened (for the right one, the plaintext letters under each cipher letter fall in a window of 10 consecutive letters), and the best 3,000 per direction are refined by hill-climbing the mixed cipher alphabet. Measured on planted texts: 250 and 400 letters solved in 4 of 4 cases; 150 letters 1 of 2 (91% and 27% of letters).
* **Four-Square** (menu 15): the annealer now runs on the shared engine with C decryption, 22 µs per step instead of 176 µs, in parallel runs with an agreement count.

### 3. Advanced Cryptanalysis & Heuristics
The core strength of the CCT lies in its algorithmic approaches to cracking ciphers without knowing the key. Recent updates include a **Dynamic Fitness Engine** supporting Pure N-Gram, Pure IoC Tolerance, and Combined scoring to actively strip away layers of Double Ciphers. It uses the AZDecrypt library of N-Grams and language Spaces

* **Simulated Annealing (SA):** For completely random Simple Substitution and complex Polyalphabetic ciphers, with N-gram/IoC scoring.
* **Genetic Algorithms (GA):** Breeds and mutates generations of keys to crack highly complex systems like the Gromark Cipher.
* **Hill Climbing:** Unscrambles complex transpositions and polyalphabetic sequences by optimizing n-gram fitness.
* **Vigenère Auto-Solver:** Key length from the column IoC tested against shuffled copies of the text, then each key letter from letter frequencies, for Vigenère and Beaufort; every result is judged against English of the same length.
* **Word Pattern Isomorphism:** Solves space-preserving substitution ciphers: word shapes (e.g., `1-2-2-1-3-4` = `ATTACK`) are matched against a dictionary, one consistent letter mapping is searched for all words at once, and the substitution annealer runs alongside; solutions are ranked by the share of dictionary words.
* **Automated Crib Dragging:** "Drags" a suspected plaintext word across a ciphertext (Vigenère, Beaufort, Variant Beaufort), ranks the key fragments by how English they look (a running key or word key), and flags fragments that repeat with a period (a periodic key).
* **Kasiski Examination:** Analyzes polyalphabetic ciphers to find repeating substrings and deduce the key length.
* **Friedman Test:** Mathematically estimates polyalphabetic key lengths using the Index of Coincidence (IoC).
* **Matrix Permutation Solver:** Generates and solves matrix-based permutations.
* **Two-Layer Solver:** Attacks ciphers made of two stacked layers (substitution, columnar transposition, Vigenère/Beaufort) with one joint annealing search. See below.
* **Known-Plaintext Columnar Search:** Given known plaintext letters at known positions, tests every column order of a columnar transposition with a periodic Vigenère/Beaufort key, exhaustively, in C or on a GPU. See below.
* **Unknown Cipher Analyzer:** For a ciphertext with no clues: measures it against English and random texts of the same length, ranks the attack pathways (which tools to open, with which settings), runs the instant attacks, and can hill-climb a pathway. See below.

### N-Gram Scoring
Scoring tools load their English n-gram scores from the `N-grams` folder. The default is the included `5-grams_english_practicalcryptography_wortschatz.txt` model; configurable solvers also let you select sizes 2 through 6, using the corresponding English datasets in that folder. Higher source-file scores indicate more likely n-grams, and the TUI reports a lower-is-better scoring cost.

The substitution simulated-annealing solver can restore word spacing using the space-aware n-gram models under `N-grams/Spaces`. It discovers the available languages and reads each model's alphabet and n-gram size from its accompanying `.ini` file instead of relying on a built-in word list.

### 4. Utilities
* **Calculate IoC (Index of Coincidence):** Determines whether a cipher is monoalphabetic or polyalphabetic.
* **Frequency Analysis:** Plots character deviations against standard English text.
* **Keyword Alphabet Generator:** Generates mixed keyed alphabets.
* **Text Formatter:** Cleans and formats ciphertexts.
* **Matrix Generator:** Dumps all possible `n x m` permutations of a ciphertext string.
* **Native Engines (menu 45):** Builds the optional C engines and lists, tunes and enables GPUs. See below.

### Known-Plaintext Columnar Search (menu option 38)

For a ciphertext with some plaintext letters known at known positions (for example `ATTACK@12, DAWN@60`, 1-indexed), the tool tests every column order of every width you choose, in the four layouts, with a periodic key of every length you choose, in both layer orders (key then transposition, and transposition then key). Each known letter implies one key value; letters that fall on the same key slot must agree. A wrong hypothesis passes each agreement with probability 1/26, so the tool keeps hypotheses with at least as many agreements as needed for about one chance hit overall, and prints them with their partial decryption (`?` where the key slot holds no known letter). It tries Vigenère and Beaufort (Variant Beaufort passes the same checks as Vigenère) on the straight alphabet, and optionally on a keyed alphabet in every plaintext/ciphertext pairing.

This is an exact test, not a heuristic: a column order and key length that are not reported are inconsistent with the known letters (or have fewer agreements than the threshold).

### Unknown Cipher Analyzer (menu option 39)

The starting point for a ciphertext with no clues. Paste the text (several lines or a `.txt` path); in about a second it shows:

1. **What the text looks like:** length and its factors (grid widths that fill a rectangle), distinct and missing letters, word-like groups. Texts written with 2-6 symbols (Polybius digits, A/B, ADFGX) are read in groups and turned into letters first.
2. **Letter statistics**, each compared with 400 English passages of the **same length**, random letters and shuffled English, instead of fixed textbook values that only hold for long texts:
   * index of coincidence (letter counts kept, or flattened by a polyalphabetic key);
   * chi-squared against English letters (are the letters themselves English: transposition);
   * adjacent-pair structure (repeat rate of adjacent pairs ÷ what independent letters would give; unchanged by a substitution and destroyed by a transposition, so it separates "substitution" from "substitution + transposition");
   * n-gram fitness (does it already read as English, as written or reversed).
3. **Periodicity:** the IoC of every L-th letter for L = 2-30, as a z-score against shuffled copies of the text. Because about 30 periods are tested at once, the threshold is Bonferroni-corrected (about 2% chance that any period passes on an aperiodic text). Friedman and Kasiski figures are shown as supporting evidence.
4. **Attack pathways, ranked** (`strong` = the statistics point to it, `possible` = not ruled out, `long shot` = consistent but not indicated), each with its evidence, the tools to open (menu numbers) and suggested settings, plus a **ruled out** list (for example Playfair when all 26 letters occur, or a doubled pair sits at positions 1-2, 3-4, ...).
5. **Instant attacks**, chosen by the profile: all 312 affine keys (Caesar, Atbash), reversal, rail fence (2-30 rails, every offset), keyless grid routes, every column order up to width 7 in the four layouts, Vigenère/Beaufort keys from letter frequencies for the likely periods on the straight and on the KRYPTOS-keyed tableau (Kryptos K1/K2 style), and, when no period is found, autokey with no word list and the 2x2/3x3 Hill row attack. Each result is judged against the same-length references: *reads as English* (at or above the English 2nd percentile), *partly English* (above the 98th percentile of shuffled text) or *not English*.

From the session menu you can then **hill-climb a pathway** (the Two-Layer Solver's annealing engine on every CPU core, with editable widths, periods, steps and runs, reporting how many independent runs agree), **open a recommended tool**, save the report, or make a **blind test**: a random passage under a random hidden cipher, to practise on and then reveal.

The analyzer ranks where to start; it does not prove a cipher type.

**Measured accuracy.** 15 ciphertexts per cell, each a random passage of English that is *not* from the analyzer's reference corpus (Python's `LICENSE.txt` and this project's own documentation, so the prose style differs from the references), under random keys: columnar widths 5-12, rail fence 3-8 rails, Vigenère/Beaufort periods 3-10, Quagmire-like and transposition-then-Vigenère periods 3-8, autokey primers 3-8, running key = another English passage. "Top" = the expected pathway ranked first; "solved" = an instant attack's best result was judged *reads as English*.

| Cipher | Top at 60 / 100 / 200 / 400 letters | Solved instantly at 60 / 100 / 200 / 400 |
|---|---|---|
| None (plaintext) | 14 / 15 / 14 / 14 | 15 / 15 / 14 / 14 |
| Caesar | 11 / 13 / 15 / 15 | 15 / 15 / 14 / 14 |
| Simple substitution | 10 / 14 / 15 / 14 | needs hill-climb |
| Columnar transposition | 14 / 15 / 15 / 15 | 1 / 5 / 7 / 6 (widths above 7 need hill-climb) |
| Rail fence | 15 / 15 / 15 / 15 | 15 / 14 / 14 / 13 |
| Substitution + transposition | 12 / 12 / 15 / 13 | needs hill-climb |
| Vigenère | 6 / 9 / 15 / 15 | 4 / 5 / 9 / 13 |
| Beaufort | 2 / 12 / 15 / 15 | 4 / 5 / 12 / 14 |
| Quagmire-like (substitution, then Vigenère) | 5 / 14 / 15 / 15 | needs hill-climb |
| Transposition, then Vigenère | 0 / 8 / 15 / 15 | needs hill-climb |
| Autokey (plaintext autokey, Vigenère) | 13 / 13 / 12 / 15 (as "aperiodic") | 11 / 15 / 11 / 13 |
| Running key | 14 / 13 / 15 / 15 (as "aperiodic") | - |
| Hill 2x2 | 0 / 0 / 0 / 0 (listed as a long shot in 9 / 15 / 15 / 15) | 6 / 11 / 11 / 12 |

What this shows, and its limits:
* From 200 letters the expected pathway is ranked first in 12-15 of 15 cases for every cipher type tested except Hill, which by design is only ever a *long shot* (the statistics cannot single it out) but is listed, and solved instantly in 11-12 of 15.
* At 60 letters, periodic ciphers are mostly **not** detected (0-6 of 15): columns of 6-20 letters carry too little signal, and the period test is deliberately strict so that aperiodic texts do not produce false periods. Short texts fall back to the *aperiodic* pathway, which still lists the periodic tools.
* 15 trials per cell is a small sample: an earlier run of the same period-detection code on different random passages gave Vigenère at 100 letters 13/15 instead of 9/15. Differences of a few cases between cells or runs are noise.
* Some correct decryptions are judged below *reads as English*, because the bar is the 2nd percentile of the Python-documentation references and other texts differ in style; they show as *partly English* and are still ranked first (example: the solved Paradigm CTF PK1, 192 letters).
* Autokey and running key are recognised only as "aperiodic"; the analyzer does not tell them apart from each other or from Gromark.
* Not calibrated: Playfair, Four-square, Bifid, Porta, Gromark, 3x3 Hill, and the KRYPTOS-tableau periodic attack (added after this calibration; checked only on Paradigm CTF PK1, where it recovers the key PROVENANCE).

### Native engines (C) and GPU (OpenCL)

The column-order searches have optional native engines. Every native engine has a pure-Python reference in the toolkit, and the tests require identical results; without the native library, or with the environment variable `CCT_NATIVE=0`, the Python code runs as before.

```bash
python -m pip install ziglang             # zig's C compiler as a pip package (no Visual Studio or gcc needed)
python scripts/native_tools.py build      # or menu 45 -> 1; the library goes to scripts/native/build/ (not committed)
python scripts/native_tools.py gpu        # or menu 45 -> 2: list GPUs, tune them, enable GPU search
```

| Tool | What runs natively | How it is checked |
|---|---|---|
| 23 Matrix Permutation Solver, brute force | Every column order, scored with the selected n-gram model; returns the same (first best) order as the Python loop | Same best order as the loop for n-gram sizes 3-4, widths 2-7, all layouts, English and random texts |
| 23 Matrix Permutation Solver and 32 Annealing: Transposition, annealing | The annealing loop: same moves, cooling schedule, acceptance rule and progress display, with the C engine's own random number generator (seeded from Python's `random`) | The reported score equals the Python fitness of the returned order; planted transpositions reach at least the true key's score |
| 38 Known-Plaintext Columnar Search | Every column order + periodic key | Identical hit lists from the Python, C and GPU engines (texts of 60, 97 and 300 letters, two alphabets, prefixed searches); a planted solution is found |
| **Every annealing solver** and tool 39 | The n-gram score (`ngram_total`) used by every fitness evaluation: 75% of an annealing step's time in a profile. Selected automatically when the library is built | Identical totals on random texts (n-gram sizes 2-6). Same seed, same result: substitution + transposition 40.1 -> 10.8 µs per step (3.7x), Vigenère 50.4 -> 17.1 µs (2.9x) |
| 17 Quagmire, 39 | Letter-frequency fit of a periodic key on every keyword alphabet | Identical chi-squared to the Python fit (3 Quagmire types, 2 variants, periods 1, 5, 6, 11) |
| 18 Bifid / Trifid, 15 Four-square | Decryption inside the annealing loop | Identical to the Python decryption (Bifid and Trifid, periods 0, 5, 7; Four-square) |
| 19 Gromark | The primer screen (every primer) | Identical scores to the Python screen |
| 39 instant attacks | Exhaustive columnar (up to width 8 instead of 7) via tool 23's engine | Same best order as the Python loop (tool 23's tests) |

A call into C through `ctypes` costs about 1 µs (measured with an empty text), and the rest of each annealing step is Python (moves, decryption glue). Moving whole annealing loops into C would be the next step; it was not done here because the gains above came with very little new C.

GPU search uses OpenCL, which ships with the graphics driver (NVIDIA, AMD, Intel), so nothing else is installed. Results are identical to the CPU: GPU hits are sorted back into CPU order, and a launch whose hits overflow the GPU buffer is redone on the CPU. The fastest number of column orders per GPU work-item differs between GPUs; `native_tools.py gpu` measures it once per device and caches it. The GPU is used when enabled and the search is at least 9 columns wide; narrower searches are faster on the CPU. `CCT_GPU=1` enables it from the environment and `CCT_GPU_DEVICE=<text>` picks a GPU by name.

Measured on a laptop (Intel i7-1280P, NVIDIA T550 Laptop GPU, Intel UHD Graphics; one process; laptop timings vary with temperature):

| Search | Python | C | GPU |
|---|---|---|---|
| Brute force, width 8, 250 letters, 5-grams | 47,000 orders/s | 417,000 orders/s | - |
| Brute force, width 10, 250 letters, 5-grams | - | 378,000 orders/s | T550 455,000 orders/s, Intel UHD 1.5 million orders/s |
| Known plaintext, width 8, 97 letters, 24 key lengths, 16 alphabet/variant pairings | 11.6 s | 0.14 s | - |

The GPU's advantage on the n-gram brute force is small on these laptop GPUs; a desktop GPU has not been measured.

### Two-Layer Solver (menu option 37)

Solves a ciphertext that was encrypted twice, for example a substitution followed by a columnar transposition. Every layer has its own key, and a single simulated-annealing search changes one layer's key per step while scoring the fully decrypted text with n-grams, so both keys are found together. Independent runs are spread across CPU cores, and the tool reports how many runs reached the same plaintext (agreement between independent runs is good evidence of a real solution).

Supported combinations (encryption order):

| Combination | Notes |
|---|---|
| Substitution + Transposition | Order does not matter: the two operations commute. |
| Transposition, then Vigenère-family | Vigenère, Beaufort or Variant Beaufort. |
| Vigenère-family, then Transposition | |
| Substitution, then Vigenère-family | Quagmire-like. |
| Vigenère-family, then Substitution | Hardest: the Vigenère layer flattens letter frequencies before the substitution. |
| Transposition + Transposition | Double columnar transposition. |
| Substitution + Substitution | Two simple substitutions compose into one simple substitution, so this is solved as a single substitution. |

Option 2 in the tool builds a test ciphertext with random keys, so you can check the solver on a case where you know the answer.

Measured success per independent run on English text (5 trials per row, 4 for the Vigenère-then-Substitution row; "solved" = at least 90% of letters correct). The tool's defaults are at least the budgets shown, and running several independent runs raises the chance that at least one succeeds:

| Combination | Letters | Steps per run | Solved per run |
|---|---|---|---|
| Substitution + Transposition, width 8 | 300 and 600 | 400,000 | 4/5 each |
| Substitution + Transposition, width 12 | 400 | 1,500,000 | 2/5 |
| Substitution + Transposition, width 16 | 600 | 1,500,000 | 1/5 |
| Transposition (width 8), then Vigenère (period 7) | 300 / 600 | 400,000 | 4/5 / 5/5 |
| Vigenère (period 7), then Transposition (width 8) | 400 | 1,500,000 | 3/5 |
| Substitution, then Vigenère (period 5) | 300 and 600 | 400,000 | 5/5 each |
| Vigenère (period 5), then Substitution | 400 | 1,500,000 | 3/4 |
| Transposition (width 5) + Transposition (width 7) | 300 and 600 | 400,000 | 5/5 each |

Short texts (under ~200 letters) and wide transpositions are much harder; the tool warns about short inputs.

### Annealing settings

The annealing solvers maximise mean n-gram log score × letter-entropy^0.5 (Gromark scores the equivalent cost, 255 minus the mean). Because it is a mean, its scale does not depend on text length; measured single-move changes are about 0.5-2 points from a random key and 25-40 points near the correct key. Cooling geometrically from 20 to 0.1 therefore starts by accepting almost any move and ends as a hill climb; in tests the Substitution, Transposition and Vigenère solvers solved every test case with that schedule at their default 1.06 million steps (8/8 per row for substitution and transposition, 6/6 for Vigenère), so their settings are unchanged. The shared engine (`scripts/annealing.py`) uses the same range, adds a final hill-climbing polish, and is now used by the Two-Layer, Beaufort, Porta, Gronsfeld, columnar-transposition and Gromark solvers, which previously started at temperatures of 1000-10000 on a 0-255 cost scale where one move changes the score by roughly 1-20, so most of each run was a random walk.

---

## Installation

1. Clone the repository to your local machine:
   ```bash
   git clone [https://github.com/Dani-Navarr0/Cipher-Cracker-Toolkit-CCT-.git](https://github.com/Dani-Navarr0/Cipher-Cracker-Toolkit-CCT-.git)
   ```
2. Run the launcher from the repository root (Python 3.10 or newer; standard library only, no `pip install` needed):
   ```bash
   python main.py
   ```

In the launcher, use the arrow keys (or W/S) to move, Left/Right to switch column, type a tool's number to jump to it (for example `37`), and press Enter to open it; `H` shows help, `A` about and `Q` quits. Every tool fits on one screen from 88 columns x 30 rows (two columns) and from 132 columns (three columns); narrower or shorter terminals scroll.

**Session ciphertext.** Press `C` in the launcher to set the ciphertext once (paste several lines, or give a `.txt` path). Every tool's ciphertext prompt then shows `[Enter = session ciphertext]`, so you press Enter instead of pasting again. Tool 39 sets it automatically. When a ciphertext is pasted into a tool's prompt in an interactive terminal, the extra lines of a multi-line paste are read as part of the ciphertext instead of answering the next prompts. Ctrl+C inside a tool returns to the menu. Colours are defined once in `scripts/theme.py`; set the `NO_COLOR` environment variable to turn them off.

Optional, for speed: build the native C engines and enable a GPU (see "Native engines (C) and GPU (OpenCL)" above). This is the only part that installs anything (`python -m pip install ziglang`); the toolkit works without it.

The first time a solver loads the text-format 5-gram model it parses it (a few seconds) and caches a binary copy in `N-grams/.cache/`; later loads take well under a second. Delete that folder at any time to force a re-parse.

## Running the tests

```bash
python -m unittest discover -s tests -t .
```

`tests/test_native.py` compares the native and GPU engines with the Python code; its tests are skipped when the native library is not built or no OpenCL GPU is present.
