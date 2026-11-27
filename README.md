# Cipher Cracker Toolkit (CCT)

A comprehensive, powerful command-line toolkit for classical cryptanalysis, cipher breaking, and automated brute-forcing. Designed for cryptography enthusiasts. 

![License](https://img.shields.io/badge/License-MIT-green.svg)

<img width="1601" height="515" alt="image" src="https://github.com/user-attachments/assets/d773e34b-7c4e-4fa2-bfe6-9c301f5c7533" />

## Features

CCT is an interactive terminal launcher (menu v2.1). The tools are grouped in the order you attack an unknown cipher, numbered by tens:

| Block | Tools |
|---|---|
| Start here | C set the session ciphertext, 1 Unknown Cipher Analyzer, 2 Index of Coincidence, 3 Frequency Analysis, 4 Kasiski, 5 Friedman |
| 1x Monoalphabetic | 11 Caesar, 12 Affine, 13 Substitution Solver, 14 Word Pattern Attack |
| 2x Periodic key | 21 Vigenère Auto-Solver, 22 Vigenère Workbench, 23 Beaufort, 24 Porta, 25 Gronsfeld, 26 Quagmire I-III |
| 3x Aperiodic / long key | 31 Autokey, 32 Running Key, 33 Crib Dragging, 34 Gromark Solver |
| 4x Transposition | 41 Rail Fence, 42 Scytale, 43 Routes & Irregular, 44 Column-Order Solver, 45 Keyed & Double Columnar |
| 5x Polygraphic & Bifid | 51 Playfair, 52 Four-Square, 53 Bifid / Trifid Solver, 54 Hill |
| 6x Two layers & cribs | 61 Two-Layer Solver, 62 Crib Columnar Search |
| 7x Encode / decode | 71 Gromark (known key), 72 Bifid (known key), 73 Polybius, 74 Modular Add / Subtract, 75 XOR |
| 8x Utilities | 81 Text Formatter, 82 Keyword Alphabet, 83 Matrix Generator |
| 9x Setup | 91 C Engines & GPU, 92 Compute Settings |

After the analyzer runs, the tools of its pathways that are not long shots are marked with • in the menu and `N` steps through them. The help screen (`H`) has a table from the old (pre-v2.1) numbers to the new ones, and the footer shows the selected tool's old number, "(was NN)", when it fits.

### 1. Substitution Ciphers
Tools to encrypt, decrypt, and brute-force substitution ciphers:
* **Caesar Cipher**
* **Vigenère Cipher**
* **Beaufort Cipher**
* **Porta Cipher**
* **Autoclave Cipher** (recovers the primer of plaintext or ciphertext autokey with no word list, Vigenère or Beaufort tableau)
* **Running Key Cipher**
* **Playfair Cipher** (annealing over the key square with no key or word list; dictionary keyword attack)
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
* **Routes & Irregular Transpositions** (menu 43): grid routes (rows, columns, snakes, diagonals, spirals; any width, optionally starting part-way into the first row), rail fence, redefence, K3-style double rotation, and Myszkowski and AMSCO with every dictionary keyword or every key up to width 7, ranked by n-gram fitness. The families are the K4 workbench's.

### Newer solvers
* **Quagmire I-III** (menu 26): a periodic key on keyword-mixed alphabets (Quagmire I: keyed plaintext alphabet; II: keyed cipher alphabet; III: both keyed, as on Kryptos), with every dictionary word tried as the alphabet keyword. Each column's shift is fitted by letter frequencies, so only the alphabet is searched; a C kernel scores all 341,591 distinct dictionary alphabets (measured 2.6-2.9 s at period 6 on a 468-letter text).
* **Bifid / Trifid Solver** (menu 53): annealing over the 5x5 square or 3x3x3 cube for each period (or the whole text as one block), entirely in C. Measured on one planted 300-letter text, 16 runs each: Bifid period 7 solved 16 of 16 at 400,000 steps; **Trifid period 7 solved 0 of 16** (also 0 of 8 at 4,000,000 steps), so Trifid is not reliably solved yet.
* **Gromark Solver** (menu 34): ciphertext only. Every primer is screened (for the right one, the plaintext letters under each cipher letter fall in a window of 10 consecutive letters), and the best 3,000 per direction are refined by hill-climbing the mixed cipher alphabet. Measured on planted texts: 250 and 400 letters solved in 4 of 4 cases; 150 letters 1 of 2 (91% and 27% of letters). The alphabet climb can stall: in one review 5 of 7 runs were exact and 2 stopped at the complementary key (88-93% of letters right). It does not solve the 78-letter known-answer text of tool 71.
* **Four-Square** (menu 52): annealing in C with parallel runs and an agreement count (11 of 16 runs solved one planted 300-letter text at 1,000,000 steps).

### 3. Advanced Cryptanalysis & Heuristics
The core strength of the CCT lies in its algorithmic approaches to cracking ciphers without knowing the key. Recent updates include a **Dynamic Fitness Engine** supporting Pure N-Gram, Pure IoC Tolerance, and Combined scoring to actively strip away layers of Double Ciphers. It uses the AZDecrypt library of N-Grams and language Spaces

* **Simulated Annealing (SA):** For completely random Simple Substitution and complex Polyalphabetic ciphers, with N-gram/IoC scoring.
* **Hill Climbing:** Unscrambles complex transpositions and polyalphabetic sequences by optimizing n-gram fitness.
* **Vigenère Auto-Solver:** Key length from the column IoC tested against shuffled copies of the text, then each key letter from letter frequencies, for Vigenère and Beaufort; every result is judged against English of the same length.
* **Word Pattern Isomorphism:** Solves space-preserving substitution ciphers: word shapes (e.g., `0-1-1-0-2-3` = `ATTACK`) are matched against a dictionary, one consistent letter mapping is searched for all words at once, and the substitution annealer runs alongside; solutions are ranked by the share of letters that fall in dictionary words, then by n-gram fitness.
* **Automated Crib Dragging:** "Drags" a suspected plaintext word across a ciphertext (Vigenère, Beaufort, Variant Beaufort), ranks the key fragments by how English they look (a running key or word key), and flags fragments that repeat with a period (a periodic key).
* **Kasiski Examination:** Analyzes polyalphabetic ciphers to find repeating substrings and deduce the key length.
* **Friedman Test:** Mathematically estimates polyalphabetic key lengths using the Index of Coincidence (IoC).
* **Column-Order Solver:** Keyless columnar transposition: every column order up to width 9, annealing above, in four layouts; annealing moves are "swap or reverse" or "swap only" (the latter was a separate tool, number 32, before menu v2.1).
* **Two-Layer Solver:** Attacks ciphers made of two stacked layers (substitution, columnar transposition, Vigenère/Beaufort) with one joint annealing search. See below.
* **Known-Plaintext Columnar Search:** Given known plaintext letters at known positions, tests every column order of a columnar transposition with a periodic Vigenère/Beaufort key, exhaustively, in C or on a GPU. See below.
* **Unknown Cipher Analyzer:** For a ciphertext with no clues: measures it against English and random texts of the same length, ranks the attack pathways (which tools to open, with which settings), runs the instant attacks, and can hill-climb a pathway. See below.

### N-Gram Scoring
Scoring tools load their English n-gram scores from the `N-grams` folder. The default is the included `5-grams_english_practicalcryptography_wortschatz.txt` model; configurable solvers also let you select sizes 2 through 6, using the corresponding English datasets in that folder. Higher source-file scores indicate more likely n-grams, and the TUI reports a lower-is-better scoring cost.

The substitution simulated-annealing solver can restore word spacing using the space-aware n-gram models under `N-grams/Spaces`. It discovers the available languages and reads each model's alphabet and n-gram size from its accompanying `.ini` file instead of relying on a built-in word list.

### 4. Identification, utilities and setup
* **Index of Coincidence (menu 2):** Determines whether a cipher is monoalphabetic or polyalphabetic.
* **Frequency Analysis (menu 3):** Tabulates letter frequencies and their deviation from English, plus bigram and trigram counts.
* **Text Formatter (menu 81):** Cleans and formats ciphertexts.
* **Keyword Alphabet (menu 82):** Generates mixed keyed alphabets.
* **Matrix Generator (menu 83):** Writes the string into every n x m grid whose size equals its length and reads the columns left to right and right to left, saving the results to a file.
* **C Engines & GPU (menu 91):** Builds the C engines (required by every solver) and lists, tunes and enables GPUs. See below.
* **Compute Settings (menu 92, key `P`):** How many worker processes the searches use, and their priority. See Installation.

### Known-Plaintext Columnar Search (menu 62)

For a ciphertext with some plaintext letters known at known positions (for example `ATTACK@12, DAWN@60`, 1-indexed), the tool tests every column order of every width you choose, in the four layouts, with a periodic key of every length you choose, in both layer orders (key then transposition, and transposition then key). Each known letter implies one key value; letters that fall on the same key slot must agree. A wrong hypothesis passes each agreement with probability 1/26, so the tool keeps hypotheses with at least as many agreements as needed for about one chance hit overall, and prints them with their partial decryption (`?` where the key slot holds no known letter). It tries Vigenère and Beaufort (Variant Beaufort passes the same checks as Vigenère) on the straight alphabet, and optionally on a keyed alphabet in every plaintext/ciphertext pairing.

This is an exact test, not a heuristic: a column order and key length that are not reported are inconsistent with the known letters (or have fewer agreements than the threshold).

### Unknown Cipher Analyzer (menu 1)

The starting point for a ciphertext with no clues. Paste the text (several lines or a `.txt` path); in about a second it shows:

1. **What the text looks like:** length and its factors (grid widths that fill a rectangle), distinct and missing letters, word-like groups. Texts written with 2-6 symbols (Polybius digits, A/B, ADFGX) are read in groups and turned into letters first.
2. **Letter statistics**, each compared with 400 English passages of the **same length**, random letters and shuffled English, instead of fixed textbook values that only hold for long texts:
   * index of coincidence (letter counts kept, or flattened by a polyalphabetic key);
   * chi-squared against English letters (are the letters themselves English: transposition);
   * adjacent-pair structure (repeat rate of adjacent pairs ÷ what independent letters would give; unchanged by a substitution and destroyed by a transposition, so it separates "substitution" from "substitution + transposition");
   * n-gram fitness (does it already read as English, as written or reversed).
3. **Periodicity:** the IoC of every L-th letter for L = 2 up to 30 (up to length/6 for texts under 180 letters), as a z-score against shuffled copies of the text. Because all those periods are tested at once, the threshold is Bonferroni-corrected over their number (about 2% chance that any period passes on an aperiodic text). Friedman and Kasiski figures are shown as supporting evidence.
4. **Attack pathways, ranked** (`strong` = the statistics point to it, `possible` = not ruled out, `long shot` = consistent but not indicated), each with its evidence, the tools to open (menu numbers; the tools of the pathways that are not long shots are also marked with • in the menu) and suggested settings, plus a **ruled out** list (for example Playfair when all 26 letters occur, or a doubled pair sits at positions 1-2, 3-4, ...).
5. **Instant attacks**, chosen by the profile: all 312 affine keys (Caesar, Atbash), reversal, rail fence (2-30 rails, every offset), keyless grid routes, every column order up to width 8 in the four layouts, Vigenère/Beaufort keys from letter frequencies on the straight and on the KRYPTOS-keyed tableau (Kryptos K1/K2 style) for the likely periods (every tested period when none is found), Quagmire I-III with every dictionary word as the alphabet keyword when a period is found, and, when no period is found, autokey with no word list and the 2x2/3x3 Hill row attack. Each result is judged against the same-length references: *reads as English* (at or above the English 2nd percentile), *partly English* (above the 98th percentile of shuffled text) or *not English*.

From the session menu you can then **hill-climb a pathway** (the Two-Layer Solver's C annealing engine, or the Playfair annealer for the Playfair pathway, on the worker processes set in Compute Settings, with editable widths, periods, steps and runs, reporting how many independent runs agree), **open a recommended tool**, save the report, or make a **blind test**: a random passage under a random hidden cipher, to practise on and then reveal.

The analyzer ranks where to start; it does not prove a cipher type.

**Measured accuracy.** 15 ciphertexts per cell, each a random passage of English that is *not* from the analyzer's reference corpus (Python's `LICENSE.txt` and this project's own documentation, so the prose style differs from the references), under random keys: columnar widths 5-12, rail fence 3-8 rails, Vigenère/Beaufort periods 3-10, Quagmire-like and transposition-then-Vigenère periods 3-8, autokey primers 3-8, running key = another English passage. "Top" = the expected pathway ranked first; "solved" = an instant attack's best result was judged *reads as English*.

| Cipher | Top at 60 / 100 / 200 / 400 letters | Solved instantly at 60 / 100 / 200 / 400 |
|---|---|---|
| None (plaintext) | 14 / 15 / 14 / 14 | 15 / 15 / 14 / 14 |
| Caesar | 11 / 13 / 15 / 15 | 15 / 15 / 14 / 14 |
| Simple substitution | 10 / 14 / 15 / 14 | needs hill-climb |
| Columnar transposition | 14 / 15 / 15 / 15 | 1 / 5 / 7 / 6 (measured when the exhaustive search stopped at width 7; wider keys need hill-climb) |
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

### C engines (required) and GPU (OpenCL)

Every annealing, dictionary and large brute-force search, and the n-gram scoring under all of them, runs in one C library, built once per machine. **There is no Python fallback**: without the library (or with the environment variable `CCT_NATIVE=0`) the solvers stop with the build instructions, and the launcher offers to build it at start-up. What stays in Python is input, small tables, output, and the loops over small keyspaces around C scoring: Caesar's 26 shifts, Affine's 312 keys, crib-drag offsets and the per-column shift fit of the Vigenère Auto-Solver.

```bash
python -m pip install ziglang             # zig's C compiler as a pip package (no Visual Studio or gcc needed)
python scripts/native_tools.py build      # or menu 91 -> 1; the library goes to scripts/native/build/ (not committed)
python scripts/native_tools.py gpu        # list GPUs and tune them (cached); enable GPU search from menu 91 -> 2 (that session) or with CCT_GPU=1
```

If menu 91 reports that zig's compiler is missing, it offers to install `ziglang` into the Python that is running the toolkit (you may have several Pythons). On Windows a library that a running toolkit has loaded cannot be overwritten; the new build then waits as `cct_native.dll.new` and is installed the next time the toolkit starts.

Each engine is its own `.c` file in `scripts/native/` (all compiled into one library, sharing `cct_common.h`):

| Engine | Tools |
|---|---|
| `cct_native.c` | n-gram scoring; column-order brute force and annealing (44); Crib Columnar Search (62) |
| `periodic_engine.c`, `periodic_dict.c` | annealing of Vigenère, Beaufort, Porta, Gronsfeld (22-25) and dictionary attacks of 22-24, any alphabet of 1-256 symbols; Gronsfeld exhaustive search; word-list keys of Modular Add / Subtract (74) and XOR (75) |
| `periodic_keyed.c` | Quagmire I-III (26) and the analyzer's keyed-tableau attack |
| `layered_engine.c`, `layered_columnar.c` | Two-Layer Solver (61), the analyzer's hill-climb, Substitution Solver (13), Keyed & Double Columnar (45) |
| `digraphic.c`, `digraphic_hill.c` | Playfair (51), Four-Square (52), Bifid / Trifid (53), Hill row attack (54) |
| `keystream_autokey.c`, `keystream_dict.c`, `gromark.c` | Autokey with and without a word list (31), Gromark Solver (34) |
| `screens_pattern.c` | Word Pattern Attack (14) |
| `screens_transposition.c` | Rail Fence (41), Scytale (42), Routes & Irregular (43) and the analyzer's keyless screens |
| `screens_stats.c` | the same-length reference statistics behind the analyzer (1) and every "reads as English" verdict |

The tests (`tests/test_c_*.py`, `tests/test_native.py`) check each engine against known answers, planted ciphertexts and small test-only reference implementations; the library is built with `-ffp-contract=off` so its fitness values equal the Python definitions bit for bit.

Measured when the Python engines were replaced (before = the previous Python engine, after = C; one 20-thread Windows machine with other jobs running, so the figures are rough):

| Search | Before | After |
|---|---|---|
| Two-Layer Solver, substitution + width-8 transposition, 300,000 steps | 2.59 s | 1.23 s |
| Substitution Solver (13), default 1,058,000 steps | 5.82 s | 3.34 s |
| Keyed Columnar (45), every order of width 10, 300 letters | 16.1 s | 1.65 s |
| Double columnar (45), 6x6 exhaustive | 10.1 s | 0.64 s |
| Playfair annealing, 100,000 steps | 8.59 s | 0.44 s |
| Playfair dictionary, 440,375 keywords | 19.0 s | 1.1-1.3 s |
| Four-Square annealing, 200,000 steps | 4.95 s | 0.76 s |
| Bifid period 7, 200,000 steps | 6.50 s | 1.67 s |
| Hill 3x3 row attack, 300 letters | 1.45 s | 0.14 s |
| Autokey with a word list (447,407 primers) | 8.04 s | 0.11 s |
| Gromark Solver, 250 letters, full solve | 295 s | 16 s (10 workers) |
| Word Pattern Attack beam search | 0.07-0.27 s | 0.01-0.07 s |

Removed with the port: Playfair's memetic attack (it reached 9-15% of letters) and its duplicate dictionary modes (now one C keyword attack); the Hill exhaustive 2x2 mode (the row attack gives the same answer); the Python search modes of Gromark (known key) (genetic, annealing, hill-climbing, dictionary, key-length brute force), now tool 34; the separate swap-only column annealer (tool 32 before menu v2.1), merged into tool 44 as "Moves: 2 = swap only"; an unused dead Python Vigenère solver in tool 21.

GPU search uses OpenCL, which ships with the graphics driver (NVIDIA, AMD, Intel), so nothing else is installed. Results are identical to the CPU: GPU hits are sorted back into CPU order, and a launch whose hits overflow the GPU buffer is redone on the CPU. The fastest number of column orders per GPU work-item differs between GPUs; `native_tools.py gpu` measures it once per device and caches it. The GPU is used when enabled and the search is at least 9 columns wide; narrower searches are faster on the CPU. `CCT_GPU=1` enables it from the environment and `CCT_GPU_DEVICE=<text>` picks a GPU by name.

Measured on a laptop (Intel i7-1280P, NVIDIA T550 Laptop GPU, Intel UHD Graphics; one process; laptop timings vary with temperature):

| Search | Former Python | C | GPU |
|---|---|---|---|
| Brute force, width 8, 250 letters, 5-grams | 47,000 orders/s | 417,000 orders/s | - |
| Brute force, width 10, 250 letters, 5-grams | - | 378,000 orders/s | T550 455,000 orders/s, Intel UHD 1.5 million orders/s |
| Known plaintext, width 8, 97 letters, 24 key lengths, 16 alphabet/variant pairings | 11.6 s | 0.14 s | - |

The GPU's advantage on the n-gram brute force is small on these laptop GPUs; a desktop GPU has not been measured.

### Two-Layer Solver (menu 61)

Solves a ciphertext that was encrypted twice, for example a substitution followed by a columnar transposition. Every layer has its own key, and a single simulated-annealing search changes one layer's key per step while scoring the fully decrypted text with n-grams, so both keys are found together. Independent runs are spread across the worker processes set in Compute Settings, and the tool reports how many runs reached the same plaintext (agreement between independent runs is good evidence of a real solution).

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

Measured success per independent run on English text with the former Python engine (5 trials per row, 4 for the Vigenère-then-Substitution row; "solved" = at least 90% of letters correct; the C engine runs the same moves and schedule, and on one planted width-6 test solved 13 of 20 runs against 4 of 10 before). The tool's defaults are at least the budgets shown, and running several independent runs raises the chance that at least one succeeds:

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

Short texts (under ~200 letters) and wide transpositions are much harder; the tool warns below 150 letters.

### Annealing settings

The annealing solvers maximise mean n-gram log score × letter-entropy^0.5 (the Gromark Solver hill-climbs its alphabet on the same fitness and does not anneal). Because it is a mean, its scale does not depend on text length; measured single-move changes are about 0.5-2 points from a random key and 25-40 points near the correct key. Cooling geometrically from 20 to 0.1 therefore starts by accepting almost any move and ends as a hill climb; in tests the Substitution, Transposition and Vigenère solvers solved every test case with that schedule at their default 1.06 million steps (8/8 per row for substitution and transposition, 6/6 for Vigenère), so their settings are unchanged. Every C annealer cools to 0.1, from 20 by default (Playfair from 8, Bifid / Trifid from 10), and all but the Column-Order Solver (44) end with a hill-climbing polish; `scripts/annealing.py` keeps the shared definitions (fitness, schedule, defaults) that the C engines reproduce. Earlier versions of several solvers started at temperatures of 1000-10000 on a 0-255 cost scale where one move changes the score by roughly 1-20, so most of each run was a random walk.

---

## Installation

1. Clone the repository to your local machine:
   ```bash
   git clone [https://github.com/Dani-Navarr0/Cipher-Cracker-Toolkit-CCT-.git](https://github.com/Dani-Navarr0/Cipher-Cracker-Toolkit-CCT-.git)
   ```
2. Install zig's C compiler and build the C engines (needed once per machine; the solvers do not run without them):
   ```bash
   python -m pip install ziglang
   python scripts/native_tools.py build
   ```
   The launcher also offers to build them at start-up, and menu 91 builds them at any time.
3. Run the launcher from the repository root (Python 3.10 or newer; apart from `ziglang` for the build, standard library only):
   ```bash
   python main.py
   ```

In the launcher, use the arrow keys (or W/S) to move, Left/Right to switch column, PgUp/PgDn to jump between blocks, type a tool's number to jump to it (for example `44`), and press Enter to open it; `C` sets the session ciphertext, `N` moves to the next tool the analyzer recommended, `P` opens the compute settings, `H` shows help, `A` about and `Q` quits. Every tool fits on one screen from 120 columns x 30 rows (three columns); narrower or shorter terminals scroll.

**Compute settings (menu 92, key `P`).** At the first launch the toolkit shows the CPU, the threads available, free memory and any GPUs (once the C engines are built) and asks for a limit on worker processes for its searches. Later launches show the saved limit and priority in one line (Enter keeps it, `C` changes it). The presets are Light (a quarter of the threads), Balanced (half, the default) and Heavy (all but two), or any number; each worker also holds its own n-gram table (about 12 MB for 5-grams, 300 MB for 6-grams). Searches can run at below-normal priority (the default), which their worker processes inherit, so other programs stay responsive. The choice is saved per machine in `cct_settings.json` (git-ignored).

**Session ciphertext.** Press `C` in the launcher to set the ciphertext once (paste several lines, or give a `.txt` path). Every tool's ciphertext prompt then shows `[Enter = session ciphertext]`, so you press Enter instead of pasting again. Tool 1 (the analyzer) sets it automatically. When a ciphertext is pasted into a tool's prompt in an interactive terminal, the extra lines of a multi-line paste are read as part of the ciphertext instead of answering the next prompts. Ctrl+C inside a tool returns to the menu. Colours are defined once in `scripts/theme.py`; set the `NO_COLOR` environment variable to turn them off.

Optional: enable a GPU for the column-order searches (see "C engines (required) and GPU (OpenCL)" above).

The first time a solver loads the text-format 5-gram model it parses it (a few seconds) and caches a binary copy in `N-grams/.cache/`; later loads take well under a second. Delete that folder at any time to force a re-parse.

## Running the tests

```bash
python -m unittest discover -s tests -t .
```

Build the C engines first: without them most tests fail with `NativeUnavailable` (only some are skipped). The GPU tests are skipped when no OpenCL GPU is present.
