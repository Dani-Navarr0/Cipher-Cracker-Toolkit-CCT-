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
* **Autoclave Cipher**
* **Running Key Cipher**
* **Playfair Cipher** (Includes Memetic Algorithm optimization)
* **Four-Square Cipher**
* **Affine Cipher**
* **Hill Cipher**
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
* **Rail Fence Cipher**

### 3. Advanced Cryptanalysis & Heuristics
The core strength of the CCT lies in its algorithmic approaches to cracking ciphers without knowing the key. Recent updates include a **Dynamic Fitness Engine** supporting Pure N-Gram, Pure IoC Tolerance, and Combined scoring to actively strip away layers of Double Ciphers. It uses the AZDecrypt library of N-Grams and language Spaces

* **Simulated Annealing (SA):** For completely random Simple Substitution and complex Polyalphabetic ciphers, with N-gram/IoC scoring.
* **Genetic Algorithms (GA):** Breeds and mutates generations of keys to crack highly complex systems like the Gromark Cipher.
* **Hill Climbing:** Unscrambles complex transpositions and polyalphabetic sequences by optimizing n-gram fitness.
* **Vigenère Auto-Solver:** Automated frequency analysis and key deduction for standard Vigenère ciphers.
* **Word Pattern Isomorphism:** Solves space-preserving substitution ciphers by mapping word shapes (e.g., `1-2-2-1-3-4`) against a dictionary (e.g., `ATTACK`).
* **Automated Crib Dragging:** "Drags" a suspected plaintext word across a ciphertext to reveal underlying key snippets.
* **Kasiski Examination:** Analyzes polyalphabetic ciphers to find repeating substrings and deduce the key length.
* **Friedman Test:** Mathematically estimates polyalphabetic key lengths using the Index of Coincidence (IoC).
* **Matrix Permutation Solver:** Generates and solves matrix-based permutations.
* **Two-Layer Solver:** Attacks ciphers made of two stacked layers (substitution, columnar transposition, Vigenère/Beaufort) with one joint annealing search. See below.

### N-Gram Scoring
Scoring tools load their English n-gram scores from the `N-grams` folder. The default is the included `5-grams_english_practicalcryptography_wortschatz.txt` model; configurable solvers also let you select sizes 2 through 6, using the corresponding English datasets in that folder. Higher source-file scores indicate more likely n-grams, and the TUI reports a lower-is-better scoring cost.

The substitution simulated-annealing solver can restore word spacing using the space-aware n-gram models under `N-grams/Spaces`. It discovers the available languages and reads each model's alphabet and n-gram size from its accompanying `.ini` file instead of relying on a built-in word list.

### 4. Utilities
* **Calculate IoC (Index of Coincidence):** Determines whether a cipher is monoalphabetic or polyalphabetic.
* **Frequency Analysis:** Plots character deviations against standard English text.
* **Keyword Alphabet Generator:** Generates mixed keyed alphabets.
* **Text Formatter:** Cleans and formats ciphertexts.
* **Matrix Generator:** Dumps all possible `n x m` permutations of a ciphertext string.

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

In the launcher, use the arrow keys (or W/S) to move, Left/Right to switch column, type a tool's number to jump to it (for example `37`), and press Enter to open it; `H` shows help and `Q` quits. Ctrl+C inside a tool returns to the menu. Colours are defined once in `scripts/theme.py`; set the `NO_COLOR` environment variable to turn them off.

The first time a solver loads the text-format 5-gram model it parses it (a few seconds) and caches a binary copy in `N-grams/.cache/`; later loads take well under a second. Delete that folder at any time to force a re-parse.

## Running the tests

```bash
python -m unittest discover -s tests -t .
```
