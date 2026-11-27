import os
import math
from typing import List, Dict
from ngram_scoring import DEFAULT_NGRAM_PATH, load_ngram_scores

# --- DUMMY UTILS CLASS (to make script standalone) ---
class DummyUtils:
    """Provides utility functions to make the script standalone."""
    def save_results_to_file(self, results: List[Dict], filename: str):
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("Scytale Cipher Brute-Force Results\n")
                f.write("=====================================\n\n")
                for result in results:
                    f.write(f"Key: {result['key']} grid columns (letters per turn)\n")
                    f.write(f"IoC Score: {result.get('ioc', 0):.4f}\n")
                    f.write(f"N-gram Score: {result.get('bigram_score', 0):.2f}\n")
                    f.write(f"Decrypted: {result['plaintext']}\n")
                    f.write("-" * 20 + "\n")
            print(f"{GREEN}Results successfully saved to {filename}{RESET}")
        except IOError as e:
            print(f"{RED}Error saving file: {e}{RESET}")

utils = DummyUtils()

# --- COLOR CODES AND PATHS ---
from theme import RED, GREEN, YELLOW, BLUE, CYAN, GREY, WHITE, RESET, banner

data_dir = os.path.join(os.path.dirname(__file__), "data")
ngram_path = DEFAULT_NGRAM_PATH

# --- SCORING FUNCTIONS ---
def calculate_ioc(text: str) -> float:
    """Calculates the Index of Coincidence for a given text."""
    text = ''.join(filter(str.isalpha, text.upper()))
    n = len(text)
    if n < 2: return 0.0
    freqs = {char: text.count(char) for char in set(text)}
    numerator = sum(count * (count - 1) for count in freqs.values())
    denominator = n * (n - 1)
    return numerator / denominator if denominator > 0 else 0.0

# --- SCYTALE CORE FUNCTIONS ---

def decrypt_scytale(ciphertext: str, sides: int) -> str:
    """
    Decrypts a Scytale cipher by simulating wrapping the text around a rod.
    The number of 'sides' is equivalent to the number of columns in the grid.
    """
    if not isinstance(sides, int) or sides <= 1:
        return ""
        
    n = len(ciphertext)
    if n == 0:
        return ""
        
    # The number of rows is determined by how many full 'wraps' are made.
    rows = math.ceil(n / sides)
    
    # Calculate how many columns are 'full' vs. 'short'.
    num_full_cols = n % sides
    if num_full_cols == 0 and n > 0:
        num_full_cols = sides
        
    grid = [['' for _ in range(sides)] for _ in range(rows)]
    
    text_idx = 0
    # Fill the grid column by column
    for col in range(sides):
        # The first `num_full_cols` have `rows` characters. The rest have `rows - 1`.
        rows_in_this_col = rows if col < num_full_cols else rows - 1
        
        for row in range(rows_in_this_col):
            if text_idx < n:
                grid[row][col] = ciphertext[text_idx]
                text_idx += 1
    
    # Read the plaintext row by row to decrypt.
    plaintext = "".join(grid[row][col] for row in range(rows) for col in range(sides))
    
    return plaintext


def brute_force_scytale(ciphertext: str):
    """
    Tries all possible numbers of sides (2..len-1) for the Scytale and ranks the
    results (C engine: every reading generated and scored in native code).
    Every side count gives a distinct reading (sides above len/2 are NOT
    redundant: they produce different short final columns). A reading is the
    grid route 'columns_down' read back, i.e. transposition_core's
    write_rows_read_cols layout with the identity column order (tested).
    'bigram_score' is ngram_scoring.score_text's cost, 255 - mean n-gram score
    over the letters (lower is better); the IoC is the same for every reading.
    """
    import native
    from native.screens import COLUMNAR, FORWARD, LAYOUTS, Sources, record_of, symbol_codes
    native.require()
    model = load_ngram_scores(str(ngram_path))
    codes, shown, decode = symbol_codes(ciphertext)
    n = len(codes)
    sources = Sources(n)
    for sides in range(2, n):
        sources.add(COLUMNAR, (sides, LAYOUTS["write_rows_read_cols"]), meta=("scytale", sides))
    print(f"{GREY}Brute forcing {max(0, n - 2)} possible key diameters...{RESET}")
    # factor 1: the C score is the mean n-gram score itself (score_text's measure)
    _, scored = sources.score(codes, _MeanScore(model), text=FORWARD)
    plains = sources.plain(shown, [ident for _, ident in scored])
    ioc = calculate_ioc(ciphertext)
    results = [{'key': sources.meta[record_of(ident)][1],
                'plaintext': decode(plain), 'ioc': ioc,
                'bigram_score': float("inf") if mean == -9999.0 else 255 - mean}
               for (mean, ident), plain in zip(scored, plains)]
    # lower cost first; ties keep the side-count order (the IoC is constant)
    results.sort(key=lambda x: (x['bigram_score'], -x['ioc']))
    return results


class _MeanScore:
    """Fitness parameters for the C screen with factor 1 (mean n-gram score)."""

    def __init__(self, model):
        self.scores, self.size, self.entropy_weight, self.fixed_factor = model.scores, model.size, 0.0, 1.0

# --- MAIN APPLICATION ---

def run():
    """Main function to run the Scytale cipher tool CLI."""
    banner("Scytale Cipher", "Ancient Greek rod transposition")
    
    ciphertext = input(f"Enter the ciphertext: {GREEN}").upper().replace(" ", "")
    
    print(f"\n{RESET}Choose a mode:")
    print(f"  ({YELLOW}1{RESET}) Decrypt with a specific key")
    print(f"  ({YELLOW}2{RESET}) Try every key and rank the results")
    print(f"{GREY}The key here is the number of grid columns (letters per turn of the strip). Some descriptions "
          f"give the other dimension, the number of rows (turns around the rod); results show both.{RESET}")
    
    mode_choice = input(f"Enter your choice (1 or 2): {GREEN}")
    print(f"{RESET}{GREY}-{RESET}" * 60)

    if mode_choice == '1':
        while True:
            try:
                sides = int(input(f"{RESET}Enter the key (grid columns): {GREEN}"))
                if sides <= 1:
                    print(f"{RED}The number of columns must be greater than 1.{RESET}")
                    continue

                plaintext = decrypt_scytale(ciphertext, sides)

                print(f"\n{YELLOW}Ciphertext:{RESET} {ciphertext}")
                print(f"{YELLOW}Key:{RESET} {sides} columns, {math.ceil(len(ciphertext) / sides)} rows")
                print(f"{YELLOW}Decrypted Text:{RESET} {plaintext}")
                break
            except ValueError:
                print(f"{RED}Invalid input. Please enter an integer.{RESET}")
            except (KeyboardInterrupt, EOFError):
                print(f"\n{GREY}Program exited.{RESET}")
                return

    elif mode_choice == '2':
        results = brute_force_scytale(ciphertext)
        
        if not results:
            print(f"{RED}Could not generate any brute-force results.{RESET}")
            return
            
        print(f"{YELLOW}--- Top 10 Brute-Force Results (Best First) ---{RESET}")
        for i, result in enumerate(results[:10]):
            color = GREEN if i == 0 else ""
            rows = math.ceil(len(result['plaintext']) / result['key'])
            print(f"{color}Columns: {result['key']:<3} rows: {rows:<3} | IoC: {result['ioc']:.4f} | N-gram Score: {result['bigram_score']:.2f} | Text: {result['plaintext']}{RESET}")

        save_choice = input(f"\n{GREY}Save all {len(results)} results to a file? ({YELLOW}Y/N{RESET}): {GREEN}").upper()
        if save_choice == 'Y':
            filename = input(f"{RESET}Enter filename (default: scytale_results.txt): {GREEN}") or "scytale_results.txt"
            utils.save_results_to_file(results, filename)
    
    else:
        print(f"{RED}Invalid choice. Please run the script again and select 1 or 2.{RESET}")

    print(f"\n{GREY}Program finished.{RESET}")

if __name__ == "__main__":
    # Create dummy data file if it doesn't exist for standalone execution
    if not os.path.exists(data_dir):
        os.makedirs(data_dir)

    try:
        run()
    except (KeyboardInterrupt, EOFError):
        print(f"\n{GREY}Program exited.{RESET}")
