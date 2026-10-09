import sys
import os
import math
from functools import lru_cache
from typing import List, Dict, Tuple
from utils.utils import get_input_ciphertexts
from ngram_scoring import DEFAULT_NGRAM_PATH, load_ngram_scores, score_text

# ANSI color codes for terminal output
RED = '\033[38;5;88m'
YELLOW = '\033[38;5;3m'
GREY = '\033[38;5;238m'
RESET = '\033[0m'
GREEN = '\033[38;5;2m'
BLUE = '\033[34m'

ngram_path = DEFAULT_NGRAM_PATH

# --- SCORING FUNCTIONS ---

def calculate_ioc(text: str) -> float:
    """Calculates the Index of Coincidence for a given text."""
    text = text.upper()
    text = ''.join(filter(str.isalpha, text))
    n = len(text)
    if n < 2:
        return 0.0
    
    freqs = {}
    for char in text:
        freqs[char] = freqs.get(char, 0) + 1
        
    numerator = sum(count * (count - 1) for count in freqs.values())
    denominator = n * (n - 1)
    
    return numerator / denominator if denominator > 0 else 0.0

@lru_cache(maxsize=None)
def load_bigram_frequencies(file_path: str) -> Dict[str, float]:
    """Loads the configured English n-gram scores."""
    return load_ngram_scores(file_path)

def calculate_bigram_score(text: str, expected_freqs: Dict[str, float]) -> float:
    """Returns the lower-is-better score for the configured n-gram model."""
    return score_text(text, expected_freqs)

# --- CAESAR CIPHER FUNCTIONS ---

def caesar_decipher(ciphertext, shift, alphabet):
    """
    Decrypts text using a Caesar cipher with a given shift value.
    Note: A positive shift here means shifting the letters to the left (decryption).
    """
    decrypted_text = []
    alphabet_length = len(alphabet)
    
    for char in ciphertext:
        if char in alphabet:
            char_index = alphabet.index(char)
            # Apply the shift (subtract for decryption)
            decrypted_index = (char_index - shift + alphabet_length) % alphabet_length
            decrypted_char = alphabet[decrypted_index]
            decrypted_text.append(decrypted_char.lower())
        else:
            # Keep non-alphabet characters as they are
            decrypted_text.append(char.lower())
            
    return ''.join(decrypted_text)

def brute_force_caesar(ciphertext, alphabet):
    """
    Tries all possible shifts, scores them, and returns a ranked list of results.
    """
    print(f"\n{GREY}Loading 5-gram scoring data...{RESET}")
    expected_freqs = load_bigram_frequencies(ngram_path)

    results = []
    alphabet_length = len(alphabet)
    
    print(f"{GREY}Brute forcing {alphabet_length} possible shifts...{RESET}")

    for shift in range(alphabet_length):
        decrypted_text = caesar_decipher(ciphertext, shift, alphabet)
        ioc = calculate_ioc(decrypted_text)
        bigram_score = calculate_bigram_score(decrypted_text, expected_freqs)
        
        results.append({
            'shift': shift,
            'text': decrypted_text,
            'ioc': ioc,
            'bigram_score': bigram_score
        })
    
    # Sort results: primary key is n-gram score (lower is better), secondary key is IoC.
    results.sort(key=lambda x: (x['bigram_score'], -x['ioc']))
    
    return results

def save_caesar_results(filename, results):
    """Saves the full list of brute-force results to a text file."""
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("Caesar Cipher Brute-Force Results\n")
            f.write("===================================\n\n")
            for result in results:
                f.write(f"Shift: {result['shift']}\n")
                f.write(f"IoC Score: {result['ioc']:.4f}\n")
                f.write(f"N-gram Score: {result['bigram_score']:.2f}\n")
                f.write(f"Plaintext: {result['text']}\n")
                f.write("-" * 20 + "\n")
        print(f"{GREEN}Results successfully saved to {filename}{RESET}")
    except IOError as e:
        print(f"{RED}Error: Could not save file. {e}{RESET}")

# --- MAIN APPLICATION ---

def run():
    """Main function to run the Caesar decipher CLI."""
    print(f"{GREY}================================{RESET}")
    print(f"{RED}= CAESAR SHIFT SOLVER  ={RESET}")
    print(f"{GREY}================================{RESET}")
    print(f"{GREY}This tool decrypts a Caesar cipher using a specific key or by brute force.{RESET}")
    print(f"{GREY}-{RESET}" * 60)
    
    # Get user inputs
    ciphertexts = get_input_ciphertexts(prompt="Enter the ciphertext")

    if not ciphertexts:
        print(f"{RED}No input provided. Returning to menu.{RESET}")
        return

    alphabet_input = input(f"{RESET}Enter custom alphabet (press Enter for default {YELLOW}A-Z{RESET}): {GREEN}").upper()
    alphabet = alphabet_input if alphabet_input else "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    print(f"{RESET}Using alphabet: {YELLOW}{alphabet}{RESET}")
    
    # Display mode options
    print(f"\n{RESET}Choose a mode:")
    print(f"  ({YELLOW}1{RESET}) Decrypt with a specific shift value")
    print(f"  ({YELLOW}2{RESET}) Brute-force all possible shifts and rank results")
    
    mode_choice = input(f"Enter your choice (1 or 2): {GREEN}")
    print(f"{RESET}{GREY}-{RESET}" * 60)

# --- LOOP THROUGH EACH INPUT ---
    for i, current_text in enumerate(ciphertexts):
        current_text = current_text.upper()
        display_sample = current_text[:40] + "..." if len(current_text) > 40 else current_text
        
        print(f"\n{BLUE}=== Processing Input #{i+1}: {display_sample} ==={RESET}")

        if mode_choice == '1':
            while True:
                try:
                    shift_input = input(f"{RESET}Enter shift (e.g. 3): {GREEN}")
                    shift = int(shift_input)
                    decrypted = caesar_decipher(current_text, shift, alphabet)
                    print(f"{YELLOW}Result:{RESET} {decrypted}")
                    break
                except ValueError:
                    print(f"{RED}Invalid integer.{RESET}")
                    
        elif mode_choice == '2':
            results = brute_force_caesar(current_text, alphabet)
            print(f"{YELLOW}--- Top 3 Results ---{RESET}")
            for res in results[:3]:
                print(f"Shift {res['shift']:<2} | IoC: {res['ioc']:.4f} | N-gram: {res['bigram_score']:.2f} | {res['text'][:50]}...")
            
            # Optional: Auto-save functionality could go here
            
    print(f"\n{GREY}Batch processing complete.{RESET}")

if __name__ == "__main__":
    try:
        run()
    except (KeyboardInterrupt, EOFError):
        print(f"\n{GREY}Program exited.{RESET}")