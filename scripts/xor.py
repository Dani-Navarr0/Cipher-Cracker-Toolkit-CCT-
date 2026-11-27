import os
import datetime
import re
from utils import utils
import attack_support
from ngram_scoring import load_ngram_scores
from native import periodic_engine

KEEP_OUTSIDE_WINDOW = 25

# ANSI color codes for terminal output
from theme import RED, GREEN, YELLOW, BLUE, CYAN, GREY, WHITE, RESET, banner

# Hardcoded path for words_alpha.txt
WORDLIST_PATH = os.path.join(os.path.dirname(__file__), "data", "words_alpha.txt")

def parse_input(input_text, input_format='string'):
    """Parse input based on the specified format."""
    if input_format == 'string':
        return [ord(c) for c in input_text]
    elif input_format == 'decimal':
        return [int(x) for x in input_text.split() if x.strip()]
    elif input_format == 'hex':
        # Remove any non-hex characters and spaces
        clean_hex = re.sub(r'[^0-9A-Fa-f]', ' ', input_text)
        # Split by spaces and convert each hex value
        return [int(x, 16) for x in clean_hex.split() if x.strip()]
    return []

def xor_values(message_values, key):
    """XOR each value in the message with the corresponding character of the key."""
    # Extend the key if necessary to match the message length
    if len(key) < len(message_values):
        key = key * (len(message_values) // len(key) + 1)
    key = key[:len(message_values)]
    
    # Perform XOR operation
    result = []
    for m_val, k_char in zip(message_values, key):
        # XOR the value with the ASCII of the key character
        xor_value = m_val ^ ord(k_char)
        result.append(xor_value)
    
    return result

def get_ascii_result(xor_result):
    """Convert XOR result to ASCII characters (Filters out non-printable control characters)."""
    return ''.join(chr(x) for x in xor_result if 32 <= x <= 126)

def print_colored_output(input_data, input_format, key, xor_result, ascii_result=None, ioc_ascii=None):
    """Print the results with color formatting."""
    print(f"\n{GREY}Input data ({input_format}):{RESET} {input_data}")
    print(f"{GREY}Key used:{RESET} {key}")
    
    # Display raw XOR result
    print(f"\n{RED}XOR Result (decimal):{RESET}")
    print(" ".join(f"{x:3d}" for x in xor_result))
    
    # Display hex representation
    print(f"\n{RED}XOR Result (hex):{RESET}")
    print(" ".join(f"{x:02X}" for x in xor_result))
    
    # Display printable character representation
    print(f"\n{YELLOW}XOR Result (Printable ASCII):{RESET}")
    print(ascii_result if ascii_result else "[No printable characters found]")
    if ioc_ascii is not None and ascii_result:
        print(f"{BLUE}ASCII IoC:{RESET} {ioc_ascii:.6f}")

CHUNK_WORDS = 20_000               # words per C call (one thread each)


def brute_force_with_ioc(ciphertext, min_ioc=0.065, max_ioc=0.07, perform_freq_analysis=False, freq_threshold=45.0):
    """Try each word in the wordlist as a key, filter by IoC for ASCII results.

    The XOR, the printable-ASCII filter, the IoC and the n-gram cost of every
    word run in C (cct_xor_dict); kept are the IoC-window hits and the
    KEEP_OUTSIDE_WINDOW most English-like non-blank results outside it."""
    if not os.path.exists(WORDLIST_PATH):
        print(f"{RED}Error: '{WORDLIST_PATH}' not found in the current directory.{RESET}")
        return []
    try:
        words, keys = attack_support.read_ascii_keys(WORDLIST_PATH)
    except Exception as e:
        print(f"{RED}Error reading wordlist: {e}{RESET}")
        return []

    model = load_ngram_scores()
    total_words = len(words)
    # Values outside 0-127 can never XOR (with an ASCII key) to printable text.
    message = bytes(value if 0 <= value < 128 else 255 for value in ciphertext)

    print(f"\n{YELLOW}Starting brute force with {total_words} words (C engine)...{RESET}")
    print(f"\n-{GREY}IoC filter range: {min_ioc} to {max_ioc} (plus the {KEEP_OUTSIDE_WINDOW} most English-like "
          f"results outside it; ranked by n-gram cost){RESET}")
    if perform_freq_analysis:
        print(f"-{GREY}Frequency analysis will be performed (threshold: {freq_threshold}){RESET}")
    print(f"{YELLOW}Testing uppercase versions of each word...{RESET}")

    chunks = [(first, min(CHUNK_WORDS, total_words - first)) for first in range(0, total_words, CHUNK_WORDS)]
    parts = attack_support.parallel_chunks(
        lambda chunk: periodic_engine.xor_dict(message, keys, chunk[0], chunk[1], model, min_ioc, max_ioc,
                                               KEEP_OUTSIDE_WINDOW),
        chunks, lambda done, total: print(f"{GREY}Progress: {RED}{done}{RESET}/{YELLOW}{total}{RESET} parts "
                                          f"checked...{RESET}", end='\r'))
    window, outside, checked = [], [], 0
    for (first, count), part in zip(chunks, parts):
        if part is not None:
            window += part[0]
            outside += part[1]
            checked += count
    window.sort()
    # The most English-like outside the window over all chunks (later word wins a tie, as before).
    outside = sorted(outside, key=lambda row: (row[1], -row[0]))[:KEEP_OUTSIDE_WINDOW]
    outside.sort(key=lambda row: (row[1], row[0]))

    print(f"{GREY}Completed! {checked} words checked.{RESET}                ")
    results, costs = [], {}
    for index, cost, ioc_ascii in window:
        test_word = words[index]
        costs[test_word] = cost
        ascii_result = get_ascii_result(xor_values(ciphertext, test_word))
        if perform_freq_analysis:
            freq_analysis, likeness_score = utils.analyze_frequency(ascii_result)
            if likeness_score <= freq_threshold:
                results.append((test_word, "ASCII", ascii_result, ioc_ascii, freq_analysis, likeness_score))
        else:
            results.append((test_word, "ASCII", ascii_result, ioc_ascii, "", float('inf')))
    for index, cost, ioc_ascii in outside:
        test_word = words[index]
        costs[test_word] = cost
        ascii_result = get_ascii_result(xor_values(ciphertext, test_word))
        results.append((test_word, "ASCII", ascii_result, ioc_ascii, "", float('inf')))

    # Frequency-analysis score first if requested, then n-gram cost (lower = more English).
    if perform_freq_analysis:
        results.sort(key=lambda x: (x[5], costs.get(x[0], 255)))
    else:
        results.sort(key=lambda x: costs.get(x[0], 255))

    return results

def run():
    banner("XOR Cipher", "String XOR decryption with IoC brute force")
    
    mode = input(f"\n{GREY}Choose mode ({RESET}{YELLOW}1 = Encrypt/Decrypt{RESET}{GREY},{RESET} {YELLOW}2 = IoC Brute Force{RESET}{GREY}): {RESET}")
    
    if mode == '1':
        # Encryption/Decryption mode
        input_format = input(f"\n{GREY}Input format ({RESET}{YELLOW}1 = string{RESET}{GREY},{RESET} {YELLOW}2 = decimal{RESET}{GREY},{RESET} {YELLOW}3 = hex{RESET}{GREY}): {RESET}")
        
        if input_format == '1':
            input_format = 'string'
            input_data = input(f"{GREY}Enter the text: {RESET}")
        elif input_format == '2':
            input_format = 'decimal'
            input_data = input(f"{GREY}Enter the decimal values (space-separated): {RESET}")
        elif input_format == '3':
            input_format = 'hex'
            input_data = input(f"{GREY}Enter the hex values (space-separated): {RESET}")
        else:
            print(f"{RED}Invalid format, defaulting to string.{RESET}")
            input_format = 'string'
            input_data = input(f"{GREY}Enter the text: {RESET}")
        
        key = input(f"{GREY}Enter the key (must be an ASCII text string): {RESET}")
        
        try:
            input_values = parse_input(input_data, input_format)
            
            if not input_values:
                print(f"{RED}Error: No valid input data found.{RESET}")
                return
                
            # Perform XOR operation
            xor_result = xor_values(input_values, key)
            
            # Extract printable ASCII
            ascii_result = get_ascii_result(xor_result)
            ioc_ascii = utils.calculate_ioc(ascii_result) if ascii_result else 0.0
            
            print_colored_output(input_data, input_format, key, xor_result, ascii_result, ioc_ascii)
                
            # Option to perform frequency analysis on ASCII
            if ascii_result:
                freq_option = input(f"\n{GREY}Perform frequency analysis on readable result? (y/n): {RESET}").lower()
                if freq_option == 'y':
                    analysis, _ = utils.analyze_frequency(ascii_result)
                    print(analysis)
                    
            # Ask if user wants to save XOR result for later use (for decrypt)
            save_option = input(f"\n{GREY}Save XOR result for later decryption? (y/n): {RESET}").lower()
            if save_option == 'y':
                save_format = input(f"{GREY}Save as ({RESET}{YELLOW}1 = decimal{RESET}{GREY},{RESET} {YELLOW}2 = hex{RESET}{GREY}): {RESET}")
                
                if save_format == '1':
                    result_str = " ".join(str(x) for x in xor_result)
                else:
                    result_str = " ".join(f"{x:02X}" for x in xor_result)
                    
                filename = input(f"{GREY}Enter filename: {RESET}")
                if not filename:
                    filename = "xor_result.txt"
                    
                try:
                    with open(filename, 'w') as f:
                        f.write(result_str)
                    print(f"{GREEN}Result saved to '{filename}'.{RESET}")
                except Exception as e:
                    print(f"{RED}Error saving file: {e}{RESET}")
                    
            # Ask if user wants to immediately decrypt with same key to verify
            verify_option = input(f"\n{GREY}Verify XOR reversibility with same key? (y/n): {RESET}").lower()
            if verify_option == 'y':
                verify_result = xor_values(xor_result, key)
                verify_ascii = get_ascii_result(verify_result)
                
                print(f"\n{YELLOW}Verification Result:{RESET}")
                print(f"{GREY}Original Input:{RESET} {input_data}")
                print(f"{GREY}After Double XOR:{RESET} {verify_ascii}")
                
                if input_format == 'string':
                    if verify_ascii == input_data:
                        print(f"{GREEN}VERIFIED: Double XOR produced original text.{RESET}")
                    else:
                        print(f"{RED}WARNING: Double XOR did not reproduce original text.{RESET}")
                else:
                    print(f"{YELLOW}NOTE: For non-string inputs, manual verification is needed.{RESET}")
                
        except Exception as e:
            print(f"{RED}Error during XOR operation: {e}{RESET}")
    
    elif mode == '2':
        # Brute force mode
        input_format = input(f"\n{GREY}Input format ({RESET}{YELLOW}1 = string{RESET}{GREY},{RESET} {YELLOW}2 = decimal{RESET}{GREY},{RESET} {YELLOW}3 = hex{RESET}{GREY}): {RESET}")
        
        if input_format == '1':
            input_format = 'string'
            ciphertext_input = input(f"{GREY}Enter the ciphertext to crack: {RESET}")
        elif input_format == '2':
            input_format = 'decimal'
            ciphertext_input = input(f"{GREY}Enter the decimal values (space-separated): {RESET}")
        elif input_format == '3':
            input_format = 'hex'
            ciphertext_input = input(f"{GREY}Enter the hex values (space-separated): {RESET}")
        else:
            print(f"{RED}Invalid format, defaulting to string.{RESET}")
            input_format = 'string'
            ciphertext_input = input(f"{GREY}Enter the ciphertext to crack: {RESET}")
        
        try:
            ciphertext = parse_input(ciphertext_input, input_format)
            
            if not ciphertext:
                print(f"{RED}Error: No valid input data found.{RESET}")
                return
            
            min_ioc = 0.065
            max_ioc = 0.07
            
            custom_ioc = input(f"{GREY}Use default IoC range (0.065-0.07)? (y/n): {RESET}").lower()
            if custom_ioc == 'n':
                try:
                    min_ioc = float(input(f"{GREY}Enter minimum IoC value: {RESET}"))
                    max_ioc = float(input(f"{GREY}Enter maximum IoC value: {RESET}"))
                except ValueError:
                    print(f"{RED}Invalid IoC values, using defaults.{RESET}")
            
            perform_freq = input(f"{GREY}Perform frequency analysis to find English-like text? (y/n): {RESET}").lower()
            perform_freq_analysis = perform_freq == 'y'
            
            freq_threshold = 45.0
            if perform_freq_analysis:
                try:
                    custom_threshold = input(f"{GREY}Use default frequency deviation threshold (45.0)? (y/n): {RESET}").lower()
                    if custom_threshold == 'n':
                        freq_threshold = float(input(f"{GREY}Enter frequency deviation threshold (lower values = more English-like): {RESET}"))
                except ValueError:
                    print(f"{RED}Invalid threshold, using default.{RESET}")
            
            results = brute_force_with_ioc(ciphertext, min_ioc, max_ioc, perform_freq_analysis, freq_threshold)
            
            if results:
                print(f"\n{GREEN}Found {len(results)} potential matches:{RESET}")
                
                display_count = min(10, len(results))
                for i, (key, result_type, result_text, ioc, freq_analysis, likeness_score) in enumerate(results[:display_count]):
                    print(f"\n{YELLOW}Match #{i+1}:{RESET}")
                    print(f"{GREY}Key:{RESET} {key}")
                    print(f"{GREY}Decrypted text:{RESET} {result_text}")
                    print(f"{GREY}IoC:{RESET} {ioc:.6f}")
                    if perform_freq_analysis:
                        print(f"{GREY}English Likeness Score:{RESET} {likeness_score:.2f} (lower is better)")
                    
                print(f"\n{GREEN}Total matches found: {len(results)}{RESET}")
                
                if perform_freq_analysis and len(results) > 0:
                    see_details = input(f"\n{GREY}View frequency analysis for a specific match? (Enter match # or 'n'): {RESET}")
                    if see_details.isdigit() and 1 <= int(see_details) <= len(results):
                        match_idx = int(see_details) - 1
                        print(results[match_idx][4]) 
                
                save_option = input(f"\n{GREY}Save results to a file? (y/n): {RESET}").lower()
                if save_option == 'y':
                    filename = input(f"{GREY}Enter filename (default: xor_results.txt): {RESET}")
                    if not filename.strip():
                        filename = "xor_results.txt"
                    utils.save_to_file_xor(results, filename)
            else:
                print(f"\n{RED}No matches found within the specified criteria.{RESET}")
        except Exception as e:
            print(f"{RED}Error during brute force: {e}{RESET}")
    
    else:
        print(f"{RED}Invalid mode selected.{RESET}")
    
    print(f"\n{RED}======================================{RESET}")

if __name__ == "__main__":
    run()