import os
import datetime
import re
from utils import utils
import attack_support
from ngram_scoring import load_ngram_scores, score_text
from native import periodic_engine

KEEP_OUTSIDE_WINDOW = 25

# ANSI color codes for terminal output
from theme import RED, GREEN, YELLOW, BLUE, CYAN, GREY, WHITE, RESET, banner

# Hardcoded path for words_alpha.txt
WORDLIST_PATH = os.path.join(os.path.dirname(__file__), "data", "words_alpha.txt")

def parse_input(input_text, input_format='string', custom_alphabet=None):
    """Parse input based on the specified format and alphabet."""
    if input_format == 'string':
        if custom_alphabet:
            return [custom_alphabet.find(c.upper()) if c.upper() in custom_alphabet else -1 for c in input_text]
        else:
            # Always parses to a 0-indexed value (A=0, B=1, ...)
            return [ord(c.upper()) - ord('A') if c.isalpha() else -1 for c in input_text]
    elif input_format == 'decimal':
        return [int(x) for x in input_text.split() if x.strip()]
    elif input_format == 'hex':
        clean_hex = re.sub(r'[^0-9A-Fa-f]', ' ', input_text)
        return [int(x, 16) for x in clean_hex.split() if x.strip()]
    return []

def modular_operation(message_values, key, operation='add', modulus=26, base_index=0):
    """
    Perform modular addition or subtraction of the message with the key.
    Note: All internal calculations are done 0-indexed (A=0).
    The base_index is a display concern handled elsewhere.
    """
    # Letters of a text key only (a space or digit is not a shift), and the key
    # advances only on message symbols, not on the spaces kept as -1.
    if isinstance(key, str):
        key = [ord(ch) - ord('A') for ch in key.upper() if 'A' <= ch <= 'Z']
    if not key:
        return list(message_values)

    result = []
    position = 0
    for m_val in message_values:
        if m_val == -1:
            result.append(-1)
            continue

        k_val = key[position % len(key)]
        position += 1
        
        # <<< CHANGE START: Removed incorrect base_index adjustments.
        # All calculations are now performed on the direct 0-indexed values.
        if operation == 'add':
            op_result = (m_val + k_val) % modulus
        else:  # subtract
            # Added modulus to handle potential negative results correctly
            op_result = (m_val - k_val + modulus) % modulus
            
        # The result is kept 0-indexed.
        result.append(op_result)
        # <<< CHANGE END
            
    return result

def map_to_alphabet(mod_result, custom_alphabet=None, base_index=0):
    """Map modular result to alphabet (either custom or A-Z)."""
    result = []
    for value in mod_result:
        if value == -1:
            result.append(' ')
        else:
            # <<< CHANGE: Removed incorrect subtraction of base_index.
            # The 'value' is already 0-indexed and ready for mapping.
            if custom_alphabet:
                if 0 <= value < len(custom_alphabet):
                    result.append(custom_alphabet[value])
                else:
                    result.append(' ')
            else:
                result.append(chr(65 + value))
    return ''.join(result)

def print_colored_output(input_data, input_format, key, mod_result, alphabet_result, operation, modulus, base_index, custom_alphabet=None, ioc=None):
    """Print the results with color formatting."""
    print(f"\n{GREY}Input data ({input_format}):{RESET} {input_data}")
    print(f"{GREY}Key used:{RESET} {key}")
    print(f"{GREY}Operation:{RESET} Modular {operation}")
    print(f"{GREY}Modulus:{RESET} {modulus} (Base index: {base_index})")
    
    if custom_alphabet:
        print(f"{GREY}Custom alphabet:{RESET} {custom_alphabet}")
    
    print(f"\n{RED}Modular Result (numeric):{RESET}")
    # <<< CHANGE: Added base_index here for display purposes only.
    print(" ".join(f"{x + base_index:3d}" if x != -1 else "   " for x in mod_result))
    
    print(f"\n{RED}Result (text):{RESET} {alphabet_result}")
    
    if ioc is not None:
        print(f"{BLUE}IoC:{RESET} {ioc:.6f}")

CHUNK_WORDS = 20_000               # words per C call (one thread each)
MAX_MODULUS = 0x10FFFF - 64          # chr(65 + value) must exist for every value below the modulus


def _modular_tables(ciphertext, operation, modulus, custom_alphabet, model):
    """How the C engine sees this attack: the key value of each ASCII key
    character (default: A-Z letters only, other characters ignored; custom
    alphabet: its index, and a word with any other character is skipped), the
    character each result value 0..modulus-1 is shown as (map_to_alphabet),
    and, for words with no key letters (modular_operation then leaves the
    message as it is), the cost/IoC/blankness of that unchanged text."""
    if custom_alphabet:
        keymap = [custom_alphabet.find(chr(code)) if chr(code) in custom_alphabet else -2 for code in range(128)]
        characters = [custom_alphabet[value] if value < len(custom_alphabet) else ' ' for value in range(modulus)]
    else:
        keymap = [code - 65 if 65 <= code <= 90 else -1 for code in range(128)]
        characters = [chr(65 + value) for value in range(modulus)]
    try:
        text = map_to_alphabet(list(ciphertext), custom_alphabet)
        identity = (score_text(text, model), utils.calculate_ioc(text), not text.strip())
    except (ValueError, OverflowError):     # a value chr() cannot show: those words are skipped
        identity = None
    return periodic_engine.ModularTables(modulus, operation != 'add', keymap, characters, identity)


def brute_force_with_ioc(ciphertext, operation, modulus, base_index, custom_alphabet=None, min_ioc=0.065, max_ioc=0.07, perform_freq_analysis=False, freq_threshold=45.0):
    """Try each word in the wordlist as a key, filter by IoC.

    The modular operation, the IoC and the n-gram cost of every word run in C
    (cct_modular_dict); kept are the IoC-window hits and the
    KEEP_OUTSIDE_WINDOW most English-like results outside it."""
    if not os.path.exists(WORDLIST_PATH):
        print(f"{RED}Error: '{WORDLIST_PATH}' not found in the current directory.{RESET}")
        return []
    if not 1 <= modulus <= MAX_MODULUS:
        print(f"{RED}The modulus must be between 1 and {MAX_MODULUS:,}.{RESET}")
        return []
    try:
        words, keys = attack_support.read_ascii_keys(WORDLIST_PATH)
    except Exception as e:
        print(f"{RED}Error reading wordlist: {e}{RESET}")
        return []

    custom_alphabet = custom_alphabet or None
    model = load_ngram_scores()
    total_words = len(words)
    tables = _modular_tables(ciphertext, operation, modulus, custom_alphabet, model)
    message = [-1 if value == -1 else value % modulus for value in ciphertext]

    print(f"\n{YELLOW}Starting brute force with {total_words} words (C engine)...{RESET}")
    print(f"\n-{GREY}IoC filter range: {min_ioc} to {max_ioc} (plus the {KEEP_OUTSIDE_WINDOW} most English-like "
          f"results outside it; ranked by n-gram cost){RESET}")
    print(f"-{GREY}Modular {operation} with modulus {modulus} (Base index: {base_index}){RESET}")
    if custom_alphabet:
        print(f"-{GREY}Using custom alphabet: {custom_alphabet}{RESET}")
    if perform_freq_analysis:
        print(f"-{GREY}Frequency analysis will be performed (threshold: {freq_threshold}){RESET}")

    chunks = [(first, min(CHUNK_WORDS, total_words - first)) for first in range(0, total_words, CHUNK_WORDS)]
    parts = attack_support.parallel_chunks(
        lambda chunk: periodic_engine.modular_dict(message, tables, keys, chunk[0], chunk[1], model, min_ioc, max_ioc,
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

    def text_for(test_word):
        if custom_alphabet:
            key = [custom_alphabet.find(c) for c in test_word]
        else:
            key = test_word
        return map_to_alphabet(modular_operation(ciphertext, key, operation, modulus, base_index), custom_alphabet,
                               base_index)

    results, costs = [], {}
    for index, cost, ioc in window:
        test_word = words[index]
        costs[test_word] = cost
        result_text = text_for(test_word)
        if perform_freq_analysis:
            freq_analysis, likeness_score = utils.analyze_frequency(result_text)
            if likeness_score <= freq_threshold:
                results.append((test_word, "Modular", result_text, ioc, freq_analysis, likeness_score))
        else:
            results.append((test_word, "Modular", result_text, ioc, "", float('inf')))
    for index, cost, ioc in outside:
        test_word = words[index]
        costs[test_word] = cost
        results.append((test_word, "Modular", text_for(test_word), ioc, "", float('inf')))

    # Frequency-analysis score first if requested, then n-gram cost (lower = more English).
    if perform_freq_analysis:
        results.sort(key=lambda x: (x[5], costs.get(x[0], 255)))
    else:
        results.sort(key=lambda x: costs.get(x[0], 255))

    return results

def run():
    banner("Modular Add / Subtract", "Combine text with a key by modular arithmetic")
    
    # Ask if user wants to use a custom alphabet
    custom_alphabet_option = input(f"\n{GREY}Use custom alphabet? (y/n): {RESET}").lower()
    custom_alphabet = None
    if custom_alphabet_option == 'y':
        custom_alphabet_input = input(f"{GREY}Enter custom alphabet (e.g., KRYPTOSABCDEFGHIJLMNQUVWXZ): {RESET}").upper()
        if custom_alphabet_input:
            custom_alphabet = custom_alphabet_input
            print(f"{YELLOW}Using custom alphabet: {custom_alphabet}{RESET}")
            print(f"{GREY}Modulus will be set to alphabet length: {len(custom_alphabet)}{RESET}")
            modulus = len(custom_alphabet)
        else:
            print(f"{RED}No custom alphabet provided, using standard A-Z.{RESET}")
            modulus = 26
    else:
        modulus = 26  # Default modulus for A-Z
    
    # Ask for base index (0 or 1)
    base_index_option = input(f"{GREY}Use which base index? (0=A-Z is 0-25, 1=A-Z is 1-26): {RESET}")
    if base_index_option == '1':
        base_index = 1
    else:
        base_index = 0
    
    mode = input(f"\n{GREY}Choose mode ({RESET}{YELLOW}1 = Encrypt/Decrypt{RESET}{GREY},{RESET} {YELLOW}2 = IoC Brute Force{RESET}{GREY}): {RESET}")
    
    if mode == '1':
        # Encryption/Decryption mode
        operation = input(f"\n{GREY}Operation ({RESET}{YELLOW}1 = add (encrypt){RESET}{GREY},{RESET} {YELLOW}2 = subtract (decrypt){RESET}{GREY}): {RESET}")
        operation = 'add' if operation == '1' else 'subtract'
        
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
        
        key = input(f"{GREY}Enter the key: {RESET}")
        
        # Parse input based on format
        try:
            input_values = parse_input(input_data, input_format, custom_alphabet)
            
            if not input_values or all(v == -1 for v in input_values):
                print(f"{RED}Error: No valid input data found or characters not in alphabet.{RESET}")
                return
            
            # Convert key to values if using custom alphabet
            if custom_alphabet and input_format == 'string':
                key_values = [custom_alphabet.find(c.upper()) if c.upper() in custom_alphabet else -1 for c in key]
                if -1 in key_values:
                    print(f"{RED}Warning: Some key characters are not in the custom alphabet.{RESET}")
                mod_result = modular_operation(input_values, key_values, operation, modulus, base_index)
            else:
                mod_result = modular_operation(input_values, key, operation, modulus, base_index)
            
            # Map to alphabet
            alphabet_result = map_to_alphabet(mod_result, custom_alphabet, base_index)
            
            # Calculate IoC
            ioc = utils.calculate_ioc(alphabet_result)
            
            # Print results
            print_colored_output(input_data, input_format, key, mod_result, alphabet_result, operation, modulus, base_index, custom_alphabet, ioc)
            
            # Option to perform frequency analysis
            freq_option = input(f"\n{GREY}Perform frequency analysis? (y/n): {RESET}").lower()
            if freq_option == 'y':
                analysis, _ = utils.analyze_frequency(alphabet_result)
                print(analysis)
            
            # Ask if user wants to save result
            save_option = input(f"\n{GREY}Save result? (y/n): {RESET}").lower()
            if save_option == 'y':
                save_format = input(f"{GREY}Save as ({RESET}{YELLOW}1 = text{RESET}{GREY},{RESET} {YELLOW}2 = numeric{RESET}{GREY}): {RESET}")
                
                if save_format == '1':
                    result_str = alphabet_result
                else:
                    result_str = " ".join(str(x) for x in mod_result if x != -1)
                    
                filename = input(f"{GREY}Enter filename: {RESET}")
                if not filename:
                    filename = "modular_result.txt"
                    
                try:
                    with open(filename, 'w') as f:
                        f.write(result_str)
                    print(f"{GREEN}Result saved to '{filename}'.{RESET}")
                except Exception as e:
                    print(f"{RED}Error saving file: {e}{RESET}")
            
            # Ask if user wants to immediately verify with reverse operation
            verify_option = input(f"\n{GREY}Verify reversibility with opposite operation? (y/n): {RESET}").lower()
            if verify_option == 'y':
                # Apply opposite operation
                reverse_op = 'subtract' if operation == 'add' else 'add'
                
                # Convert key to values if using custom alphabet
                if custom_alphabet and input_format == 'string':
                    reverse_result = modular_operation(mod_result, key_values, reverse_op, modulus, base_index)
                else:
                    reverse_result = modular_operation(mod_result, key, reverse_op, modulus, base_index)
                
                # Map back to original alphabet
                reverse_text = map_to_alphabet(reverse_result, custom_alphabet, base_index)
                
                print(f"\n{YELLOW}Verification Result:{RESET}")
                print(f"{GREY}Original Input:{RESET} {input_data}")
                print(f"{GREY}After Reverse Operation:{RESET} {reverse_text}")
                
                if input_format == 'string':
                    # Compare handling non-alphabet characters
                    orig_text = ''.join(c if custom_alphabet is None or c.upper() in custom_alphabet else ' ' 
                                    for c in input_data.upper())
                    if reverse_text.replace(' ', '') == orig_text.replace(' ', ''):
                        print(f"{GREEN}VERIFIED: Reverse operation produced original text.{RESET}")
                    else:
                        print(f"{RED}WARNING: Reverse operation did not reproduce original text.{RESET}")
                else:
                    print(f"{YELLOW}NOTE: For non-string inputs, manual verification is needed.{RESET}")
                
        except Exception as e:
            print(f"{RED}Error during modular operation: {e}{RESET}")
    
    elif mode == '2':
        # Brute force mode
        operation = input(f"\n{GREY}Operation to test ({RESET}{YELLOW}1 = add{RESET}{GREY},{RESET} {YELLOW}2 = subtract{RESET}{GREY}): {RESET}")
        operation = 'add' if operation == '1' else 'subtract'
        
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
        
        # Parse input based on format
        try:
            ciphertext = parse_input(ciphertext_input, input_format, custom_alphabet)
            
            if not ciphertext or all(v == -1 for v in ciphertext):
                print(f"{RED}Error: No valid input data found or characters not in alphabet.{RESET}")
                return
            
            # Check if wordlist exists
            if not os.path.exists(WORDLIST_PATH):
                print(f"{RED}Error: '{WORDLIST_PATH}' not found in the current directory.{RESET}")
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
            
            # Ask if frequency analysis should be performed
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
            
            results = brute_force_with_ioc(
                ciphertext, operation, modulus, base_index, custom_alphabet,
                min_ioc, max_ioc, perform_freq_analysis, freq_threshold
            )
            
            if results:
                print(f"\n{GREEN}Found {len(results)} potential matches:{RESET}")
                
                # Display top results
                display_count = min(10, len(results))
                for i, (key, result_type, result_text, ioc, freq_analysis, likeness_score) in enumerate(results[:display_count]):
                    print(f"\n{YELLOW}Match #{i+1}:{RESET}")
                    print(f"{GREY}Key:{RESET} {key}")
                    print(f"{GREY}Type:{RESET} {result_type}")
                    print(f"{GREY}Decrypted text:{RESET} {result_text}")
                    print(f"{GREY}IoC:{RESET} {ioc:.6f}")
                    if perform_freq_analysis:
                        print(f"{GREY}English Likeness Score:{RESET} {likeness_score:.2f} (lower is better)")
                    
                print(f"\n{GREEN}Total matches found: {len(results)}{RESET}")
                
                # Ask to see more details of a specific match
                if perform_freq_analysis and len(results) > 0:
                    see_details = input(f"\n{GREY}View frequency analysis for a specific match? (Enter match # or 'n'): {RESET}")
                    if see_details.isdigit() and 1 <= int(see_details) <= len(results):
                        match_idx = int(see_details) - 1
                        print(results[match_idx][4])  # Print the frequency analysis
                
                # Ask to save results to a file
                save_option = input(f"\n{GREY}Save results to a file? (y/n): {RESET}").lower()
                if save_option == 'y':
                    filename = input(f"{GREY}Enter filename (default: xor_results.txt): {RESET}")
                    if not filename.strip():
                        filename = "xor_results.txt"
                    utils.save_to_file_mod(results, filename)
            else:
                print(f"\n{RED}No matches found within the specified criteria.{RESET}")
        except Exception as e:
            print(f"{RED}Error during brute force: {e}{RESET}")
    
    else:
        print(f"{RED}Invalid mode selected.{RESET}")
    
    print(f"\n{RED}======================================{RESET}")

if __name__ == "__main__":
    run()