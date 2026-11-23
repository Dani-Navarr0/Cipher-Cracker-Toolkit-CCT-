import os
import argparse
from utils import utils

# ANSI color codes for terminal output
from theme import RED, GREEN, YELLOW, BLUE, CYAN, GREY, WHITE, RESET, banner

# Hardcoded path for words_alpha.txt
WORDLIST_PATH = os.path.join(os.path.dirname(__file__), "data", "words_alpha.txt")

def create_tabula_recta(alphabet):
    """Create a tabula recta based on the provided alphabet."""
    tabula = {}
    for i, row_char in enumerate(alphabet):
        tabula[row_char] = {}
        for j, col_char in enumerate(alphabet):
            # Calculate the index of the character in the alphabet
            idx = (i + j) % len(alphabet)
            tabula[row_char][col_char] = alphabet[idx]
    return tabula

def decrypt_autokey(ciphertext, primer, alphabet, tabula_recta):
    """Decrypt Autokey cipher with the given primer."""
    key = primer
    plaintext = ""
    
    for i, char in enumerate(ciphertext):
        if char not in alphabet:
            plaintext += char
            continue
            
        # Find the column in tabula recta where ciphertext char appears in the row corresponding to current key char
        if i < len(key):
            key_char = key[i]
        else:
            key_char = plaintext[i - len(key)]
            
        if key_char not in alphabet:
            continue
            
        # Find the plaintext character
        for col_char in alphabet:
            if tabula_recta[key_char][col_char] == char:
                plaintext += col_char
                break
    
    return plaintext

def contains_fragment(plaintext, fragment, case_sensitive=False):
    """Check if plaintext contains the specified fragment."""
    if not case_sensitive:
        return fragment.lower() in plaintext.lower()
    return fragment in plaintext

def brute_force_autokey(ciphertext, alphabet, min_ioc=0.065, max_ioc=0.07, 
                        known_fragments=None, perform_freq_analysis=False, 
                        freq_threshold=45.0):
    """Try each word in the wordlist as a primer, filter by IoC and known fragments."""
    try:
        if not os.path.exists(WORDLIST_PATH):
            print(f"{RED}Error: '{WORDLIST_PATH}' not found in the current directory.{RESET}")
            return []
            
        with open(WORDLIST_PATH, 'r', encoding='utf-8') as file:
            words = [word.strip() for word in file if word.strip()]
    except Exception as e:
        print(f"{RED}Error reading wordlist: {e}{RESET}")
        return []
    
    results = []
    total_words = len(words)
    
    # Create the tabula recta
    tabula_recta = create_tabula_recta(alphabet)
    
    print(f"\n{YELLOW}Starting brute force with {total_words} words...{RESET}")
    print(f"\n-{GREY}IoC filter range: {min_ioc} to {max_ioc}{RESET}")
    if perform_freq_analysis:
        print(f"-{GREY}Frequency analysis will be performed (threshold: {freq_threshold}){RESET}")
    if known_fragments:
        print(f"-{GREY}Known fragments will be checked: {known_fragments}{RESET}")
    
    # Add case testing based on alphabet case
    is_upper = alphabet[0].isupper()
    case_transform = str.upper if is_upper else str.lower
    print(f"{YELLOW}Testing {'uppercase' if is_upper else 'lowercase'} versions of each word to match alphabet{RESET}")
    
    words_checked = 0
    for word in words:
        words_checked += 1
        if words_checked % 1000 == 0:
            print(f"{GREY}Progress: {RED}{words_checked}{RESET}/{YELLOW}{total_words}{RESET} words checked...{RESET}", end='\r')
        
        # Skip empty words or words with characters not in alphabet
        if not word or not all(case_transform(c) in alphabet for c in word if c.isalpha()):
            continue
        
        # Try the word as primer in proper case
        primer = case_transform(word)
        
        try:
            # Decrypt with the primer
            plaintext = decrypt_autokey(ciphertext, primer, alphabet, tabula_recta)
            # Calculate IoC
            ioc = utils.calculate_ioc(plaintext)
            
            # Check against known fragments
            if known_fragments:
                fragment_match = any(contains_fragment(plaintext, fragment) for fragment in known_fragments)
            else:
                fragment_match = False  # No fragments: rely on the IoC / frequency filters
            
            # Check IoC range
            ioc_match = min_ioc <= ioc <= max_ioc
            
            if ioc_match or fragment_match:
                if perform_freq_analysis:
                    freq_analysis, likeness_score = utils.analyze_frequency(plaintext)
                    if likeness_score <= freq_threshold:
                        results.append((primer, plaintext, ioc, freq_analysis, likeness_score))
                else:
                    results.append((primer, plaintext, ioc, "", float('inf')))
        except Exception as e:
            # Skip errors for individual words
            continue
    
    print(f"{GREY}Completed! {total_words} words checked.{RESET}                ")
    
    # Sort results - first by fragment match, then by frequency analysis score if available, then by IoC
    if perform_freq_analysis:
        results.sort(key=lambda x: (x[4], -x[2]))  # Sort by likeness score, then by IoC (descending)
    else:
        results.sort(key=lambda x: x[2], reverse=True)  # Sort by IoC
        
    return results

def normalize_input(text, alphabet):
    """Normalize input text to match the alphabet."""
    result = ""
    for c in text:
        if c.upper() in alphabet.upper():
            # Match case with alphabet
            if alphabet[0].isupper():
                result += c.upper()
            else:
                result += c.lower()
    return result

def test_known_case():
    """Test a known case to verify the decryption algorithm."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    primer = "QUEENLY"
    ciphertext = "QNXEPVYTWTWP"
    expected_plaintext = "attackatdawn"
    
    # Create the tabula recta
    tabula_recta = create_tabula_recta(alphabet)
    
    # Decrypt with the known primer
    plaintext = decrypt_autokey(ciphertext, primer, alphabet, tabula_recta)
    
    print(f"Primer: {primer}")
    print(f"Ciphertext: {ciphertext}")
    print(f"Decrypted: {plaintext}")
    print(f"Expected: {expected_plaintext}")
    print(f"Match: {expected_plaintext in plaintext.lower()}")
    
    return plaintext

def run():
    banner("Autokey Cipher", "Primer-keyed autoclave: decrypt or brute-force primers")
    
    # Get the alphabet
    default_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

    custom_alphabet = input(f"\n{GREY}Use custom alphabet? (y/n, default is A-Z): {RESET}").lower()
    
    if custom_alphabet == 'y':
        alphabet = input(f"{GREY}Enter custom alphabet: {RESET}")
        # Validate: unique characters only
        if len(set(alphabet)) != len(alphabet):
            print(f"{RED}Warning: Duplicate characters in alphabet. Removing duplicates.{RESET}")
            alphabet = ''.join(dict.fromkeys(alphabet))
        print(f"{GREEN}Using alphabet: {alphabet}{RESET}")
    else:
        alphabet = default_alphabet
        print(f"{GREEN}Using standard alphabet: {alphabet}{RESET}")
    
    # Get ciphertext
    ciphertext = input(f"\n{GREY}Enter the ciphertext to crack: {RESET}")
    
    # Normalize ciphertext to match alphabet
    ciphertext = normalize_input(ciphertext, alphabet)
    if not ciphertext:
        print(f"{RED}Error: No valid characters found in ciphertext after normalization.{RESET}")
        return
    
    # Check if wordlist exists
    if not os.path.exists(WORDLIST_PATH):
        print(f"{RED}Error: '{WORDLIST_PATH}' not found in the current directory.{RESET}")
        return
    
    # Get known plaintext fragments
    known_fragments = []
    use_fragments = input(f"\n{GREY}Do you have known plaintext fragments? (y/n): {RESET}").lower()
    if use_fragments == 'y':
        while True:
            fragment = input(f"{GREY}Enter a known fragment (or press Enter to finish): {RESET}")
            if not fragment:
                break
            known_fragments.append(fragment)
    
    min_ioc = 0.065
    max_ioc = 0.07
    
    custom_ioc = input(f"\n{GREY}Use default IoC range (0.065-0.07)? (y/n): {RESET}").lower()
    if custom_ioc == 'n':
        try:
            min_ioc = float(input(f"{GREY}Enter minimum IoC value: {RESET}"))
            max_ioc = float(input(f"{GREY}Enter maximum IoC value: {RESET}"))
        except ValueError:
            print(f"{RED}Invalid IoC values, using defaults.{RESET}")
    
    # Ask if frequency analysis should be performed
    perform_freq = input(f"\n{GREY}Perform frequency analysis to find English-like text? (y/n): {RESET}").lower()
    perform_freq_analysis = perform_freq == 'y'
    
    freq_threshold = 45.0
    if perform_freq_analysis:
        try:
            custom_threshold = input(f"{GREY}Use default frequency deviation threshold (45.0)? (y/n): {RESET}").lower()
            if custom_threshold == 'n':
                freq_threshold = float(input(f"{GREY}Enter frequency deviation threshold (lower values = more English-like): {RESET}"))
        except ValueError:
            print(f"{RED}Invalid threshold, using default.{RESET}")
    
    # Run the brute force
    results = brute_force_autokey(
        ciphertext, 
        alphabet, 
        min_ioc, 
        max_ioc, 
        known_fragments,
        perform_freq_analysis, 
        freq_threshold
    )

    if results:
        print(f"\n{GREEN}Found {len(results)} potential matches:{RESET}")
        
        # Display top results
        display_count = min(10, len(results))
        for i, (primer, plaintext, ioc, freq_analysis, likeness_score) in enumerate(results[:display_count]):
            print(f"\n{YELLOW}Match #{i+1}:{RESET}")
            print(f"{GREY}Primer:{RESET} {primer}")
            print(f"{GREY}Decrypted text:{RESET} {plaintext}")
            print(f"{GREY}IoC:{RESET} {ioc:.6f}")
            if perform_freq_analysis:
                print(f"{GREY}English Likeness Score:{RESET} {likeness_score:.2f} (lower is better)")
        
        print(f"\n{GREEN}Total matches found: {len(results)}{RESET}")
        
        # Ask to see more details of a specific match
        if perform_freq_analysis and len(results) > 0:
            see_details = input(f"\n{GREY}View frequency analysis for a specific match? (Enter match # or 'n'): {RESET}")
            if see_details.isdigit() and 1 <= int(see_details) <= len(results):
                match_idx = int(see_details) - 1
                print(results[match_idx][3])  # Print the frequency analysis
        
        # Ask to save results to a file
        save_option = input(f"\n{GREY}Save results to a file? (y/n): {RESET}").lower()
        if save_option == 'y':
            filename = input(f"{GREY}Enter filename (default: autokey_results.txt): {RESET}")
            if not filename.strip():
                filename = "autokey_results.txt"
            utils.save_to_file_autokey(results, filename)
    else:
        print(f"\n{RED}No matches found within the specified criteria.{RESET}")
        
        # Offer to relax constraints
        relax = input(f"{GREY}Would you like to relax constraints and try again? (y/n): {RESET}").lower()
        if relax == 'y':
            print(f"\n{YELLOW}Suggestions:{RESET}")
            print(f"1. Widen the IoC range (try 0.05-0.08)")
            print(f"2. Increase frequency threshold (try 60.0)")
            print(f"3. Remove or simplify known plaintext fragments")
            try_again = input(f"\n{GREY}Try again with relaxed constraints? (y/n): {RESET}").lower()
            if try_again == 'y':
                # Could implement recursive call to run() here
                print(f"{YELLOW}Please restart the program and apply relaxed constraints.{RESET}")

def main():
    parser = argparse.ArgumentParser(description='Autokey Cipher Brute Force Tool')
    parser.add_argument('--file', help='Input ciphertext from file')
    parser.add_argument('--alphabet', default='ABCDEFGHIJKLMNOPQRSTUVWXYZ', help='Custom alphabet')
    parser.add_argument('--min-ioc', type=float, default=0.065, help='Minimum IoC threshold')
    parser.add_argument('--max-ioc', type=float, default=0.07, help='Maximum IoC threshold')
    parser.add_argument('--fragments', nargs='+', help='Known plaintext fragments')
    parser.add_argument('--wordlist', default='words_alpha.txt', help='Path to wordlist file')
    parser.add_argument('--freq-threshold', type=float, default=45.0, help='Frequency analysis threshold')
    parser.add_argument('--output', help='Output results to file')
    
    args = parser.parse_args()
    
    # If command line arguments are provided, use them
    if len(sys.argv) > 1:
        # Override wordlist path if specified
        if args.wordlist:
            global WORDLIST_PATH
            WORDLIST_PATH = args.wordlist
            
        # Get ciphertext from file or prompt
        ciphertext = ""
        if args.file:
            try:
                with open(args.file, 'r', encoding='utf-8') as file:
                    ciphertext = file.read()
            except Exception as e:
                print(f"{RED}Error reading input file: {e}{RESET}")
                return
        else:
            ciphertext = input(f"{GREY}Enter the ciphertext to crack: {RESET}")
            
        # Normalize ciphertext
        ciphertext = normalize_input(ciphertext, args.alphabet)
        
        # Run the brute force with command line parameters
        results = brute_force_autokey(
            ciphertext,
            args.alphabet,
            args.min_ioc,
            args.max_ioc,
            args.fragments,
            True if args.freq_threshold != 45.0 else False,
            args.freq_threshold
        )
        
        # Display results
        if results:
            print(f"\n{GREEN}Found {len(results)} potential matches:{RESET}")
            display_count = min(10, len(results))
            for i, (primer, plaintext, ioc, freq_analysis, likeness_score) in enumerate(results[:display_count]):
                print(f"\n{YELLOW}Match #{i+1}:{RESET}")
                print(f"{GREY}Primer:{RESET} {primer}")
                print(f"{GREY}Decrypted text:{RESET} {plaintext}")
                print(f"{GREY}IoC:{RESET} {ioc:.6f}")
                if likeness_score != float('inf'):
                    print(f"{GREY}English Likeness Score:{RESET} {likeness_score:.2f} (lower is better)")
            
            # Save to file if requested
            if args.output:
                utils.save_to_file_autokey(results, args.output)
        else:
            print(f"\n{RED}No matches found within the specified criteria.{RESET}")
    else:
        # Interactive mode
        run()

if __name__ == "__main__":
    import sys
    main()