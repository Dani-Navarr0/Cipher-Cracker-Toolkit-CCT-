from collections import Counter
from typing import List, Dict, Tuple
import datetime
import os

# ANSI color codes for terminal output
import sys as _sys
_SCRIPTS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts")
if _SCRIPTS not in _sys.path:
    _sys.path.append(_SCRIPTS)
from theme import RED, GREEN, YELLOW, BLUE, GREY, RESET  # noqa: E402

def calculate_ioc(text: str) -> float:
    """
    Calculate Index of Coincidence for the given text.
    The IoC measures the probability that any two randomly selected letters in the text are the same.
    English text typically has an IoC around 0.067.
    """
    # Filter only alphabet characters
    text = ''.join(c for c in text.upper() if c.isalpha())
    
    if len(text) <= 1:
        return 0.0
    
    # Count occurrences of each letter
    letter_counts = Counter(text)
    
    # Calculate IoC: sum(ni * (ni-1)) / (N * (N-1))
    # where ni is the count of each letter and N is the total length
    n = len(text)
    numerator = sum(count * (count - 1) for count in letter_counts.values())
    denominator = n * (n - 1)
    
    return numerator / denominator if denominator > 0 else 0.0

def save_results_to_file(results: List[Dict], filename: str, include_phrases: bool = True):
    """Save results to a text file."""
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            for result in results:
                f.write("-" * 50 + "\n")
                f.write(f"Key: {result['key']}\n")
                f.write(f"IoC: {result['ioc']:.6f}\n")
                if include_phrases and 'matched_phrases' in result:
                    f.write(f"Matched phrases: {', '.join(result['matched_phrases'])}\n")
                f.write(f"Plaintext: {result['plaintext']}\n")
                f.write("-" * 50 + "\n\n")
        
        print(f"Results saved to {filename}")
    except Exception as e:
        print(f"{RED}Error saving results to file: {e}{RESET}")

def save_to_file_autokey(results, filename):
    """Save the results to a text file."""
    try:
        with open(filename, 'w', encoding='utf-8') as file:
            file.write(f"Autokey Decryption Results - {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            file.write(f"=" * 80 + "\n\n")
            
            for i, result_data in enumerate(results):
                primer, plaintext, ioc, frequency_analysis, likeness_score = result_data
                
                file.write(f"Match #{i+1}\n")
                file.write(f"Primer: {primer}\n")
                file.write(f"Decrypted Text: {plaintext}\n")
                file.write(f"IoC: {ioc:.6f}\n")
                file.write(f"English Likeness Score: {likeness_score:.2f} (lower is better)\n\n")
                
                # Strip color codes for file output
                clean_analysis = ""
                skip_mode = False
                for c in frequency_analysis:
                    if c == '\033':
                        skip_mode = True
                    elif skip_mode and c == 'm':
                        skip_mode = False
                    elif not skip_mode:
                        clean_analysis += c
                
                file.write(clean_analysis + "\n")
                file.write(f"{'=' * 80}\n\n")
                
            file.write(f"Total matches found: {len(results)}\n")
            
        print(f"\n{GREEN}Results saved to '{filename}'.{RESET}")
        return True
    except Exception as e:
        print(f"{RED}Error saving results: {e}{RESET}")
        return False

def save_to_file_xor(results, filename):
    """Save the results to a text file."""
    try:
        with open(filename, 'w', encoding='utf-8') as file:
            file.write(f"XOR Decryption Results - {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            file.write(f"=" * 80 + "\n\n")
            
            for i, result_data in enumerate(results):
                key, result_type, result_text, ioc, frequency_analysis, likeness_score = result_data
                
                file.write(f"Match #{i+1}\n")
                file.write(f"Key: {key}\n")
                file.write(f"Result Type: {result_type}\n")
                file.write(f"Decrypted Text: {result_text}\n")
                file.write(f"IoC: {ioc:.6f}\n")
                file.write(f"English Likeness Score: {likeness_score:.2f} (lower is better)\n\n")
                
                # Strip color codes for file output
                clean_analysis = ""
                skip_mode = False
                for c in frequency_analysis:
                    if c == '\033':
                        skip_mode = True
                    elif skip_mode and c == 'm':
                        skip_mode = False
                    elif not skip_mode:
                        clean_analysis += c
                
                file.write(clean_analysis + "\n")
                file.write(f"{'=' * 80}\n\n")
                
            file.write(f"Total matches found: {len(results)}\n")
            
        print(f"\n{GREEN}Results saved to '{filename}'.{RESET}")
        return True
    except Exception as e:
        print(f"{RED}Error saving results: {e}{RESET}")
        return False

def save_to_file_mod(results, filename):
    """Save the results to a text file."""
    try:
        with open(filename, 'w', encoding='utf-8') as file:
            file.write(f"Modular Cipher Results - {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            file.write(f"=" * 80 + "\n\n")
            
            for i, result_data in enumerate(results):
                key, result_type, result_text, ioc, frequency_analysis, likeness_score = result_data
                
                file.write(f"Match #{i+1}\n")
                file.write(f"Key: {key}\n")
                file.write(f"Result Type: {result_type}\n")
                file.write(f"Decrypted Text: {result_text}\n")
                file.write(f"IoC: {ioc:.6f}\n")
                file.write(f"English Likeness Score: {likeness_score:.2f} (lower is better)\n\n")
                
                # Strip color codes for file output
                clean_analysis = ""
                skip_mode = False
                for c in frequency_analysis:
                    if c == '\033':
                        skip_mode = True
                    elif skip_mode and c == 'm':
                        skip_mode = False
                    elif not skip_mode:
                        clean_analysis += c
                
                file.write(clean_analysis + "\n")
                file.write(f"{'=' * 80}\n\n")
                
            file.write(f"Total matches found: {len(results)}\n")
            
        print(f"\n{GREEN}Results saved to '{filename}'.{RESET}")
        return True
    except Exception as e:
        print(f"{RED}Error saving results: {e}{RESET}")
        return False

def save_to_file_hill(results, filename):
    """Save Hill cipher results to a file."""
    try:
        with open(filename, 'w', encoding='utf-8') as file:
            file.write(f"Hill Cipher Brute Force Results\n")
            file.write(f"==============================\n\n")
            
            for i, (word, matrix, plaintext, ioc, freq_analysis, likeness_score, convention) in enumerate(results):
                file.write(f"Match #{i+1}:\n")
                file.write(f"Key Word: {word}\n")
                file.write(f"Key Matrix:\n")
                for row in matrix:
                    file.write(f"  {row}\n")
                file.write(f"Vector Convention: {convention}\n")
                file.write(f"Decrypted text: {plaintext}\n")
                file.write(f"IoC: {ioc:.6f}\n")
                if likeness_score != float('inf'):
                    file.write(f"English Likeness Score: {likeness_score:.2f} (lower is better)\n")
                if freq_analysis:
                    file.write(f"Frequency Analysis:\n{freq_analysis}\n")
                file.write("\n" + "-"*50 + "\n\n")
            
        print(f"{GREEN}Results saved to {filename}{RESET}")
    except Exception as e:
        print(f"{RED}Error saving to file: {e}{RESET}")

def analyze_frequency(text):
    """
    Analyze character frequency in the plaintext and calculate a likeness score to English.
    
    Args:
        text (str): The plaintext to analyze
        
    Returns:
        tuple: (analysis_text, likeness_score) where analysis_text is a string 
               and likeness_score is a float (lower is more likely to be English)
    """
    analysis_text = f"\n{YELLOW}Frequency Analysis{RESET}\n"
    analysis_text += f"{GREY}-{RESET}" * 50 + "\n"
    
    # Ensure text is uppercase for consistency
    text = text.upper()
    
    # Count letter frequencies
    letter_count = {}
    total_letters = 0
    
    for char in text:
        if char.isalpha():
            letter_count[char] = letter_count.get(char, 0) + 1
            total_letters += 1
    
    # If there's no text to analyze, return early
    if total_letters == 0:
        return f"{RED}No letters to analyze{RESET}", float('inf')
    
    # Calculate frequencies and sort by frequency (descending)
    frequencies = [(char, count, count/total_letters*100) for char, count in letter_count.items()]
    frequencies.sort(key=lambda x: x[1], reverse=True)
    
    # Build analysis text
    analysis_text += f"{'Character':<10}{'Count':<10}{'Frequency %':<15}{'Bar Chart'}\n"
    analysis_text += f"{GREY}-{RESET}" * 50 + "\n"
    
    for char, count, percentage in frequencies:
        bar_length = int(percentage) * 2  # Scale for better visualization
        bar = "█" * bar_length
        analysis_text += f"{char:<10}{count:<10}{percentage:.2f}%{'':<10}{RED}{bar}{RESET}\n"
    
    # Add some statistical analysis
    analysis_text += f"{GREY}-{RESET}" * 50 + "\n"
    analysis_text += f"Total letters analyzed: {YELLOW}{total_letters}{RESET}\n"
    
    # Compare with English language frequency
    english_freq = {
        'E': 12.02, 'T': 9.10, 'A': 8.12, 'O': 7.68, 'I': 7.31, 'N': 6.95,
        'S': 6.28, 'R': 6.02, 'H': 5.92, 'D': 4.32, 'L': 3.98, 'U': 2.88,
        'C': 2.71, 'M': 2.61, 'F': 2.30, 'Y': 2.11, 'W': 2.09, 'G': 2.03,
        'P': 1.82, 'B': 1.49, 'V': 1.11, 'K': 0.69, 'X': 0.17, 'Q': 0.11,
        'J': 0.10, 'Z': 0.07
    }
    
    # Calculate deviation from English frequency and a score
    analysis_text += f"\n{YELLOW}Deviation from Standard English{RESET}\n"
    analysis_text += f"{'Character':<10}{'Text %':<15}{'English %':<15}{'Deviation'}\n"
    analysis_text += f"{GREY}-{RESET}" * 50 + "\n"
    
    # Convert frequencies to a dict for easier lookup
    text_freq = {char: percentage for char, _, percentage in frequencies}
    
    # Calculate total deviation as a score (lower is better)
    total_deviation = 0
    
    for char in sorted(english_freq.keys()):
        text_percentage = text_freq.get(char, 0)
        eng_percentage = english_freq[char]
        deviation = text_percentage - eng_percentage
        total_deviation += abs(deviation)
        
        # Highlight significant deviations with original colors
        if abs(deviation) > 3:
            color = RED
        elif abs(deviation) > 1.5:
            color = YELLOW
        else:
            color = RESET
            
        analysis_text += f"{char:<10}{text_percentage:.2f}%{'':<10}{eng_percentage:.2f}%{'':<10}{color}{deviation:+.2f}%{RESET}\n"
    
    # Look for recurring patterns (potential key length indicators)
    analysis_text += f"\n{YELLOW}Common Bigrams and Trigrams{RESET}\n"
    
    # Analyze bigrams
    bigrams = {}
    for i in range(len(text) - 1):
        if text[i].isalpha() and text[i+1].isalpha():
            bigram = text[i:i+2]
            bigrams[bigram] = bigrams.get(bigram, 0) + 1
    
    # Analyze trigrams
    trigrams = {}
    for i in range(len(text) - 2):
        if text[i].isalpha() and text[i+1].isalpha() and text[i+2].isalpha():
            trigram = text[i:i+3]
            trigrams[trigram] = trigrams.get(trigram, 0) + 1
    
    # Show top bigrams
    top_bigrams = sorted(bigrams.items(), key=lambda x: x[1], reverse=True)[:8]
    analysis_text += f"Top Bigrams: "
    analysis_text += ", ".join([f"{RED}{b}{RESET}({c})" for b, c in top_bigrams]) + "\n"
    
    # Show top trigrams
    top_trigrams = sorted(trigrams.items(), key=lambda x: x[1], reverse=True)[:8]
    analysis_text += f"Top Trigrams: "
    analysis_text += ", ".join([f"{RED}{t}{RESET}({c})" for t, c in top_trigrams]) + "\n"
    
    # Add Index of Coincidence calculation
    ioc = calculate_ioc(text)
    analysis_text += f"\n{YELLOW}Index of Coincidence: {RED}{ioc:.6f}{RESET}\n"
    analysis_text += f"Typical English text IoC: {YELLOW}0.0667{RESET}\n"
    
    analysis_text += f"\n{GREY}Analysis complete.{RESET}"
    
    # Return the analysis text and total deviation score
    return analysis_text, total_deviation

def analyze_frequency_vg(text):
    """
    Analyze character frequency in the plaintext and display results.
    
    Args:
        text (str): The plaintext to analyze
    """
    print(f"\n{YELLOW}Frequency Analysis{RESET}")
    print(f"{GREY}-{RESET}" * 50)
    
    
    # Ensure text is uppercase for consistency
    text = text.upper()
    
    # Count letter frequencies
    letter_count = {}
    total_letters = 0
    
    for char in text:
        if char.isalpha():
            letter_count[char] = letter_count.get(char, 0) + 1
            total_letters += 1
    
    # Calculate frequencies and sort by frequency (descending)
    frequencies = [(char, count, count/total_letters*100) for char, count in letter_count.items()]
    frequencies.sort(key=lambda x: x[1], reverse=True)
    
    # Display results
    print(f"{'Character':<10}{'Count':<10}{'Frequency %':<15}{'Bar Chart'}")
    print(f"{GREY}-{RESET}" * 50)
    
    for char, count, percentage in frequencies:
        bar_length = int(percentage) * 2  # Scale for better visualization
        bar = "█" * bar_length
        print(f"{char:<10}{count:<10}{percentage:.2f}%{'':<10}{RED}{bar}{RESET}")
    
    # Add some statistical analysis
    print(f"{GREY}-{RESET}" * 50)
    print(f"Total letters analyzed: {YELLOW}{total_letters}{RESET}")
    
    # Compare with English language frequency
    english_freq = {
        'E': 12.02, 'T': 9.10, 'A': 8.12, 'O': 7.68, 'I': 7.31, 'N': 6.95,
        'S': 6.28, 'R': 6.02, 'H': 5.92, 'D': 4.32, 'L': 3.98, 'U': 2.88,
        'C': 2.71, 'M': 2.61, 'F': 2.30, 'Y': 2.11, 'W': 2.09, 'G': 2.03,
        'P': 1.82, 'B': 1.49, 'V': 1.11, 'K': 0.69, 'X': 0.17, 'Q': 0.11,
        'J': 0.10, 'Z': 0.07
    }
    
    # Calculate deviation from English frequency
    print(f"\n{YELLOW}Deviation from Standard English{RESET}")
    print(f"{'Character':<10}{'Text %':<15}{'English %':<15}{'Deviation'}")
    print(f"{GREY}-{RESET}" * 50)
    
    # Convert frequencies to a dict for easier lookup
    text_freq = {char: percentage for char, _, percentage in frequencies}
    
    for char in sorted(english_freq.keys()):
        text_percentage = text_freq.get(char, 0)
        eng_percentage = english_freq[char]
        deviation = text_percentage - eng_percentage
        
        # Highlight significant deviations
        if abs(deviation) > 3:
            color = RED
        elif abs(deviation) > 1.5:
            color = YELLOW
        else:
            color = RESET
            
        print(f"{char:<10}{text_percentage:.2f}%{'':<10}{eng_percentage:.2f}%{'':<10}{color}{deviation:+.2f}%{RESET}")
    
    # Look for recurring patterns (potential key length indicators)
    print(f"\n{YELLOW}Common Bigrams and Trigrams{RESET}")
    
    # Analyze bigrams
    bigrams = {}
    for i in range(len(text) - 1):
        if text[i].isalpha() and text[i+1].isalpha():
            bigram = text[i:i+2]
            bigrams[bigram] = bigrams.get(bigram, 0) + 1
    
    # Analyze trigrams
    trigrams = {}
    for i in range(len(text) - 2):
        if text[i].isalpha() and text[i+1].isalpha() and text[i+2].isalpha():
            trigram = text[i:i+3]
            trigrams[trigram] = trigrams.get(trigram, 0) + 1
    
    # Show top bigrams
    top_bigrams = sorted(bigrams.items(), key=lambda x: x[1], reverse=True)[:8]
    print(f"Top Bigrams: ", end="")
    print(", ".join([f"{RED}{b}{RESET}({c})" for b, c in top_bigrams]))
    
    # Show top trigrams
    top_trigrams = sorted(trigrams.items(), key=lambda x: x[1], reverse=True)[:8]
    print(f"Top Trigrams: ", end="")
    print(", ".join([f"{RED}{t}{RESET}({c})" for t, c in top_trigrams]))
    
    # Add Index of Coincidence calculation
    ioc = calculate_ioc(text)
    print(f"\n{YELLOW}Index of Coincidence: {RED}{ioc:.6f}{RESET}")
    print(f"Typical English text IoC: {YELLOW}0.0667{RESET}")
    
    print(f"\n{GREY}Analysis complete.{RESET}")

def get_input_ciphertexts(prompt="Enter ciphertext"):
    """
    Asks user for manual input or file path.
    Returns a LIST of strings to be processed.
    """
    print(f"\n{YELLOW}Input Method:{RESET}")
    print(f"[{YELLOW}1{RESET}] Manual Entry")
    print(f"[{YELLOW}2{RESET}] Load from .txt file (Batch Process)")
    
    choice = input(f"{GREEN}Select option (1/2): {RESET}").strip()
    
    ciphertexts = []
    
    if choice == '2':
        file_path = input(f"{GREY}Enter file path (e.g. inputs.txt): {RESET}").strip()
        # Remove quotes if user dragged and dropped file
        file_path = file_path.replace('"', '').replace("'", "")
        
        if os.path.exists(file_path):
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    # Read lines, strip whitespace, ignore empty lines
                    lines = [line.strip() for line in f.readlines()]
                    ciphertexts = [line for line in lines if line]
                print(f"{GREEN}Successfully loaded {len(ciphertexts)} inputs from file.{RESET}")
            except Exception as e:
                print(f"{RED}Error reading file: {e}{RESET}")
        else:
            print(f"{RED}File not found: {file_path}{RESET}")
    else:
        # Default to manual
        text = input(f"{GREY}{prompt}: {RESET}").strip()
        if text:
            ciphertexts.append(text)
            
    return ciphertexts