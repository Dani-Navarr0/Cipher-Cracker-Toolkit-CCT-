# ANSI color codes for terminal output
from theme import RED, GREEN, YELLOW, BLUE, CYAN, GREY, WHITE, RESET, banner

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
     
    # Return the analysis text and total deviation score
    return analysis_text, total_deviation

def run():
    banner("Frequency Analysis", "Letter, bigram and trigram statistics vs English")
    
    input_string = input(f"{GREY}Enter ciphertext: {RESET}")
    if not any(ch.isalpha() for ch in input_string):
        print(f"{RED}Error: no letters in the input.{RESET}")
        return

    analysis_text, total_deviation = analyze_frequency(input_string)
    print(analysis_text)
    print(f"{GREY}Total Deviation Score:{RESET} {YELLOW}{total_deviation:.2f}{RESET}")

if __name__ == "__main__":
    run()