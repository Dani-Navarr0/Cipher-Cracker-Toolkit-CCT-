import os

from theme import RED, GREEN, YELLOW, BLUE, CYAN, GREY, WHITE, RESET, banner
dictionary_path = os.path.join(os.path.dirname(__file__), "data", "words_alpha.txt")

def get_word_pattern(word):
    """Converts a word to a pattern string (e.g., 'ATTACK' -> '0-1-1-0-2-3')"""
    pattern, char_map, next_num = [], {}, 0
    for char in word:
        if char not in char_map:
            char_map[char] = str(next_num)
            next_num += 1
        pattern.append(char_map[char])
    return "-".join(pattern)

def load_pattern_dict():
    patterns = {}
    try:
        with open(dictionary_path, 'r', encoding='utf-8') as f:
            for line in f:
                word = line.strip().upper()
                if len(word) > 1: # Ignore 1-letter words for cleaner output
                    p = get_word_pattern(word)
                    if p not in patterns: patterns[p] = []
                    patterns[p].append(word)
    except FileNotFoundError:
        print(f"{RED}Dictionary not found at {dictionary_path}{RESET}")
    return patterns

def run():
    banner("Word Pattern Isomorphism", "Match word shapes such as 1-2-2-1 against a dictionary")
    
    ciphertext = input(f"{GREY}Enter ciphertext (MUST contain spaces): {RESET}").upper()
    if not ciphertext.strip(): return
    
    print(f"\n{YELLOW}Loading dictionary patterns...{RESET}")
    pattern_dict = load_pattern_dict()
    
    words = ciphertext.split()
    print(f"\n{YELLOW}Pattern Matches for longest words:{RESET}")
    print(f"{GREY}-{RESET}" * 50)
    
    # Sort words by length descending (longer words have fewer pattern collisions)
    words.sort(key=len, reverse=True)
    
    for word in words[:5]: # Only show top 5 longest words
        clean_word = "".join(c for c in word if c.isalpha())
        if len(clean_word) < 2: continue
        
        pattern = get_word_pattern(clean_word)
        matches = pattern_dict.get(pattern, [])
        
        print(f"Cipher Word: {GREEN}{clean_word}{RESET} (Pattern: {pattern})")
        if matches:
            display_matches = ", ".join(matches[:15]) + ("..." if len(matches) > 15 else "")
            print(f"Possibilities: {YELLOW}{display_matches}{RESET}\n")
        else:
            print(f"{RED}No English dictionary words match this pattern.{RESET}\n")