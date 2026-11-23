import string

from theme import RED, GREEN, YELLOW, BLUE, CYAN, GREY, WHITE, RESET, banner

# Standard English letter frequencies
ENGLISH_FREQ = {
    'A': 0.08167, 'B': 0.01492, 'C': 0.02782, 'D': 0.04253, 'E': 0.12702, 'F': 0.02228,
    'G': 0.02015, 'H': 0.06094, 'I': 0.06966, 'J': 0.00015, 'K': 0.00772, 'L': 0.04025,
    'M': 0.02406, 'N': 0.06749, 'O': 0.07507, 'P': 0.01929, 'Q': 0.00095, 'R': 0.05987,
    'S': 0.06327, 'T': 0.09056, 'U': 0.02758, 'V': 0.00978, 'W': 0.02360, 'X': 0.00150,
    'Y': 0.01974, 'Z': 0.00074
}

def chi_squared(text):
    if not text: return float('inf')
    counts = {char: text.count(char) for char in string.ascii_uppercase}
    length = len(text)
    chi2 = 0
    for char in string.ascii_uppercase:
        expected = ENGLISH_FREQ[char] * length
        observed = counts[char]
        if expected > 0:
            chi2 += ((observed - expected) ** 2) / expected
    return chi2

def get_caesar_shift(text):
    """Finds the most likely Caesar shift for a slice of text using Chi-Squared."""
    best_shift = 0
    best_chi2 = float('inf')
    
    for shift in range(26):
        shifted_text = "".join(chr(((ord(c) - 65 - shift) % 26) + 65) for c in text)
        score = chi_squared(shifted_text)
        if score < best_chi2:
            best_chi2 = score
            best_shift = shift
            
    return best_shift, best_chi2

def auto_crack_vigenere(ciphertext, max_key_len=20):
    ciphertext = "".join(filter(str.isalpha, ciphertext.upper()))
    best_overall_key = ""
    best_overall_score = float('inf')
    
    print(f"{GREY}Testing key lengths 1 to {max_key_len}...{RESET}")
    
    for key_len in range(1, max_key_len + 1):
        # Split text into columns based on key length
        columns = [""] * key_len
        for i, char in enumerate(ciphertext):
            columns[i % key_len] += char
            
        # Solve each column as a Caesar cipher
        key = ""
        total_chi2 = 0
        for col in columns:
            shift, score = get_caesar_shift(col)
            key += chr(shift + 65)
            total_chi2 += score
            
        # Normalize score based on text length so we can compare different key lengths safely
        normalized_score = total_chi2 / max(1, len(ciphertext))
        
        if normalized_score < best_overall_score:
            best_overall_score = normalized_score
            best_overall_key = key
            
    return best_overall_key

def decrypt_vig(ciphertext, key):
    pt = ""
    key_idx = 0
    for char in ciphertext:
        if char.isalpha():
            shift = ord(key[key_idx % len(key)].upper()) - 65
            base = 65 if char.isupper() else 97
            pt += chr(((ord(char) - base - shift) % 26) + base)
            key_idx += 1
        else:
            pt += char
    return pt

def run():
    banner("Vigenere Auto-Solver", "Key length plus per-column frequency analysis")
    
    ciphertext = input(f"{GREY}Enter Vigenère ciphertext: {RESET}")
    if not ciphertext.strip(): return
    
    print(f"\n{YELLOW}Analyzing frequencies and cracking...{RESET}")
    best_key = auto_crack_vigenere(ciphertext)
    
    print(f"\n{YELLOW}CRACK SUCCESSFUL:{RESET}")
    print(f"Extracted Key: {GREEN}{best_key}{RESET} (Length: {len(best_key)})")
    print(f"Plaintext:\n{GREEN}{decrypt_vig(ciphertext, best_key)}{RESET}\n")