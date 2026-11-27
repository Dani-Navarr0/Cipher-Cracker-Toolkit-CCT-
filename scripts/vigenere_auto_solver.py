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
    """Key length from the column IoC (tested against shuffled copies of the
    text), then each key letter from letter frequencies, for Vigenere and
    Beaufort. Every candidate is judged against English of the same length."""
    import cipher_profile as cp
    from ngram_scoring import text_to_codes

    banner("Vigenere Auto-Solver", "Key length plus per-column frequency analysis (Vigenere and Beaufort)")
    ciphertext = input(f"{GREY}Enter Vigenère ciphertext: {RESET}")
    codes = text_to_codes(ciphertext)
    if len(codes) < cp.MIN_LETTERS:
        print(f"{RED}Need at least {cp.MIN_LETTERS} letters.{RESET}")
        return
    default_max = max(2, min(40, len(codes) // 5))
    text = input(f"Longest key length to test (Enter = {YELLOW}{default_max}{RESET}): ").strip()
    max_period = int(text) if text.isdigit() and int(text) >= 2 else default_max
    max_period = min(max_period, len(codes) // 2)

    print(f"\n{YELLOW}Testing key lengths 2-{max_period}...{RESET}")
    rows = cp.periodicity(codes, max_period)
    found = cp.likely_periods(rows)
    ranked = sorted(rows[1:], key=lambda row: -row['z'])
    print(f"{GREY}Column IoC per key length (z = standard deviations above shuffled copies; "
          f"significant at z >= {cp.z_threshold(max_period - 1):.2f}):{RESET}")
    for row in ranked[:6]:
        mark = f"{GREEN}significant{RESET}" if row['signal'] else f"{GREY}not significant{RESET}"
        print(f"  length {YELLOW}{row['period']:>2}{RESET}  column IoC {row['ioc']:.4f}  z {row['z']:5.1f}  {mark}")
    periods = found[:3] if found else [row['period'] for row in ranked[:3]]
    if not found:
        print(f"{YELLOW}No key length stands out: this may not be a periodic cipher, or the key is longer than "
              f"{max_period}. Trying the three strongest lengths anyway.{RESET}")

    refs = cp.references(len(codes))
    candidates = cp.attack_periodic(codes, cp.fitness_function(), periods)
    print(f"\n{YELLOW}Best decryptions{RESET} {GREY}(judged against {len(codes)}-letter English and shuffled text):{RESET}")
    for rank, candidate in enumerate(candidates[:4], start=1):
        verdict = cp.judge(candidate.fitness, refs)
        colour = GREEN if verdict == "reads as English" else YELLOW if verdict == "partly English" else GREY
        print(f"\n{rank}. {candidate.method}, {candidate.key}  fitness {candidate.fitness:.1f} {colour}[{verdict}]{RESET}")
        print(f"   {candidate.plaintext}")
    if cp.judge(candidates[0].fitness, refs) != "reads as English":
        print(f"\n{YELLOW}Not solved. A partly English result usually has a few wrong key letters (short columns): "
              f"anneal that key length in tool 1. A mixed alphabet (Quagmire) needs tool 37, combination 4 or 5.{RESET}")