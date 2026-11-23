# scripts/kasiski.py
import math
from collections import Counter

# ANSI color codes
from theme import RED, GREEN, YELLOW, BLUE, CYAN, GREY, WHITE, RESET, banner

def get_factors(n):
    """Returns all factors of a number (excluding 1)."""
    factors = set()
    for i in range(2, int(math.sqrt(n)) + 1):
        if n % i == 0:
            factors.add(i)
            factors.add(n // i)
    if n > 1:
        factors.add(n)
    return sorted(list(factors))

def find_repeating_sequences(text, min_length=3, max_length=6):
    """Finds repeating sequences of characters and the distances between them."""
    text = "".join(filter(str.isalpha, text.upper()))
    sequences = {}
    
    # Extract all possible sequences of lengths between min_length and max_length
    for length in range(max_length, min_length - 1, -1):
        for i in range(len(text) - length):
            seq = text[i:i+length]
            
            # If we already found a longer sequence containing this, skip to avoid double counting
            if any(seq in longer_seq for longer_seq in sequences.keys() if len(longer_seq) > length):
                continue
                
            # Find all occurrences of the sequence
            start = 0
            positions = []
            while True:
                pos = text.find(seq, start)
                if pos == -1:
                    break
                positions.append(pos)
                start = pos + 1
                
            if len(positions) > 1:
                sequences[seq] = positions
                
    return sequences

def analyze_kasiski(ciphertext):
    """Performs the full Kasiski examination and returns likely key lengths."""
    print(f"\n{YELLOW}--- Kasiski Examination ---{RESET}")
    
    sequences = find_repeating_sequences(ciphertext)
    if not sequences:
        print(f"{RED}No repeating sequences found. Kasiski method cannot be applied.{RESET}")
        return []
        
    distances = []
    print(f"{GREY}Found Repeating Sequences:{RESET}")
    print(f"{'Sequence':<10} | {'Count':<5} | {'Positions'}")
    print("-" * 50)
    
    # Calculate distances between adjacent occurrences
    # Use every repeated sequence for the statistics; only the display is capped.
    for shown, (seq, positions) in enumerate(sequences.items()):
        if shown < 10:
            print(f"{GREEN}{seq:<10}{RESET} | {len(positions):<5} | {positions}")
        for i in range(len(positions) - 1):
            distance = positions[i+1] - positions[i]
            distances.append(distance)

    # Find the factors of all distances
    factor_counts = Counter()
    for distance in distances:
        factors = get_factors(distance)
        for factor in factors:
            factor_counts[factor] += 1
            
    print(f"\n{YELLOW}Likely Key Lengths (Based on factor frequency):{RESET}")
    print(f"{'Key Length':<12} | {'Occurrences (Factor Score)'}")
    print("-" * 50)
    
    # Sort factors by frequency, ignoring lengths > 20 as they are less common for basic ciphers
    likely_lengths = []
    top_count = factor_counts.most_common(1)[0][1] if factor_counts else 0
    for factor, count in factor_counts.most_common():
        if 2 <= factor <= 20:
            color = GREEN if count > top_count * 0.7 else YELLOW
            print(f"{color}{factor:<12}{RESET} | {count}")
            likely_lengths.append(factor)
            
    return likely_lengths

def run():
    banner("Kasiski Examination", "Repeated sequences reveal the key length")
    
    ciphertext = input(f"{GREY}Enter ciphertext (e.g., from a Vigenère cipher): {RESET}")
    if not ciphertext:
        return
        
    analyze_kasiski(ciphertext)

if __name__ == "__main__":
    run()