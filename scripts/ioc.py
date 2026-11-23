from collections import Counter

# ANSI color codes for terminal output
from theme import RED, GREEN, YELLOW, BLUE, CYAN, GREY, WHITE, RESET, banner

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

def run():
    banner("Index of Coincidence", "English ~0.066, random letters ~0.038")
    
    input_string = input(f"{GREY}Enter your string: {RESET}")

    print(f"{GREY}Index of Coincidence:{RESET} {calculate_ioc(input_string)}")
    print(f"{GREY}English IoC:{RESET} {YELLOW}0.0665{RESET}")
    print(f"{GREEN}===================================={RESET}")
    
    if not input_string:
        print(f"{RED}Error: Empty input string.{RESET}")
        return

if __name__ == "__main__":
    run()