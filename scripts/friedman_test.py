from theme import RED, GREEN, YELLOW, BLUE, CYAN, GREY, WHITE, RESET, banner

def calculate_ioc(text):
    text = ''.join(filter(str.isalpha, text.upper()))
    n = len(text)
    if n <= 1: return 0.0
    freqs = {char: text.count(char) for char in set(text)}
    numerator = sum(count * (count - 1) for count in freqs.values())
    return numerator / (n * (n - 1))

def run():
    banner("Friedman Test", "Estimate a polyalphabetic key length from the IoC")
    
    text = input(f"{GREY}Enter ciphertext: {RESET}")
    text = ''.join(filter(str.isalpha, text.upper()))
    n = len(text)
    
    if n < 10:
        print(f"{RED}Ciphertext too short for reliable estimation.{RESET}")
        return
        
    ioc = calculate_ioc(text)
    
    # Constants for standard English
    kp = 0.0667  # Probability of coincidence for English
    kr = 0.0385  # Probability of coincidence for random text
    
    # Friedman formula
    numerator = kp - kr
    denominator = ioc - kr
    
    if denominator <= 0:
        estimated_length = "Infinity (IoC is exactly random or worse)"
    else:
        estimated_length = numerator / denominator
        
    print(f"\n{GREY}Text Length (N):{RESET} {n}")
    print(f"{GREY}Calculated IoC:{RESET} {ioc:.4f}")
    print(f"{GREY}-{RESET}" * 40)
    
    if isinstance(estimated_length, float):
        print(f"{YELLOW}Estimated Key Length: {GREEN}{estimated_length:.2f}{RESET}")
        print(f"-> You should try brute-forcing key lengths of {YELLOW}{max(1, int(estimated_length))}{RESET} or {YELLOW}{int(estimated_length) + 1}{RESET}")
    else:
        print(f"{RED}Estimated Key Length: {estimated_length}{RESET}")