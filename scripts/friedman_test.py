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
        print(f"{YELLOW}Friedman estimate of the key length: {GREEN}{estimated_length:.1f}{RESET}")
        if ioc >= 0.06:
            print(f"{GREY}The IoC is English-like: probably not a polyalphabetic cipher at all "
                  f"(substitution and/or transposition).{RESET}")
        else:
            print(f"{GREY}This is a rough estimate: one IoC value from a finite text can be off by a factor of two "
                  f"(measured: a 7-letter key gave 9.9 and 12.5, a 10-letter key 7.5 and 15.8, on 906- and "
                  f"468-letter texts). Use it as an order of magnitude; "
                  f"30 Vigenere Auto-Solver tests each key length directly.{RESET}")
    else:
        print(f"{RED}Estimated key length: {estimated_length}{RESET}")