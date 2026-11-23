import os

# ANSI color codes for terminal output
from theme import RED, GREEN, YELLOW, BLUE, CYAN, GREY, WHITE, RESET, banner

DEFAULT_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

def generate_keyword_alphabet(keyword: str, base_alphabet: str = DEFAULT_ALPHABET) -> str:
    """Generates a keyed alphabet by deduplicating a keyword and appending the remaining alphabet."""
    # Filter for alphabetic characters only and convert to uppercase
    keyword = "".join(filter(str.isalpha, keyword.upper()))
    
    custom_alphabet = []
    seen = set()
    
    # 1. Add deduplicated letters from the keyword
    for char in keyword:
        if char not in seen:
            seen.add(char)
            custom_alphabet.append(char)
            
    # 2. Append remaining letters from the base alphabet
    for char in base_alphabet:
        if char not in seen:
            custom_alphabet.append(char)
            
    return "".join(custom_alphabet)

def run():
    banner("Keyword Alphabet Generator", "Build mixed alphabets from a keyword")
    
    while True:
        keywords_input = input(f"\n{GREY}Enter keyword(s) separated by commas (or 'Q' to quit): {RESET}").strip()
        
        if not keywords_input:
            print(f"{RED}Error: Input cannot be empty.{RESET}")
            continue
            
        if keywords_input.upper() == 'Q':
            print(f"{YELLOW}Returning to main menu...{RESET}")
            break
            
        # Parse multiple keywords
        keywords = [k.strip() for k in keywords_input.split(",") if k.strip()]
        
        if not keywords:
            continue

        results = []
        
        print(f"\n{CYAN}Standard Alphabet:{RESET} {DEFAULT_ALPHABET}")
        print(f"{GREY}-{RESET}" * 60)
        
        # Generate and print each alphabet
        for kw in keywords:
            alphabet = generate_keyword_alphabet(kw)
            results.append((kw, alphabet))
            # Truncate keyword display if it's absurdly long for console formatting
            display_kw = kw[:15] + "..." if len(kw) > 15 else kw
            print(f"{CYAN}Keyword:{RESET} {display_kw:<18} {CYAN}Alphabet:{RESET} {YELLOW}{alphabet}{RESET}")
            
        print(f"{GREY}-{RESET}" * 60)
        
        # Save logic
        save = input(f"\nSave these {len(results)} alphabet(s) to a text file? ({YELLOW}Y/N{RESET}): ").strip().upper()
        if save == 'Y':
            filename = input("Enter filename (default: custom_alphabets.txt): ").strip() or "custom_alphabets.txt"
            if not filename.endswith(".txt"):
                filename += ".txt"
            try:
                with open(filename, "w", encoding="utf-8") as f:
                    f.write(f"Standard Alphabet: {DEFAULT_ALPHABET}\n")
                    f.write("=" * 45 + "\n\n")
                    for kw, alpha in results:
                        f.write(f"Keyword:  {kw}\n")
                        f.write(f"Alphabet: {alpha}\n")
                        f.write("-" * 30 + "\n")
                print(f"{GREEN}Successfully saved {len(results)} alphabet(s) to {filename}{RESET}")
            except Exception as e:
                print(f"{RED}Error saving file: {e}{RESET}")

if __name__ == "__main__":
    run()