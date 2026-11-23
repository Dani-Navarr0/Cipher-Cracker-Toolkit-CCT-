from theme import RED, GREEN, YELLOW, BLUE, CYAN, GREY, WHITE, RESET, banner

def run():
    banner("Text Formatter", "Clean and reshape ciphertext")
    
    text = input(f"{GREY}Enter text to format: {RESET}")
    if not text: return
    
    print(f"\n{YELLOW}Available Operations:{RESET}")
    print(f"({YELLOW}1{RESET}) Strip everything except letters (Uppercase)")
    print(f"({YELLOW}2{RESET}) Remove spaces only")
    print(f"({YELLOW}3{RESET}) Format into blocks of 5 (Standard Crypto Format)")
    print(f"({YELLOW}4{RESET}) Reverse the text")
    
    choice = input(f"{GREY}Selection: {RESET}")
    
    print(f"\n{GREEN}Result:{RESET}")
    if choice == '1':
        print("".join(filter(str.isalpha, text)).upper())
    elif choice == '2':
        print(text.replace(" ", ""))
    elif choice == '3':
        clean = "".join(filter(str.isalpha, text)).upper()
        print(" ".join(clean[i:i+5] for i in range(0, len(clean), 5)))
    elif choice == '4':
        print(text[::-1])