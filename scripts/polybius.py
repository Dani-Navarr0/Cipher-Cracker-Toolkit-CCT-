import math

from theme import RED, GREEN, YELLOW, BLUE, CYAN, GREY, WHITE, RESET, banner

def build_polybius_square(key=""):
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ" # I and J combined
    key = "".join(dict.fromkeys(filter(str.isalpha, key.upper().replace("J", "I"))))
    square_chars = key + "".join(c for c in alphabet if c not in key)
    
    return {square_chars[i]: f"{(i//5)+1}{(i%5)+1}" for i in range(25)}

def run():
    banner("Polybius Square", "Letters to grid coordinates and back")
    
    mode = input(f"Choose a mode:\n({YELLOW}1{RESET}) Encrypt\n({YELLOW}2{RESET}) Decrypt\n{GREY}Selection: {RESET}")
    key = input(f"{GREY}Enter optional key (leave blank for standard alphabet): {RESET}").upper()
    text = input(f"{GREY}Enter text: {RESET}").upper()
    
    square = build_polybius_square(key)
    inv_square = {v: k for k, v in square.items()}
    
    if mode == '1':
        result = ""
        for char in text.replace("J", "I"):
            if char in square:
                result += square[char] + " "
        print(f"\n{GREEN}Ciphertext:{RESET} {result.strip()}")
        
    elif mode == '2':
        # Clean up input (remove spaces, get only numbers)
        clean_text = "".join(filter(str.isdigit, text))
        result = ""
        for i in range(0, len(clean_text), 2):
            pair = clean_text[i:i+2]
            if pair in inv_square:
                result += inv_square[pair]
        print(f"\n{GREEN}Plaintext:{RESET} {result}")