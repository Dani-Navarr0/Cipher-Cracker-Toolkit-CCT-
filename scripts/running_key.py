import string
from utils.utils import get_input_ciphertexts

from theme import RED, GREEN, YELLOW, BLUE, CYAN, GREY, WHITE, RESET, banner

def decrypt_running_key(ciphertext: str, key_text: str) -> str:
    key_chars = [k for k in key_text.upper() if "A" <= k <= "Z"]
    if not key_chars: return ciphertext
    needed = sum(1 for char in ciphertext if char.isalpha())
    if len(key_chars) < needed:
        raise ValueError(f"Running key has {len(key_chars)} letters but the ciphertext needs {needed}.")

    plaintext = []
    k_idx = 0
    for char in ciphertext:
        if char.isalpha():
            shift = ord(key_chars[k_idx]) - 65
            base = 65 if char.isupper() else 97
            plaintext.append(chr(((ord(char) - base - shift + 26) % 26) + base))
            k_idx += 1
        else:
            plaintext.append(char)
    return "".join(plaintext)

def crib_drag(ciphertext: str, crib: str):
    ciphertext_chars = [c for c in ciphertext.upper() if c.isalpha()]
    crib_chars = [c for c in crib.upper() if c.isalpha()]
    
    if len(crib_chars) > len(ciphertext_chars):
        print(f"{RED}Crib is longer than ciphertext!{RESET}")
        return
        
    print(f"\n{YELLOW}--- Crib Drag Results for '{crib.upper()}' ---{RESET}")
    print(f"{GREY}Showing underlying key snippets if '{crib.upper()}' was at that position:{RESET}\n")
    
    for offset in range(len(ciphertext_chars) - len(crib_chars) + 1):
        key_snippet = []
        for i in range(len(crib_chars)):
            c_val = ord(ciphertext_chars[offset + i]) - 65
            p_val = ord(crib_chars[i]) - 65
            # K = C - P mod 26
            k_val = (c_val - p_val + 26) % 26
            key_snippet.append(chr(k_val + 65))
            
        print(f"Offset {offset:>3}: {GREEN}{''.join(key_snippet)}{RESET}")

def run():
    banner("Running Key Cipher", "Book-key decryption and crib dragging")
    ciphers = get_input_ciphertexts()
    if not ciphers: return
    
    print(f"\n  ({YELLOW}1{RESET}) Direct Decryption (Provide full text key)\n  ({YELLOW}2{RESET}) Crib Dragging (Search for known plaintext words)")
    mode = input(">> ").strip()
    
    for cipher in ciphers:
        if mode == '1':
            key = input(f"{YELLOW}Enter the running key text:{RESET}\n>> ")
            try:
                print(f"\n{GREEN}Plaintext:{RESET}\n{decrypt_running_key(cipher, key)}")
            except ValueError as error:
                print(f"{RED}{error}{RESET}")
        elif mode == '2':
            while True:
                crib = input(f"\nEnter a Crib word to drag (or 'Q' to quit): ").strip()
                if crib.upper() == 'Q': break
                crib_drag(cipher, crib)