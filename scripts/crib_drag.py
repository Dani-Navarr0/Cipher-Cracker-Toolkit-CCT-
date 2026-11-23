from theme import RED, GREEN, YELLOW, BLUE, CYAN, GREY, WHITE, RESET, banner

def run():
    banner("Crib Dragging", "Slide a known word across the ciphertext to expose key fragments")
    
    ciphertext = input(f"{GREY}Enter ciphertext: {RESET}")
    ciphertext = "".join(filter(str.isalpha, ciphertext.upper()))
    
    crib = input(f"{GREY}Enter suspected plaintext word (the 'crib'): {RESET}")
    crib = "".join(filter(str.isalpha, crib.upper()))
    
    if len(crib) > len(ciphertext):
        print(f"{RED}Error: Crib cannot be longer than ciphertext.{RESET}")
        return
        
    print(f"\n{YELLOW}Dragging '{crib}' across ciphertext (Vigenère Subtraction)...{RESET}")
    print(f"{'Pos':<5} | {'Cipher Slice':<15} | {'Resulting Key Snippet'}")
    print(f"{GREY}-{RESET}" * 50)
    
    for i in range(len(ciphertext) - len(crib) + 1):
        cipher_slice = ciphertext[i:i+len(crib)]
        
        # Vigenere Subtraction: Key = Ciphertext - Plaintext
        key_snippet = ""
        for c_char, p_char in zip(cipher_slice, crib):
            diff = (ord(c_char) - ord(p_char)) % 26
            key_snippet += chr(diff + 65)
            
        print(f"{i:<5} | {cipher_slice:<15} | {GREEN}{key_snippet}{RESET}")
        
    print(f"\n{YELLOW}Tip: Look for key snippets that form recognizable English words!{RESET}")