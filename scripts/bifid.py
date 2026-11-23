from theme import RED, GREEN, YELLOW, BLUE, CYAN, GREY, WHITE, RESET, banner

def build_square(key=""):
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    key = "".join(dict.fromkeys(filter(str.isalpha, key.upper().replace("J", "I"))))
    chars = key + "".join(c for c in alphabet if c not in key)
    return {chars[i]: ((i//5)+1, (i%5)+1) for i in range(25)}, {((i//5)+1, (i%5)+1): chars[i] for i in range(25)}

def encrypt_bifid(text, key):
    text = "".join(filter(str.isalpha, text.upper().replace("J", "I")))
    char_to_coord, coord_to_char = build_square(key)
    
    rows, cols = [], []
    for char in text:
        r, c = char_to_coord[char]
        rows.append(r)
        cols.append(c)
        
    combined = rows + cols
    ciphertext = ""
    for i in range(0, len(combined), 2):
        ciphertext += coord_to_char[(combined[i], combined[i+1])]
    return ciphertext

def decrypt_bifid(text, key):
    text = "".join(filter(str.isalpha, text.upper().replace("J", "I")))
    char_to_coord, coord_to_char = build_square(key)
    
    coords = []
    for char in text:
        r, c = char_to_coord[char]
        coords.extend([r, c])
        
    half = len(coords) // 2
    rows = coords[:half]
    cols = coords[half:]
    
    plaintext = ""
    for r, c in zip(rows, cols):
        plaintext += coord_to_char[(r, c)]
    return plaintext

def run():
    banner("Bifid Cipher", "Polybius-square fractionation cipher")
    
    mode = input(f"Choose a mode: ({YELLOW}1{RESET} = Encrypt, {YELLOW}2{RESET} = Decrypt): ")
    key = input(f"{GREY}Enter key (or leave blank): {RESET}")
    text = input(f"{GREY}Enter text: {RESET}")
    
    if mode == '1':
        print(f"\n{GREEN}Ciphertext:{RESET} {encrypt_bifid(text, key)}")
    elif mode == '2':
        print(f"\n{GREEN}Plaintext:{RESET} {decrypt_bifid(text, key)}")