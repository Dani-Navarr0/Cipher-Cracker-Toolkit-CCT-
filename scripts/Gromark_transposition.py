"""Gromark cipher (tool 71): keyed mixed alphabet + chain-added numeric primer.

One-shot work only: the known-answer test and decryption with a known keyword
and primer. Ciphertext-only attacks are tool 34 (gromark_solver), whose C
engines screen every primer and hill-climb the mixed cipher alphabet with no
keyword, dictionary or crib. The former dictionary, key-length brute-force,
hill-climbing, annealing and genetic modes of this tool were removed: they ran
in Python, were not measured to solve anything, and their 'dragged' crib match
accepted most wrong keys (847 of 1,000 wrong primers for TESTING on a
250-letter text).

Model: the cipher letter's position in the keyed alphabet minus the running
key digit gives the plaintext letter (p = CA.index(c) - d), i.e. tool 34's
"right" direction (sign +1).
"""
from theme import GREEN, GREY, RED, RESET, YELLOW, banner

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
# Known-answer test case (menu 1)
TEST_CIPHERTEXT = "OHRERPHTMNUQDPUYQTGQHABASQXPTHPYSIXJUFVKNGNDRRIOMAEJGZKHCBNDBIWLDGVWDDVLXCSCZS"
TEST_KEYWORD, TEST_PRIMER = "GRONSFELD", "32941"


def create_keyed_alphabet(keyword: str, alphabet: str = ALPHABET) -> str:
    """Keyword-columnar mixed alphabet: keyword (repeats dropped) + the rest of
    the alphabet written in rows under the keyword, read off by columns in the
    alphabetical order of the keyword letters."""
    keyword = ''.join(dict.fromkeys(keyword.upper()))
    remaining = ''.join(c for c in alphabet if c not in keyword)
    base = keyword + remaining
    cols = len(keyword)
    if cols == 0:
        return alphabet
    rows = (len(base) + cols - 1) // cols
    block = [['' for _ in range(cols)] for _ in range(rows)]
    idx = 0
    for i in range(rows):
        for j in range(cols):
            if idx < len(base):
                block[i][j] = base[idx]
                idx += 1
    final_col_order = [i for char, i in sorted((char, i) for i, char in enumerate(keyword))]
    return ''.join(block[row][col] for col in final_col_order for row in range(rows)
                   if row < len(block) and col < len(block[row]) and block[row][col])


def generate_running_key(primer: str, length: int) -> str:
    """Gromark chain addition: each digit = (digit 5 back + digit 4 back) mod 10."""
    digits = [int(d) for d in primer if d.isdigit()]
    if len(digits) != 5:
        return ""
    for i in range(5, length):
        digits.append((digits[i - 5] + digits[i - 4]) % 10)
    return ''.join(map(str, digits[:max(length, 0)]))


def decrypt_gromark(ciphertext: str, mixed_alphabet: str, running_key: str, alphabet: str = ALPHABET) -> str:
    result = []
    len_alpha = len(alphabet)
    key_position = 0  # Advances only on enciphered letters, not spaces/punctuation.
    for char in ciphertext:
        if char in mixed_alphabet and key_position < len(running_key):
            straight_letter = alphabet[mixed_alphabet.find(char)]
            shift = int(running_key[key_position])
            key_position += 1
            result.append(alphabet[(alphabet.find(straight_letter) - shift) % len_alpha].lower())
        else:
            result.append(char.lower())
    return ''.join(result)


# --- menu ---

def run_test_case():
    print(f"\n{GREEN}--- Known-Answer Test Case ---{RESET}")
    mixed = create_keyed_alphabet(TEST_KEYWORD, ALPHABET)
    running = generate_running_key(TEST_PRIMER, len(TEST_CIPHERTEXT))
    decrypted = decrypt_gromark(TEST_CIPHERTEXT, mixed, running, ALPHABET)
    print(f"Ciphertext: {TEST_CIPHERTEXT}\nKeyword: {YELLOW}{TEST_KEYWORD}{RESET} | Primer: {YELLOW}{TEST_PRIMER}{RESET}\n"
          f"Decrypted: {decrypted}")


def run_direct_decryption():
    print(f"\n{GREEN}--- Direct Decryption ---{RESET}")
    ciphertext = input("Enter ciphertext: ").upper()
    keyword = input("Enter keyword: ").upper()
    primer = input("Enter primer (5-digit number): ").strip()
    if len(primer) != 5 or not primer.isdigit():
        print(f"{RED}The primer must be exactly 5 digits (got '{primer}').{RESET}")
        return
    alphabet = input("Enter alphabet (default: A-Z): ").upper() or ALPHABET
    mixed = create_keyed_alphabet(keyword, alphabet)
    running = generate_running_key(primer, len(ciphertext))
    print(f"Mixed alphabet: {YELLOW}{mixed}{RESET}")
    print(f"Decrypted Text: {decrypt_gromark(ciphertext, mixed, running, alphabet)}")


def run():
    banner("Gromark Cipher", "Keyed alphabet + chain-added numeric primer")
    while True:
        print("\nSelect an option:")
        print(f"  {YELLOW}1{RESET}) Run Known-Answer Test Case")
        print(f"  {YELLOW}2{RESET}) Direct Decryption (known keyword and primer)")
        print(f"  {YELLOW}3{RESET}) Ciphertext-only attack {GREY}(opens tool 34, Gromark Solver: no keyword, "
              f"word list or crib needed; A-Z only; needs a long text: it does not solve the 78-letter "
              f"test case of option 1){RESET}")
        print(f"  {YELLOW}4{RESET}) Exit")
        choice = input(">> ").strip()
        if choice == '1':
            run_test_case()
        elif choice == '2':
            run_direct_decryption()
        elif choice == '3':
            import gromark_solver
            gromark_solver.run()
        elif choice == '4':
            break
        else:
            print(f"{RED}Invalid choice. Please select a valid option.{RESET}")


if __name__ == "__main__":
    run()
