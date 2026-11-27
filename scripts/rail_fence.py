"""Rail fence (zig-zag) transposition: decrypt with a known key, or try every
rail count and starting offset (also on the reversed text) and rank the
readings by n-gram fitness.

The offset is where on the zig-zag the first letter sits (0 = top rail,
going down); some variants start part-way through a cycle.
"""
from theme import BOLD, CYAN, GREEN, GREY, RED, RESET, YELLOW, banner, option


def rail_order(length, rails, offset=0):
    """Plaintext position of each ciphertext position (rails read top to bottom)."""
    if rails < 2:
        return list(range(length))
    cycle = 2 * (rails - 1)
    rows = []
    for position in range(length):
        phase = (position + offset) % cycle
        rows.append(phase if phase < rails else cycle - phase)
    return sorted(range(length), key=lambda position: (rows[position], position))


def decrypt_rail_fence(ciphertext, rails, offset=0):
    """Decrypt any sequence of characters (no marker characters are used, so
    every symbol, '*' included, survives)."""
    if rails <= 1:
        return ciphertext
    plain = [""] * len(ciphertext)
    for cipher_position, plain_position in enumerate(rail_order(len(ciphertext), rails, offset)):
        plain[plain_position] = ciphertext[cipher_position]
    return "".join(plain)


def encrypt_rail_fence(plaintext, rails, offset=0):
    if rails <= 1:
        return plaintext
    return "".join(plaintext[position] for position in rail_order(len(plaintext), rails, offset))


def rank_all(letters, max_rails, fitness):
    """Every rail count 2..max_rails and every offset, on the text and on its
    reverse, scored in C (``fitness``: an annealing.Fitness, normally
    cipher_profile.fitness_function()). Returns every reading, best first:
    (fitness, rails, offset, text reversed, plaintext); ties keep the order
    text forwards then reversed, rails, offset."""
    from native.screens import FORWARD, READ, REVERSED, ZIGZAG, Sources, record_of, symbol_codes
    codes, shown, decode = symbol_codes(letters)
    n = len(codes)
    sources = Sources(n)
    keys = []
    for rails in range(2, max_rails + 1):
        for offset in range(2 * (rails - 1)):
            sources.add(ZIGZAG, (rails, offset), directions=READ, meta=("rail_fence", rails, offset))
            keys.append((rails, offset))
    results = []
    for reverse, text in ((False, FORWARD), (True, REVERSED)):
        _, scored = sources.score(codes, fitness, text=text)
        plains = sources.plain(shown, [ident for _, ident in scored])
        results += [(score, *keys[record_of(ident)], reverse, decode(plain))
                    for (score, ident), plain in zip(scored, plains)]
    results.sort(key=lambda result: -result[0])
    return results


def run():
    banner("Rail Fence Cipher", "Zig-zag transposition: decrypt, or rank every rail count and offset")
    option(1, "Rank every rail count and offset", "(recommended for an unknown key)")
    option(2, "Decrypt with a known number of rails")
    option(3, "Encrypt")
    mode = input("Select (Enter = 1): ").strip() or "1"
    text = input(f"{GREY}Enter ciphertext: {RESET}") if mode != "3" else input(f"{GREY}Enter plaintext: {RESET}")
    letters = "".join(ch for ch in text.upper() if "A" <= ch <= "Z")
    if len(letters) < 3:
        print(f"{RED}Need at least 3 letters (spaces and punctuation are removed).{RESET}")
        return
    if len(letters) != len(text.replace(" ", "")):
        print(f"{GREY}Using the {len(letters)} letters A-Z only (spaces, digits and punctuation removed).{RESET}")

    if mode in ("2", "3"):
        try:
            rails = int(input("Number of rails: ").strip())
            offset = int(input("Starting offset (Enter = 0): ").strip() or 0)
        except ValueError:
            print(f"{RED}Not a number.{RESET}")
            return
        result = (encrypt_rail_fence if mode == "3" else decrypt_rail_fence)(letters, rails, offset)
        print(f"\n{GREEN}{result}{RESET}")
        return

    import cipher_profile as cp
    default_max = min(40, len(letters) - 1)
    answer = input(f"Most rails to try (Enter = {YELLOW}{default_max}{RESET}): ").strip()
    max_rails = min(int(answer), len(letters) - 1) if answer.isdigit() and int(answer) >= 2 else default_max
    results = rank_all(letters, max_rails, cp.fitness_function())
    refs = cp.references(len(letters)) if len(letters) >= cp.MIN_LETTERS else None
    print(f"\n{BOLD}Best readings of {len(results):,}{RESET} {GREY}(rails 2-{max_rails}, every offset, "
          f"text forwards and reversed; higher fitness = more English){RESET}")
    for rank, (score, rails, offset, reverse, plain) in enumerate(results[:10], start=1):
        verdict = f" [{cp.judge(score, refs)}]" if refs else ""
        colour = GREEN if "reads" in verdict else YELLOW if "partly" in verdict else GREY
        detail = f"{rails} rails" + (f", offset {offset}" if offset else "") + (", text reversed" if reverse else "")
        print(f"{rank:>2}. {CYAN}{detail:<28}{RESET} fitness {score:6.1f}{colour}{verdict}{RESET}")
        print(f"    {plain}")


if __name__ == "__main__":
    run()
