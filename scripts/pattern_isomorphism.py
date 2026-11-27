"""Word pattern isomorphism: for a simple substitution that kept its word
boundaries, match each cipher word's letter pattern (ATTACK = 0-1-1-0-2-3)
against a dictionary, then search for ONE letter mapping that turns every word
into a dictionary word at the same time (beam search, most constrained words
first, one-to-one letters). Candidate words are ranked by how English they
look on 3-grams, since the word list has no frequencies and includes many rare
words. The pattern matching, the word scores and the beam search run in C
(native/screens_pattern.c); the annealer runs come from the C layered engine
(two_layer.solve_job).
"""
import os
import re
from functools import lru_cache

from theme import BOLD, CYAN, GREEN, GREY, RED, RESET, YELLOW, banner

dictionary_path = os.path.join(os.path.dirname(__file__), "data", "words_alpha.txt")
# Words shorter than 3 letters have no 3-gram score: these score 120, others 60.
SHORT_COMMON = ("A", "I", "AN", "AS", "AT", "BE", "BY", "DO", "GO", "HE", "IF", "IN", "IS", "IT",
                "ME", "MY", "NO", "OF", "ON", "OR", "SO", "TO", "UP", "US", "WE")


def get_word_pattern(word):
    """Converts a word to a pattern string (e.g., 'ATTACK' -> '0-1-1-0-2-3')"""
    pattern, char_map, next_num = [], {}, 0
    for char in word:
        if char not in char_map:
            char_map[char] = str(next_num)
            next_num += 1
        pattern.append(char_map[char])
    return "-".join(pattern)


@lru_cache(maxsize=1)
def load_dictionary():
    """The word list as a native.screens.PatternDictionary: A-Z words only
    (entries with other characters are left out), each word once, 'A' and 'I'
    the only one-letter words; every word scored on 3-grams in C."""
    import native
    from native.screens import PatternDictionary
    from ngram_scoring import load_ngram_scores, resolve_ngram_path
    native.require()
    words = {}
    try:
        with open(dictionary_path, 'r', encoding='utf-8') as f:
            for line in f:
                word = line.strip().upper()
                if word.isascii() and word.isalpha() and (len(word) > 1 or word in ("A", "I")):
                    words[word] = None
    except FileNotFoundError:
        print(f"{RED}Dictionary not found at {dictionary_path}{RESET}")
    return PatternDictionary(list(words), load_ngram_scores(resolve_ngram_path(3)).scores, 3, SHORT_COMMON)


def candidates_for(word, limit=400):
    """(number of dictionary words with the pattern of ``word``, the most
    English-looking ``limit`` of them, best first)."""
    return load_dictionary().matches(word, limit)


def solve(cipher_words, beam=300, per_word=400):
    """Best joint letter mappings, best first: list of (score, mapping dict).
    Cipher words are A-Z (case is ignored); the search runs in C."""
    words = [w.upper() for w in cipher_words if w]
    return load_dictionary().solve(list(dict.fromkeys(words)), beam, per_word)


def decode(text, mapping):
    return "".join(mapping.get(ch, "?") if "A" <= ch <= "Z" else ch for ch in text.upper())


@lru_cache(maxsize=1)
def dictionary_words():
    return frozenset(load_dictionary().words)


def word_share(decoded_words):
    """Share of letters that sit in decoded words found in the dictionary."""
    words = dictionary_words()
    total = sum(len(w) for w in decoded_words) or 1
    return sum(len(w) for w in decoded_words if w in words) / total


def anneal_candidates(cipher_words, runs=4, steps=400_000):
    """Mappings from the substitution annealer (ignores word boundaries; robust
    on short texts), run in parallel. Returns a list of cipher->plain dicts."""
    import random
    from concurrent.futures import ProcessPoolExecutor
    from ngram_scoring import DEFAULT_NGRAM_PATH, text_to_codes
    from two_layer import solve_job
    cipher = text_to_codes("".join(cipher_words))
    jobs = [{'cipher': cipher, 'encryption': [("sub", None)], 'iterations': steps, 'ngram_path': str(DEFAULT_NGRAM_PATH),
             'entropy_weight': 0.5, 'seed': random.randrange(2 ** 32), 'label': 'substitution'} for _ in range(runs)]
    import compute
    with ProcessPoolExecutor(max_workers=compute.workers(runs)) as pool:
        results = list(pool.map(solve_job, jobs))
    joined = "".join(cipher_words)
    mappings = []
    for result in results:
        mapping = {}
        for c, p in zip(joined, result['plaintext']):
            mapping[c] = p
        mappings.append(mapping)
    return mappings


def best_solutions(cipher_words, use_annealing=True):
    """Joint word-pattern mappings plus annealer mappings, ranked by the share
    of dictionary words, then by n-gram fitness. List of (share, text, mapping)."""
    import cipher_profile as cp
    from ngram_scoring import text_to_codes
    mappings = [mapping for _, mapping in solve(cipher_words)[:20]]
    if use_annealing:
        mappings += anneal_candidates(cipher_words)
    fitness = cp.fitness_function()
    ranked, seen = [], set()
    for mapping in mappings:
        decoded = [decode(w, mapping) for w in cipher_words]
        text = " ".join(decoded)
        if text in seen:
            continue
        seen.add(text)
        ranked.append((word_share(decoded), fitness(text_to_codes(text)), text, mapping))
    ranked.sort(key=lambda entry: (-entry[0], -entry[1]))
    return [(share, text, mapping) for share, _, text, mapping in ranked]


def run():
    banner("Word Pattern Isomorphism", "Substitution with word boundaries: match word shapes, then solve all words jointly")

    ciphertext = input(f"{GREY}Enter ciphertext (MUST contain spaces): {RESET}").upper()
    words = [w for w in (re.sub(r"[^A-Z]", "", part) for part in ciphertext.split()) if w]
    if len(words) < 2:
        print(f"{RED}Need a ciphertext with word spaces (at least two words).{RESET}")
        return

    import native
    native.require()
    print(f"\n{YELLOW}Loading the dictionary...{RESET}")
    load_dictionary()

    print(f"\n{BOLD}Pattern matches, longest words first{RESET} {GREY}(most English-looking first){RESET}")
    for word in sorted(set(words), key=len, reverse=True)[:6]:
        total, matches = candidates_for(word, 10)
        print(f"  {GREEN}{word}{RESET} ({get_word_pattern(word)}): "
              + (f"{YELLOW}{', '.join(matches)}{RESET}{GREY}{f' ... ({total} in all)' if total > 10 else ''}{RESET}"
                 if matches else f"{RED}no dictionary word has this pattern (a name?){RESET}"))

    print(f"\n{GREY}Solving: joint word-pattern search, plus 4 runs of the substitution annealer "
          f"(about 10-30 s)...{RESET}")
    solutions = best_solutions(words)
    if not solutions:
        print(f"{RED}No consistent mapping found.{RESET}")
        return
    print(f"\n{BOLD}Best solutions{RESET} {GREY}(ranked by the share of letters in dictionary words; "
          f"'?' = a letter nothing fixed){RESET}")
    for rank, (share, text, mapping) in enumerate(solutions[:3], start=1):
        print(f"  {rank}. {share:4.0%} dictionary words  {CYAN}{text}{RESET}")
    best = solutions[0][2]
    key = "".join(best.get(ch, "?") for ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    print(f"\n  {GREY}Cipher ABCDEFGHIJKLMNOPQRSTUVWXYZ{RESET}\n  {GREY}Plain  {RESET}{YELLOW}{key}{RESET}")
    print(f"\n{GREY}Partial or odd words? Use the mapping as a start in 31 Annealing: Substitution, or remove "
          f"proper names from the text and run again.{RESET}")


if __name__ == "__main__":
    run()
