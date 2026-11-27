"""Word pattern isomorphism: for a simple substitution that kept its word
boundaries, match each cipher word's letter pattern (ATTACK = 0-1-1-0-2-3)
against a dictionary, then search for ONE letter mapping that turns every word
into a dictionary word at the same time (beam search, most constrained words
first, one-to-one letters). Candidate words are ranked by how English they
look on 3-grams, since the word list has no frequencies and includes many rare
words.
"""
import os
import re
from functools import lru_cache

from theme import BOLD, CYAN, GREEN, GREY, RED, RESET, YELLOW, banner

dictionary_path = os.path.join(os.path.dirname(__file__), "data", "words_alpha.txt")


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
def load_pattern_dict():
    patterns = {}
    try:
        with open(dictionary_path, 'r', encoding='utf-8') as f:
            for line in f:
                word = line.strip().upper()
                if len(word) > 1 or word in ("A", "I"):
                    patterns.setdefault(get_word_pattern(word), []).append(word)
    except FileNotFoundError:
        print(f"{RED}Dictionary not found at {dictionary_path}{RESET}")
    return patterns


@lru_cache(maxsize=1)
def _trigram_model():
    from ngram_scoring import load_ngram_scores, resolve_ngram_path
    return load_ngram_scores(resolve_ngram_path(3))


def word_score(word):
    """Mean 3-gram score of the word (0-255; higher = more English-looking)."""
    from ngram_scoring import ngram_total, text_to_codes
    model = _trigram_model()
    codes = text_to_codes(word)
    windows = len(codes) - 2
    if windows <= 0:
        return 120.0 if word in ("A", "I", "AN", "AS", "AT", "BE", "BY", "DO", "GO", "HE", "IF", "IN", "IS", "IT",
                                 "ME", "MY", "NO", "OF", "ON", "OR", "SO", "TO", "UP", "US", "WE") else 60.0
    return ngram_total(codes, model.scores, 3) / windows


def candidates_for(word, patterns, limit=400):
    matches = patterns.get(get_word_pattern(word), [])
    return sorted(matches, key=lambda w: -word_score(w))[:limit]


def solve(cipher_words, beam=300, per_word=400):
    """Best joint letter mappings, best first: list of (score, mapping dict)."""
    patterns = load_pattern_dict()
    distinct = list(dict.fromkeys(w for w in cipher_words if w))
    options = {w: candidates_for(w, patterns, per_word) for w in distinct}
    order = sorted((w for w in distinct if options[w]), key=lambda w: (len(options[w]), -len(w)))
    beams = [(0.0, {}, {})]          # (score, cipher->plain, plain->cipher)
    for word in order:
        expanded = []
        everything = patterns.get(get_word_pattern(word), [])
        index = {}                   # (position, letter) -> set of dictionary words, built on demand
        filtered = {}
        for score, forward, backward in beams:
            # Letters already fixed by earlier words select from the WHOLE word list
            # (a common word can rank low on 3-grams); otherwise use the ranked top.
            known = tuple(forward.get(c) for c in word)
            if known not in filtered:
                fixed = [(i, letter) for i, letter in enumerate(known) if letter]
                if fixed:
                    sets = []
                    for i, letter in fixed:
                        if (i, letter) not in index:
                            index[(i, letter)] = {w for w in everything if w[i] == letter}
                        sets.append(index[(i, letter)])
                    pool = set.intersection(*sets) if sets else set()
                    filtered[known] = sorted(pool, key=lambda w: -word_score(w))[:per_word]
                else:
                    filtered[known] = options[word]
            for candidate in filtered[known]:
                new_forward, new_backward, ok = None, None, True
                for c, p in zip(word, candidate):
                    mapped = forward.get(c) if new_forward is None else new_forward.get(c)
                    if mapped is not None:
                        if mapped != p:
                            ok = False
                            break
                        continue
                    owner = backward.get(p) if new_backward is None else new_backward.get(p)
                    if owner is not None and owner != c:
                        ok = False
                        break
                    if new_forward is None:
                        new_forward, new_backward = dict(forward), dict(backward)
                    new_forward[c], new_backward[p] = p, c
                if ok:
                    expanded.append((score + word_score(candidate) * len(candidate),
                                     new_forward or forward, new_backward or backward))
        if expanded:                 # a word nothing fits (a name?) is skipped, not fatal
            expanded.sort(key=lambda entry: -entry[0])
            beams = expanded[:beam]
    return [(score, forward) for score, forward, _ in beams]


def decode(text, mapping):
    return "".join(mapping.get(ch, "?") if "A" <= ch <= "Z" else ch for ch in text.upper())


@lru_cache(maxsize=1)
def dictionary_words():
    return frozenset(w for words in load_pattern_dict().values() for w in words)


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
    with ProcessPoolExecutor(max_workers=min(runs, max(1, (os.cpu_count() or 2) - 1))) as pool:
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

    print(f"\n{YELLOW}Loading dictionary patterns...{RESET}")
    patterns = load_pattern_dict()

    print(f"\n{BOLD}Pattern matches, longest words first{RESET} {GREY}(most English-looking first){RESET}")
    for word in sorted(set(words), key=len, reverse=True)[:6]:
        matches = candidates_for(word, patterns, 10)
        total = len(patterns.get(get_word_pattern(word), []))
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
