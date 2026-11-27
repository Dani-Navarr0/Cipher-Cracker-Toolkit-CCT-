"""Tests for the periodic-key C engines (scripts/native/periodic_engine.c,
periodic_dict.c): the annealer behind periodic_solver.solve_periodic, the
dictionary attack (attack_support.run_batches), the Gronsfeld exhaustive
search, and the XOR and modular word-list attacks.

Planted ciphertexts must give back their keys. Where the C engine must give
exactly what the old Python loops gave, the loop is copied here as a
"test-only reference" (it is not part of the toolkit).
Run: python -m unittest tests.test_c_periodic
"""
import heapq
import os
import random
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for path in (ROOT, os.path.join(ROOT, "scripts")):
    if path not in sys.path:
        sys.path.insert(0, path)

import ngram_scoring  # noqa: E402
from annealing import Fitness, Schedule  # noqa: E402
from ngram_scoring import score_text, text_to_codes  # noqa: E402
from utils.utils import calculate_ioc  # noqa: E402

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KRYPTOS = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
TEXT = ("It was the best of times and the worst of times, and nobody in the small town by the river knew "
        "what would happen next. The old ferryman said that the water had been rising for three days and "
        "that the bridge would not stand another night. So the people gathered their animals and their "
        "children and walked slowly up the hill toward the church, where the bells were already ringing "
        "and the lamps had been lit in every window.")
LETTERS = "".join(c for c in TEXT.upper() if "A" <= c <= "Z")
# Characters the decrypt functions treat specially: non-ASCII letters that pass
# through (é, ß -> 'SS' when scored), ones whose upper case is in the alphabet
# (ı -> I, ſ -> S, decrypted), and a ligature whose upper case is two letters (ﬆ).
ODD = "Café déjà-vu: straße, ıſ ﬆ 42! "


# Alphabets that are not a permutation of A-Z: I/J merged (25), with digits (36),
# Spanish with N-tilde (27, a symbol shown as no A-Z letter), with capital
# sharp s (its lower case 'ß' is scored as two letters, 'SS'), with a repeated
# letter, and a short one (7, fewer symbols than the 10 Gronsfeld digits).
OTHER_ALPHABETS = ("ABCDEFGHIKLMNOPQRSTUVWXYZ", "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
                   "ABCDEFGHIJKLMNÑOPQRSTUVWXYZ", "ABCDEFGHIJKLMNOPQRSTUVWXYZẞ", "KRYPTOSABCDEFGHIJKLMNQUVWXZ",
                   "ETAOINS")


def model(size=4):
    return ngram_scoring.load_ngram_scores(ngram_scoring.resolve_ngram_path(size))


def periodic_encrypt(text, key, alphabet, rule_encrypt):
    """Encrypt the characters whose upper case is in the alphabet (indices as
    the tools' {char: index} dictionaries: the last occurrence); others unchanged."""
    index_of = {char: i for i, char in enumerate(alphabet)}
    out, j = [], 0
    for char in text:
        upper = char.upper()
        if upper in index_of:
            out.append(alphabet[rule_encrypt(index_of[upper], index_of[key[j % len(key)]], len(alphabet))])
            j += 1
        else:
            out.append(char)
    return "".join(out)


def vigenere_encrypt(text, key, alphabet=ALPHABET):
    return periodic_encrypt(text, key, alphabet, lambda p, k, m: (p + k) % m)


def beaufort_encrypt(text, key, alphabet=ALPHABET):
    return periodic_encrypt(text, key, alphabet, lambda p, k, m: (k - p) % m)


def porta_encrypt(text, key, alphabet=ALPHABET):
    import porta    # Porta is its own inverse (on an even-length alphabet)
    return periodic_encrypt(text, key, alphabet, porta.porta_rule)


def gronsfeld_encrypt(text, key, alphabet=ALPHABET):
    """As Gronsfeld.gronsfeld_decrypt finds symbols: upper case in the alphabet, first index."""
    out, j = [], 0
    for char in text:
        upper = char.upper()
        if upper in alphabet:
            out.append(alphabet[(alphabet.index(upper) + int(key[j % len(key)])) % len(alphabet)])
            j += 1
        else:
            out.append(char)
    return "".join(out)


# ------------------------------------------------------------------ test-only references

def reference_periodic_fitness(plain_codes, ngram_model, mode, ioc_range, weight=0.5):
    """Test-only reference: solve_periodic's Python fitness before the C port."""
    base = Fitness(ngram_model, weight)
    min_ioc, max_ioc = ioc_range
    total = len(plain_codes)
    ioc = 0.0 if total < 2 else sum(plain_codes.count(c) * (plain_codes.count(c) - 1)
                                    for c in range(26)) / (total * (total - 1))
    penalty = 0.0 if min_ioc <= ioc <= max_ioc else min(abs(ioc - min_ioc), abs(ioc - max_ioc))
    if mode == 2:
        return -penalty * 1000.0
    if mode == 3:
        return base(plain_codes) * max(0.05, 1.0 - penalty * 20.0)
    return base(plain_codes)


def reference_score_batch(decrypt, words, ciphertext, alphabet, phrases, ngram_model, min_ioc, max_ioc, top=25):
    """Test-only reference: attack_support.score_batch's Python loop before the C port."""
    from attack_support import contains_all_phrases
    kept, others = [], []
    for word in words:
        plaintext = decrypt(ciphertext, word, alphabet)
        score = score_text(plaintext, ngram_model)
        ioc = calculate_ioc(plaintext)
        match = contains_all_phrases(plaintext, phrases)
        entry = (score, word, plaintext, ioc, match)
        if match or min_ioc <= ioc <= max_ioc:
            kept.append(entry)
        else:
            others.append(entry)
    kept.extend(heapq.nsmallest(top, others, key=lambda entry: entry[0]))
    return [(word, plaintext, ioc, score, match) for score, word, plaintext, ioc, match in kept]


def reference_gronsfeld_batch(ciphertext, alphabet, start, end, key_length, ngram_model, known, keep=50):
    """Test-only reference: Gronsfeld.process_exhaustive_batch's Python loop before the C port."""
    from Gronsfeld import gronsfeld_decrypt, utils
    kept, matched = [], []
    for number in range(start, end):
        key = str(number).zfill(key_length)
        decrypted = gronsfeld_decrypt(ciphertext, key, alphabet)
        score = score_text(decrypted, ngram_model)
        if known and any(word.lower() in decrypted for word in known):
            matched.append((score, key, decrypted))
        elif len(kept) < keep:
            heapq.heappush(kept, (-score, key, decrypted))
        elif -score > kept[0][0]:
            heapq.heapreplace(kept, (-score, key, decrypted))
    entries = matched + [(-negative, key, text) for negative, key, text in kept]
    return [{'key': key, 'decrypted': text, 'ioc': utils.calculate_ioc(text), 'score': score}
            for score, key, text in entries]


def reference_word_attack(words, make_text, kind, min_ioc, max_ioc, outside_needs_text, keep=25):
    """Test-only reference: the xor / modular_add_sub brute_force_with_ioc loops
    before the C port (no frequency analysis). make_text(upper word) -> text or None (skip)."""
    ngram_model = ngram_scoring.load_ngram_scores()
    results, outside, costs = [], [], {}
    for checked, word in enumerate(words, start=1):
        if not word or not all(ord(c) < 128 for c in word):
            continue
        test_word = word.upper()
        text = make_text(test_word)
        if text is None:
            continue
        ioc = calculate_ioc(text)
        cost = score_text(text, ngram_model)
        costs[test_word] = cost
        if min_ioc <= ioc <= max_ioc and len(text.strip()) > 0:
            results.append((test_word, kind, text, ioc, "", float('inf')))
        elif text.strip() or not outside_needs_text:
            heapq.heappush(outside, (-cost, checked, (test_word, kind, text, ioc, "", float('inf'))))
            if len(outside) > keep:
                heapq.heappop(outside)
    results += [entry for _, _, entry in outside]
    results.sort(key=lambda x: costs.get(x[0], 255))
    return results, costs


def normalised(rows, costs):
    """Rows in a tie-independent order (cost, then the row itself)."""
    return sorted(rows, key=lambda row: (costs[row[0]], row[0], row[2]))


# ------------------------------------------------------------------ annealer

class PeriodicAnnealerTests(unittest.TestCase):
    def test_c_score_matches_python_fitness(self):
        from native import periodic_engine
        rng = random.Random(3)
        m = model(4)
        symbols = [ALPHABET.index(c) for c in vigenere_encrypt(LETTERS[:180], "LANTERN")]
        tables = b"".join(bytes((c - k) % 26 for c in range(26)) for k in range(26))
        for mode in (1, 2, 3):
            for ioc_range in ((0.060, 0.070), (0.03, 0.045)):
                built, keep = periodic_engine.problem(symbols, 7, tables, 26, m, 0.5, mode, ioc_range)
                for _ in range(20):
                    key = [rng.randrange(26) for _ in range(7)]
                    plain = bytes((s - key[i % 7]) % 26 for i, s in enumerate(symbols))
                    expected = reference_periodic_fitness(plain, m, mode, ioc_range)
                    got = periodic_engine.score_key(built, key)
                    self.assertAlmostEqual(got, expected, delta=1e-9 * max(1.0, abs(expected)))

    def test_planted_keys_are_recovered(self):
        import beaufort
        import porta
        from periodic_solver import solve_periodic
        random.seed(5)
        m = model(4)
        cases = [
            ("vigenere", vigenere_encrypt(LETTERS, "LANTERN"), lambda c, k, n: (c - k) % n, "LANTERN"),
            ("beaufort", beaufort_encrypt(LETTERS, "LANTERN"), beaufort.beaufort_rule, "LANTERN"),
            ("porta", porta_encrypt(LETTERS, "LANTERN"), porta.porta_rule, None),
        ]
        for name, cipher, rule, key in cases:
            results = solve_periodic(cipher, ALPHABET, ALPHABET, 7, rule, m, Schedule(40_000), restarts=2)
            self.assertEqual(results[0][2], LETTERS, name)
            if key:
                self.assertEqual(results[0][0], key, name)
            # the reported fitness is the fitness of the reported plaintext
            self.assertAlmostEqual(results[0][1], Fitness(m)(text_to_codes(results[0][2])), places=9)
            self.assertGreaterEqual(results[0][1], results[-1][1])

    def test_keyed_alphabet_and_punctuation(self):
        from periodic_solver import solve_periodic
        random.seed(6)
        cipher = vigenere_encrypt(TEXT, "PALIMPSEST", KRYPTOS)
        results = solve_periodic(cipher, KRYPTOS, KRYPTOS, 10, lambda c, k, n: (c - k) % n, model(4),
                                 Schedule(60_000), restarts=3)
        self.assertEqual(results[0][0], "PALIMPSEST")
        self.assertEqual(results[0][2], LETTERS)

    def test_gronsfeld_modes(self):
        from periodic_solver import solve_periodic
        random.seed(7)
        cipher = "".join(ALPHABET[(ALPHABET.index(c) + int("31415"[i % 5])) % 26] for i, c in enumerate(LETTERS))
        for mode in ("1", "3"):
            results = solve_periodic(cipher, ALPHABET, "0123456789", 5, lambda c, d, n: (c - d) % n, model(4),
                                     Schedule(30_000), restarts=2, ioc_range=(0.060, 0.070), scoring_mode=mode)
            self.assertEqual(results[0][0], "31415", mode)
        # mode 2 (IoC target only) runs and reports a non-positive penalty score
        results = solve_periodic(cipher, ALPHABET, "0123456789", 5, lambda c, d, n: (c - d) % n, model(4),
                                 Schedule(5_000), scoring_mode="2")
        self.assertLessEqual(results[0][1], 0.0)

    def test_refused_inputs(self):
        from periodic_solver import solve_periodic
        rule = lambda c, k, n: (c - k) % n  # noqa: E731
        self.assertIsNone(solve_periodic("123", ALPHABET, ALPHABET, 3, rule, model(4)))        # nothing to decrypt
        self.assertIsNone(solve_periodic("ABC", ALPHABET, ALPHABET, 0, rule, model(4)))        # no key
        self.assertIsNone(solve_periodic("ABC", "", ALPHABET, 3, rule, model(4)))              # no alphabet
        self.assertIsNone(solve_periodic("ABC", "".join(map(chr, range(65, 65 + 257))), ALPHABET, 3, rule,
                                         model(4)))                                              # over 256 symbols
        self.assertIsNone(solve_periodic("ABC", ALPHABET, "", 3, rule, model(4)))              # no key symbols

    def test_general_alphabets_score_the_shown_text(self):
        """The C score of a key = annealing.Fitness (or the IoC modes) of the A-Z
        letters of the text the decrypt functions show (decrypted symbols as
        alphabet[p].lower(), other characters as they are, J of an I/J alphabet included)."""
        import vigenere
        from native import periodic_engine
        from periodic_solver import solve_periodic
        rng = random.Random(4)
        m4 = model(4)
        for alphabet in OTHER_ALPHABETS:
            n = len(alphabet)
            cipher = vigenere_encrypt(ODD + TEXT[:150] + " 0123 ÑẞJ", "LANTERN" if "L" in alphabet else "TEA",
                                      alphabet)
            index_of = {char: i for i, char in enumerate(alphabet)}
            symbols, layout = [], []
            for char in cipher:
                if char.upper() in index_of:
                    layout.append(len(symbols))
                    symbols.append(index_of[char.upper()])
                else:
                    layout.extend(-(code + 1) for code in text_to_codes(char.lower()))
            tables = b"".join(bytes((c - k) % n for c in range(n)) for k in range(n))
            codes = [text_to_codes(char.lower()) for char in alphabet]
            for mode in (1, 2, 3):
                built, keep = periodic_engine.problem(symbols, 5, tables, n, m4, 0.5, mode, (0.060, 0.070), n,
                                                      layout, codes)
                for _ in range(10):
                    key = [rng.randrange(n) for _ in range(5)]
                    shown = vigenere.decrypt_vigenere(cipher, "".join(alphabet[k] for k in key), alphabet)
                    if len(set(alphabet)) < n:     # repeated letter: the tool's key letter is its last index
                        continue
                    expected = reference_periodic_fitness(text_to_codes(shown), m4, mode, (0.060, 0.070))
                    got = periodic_engine.score_key(built, key)
                    self.assertAlmostEqual(got, expected, delta=1e-9 * max(1.0, abs(expected)), msg=alphabet)
        # the annealer finds planted keys on these alphabets and reports the shown text's fitness
        random.seed(8)
        for alphabet in OTHER_ALPHABETS[:5]:
            cipher = vigenere_encrypt(TEXT + " JJ", "LANTERN", alphabet)
            results = solve_periodic(cipher, alphabet, alphabet, 7, vigenere.vigenere_rule, m4, Schedule(40_000),
                                     restarts=2)
            shown = vigenere.decrypt_vigenere(cipher, results[0][0], alphabet)
            self.assertEqual(results[0][0], "LANTERN", alphabet)
            self.assertEqual(results[0][2], ngram_scoring.codes_to_text(text_to_codes(shown)), alphabet)
            self.assertAlmostEqual(results[0][1], Fitness(m4)(text_to_codes(shown)), places=9)

    def test_gronsfeld_annealing_on_a_short_alphabet(self):
        from periodic_solver import solve_periodic
        random.seed(10)
        alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
        cipher = gronsfeld_encrypt(TEXT.replace("j", "i"), "31415", alphabet)
        results = solve_periodic(cipher, alphabet, "0123456789", 5, lambda c, d, n: (c - d) % n, model(4),
                                 Schedule(30_000), restarts=2, scoring_mode="3")
        self.assertEqual(results[0][0], "31415")

    def test_progress_reports(self):
        from native import periodic_engine
        symbols = [ALPHABET.index(c) for c in vigenere_encrypt(LETTERS * 3, "KEY")]
        tables = b"".join(bytes((c - k) % 26 for c in range(26)) for k in range(26))
        built, keep = periodic_engine.problem(symbols, 3, tables, 26, model(4))
        calls = []
        key, score, plain = periodic_engine.anneal(built, 300_000, 20.0, 0.1, 12345, report_seconds=0.0,
                                                   report=lambda *args: calls.append(args))
        self.assertGreaterEqual(len(calls), 2)                 # the C loop runs in chunks
        steps = [step for step, _, _, _ in calls]
        self.assertEqual(steps, sorted(steps))
        for step, temp, best, best_key in calls:
            self.assertTrue(0 < step <= 300_000 and 0.1 <= temp <= 20.0 and len(best_key) == 3)
        self.assertEqual("".join(ALPHABET[k] for k in key), "KEY")
        self.assertEqual(plain, text_to_codes(LETTERS * 3))

    def test_vigenere_tool_routes_to_the_c_engine(self):
        import vigenere
        random.seed(9)
        cipher = vigenere_encrypt(TEXT, "LANTERN")
        results = vigenere.run_simulated_annealing_attack(cipher, ALPHABET, None, {
            'min_key_length': 6, 'max_key_length': 7, 'starting_temp': 20.0, 'cooling_rate': 0.9,
            'steps_per_temp': 600, 'runs': 2, 'ent_weight': 0.5, 'ngram_path': model(4)})
        self.assertEqual(len(results), 4)
        self.assertEqual(set(results[0]), {'key', 'key_length', 'plaintext', 'bigram_score', 'ioc', 'alphabet_used'})
        self.assertEqual(results[0]['key'], "LANTERN")
        self.assertEqual(results[0]['plaintext'], vigenere.decrypt_vigenere(cipher, "LANTERN", ALPHABET))
        # a 25-letter (I/J merged) alphabet runs in the same C engine
        alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
        cipher = vigenere_encrypt(TEXT, "LANTERN", alphabet)
        results = vigenere.run_simulated_annealing_attack(cipher, alphabet, None, {
            'min_key_length': 7, 'max_key_length': 7, 'starting_temp': 20.0, 'cooling_rate': 0.9,
            'steps_per_temp': 800, 'runs': 2, 'ent_weight': 0.5, 'ngram_path': model(4)})
        self.assertEqual(results[0]['key'], "LANTERN")
        self.assertEqual(results[0]['plaintext'], vigenere.decrypt_vigenere(cipher, "LANTERN", alphabet))

    def test_vigenere_schedule_matches_the_old_level_loop(self):
        import vigenere
        for start, rate, steps in ((20.0, 0.995, 1000), (10.0, 0.95, 500), (0.5, 0.9, 7)):
            levels, temp = 0, start          # test-only reference: the old while loop's level count
            while temp > 0.1:
                temp *= rate
                levels += 1
            schedule = vigenere.schedule_from_levels(start, rate, steps)
            self.assertEqual(schedule.iterations, steps * levels)
            self.assertEqual((schedule.t_start, schedule.t_end), (start, 0.1))
        for bad in ((20.0, 1.0, 10), (0.05, 0.9, 10), (20.0, 0.9, 0)):
            with self.assertRaises(ValueError):
                vigenere.schedule_from_levels(*bad)


# ------------------------------------------------------------------ dictionary attack

class DictionaryAttackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import attack_support
        import vigenere
        cls.words = list(attack_support.load_dictionary(vigenere.dictionary_path, ALPHABET)[:2300])
        cls.words[1234] = "LANTERN"
        cls.model = model(4)

    def run_both(self, module, decrypt, cipher, alphabet, phrases, min_ioc, max_ioc, words=None):
        import attack_support
        words = self.words if words is None else words
        got = attack_support.run_batches(decrypt, words, cipher, alphabet, phrases, self.model, min_ioc, max_ioc)
        expected = []
        for start in range(0, len(words), attack_support.BATCH_SIZE):
            expected += reference_score_batch(decrypt, words[start:start + attack_support.BATCH_SIZE], cipher,
                                              alphabet, phrases, self.model, min_ioc, max_ioc)
        self.assertEqual([(r['key'], r['plaintext'], r['ioc'], r['bigram_score'], r['is_phrase_match'])
                          for r in got], expected, module.__name__)
        return got

    def test_matches_the_python_loop_exactly(self):
        import beaufort
        import porta
        import vigenere
        for module, decrypt, encrypt in ((vigenere, vigenere.decrypt_vigenere, vigenere_encrypt),
                                         (beaufort, beaufort.decrypt_beaufort, beaufort_encrypt),
                                         (porta, porta.decrypt_porta, porta_encrypt)):
            for alphabet in (ALPHABET, KRYPTOS):
                cipher = encrypt(ODD + TEXT[:160], "LANTERN", alphabet)
                self.run_both(module, decrypt, cipher, alphabet, [], 0.060, 0.075)
        cipher = vigenere_encrypt(ODD + TEXT[:160], "LANTERN", KRYPTOS)
        self.run_both(vigenere, vigenere.decrypt_vigenere, cipher, KRYPTOS, ["the best", "TIMES"], 0.060, 0.075)
        cipher = porta_encrypt(ODD + TEXT[:160], "LANTERN")
        self.run_both(porta, porta.decrypt_porta, cipher, ALPHABET, ["the", ""], 0.0, 0.0)

    def test_planted_key_ranks_first(self):
        import attack_support
        import beaufort
        import porta
        import vigenere
        for decrypt, encrypt in ((vigenere.decrypt_vigenere, vigenere_encrypt),
                                 (beaufort.decrypt_beaufort, beaufort_encrypt),
                                 (porta.decrypt_porta, porta_encrypt)):
            cipher = encrypt(TEXT, "LANTERN")
            results = attack_support.sort_results(attack_support.run_batches(
                decrypt, self.words, cipher, ALPHABET, [], self.model, 0.065, 0.070))
            self.assertEqual(decrypt(cipher, results[0]['key'], ALPHABET), TEXT.lower())
            results = attack_support.sort_results(attack_support.run_batches(
                decrypt, self.words, cipher, ALPHABET, ["ferryman"], self.model, 0.065, 0.070))
            self.assertTrue(results[0]['is_phrase_match'])
            self.assertEqual(results[0]['matched_phrases'], ["ferryman"])

    def test_other_alphabets_match_the_python_loop(self):
        import attack_support
        import beaufort
        import porta
        import vigenere
        for alphabet in OTHER_ALPHABETS:
            words = [w for w in attack_support.load_dictionary(vigenere.dictionary_path, alphabet)[:2100]]
            words[700] = "LANTERN" if "L" in alphabet else "TEA"
            for module, decrypt, encrypt in ((vigenere, vigenere.decrypt_vigenere, vigenere_encrypt),
                                             (beaufort, beaufort.decrypt_beaufort, beaufort_encrypt),
                                             (porta, porta.decrypt_porta, porta_encrypt)):
                cipher = encrypt(ODD + TEXT[:160] + " ÑẞJ 2024", words[700], alphabet)
                self.run_both(module, decrypt, cipher, alphabet, ["THE", "e"], 0.060, 0.075, words)
                got = self.run_both(module, decrypt, cipher, alphabet, [], 0.060, 0.075, words)
                if module is not porta:
                    best = attack_support.sort_results(got)[0]
                    self.assertEqual(best['key'], words[700], (alphabet, module.__name__))

    def test_refusals(self):
        import attack_support
        import vigenere
        with self.assertRaises(ValueError):
            attack_support.run_batches(lambda c, k, a: c, ["KEY"], "ABC", ALPHABET, [], self.model, 0.06, 0.07)
        self.assertEqual(attack_support.run_batches(vigenere.decrypt_vigenere, ["KEY"], "ABC", "", [],
                                                    self.model, 0.06, 0.07), [])


# ------------------------------------------------------------------ Gronsfeld exhaustive

class GronsfeldExhaustiveTests(unittest.TestCase):
    def test_matches_the_python_loop(self):
        import Gronsfeld as g
        m = model(4)
        for alphabet in (ALPHABET, KRYPTOS):
            key = "314"
            cipher, j = [], 0
            for char in ODD + TEXT[:120]:
                upper = char.upper()
                if upper in alphabet:
                    cipher.append(alphabet[(alphabet.index(upper) + int(key[j % 3])) % 26])
                    j += 1
                else:
                    cipher.append(char)
            cipher = "".join(cipher)
            for known in ([], ["RIVER", "zzz"], ["THE"]):
                got = g.process_exhaustive_batch((cipher, alphabet, 0, 1000, 3, m, known))
                expected = reference_gronsfeld_batch(cipher, alphabet, 0, 1000, 3, m, known)
                matched = [row for row in expected if known and any(w.lower() in row['decrypted'] for w in known)]
                self.assertEqual(got[:len(matched)], matched)
                key_of = lambda row: (row['score'], row['key'])  # noqa: E731
                self.assertEqual(sorted(got[len(matched):], key=key_of),
                                 sorted(expected[len(matched):], key=key_of))
                self.assertLessEqual(len(got) - len(matched), g.KEEP_PER_BATCH)

    def test_planted_five_digit_key(self):
        import Gronsfeld as g
        key = "31415"
        cipher = "".join(ALPHABET[(ALPHABET.index(c) + int(key[i % 5])) % 26] for i, c in enumerate(LETTERS[:150]))
        rows = g.process_exhaustive_batch((cipher, ALPHABET, 0, 100_000, 5, model(5), []))
        self.assertEqual(min(rows, key=lambda r: r['score'])['key'], key)

    def test_keys_longer_than_the_key_length(self):
        import Gronsfeld as g
        m = model(4)
        cipher = LETTERS[:60]
        got = g.process_exhaustive_batch((cipher, ALPHABET, 90, 120, 2, m, []))
        expected = reference_gronsfeld_batch(cipher, ALPHABET, 90, 120, 2, m, [])
        self.assertEqual(sorted(r['key'] for r in got), sorted(r['key'] for r in expected))

    def test_other_alphabets_match_the_python_loop(self):
        import Gronsfeld as g
        m = model(4)
        # Gronsfeld.run passes the alphabet as typed (upper case); a lower-case 'ß' here
        # is a symbol shown as two scored letters.
        for alphabet in OTHER_ALPHABETS + ("ABCDEFGHIJKLMNOPQRSTUVWXYZß",):
            cipher = gronsfeld_encrypt(ODD + TEXT[:120] + " J 7", "314", alphabet)
            for known in ([], ["RIVER", "zzz"], ["ß"]):
                got = g.process_exhaustive_batch((cipher, alphabet, 0, 1000, 3, m, known))
                expected = reference_gronsfeld_batch(cipher, alphabet, 0, 1000, 3, m, known)
                matched = [row for row in expected if known and any(w.lower() in row['decrypted'] for w in known)]
                self.assertEqual(got[:len(matched)], matched, alphabet)
                key_of = lambda row: (row['score'], row['key'])  # noqa: E731
                self.assertEqual(sorted(got[len(matched):], key=key_of),
                                 sorted(expected[len(matched):], key=key_of), alphabet)
        # planted key ranks first on a 25-letter alphabet
        alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
        cipher = gronsfeld_encrypt(LETTERS[:150].replace("J", "I"), "31415", alphabet)
        rows = g.process_exhaustive_batch((cipher, alphabet, 0, 100_000, 5, model(5), []))
        self.assertEqual(min(rows, key=lambda r: r['score'])['key'], "31415")

    def test_refuses_alphabets_c_cannot_hold(self):
        import Gronsfeld as g
        with self.assertRaises(ValueError):
            g.process_exhaustive_batch(("ABC", "", 0, 10, 1, model(4), []))
        with self.assertRaises(ValueError):
            g.process_exhaustive_batch(("ABC", "".join(map(chr, range(65, 65 + 257))), 0, 10, 1, model(4), []))


# ------------------------------------------------------------------ XOR and modular word lists

class WordListAttackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(os.path.join(ROOT, "scripts", "data", "words_alpha.txt"), encoding="utf-8") as handle:
            lines = handle.read().splitlines()
        rng = random.Random(11)
        words = lines[:150] + rng.sample(lines, 2500) + ["lantern", "Lantern", "café", "e-mail", "  spaced  ",
                                                         "1541-", "001-", "x", "KRYPTOS", ""]
        rng.shuffle(words)
        cls.words = words
        handle = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8")
        handle.write("\n".join(words))
        handle.close()
        cls.path = handle.name

    @classmethod
    def tearDownClass(cls):
        os.unlink(cls.path)

    def check(self, got, expected, costs):
        self.assertEqual(normalised([row[:4] for row in got], costs), normalised([row[:4] for row in expected], costs))
        self.assertEqual([costs[row[0]] for row in got], [costs[row[0]] for row in expected])

    def test_xor_matches_the_python_loop(self):
        import xor
        values = xor.parse_input(TEXT[:200])
        cipher = xor.xor_values(values, "LANTERN") + [300, -5, 200]
        old_path, xor.WORDLIST_PATH = xor.WORDLIST_PATH, self.path
        try:
            for low, high in ((0.065, 0.07), (0.0, 1.0), (0.0, 0.0)):
                got = xor.brute_force_with_ioc(cipher, low, high)
                expected, costs = reference_word_attack(
                    [line.strip() for line in self.words if line.strip()],
                    lambda word: xor.get_ascii_result(xor.xor_values(cipher, word)), "ASCII", low, high, True)
                self.check(got, expected, costs)
        finally:
            xor.WORDLIST_PATH = old_path

    def test_modular_matches_the_python_loop(self):
        import modular_add_sub as mod
        cases = [
            (mod.parse_input(TEXT[:200]), "add", 26, None),
            (mod.parse_input(TEXT[:200]), "subtract", 26, None),
            (mod.parse_input(TEXT[:200], 'string', KRYPTOS), "subtract", 26, KRYPTOS),
            ([5, 900, -1, 3, 41, 2, -7, 12, 30, 1, 0, 25, 77, 8, 14] * 8, "add", 40, None),
        ]
        old_path, mod.WORDLIST_PATH = mod.WORDLIST_PATH, self.path
        try:
            for values, operation, modulus, custom in cases:
                def make_text(word):
                    if custom:
                        key = [custom.find(c) if c in custom else -1 for c in word]
                        if -1 in key:
                            return None
                    else:
                        key = word
                    return mod.map_to_alphabet(mod.modular_operation(values, key, operation, modulus, 0), custom, 0)
                for low, high in ((0.065, 0.07), (0.0, 1.0)):
                    got = mod.brute_force_with_ioc(values, operation, modulus, 0, custom, low, high)
                    expected, costs = reference_word_attack([line.strip() for line in self.words if line.strip()],
                                                            make_text, "Modular", low, high, False)
                    self.check(got, expected, costs)
        finally:
            mod.WORDLIST_PATH = old_path

    def test_planted_keys_rank_first_on_the_full_list(self):
        import modular_add_sub as mod
        import xor
        cipher = xor.xor_values(xor.parse_input(TEXT), "LANTERN")
        self.assertEqual(xor.brute_force_with_ioc(cipher)[0][0], "LANTERN")
        cipher = mod.modular_operation(mod.parse_input(TEXT), "LANTERN", "add")
        self.assertEqual(mod.brute_force_with_ioc(cipher, "subtract", 26, 0)[0][0], "LANTERN")

    def test_modular_refuses_a_bad_modulus(self):
        import modular_add_sub as mod
        self.assertEqual(mod.brute_force_with_ioc([1, 2, 3], "add", 0, 0), [])


if __name__ == "__main__":
    unittest.main()
