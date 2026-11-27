"""Statistics for an unknown ciphertext, and the attack pathways they point to.

Every test compares the ciphertext with reference samples of the SAME length:
English passages, uniformly random letters, and shuffled copies of the
ciphertext. A statistic is called "English-like" or "random-like" from where
it falls in those samples (percentiles), the way the K4 workbench screens its
hypotheses, so the thresholds adapt to the text length instead of being fixed
numbers that only hold for long texts.

The statistics and what each one separates:

* Index of coincidence (IoC). Substitution and transposition keep the
  plaintext's letter counts, so they keep English's IoC (~0.066); periodic,
  autokey and running keys flatten it towards random letters (~0.038).
* Chi-squared against English letter frequencies. Low only when the letters
  themselves are English, i.e. transposition (or no cipher).
* Adjacent-letter structure: how often adjacent pairs repeat, divided by what
  independent letters with the same counts would give. Both are unchanged by a
  simple substitution, and a transposition destroys the adjacency, so this
  separates "substitution only" from "substitution and transposition".
* IoC of every L-th letter (period L). Under a periodic key of period L, each
  column is one simple substitution of English, so its IoC returns to English.
* N-gram fitness (the solvers' own score). Used to judge decryptions.
"""
import random
import re
from collections import Counter
from dataclasses import dataclass, field
from functools import lru_cache

from annealing import Fitness
from layered import ALPHABET, ENGLISH_FREQUENCIES, TRANSPOSITION_MODES, PeriodicLayer
from ngram_scoring import DEFAULT_NGRAM_PATH, codes_to_text, load_ngram_scores, text_to_codes
from rail_fence import rail_order
from transposition_core import make_permuter

# Percentiles used for "inside the reference range": 2nd and 98th.
LOW_Q, HIGH_Q = 0.02, 0.98
REFERENCE_SAMPLES = 400
PERIOD_SAMPLES = 200
MIN_LETTERS = 20


# ------------------------------------------------------------------ references

@lru_cache(maxsize=1)
def english_corpus() -> bytes:
    """English prose from the Python documentation shipped with Python
    (the same source the Two-Layer Solver and the K4 workbench use)."""
    import pydoc_data.topics as topics
    lines = [line.strip() for text in topics.topics.values() for line in text.splitlines()]
    prose = " ".join(line for line in lines
                     if len(line) > 40 and not re.search(r"[=()\[\]{}:<>#_*`|\\/@$%^~]", line))
    return text_to_codes(prose)


def english_samples(length: int, count: int, seed: int) -> list:
    corpus = english_corpus()
    rng = random.Random(seed)
    return [corpus[start:start + length]
            for start in (rng.randrange(0, len(corpus) - length) for _ in range(count))]


class Reference:
    """Sorted sample values of one statistic."""

    def __init__(self, values):
        self.values = sorted(values)

    def quantile(self, q: float) -> float:
        index = min(len(self.values) - 1, max(0, int(q * len(self.values))))
        return self.values[index]

    def fraction_below(self, value: float) -> float:
        """Share of samples at or below ``value``."""
        low, high = 0, len(self.values)
        while low < high:
            middle = (low + high) // 2
            if self.values[middle] <= value:
                low = middle + 1
            else:
                high = middle
        return low / len(self.values)

    @property
    def mean(self) -> float:
        return sum(self.values) / len(self.values)

    @property
    def sd(self) -> float:
        mean = self.mean
        return (sum((x - mean) ** 2 for x in self.values) / len(self.values)) ** 0.5 or 1e-9


# ------------------------------------------------------------------ statistics

def letter_counts(codes) -> list:
    return [codes.count(code) for code in range(26)]


def ioc(codes) -> float:
    total = len(codes)
    if total < 2:
        return 0.0
    return sum(n * (n - 1) for n in letter_counts(codes)) / (total * (total - 1))


def chi_squared(codes) -> float:
    total = len(codes)
    if not total:
        return 0.0
    chi = 0.0
    for code, observed in enumerate(letter_counts(codes)):
        expected = ENGLISH_FREQUENCIES[code] * total / 100
        chi += (observed - expected) ** 2 / expected
    return chi


def adjacency(codes) -> float:
    """Repeat rate of adjacent letter pairs divided by the rate expected for
    independent letters with the same counts (IoC squared). About 1 for
    shuffled letters, clearly above 1 for English in its own order.
    Unchanged by any simple substitution."""
    pairs = len(codes) - 1
    letters_ioc = ioc(codes)
    if pairs < 2 or letters_ioc <= 0:
        return 0.0
    counts = Counter(a * 26 + b for a, b in zip(codes, codes[1:]))
    pair_ioc = sum(n * (n - 1) for n in counts.values()) / (pairs * (pairs - 1))
    return pair_ioc / (letters_ioc * letters_ioc)


def column_ioc(codes, period: int) -> float:
    """IoC of every ``period``-th letter, pooled over the columns."""
    numerator = denominator = 0
    for column in range(period):
        letters = codes[column::period]
        n = len(letters)
        numerator += sum(c * (c - 1) for c in letter_counts(letters))
        denominator += n * (n - 1)
    return numerator / denominator if denominator else 0.0


@lru_cache(maxsize=8)
def fitness_function(ngram_path: str = str(DEFAULT_NGRAM_PATH)) -> Fitness:
    """The solvers' fitness (mean n-gram score x entropy^0.5); higher = more English."""
    return Fitness(load_ngram_scores(ngram_path), 0.5)


@lru_cache(maxsize=16)
def references(length: int, ngram_path: str = str(DEFAULT_NGRAM_PATH), samples: int = REFERENCE_SAMPLES) -> dict:
    """Reference distributions for texts of ``length`` letters (deterministic):
    English passages, shuffled copies of them and uniformly random letters.
    The shuffles, random texts and every statistic are computed in C
    (native/screens_stats.c, the definitions of ioc, chi_squared, adjacency and
    the fitness below)."""
    from native import screens
    fitness = fitness_function(ngram_path)
    english = english_samples(length, samples, seed=length)
    shuffled, uniform = screens.reference_samples(english, length, seed=length + 1)
    english_stats = screens.text_stats(english, length, fitness, ENGLISH_FREQUENCIES)
    shuffled_stats = screens.text_stats(shuffled, length, fitness, ENGLISH_FREQUENCIES, ("adjacency", "fitness"))
    random_stats = screens.text_stats(uniform, length, fitness, ENGLISH_FREQUENCIES, ("ioc",))
    return {
        'english_ioc': Reference(english_stats['ioc']),
        'random_ioc': Reference(random_stats['ioc']),
        'english_chi': Reference(english_stats['chi']),
        'english_adjacency': Reference(english_stats['adjacency']),
        'shuffled_adjacency': Reference(shuffled_stats['adjacency']),
        'english_fitness': Reference(english_stats['fitness']),
        'shuffled_fitness': Reference(shuffled_stats['fitness']),
    }


# ------------------------------------------------------------------ input handling

@dataclass
class Prepared:
    """The ciphertext as letter codes, plus what was noticed about the raw input."""
    raw: str
    codes: bytes
    notes: list = field(default_factory=list)
    word_lengths: list = field(default_factory=list)
    regrouped: str = ""      # description when symbols were regrouped into letters


def regroup_symbols(symbols: str):
    """Texts written with only a few symbols (digits 1-5, A/B, ADFGX...) are
    usually fractionated: groups of g symbols stand for one letter. Map each
    distinct group to a letter in order of first appearance. When nothing else
    was done (no transposition), the result is a simple substitution of the
    plaintext. Returns (letters, group size, symbol set) or None."""
    distinct = sorted(set(symbols))
    k = len(distinct)
    if k < 2 or k > 6:
        return None
    group = next(g for g in range(1, 6) if k ** g >= 25)
    if len(symbols) % group or len(symbols) // group < MIN_LETTERS:
        return None
    groups = [symbols[i:i + group] for i in range(0, len(symbols), group)]
    order = list(dict.fromkeys(groups))
    if len(order) > 26:
        return None
    letter_for = {g: ALPHABET[i] for i, g in enumerate(order)}
    return "".join(letter_for[g] for g in groups), group, "".join(distinct)


def prepare(raw: str) -> Prepared:
    text = raw.strip()
    letters = re.sub(r"[^A-Za-z]", "", text).upper()
    digits = re.sub(r"[^0-9]", "", text)
    notes, word_lengths = [], []

    words = re.findall(r"[A-Za-z]+", text)
    if len(words) >= 4 and re.search(r"\s", text):
        word_lengths = [len(w) for w in words]
        lengths = Counter(word_lengths)
        notes.append(f"The text is split into {len(words)} groups; lengths: "
                     + ", ".join(f"{n}x{length}" for length, n in sorted(lengths.items())[:12]) + ".")
        if len(lengths) == 1:
            notes.append(f"Every group has {word_lengths[0]} letters: that is a transmission grouping, "
                         f"not word boundaries.")
            word_lengths = []
        else:
            notes.append("Groups of different lengths may be real word boundaries: a simple substitution that "
                         "kept them can be attacked by word patterns (tool 14).")

    # Mostly digits, or only a handful of distinct letters: fractionation.
    symbols = digits if len(digits) > len(letters) else letters
    regrouped = ""
    if len(set(symbols)) <= 6:
        converted = regroup_symbols(symbols)
        if converted:
            converted_letters, group, alphabet = converted
            regrouped = (f"The text uses only the symbols {alphabet}. Read in groups of {group}, it has "
                         f"{len(set(converted_letters))} distinct groups; each group was replaced by a letter "
                         f"(first group = A, next new group = B, ...) and the analysis below is of that text.")
            letters = converted_letters
        elif len(digits) > len(letters):
            notes.append(f"The text is mostly digits ({len(digits)}), with {len(set(digits))} distinct digits; "
                         f"it could not be read as groups of a fixed size.")
    if len(digits) and len(letters) and not regrouped and len(digits) <= len(letters):
        notes.append(f"{len(digits)} digit(s) in the text were ignored.")
    return Prepared(raw=text, codes=text_to_codes(letters), notes=notes,
                    word_lengths=word_lengths, regrouped=regrouped)


# ------------------------------------------------------------------ periodicity

def periodicity(codes, max_period: int, samples: int = PERIOD_SAMPLES, seed: int = 7) -> list:
    """Column IoC for periods 1..max_period with two references per period:
    shuffled copies of the ciphertext (no period: chance) and English samples
    split the same way (what a periodic key of that period would leave).

    ``z`` is the distance from the chance mean in chance standard deviations.
    Many periods are tested at once, so a single period passing at the 2%
    level would happen by luck in about half of all aperiodic texts; the
    threshold is therefore Bonferroni-corrected (see ``z_threshold``).

    The shuffles and every column IoC are computed in C
    (native/screens_stats.c); ``seed`` seeds its random generator."""
    from native import screens
    english = english_samples(len(codes), samples, seed=len(codes) + 2)
    values, columns = screens.periodicity(bytes(codes), max_period, english, seed)
    threshold = z_threshold(max_period - 1)
    rows = []
    for period, value, (chance, english_values) in zip(range(1, max_period + 1), values, columns):
        chance_mean = sum(chance) / len(chance)
        chance_sd = (sum((x - chance_mean) ** 2 for x in chance) / len(chance)) ** 0.5 or 1e-9
        chance = Reference(chance)
        hypothesis = Reference(english_values)
        z = (value - chance_mean) / chance_sd
        rows.append({
            'period': period, 'ioc': value, 'z': z,
            'chance_high': chance.quantile(HIGH_Q),
            'english_low': hypothesis.quantile(LOW_Q),
            'signal': z >= threshold,
            'english_like': value >= hypothesis.quantile(LOW_Q),
            'english_values': english_values,
        })
    return rows


def z_threshold(tests: int, family_error: float = 0.02) -> float:
    """One-sided normal threshold so that ``tests`` periods together pass by
    chance with probability about ``family_error``."""
    from statistics import NormalDist
    return NormalDist().inv_cdf(1 - family_error / max(1, tests))


def likely_periods(rows) -> list:
    """Periods whose columns are above chance AND English-like, best first.

    A true period's multiples pass as well, and a divisor of the true period
    can pass partly (its columns mix a few alphabets). For the strongest
    period P, a passing divisor d is preferred only when IoC(P) - IoC(d) is no
    larger than English itself shows (98th percentile of the same difference
    over the English samples): if d were the key length, splitting further
    into P columns would not raise the IoC."""
    passing = [row for row in rows if row['period'] > 1 and row['signal']]
    if not any(row['english_like'] for row in passing):
        return []
    # Ranked by signal strength. Not every passing period has to be English-like
    # (a passage with a low IoC of its own falls just short at the true period).
    passing.sort(key=lambda row: -row['z'])
    by_period = {row['period']: row for row in rows}

    def key_length(row):
        for divisor in sorted(other['period'] for other in passing):
            if divisor >= row['period'] or row['period'] % divisor:
                continue
            small = by_period[divisor]
            gaps = Reference(a - b for a, b in zip(row['english_values'], small['english_values']))
            if row['ioc'] - small['ioc'] <= gaps.quantile(HIGH_Q):
                return divisor
        return row['period']

    ordered = [key_length(row) for row in passing]
    return list(dict.fromkeys(ordered + [row['period'] for row in passing]))


def ordinal(number: int) -> str:
    suffix = "th" if 10 <= number % 100 <= 20 else {1: "st", 2: "nd", 3: "rd"}.get(number % 10, "th")
    return f"{number}{suffix}"


def friedman_estimate(value: float) -> float | None:
    if value <= 0.0385:
        return None
    return (0.0667 - 0.0385) / (value - 0.0385)


def kasiski(codes, min_length: int = 3, max_factor: int = 30) -> list:
    """(factor, count) for the distances between repeated trigrams or longer."""
    positions = {}
    for i in range(len(codes) - min_length + 1):
        positions.setdefault(codes[i:i + min_length], []).append(i)
    factors = Counter()
    for found in positions.values():
        for a, b in zip(found, found[1:]):
            distance = b - a
            for f in range(2, min(distance, max_factor) + 1):
                if distance % f == 0:
                    factors[f] += 1
    return factors.most_common(6)


# ------------------------------------------------------------------ instant attacks

@dataclass
class Candidate:
    method: str
    key: str
    plaintext: str
    fitness: float


def _best(candidates, top=3):
    return sorted(candidates, key=lambda c: -c.fitness)[:top]


def attack_affine(codes, fitness) -> list:
    """Every affine key a*x + b (Caesar is a = 1, Atbash is a = 25, b = 25): 312 keys."""
    out = []
    for a in (1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25):
        inverse = pow(a, -1, 26)
        for b in range(26):
            table = bytes((inverse * (c - b)) % 26 for c in range(26)) + bytes(230)
            plain = codes.translate(table)
            name = "Caesar" if a == 1 else "Atbash" if (a, b) == (25, 25) else "Affine"
            key = f"shift {b} ({ALPHABET[b]})" if a == 1 else f"a={a}, b={b}"
            out.append(Candidate(name, key, codes_to_text(plain), fitness(plain)))
    return _best(out)


rail_fence_order = rail_order  # plaintext position of each ciphertext position


def attack_routes(codes, fitness, max_rails: int = 30) -> list:
    """Reversal, rail fence (2..max_rails rails, every starting offset), and
    writing the text into a w-column grid read the other way (scytale-like
    routes, keyless columnar), each also on the reversed text. Every reading is
    generated and scored in C; ties keep the order: text forwards (rail fence,
    then grids), the reversed text itself, then the same on the reversed text."""
    from native.screens import BOTH, COLUMNAR, LAYOUTS, READ, ZIGZAG, Sources, record_of
    codes = bytes(codes)
    n = len(codes)
    sources = Sources(n)
    names = []
    for rails in range(2, min(max_rails, n - 1) + 1):
        for offset in range(2 * (rails - 1)):
            sources.add(ZIGZAG, (rails, offset), directions=READ, meta=("rail_fence", rails, offset))
            names.append(("Rail fence", f"{rails} rails" + (f", offset {offset}" if offset else "")))
    for width in range(2, n // 2 + 1):
        for mode in TRANSPOSITION_MODES:
            sources.add(COLUMNAR, (width, LAYOUTS[mode]), meta=("columnar", width, mode))
            names.append(("Route (keyless grid)", f"width {width}, {TRANSPOSITION_MODES[mode]}"))
    _, scored = sources.score(codes, fitness, text=BOTH)
    reversed_text = codes[::-1]
    count = len(names)
    # (score, position in the original candidate order, id; None = the reversed text itself)
    ranked = [(score, (ident & 1) * (count + 1) + record_of(ident), ident) for score, ident in scored]
    ranked.append((fitness(reversed_text), count, None))
    best = sorted(ranked, key=lambda entry: (-entry[0], entry[1]))[:3]
    plains = sources.plain(codes, [ident for _, _, ident in best if ident is not None])
    out = []
    for score, _, ident in best:
        if ident is None:
            out.append(Candidate("Reversed text", "-", codes_to_text(reversed_text), score))
            continue
        method, key = names[record_of(ident)]
        out.append(Candidate(method, key + (" (text reversed first)" if ident & 1 else ""),
                             codes_to_text(plains.pop(0)), score))
    return out


def attack_small_columnar(codes, fitness, max_width: int = 8) -> list:
    """Every column order of every width up to ``max_width`` (C brute force,
    the same first-best order as tool 44), four layouts."""
    import native
    from native import perm as native_perm
    native.require()
    n = len(codes)
    out = []
    model = load_ngram_scores(str(DEFAULT_NGRAM_PATH))
    for width in range(2, min(max_width, n - 1) + 1):
        for mode in TRANSPOSITION_MODES:
            order = native_perm.best_order(codes_to_text(codes), width, mode, model)
            if order is None:
                continue
            plain = make_permuter(n, width, mode)(codes, order)
            out.append(Candidate("Columnar (exhaustive)", f"width {width}, order {list(order)}, "
                                 f"{TRANSPOSITION_MODES[mode]}", codes_to_text(plain), fitness(plain)))
    return _best(out)


def attack_periodic(codes, fitness, periods) -> list:
    """Vigenere and Beaufort on the straight alphabet: each key letter chosen by
    letter frequencies alone (chi-squared per column). Exact enough for any
    period whose columns hold ~10+ letters; Variant Beaufort gives the same
    plaintext as Vigenere with the negated key."""
    out = []
    for period in periods:
        for variant in ("vigenere", "beaufort"):
            layer = PeriodicLayer(period, variant)
            layer.seed(codes)
            plain = layer.decrypt(codes)
            key = "".join(ALPHABET[k] for k in layer.key)
            name = "Vigenere" if variant == "vigenere" else "Beaufort"
            out.append(Candidate(name, f"period {period}, key {key}", codes_to_text(plain), fitness(plain)))
    return _best(out, top=4)


# Keyed alphabets tried by the periodic attack (Kryptos K1/K2 use this one on
# both the plaintext and the cipher side of the tableau).
KEYED_ALPHABETS = {"KRYPTOS": "KRYPTOSABCDEFGHIJLMNQUVWXZ"}


def attack_periodic_keyed(codes, fitness, periods, alphabets=None) -> list:
    """Vigenere and Beaufort on a keyed tableau (rows and columns in the keyed
    alphabet's order), each key letter chosen by letter frequencies:
    Vigenere  p = A[(A.index(c) - A.index(k)) mod 26]
    Beaufort  p = A[(A.index(k) - A.index(c)) mod 26]
    This is Quagmire III with that alphabet: keyword_periodic.solve_alphabet
    (shifts chosen in C) does the work."""
    import keyword_periodic as kp
    out = []
    for name, alphabet in (alphabets or KEYED_ALPHABETS).items():
        for variant in ("vigenere", "beaufort"):
            for period in periods:
                plain, key = kp.solve_alphabet(codes, period, alphabet, 3, 0 if variant == "vigenere" else 1)
                out.append(Candidate(f"{'Vigenere' if variant == 'vigenere' else 'Beaufort'} ({name} alphabet)",
                                     f"period {period}, key {key}", codes_to_text(plain), fitness(plain)))
    return _best(out, top=4)


def attack_quagmire(codes, fitness, period) -> list:
    """Quagmire I-III with every dictionary word as the alphabet keyword (C
    engine, keyword_periodic.search)."""
    import keyword_periodic as kp
    words = kp.load_words()
    out = []
    for score, word, mode, variant, key, plain in kp.search(codes, period, kp.distinct_alphabets(words), fitness=fitness)[:3]:
        out.append(Candidate(f"{kp.MODES[mode].split(' (')[0]} {'Vigenere' if variant == 0 else 'Beaufort'}",
                             f"alphabet keyword {word}, period {period}, key {key}", plain, score))
    return out


def attack_autokey(codes, fitness, max_length) -> list:
    """Plaintext and ciphertext autokey, Vigenere and Beaufort tableaux, every
    primer length up to ``max_length``, with no word list (see autoclave.py)."""
    import autoclave
    out = []
    for score, kind, variant, primer, plain in autoclave.attack(codes, max_length, fitness)[:3]:
        out.append(Candidate("Autokey", autoclave.describe(kind, variant, primer), codes_to_text(plain), score))
    return out


def attack_hill(codes) -> list:
    """2x2 and 3x3 Hill, ciphertext only (row-by-row attack, see hill.py),
    for lengths that are a multiple of the block size."""
    import hill
    out = []
    for size in (2, 3):
        if len(codes) % size or len(codes) < 12 * size:
            continue
        for result in hill.row_attack(codes_to_text(codes), size, top=2):
            out.append(Candidate(f"Hill {size}x{size}", f"key {result['key_rep']} {result['key_matrix']}",
                                 result['plaintext'], result['fitness']))
    return out


# ------------------------------------------------------------------ the profile

@dataclass
class AttackPlan:
    """An annealing search the analyzer can run with the Two-Layer engine.
    ``layers`` are in ENCRYPTION order: "sub", "trans" or "periodic"."""
    label: str
    layers: tuple
    steps: int
    runs: int
    widths: list = field(default_factory=list)
    modes: list = field(default_factory=lambda: ["write_rows_read_cols"])
    periods: list = field(default_factory=list)
    variant: str = "vigenere"

    def combos(self) -> list:
        """Every parameter combination, as the Two-Layer engine's 'encryption' lists."""
        options = []
        for kind in self.layers:
            if kind == "sub":
                options.append([("sub", None)])
            elif kind == "trans":
                options.append([("trans", (w, m)) for w in self.widths for m in self.modes])
            else:
                options.append([("periodic", (p, self.variant)) for p in self.periods])
        combos = [[]]
        for choices in options:
            combos = [existing + [entry] for existing in combos for entry in choices]
        return combos


@dataclass
class Pathway:
    title: str
    strength: str            # "solved", "strong", "possible" or "long shot"
    evidence: list
    tools: list              # (tool module name, what to do there); the launcher shows its menu number
    plan: list = field(default_factory=list)   # AttackPlan entries


@dataclass
class Profile:
    prepared: Prepared
    length: int
    stats: dict
    refs: dict
    periods: list
    period_candidates: list
    kasiski: list
    flags: dict
    pathways: list
    ruled_out: list
    instant: list = field(default_factory=list)


STRENGTH_ORDER = {"solved": 0, "strong": 1, "possible": 2, "long shot": 3}


def describe_position(value, reference: Reference) -> str:
    return f"{100 * reference.fraction_below(value):.0f}th percentile"


def profile(raw: str, ngram_path: str = str(DEFAULT_NGRAM_PATH), max_period: int | None = None) -> Profile | None:
    """Measure the ciphertext and derive ranked pathways. None if too short."""
    prepared = prepare(raw)
    codes = prepared.codes
    n = len(codes)
    if n < MIN_LETTERS:
        return None
    refs = references(n, ngram_path)
    fitness = fitness_function(ngram_path)

    stats = {
        'ioc': ioc(codes), 'chi': chi_squared(codes), 'adjacency': adjacency(codes),
        'fitness': fitness(codes), 'fitness_reversed': fitness(codes[::-1]),
        'distinct': len(set(codes)),
        'missing': "".join(ALPHABET[c] for c in range(26) if c not in codes),
        'aligned_doubles': sum(1 for i in range(0, n - 1, 2) if codes[i] == codes[i + 1]),
        'doubles': sum(1 for a, b in zip(codes, codes[1:]) if a == b),
    }
    max_period = max_period or max(2, min(30, n // 6))
    periods = periodicity(codes, max_period)
    candidates = likely_periods(periods)

    english_fitness_low = refs['english_fitness'].quantile(LOW_Q)
    flags = {
        'reads_english': max(stats['fitness'], stats['fitness_reversed']) >= english_fitness_low,
        'ioc_english': stats['ioc'] >= refs['english_ioc'].quantile(LOW_Q),
        'ioc_random': stats['ioc'] <= refs['random_ioc'].quantile(HIGH_Q),
        'letters_english': stats['chi'] <= refs['english_chi'].quantile(HIGH_Q),
        'order_english': stats['adjacency'] >= refs['english_adjacency'].quantile(LOW_Q),
        'order_scrambled': stats['adjacency'] <= refs['shuffled_adjacency'].quantile(HIGH_Q),
    }
    # Letter counts kept (substitution and/or transposition): an English-like
    # IoC, or letters that are English letters outright (no polyalphabetic key
    # leaves English letter frequencies, even when the passage's own IoC is low).
    # A passage can have an IoC a little below the references (whose 2nd
    # percentile is the bar) and still be a substitution or transposition.
    # Borderline: within 3 SD of the English mean, above random letters'
    # 98th percentile, and no period found. Then both branches are listed.
    english_ioc = refs['english_ioc']
    flags['ioc_borderline'] = (not flags['ioc_english'] and not flags['letters_english'] and not candidates
                               and stats['ioc'] >= english_ioc.mean - 3 * english_ioc.sd
                               and stats['ioc'] > refs['random_ioc'].quantile(HIGH_Q))
    flags['counts_kept'] = flags['ioc_english'] or flags['letters_english'] or flags['ioc_borderline']
    # Short texts: the two adjacency ranges overlap; longer texts: a value can
    # fall between them. Either way, lean towards the nearer reference
    # (distance in that reference's standard deviations).
    english_adj, shuffled_adj = refs['english_adjacency'], refs['shuffled_adjacency']
    flags['order_leans_english'] = (
        (english_adj.mean - stats['adjacency']) / english_adj.sd
        < (stats['adjacency'] - shuffled_adj.mean) / shuffled_adj.sd)
    result = Profile(prepared, n, stats, refs, periods, candidates, kasiski(codes), flags, [], [])
    result.pathways, result.ruled_out = derive_pathways(result)
    return result


def run_instant_attacks(result: Profile, ngram_path: str = str(DEFAULT_NGRAM_PATH)) -> list:
    """Keyless and small-keyspace attacks that take seconds, chosen by the profile."""
    codes = result.prepared.codes
    fitness = fitness_function(ngram_path)
    candidates = attack_affine(codes, fitness)
    if result.flags['counts_kept']:
        candidates += attack_routes(codes, fitness)
        candidates += attack_small_columnar(codes, fitness)
    if not result.flags['counts_kept'] or result.flags['ioc_borderline']:
        periods = result.period_candidates[:3] or list(range(2, len(result.periods) + 1))
        candidates += attack_periodic(codes, fitness, periods)
        candidates += attack_periodic_keyed(codes, fitness, periods)
        if result.period_candidates:
            candidates += attack_quagmire(codes, fitness, result.period_candidates[0])
        if not result.period_candidates:
            candidates += attack_autokey(codes, fitness, max(1, min(12, len(codes) // 8)))
            candidates += attack_hill(codes)
    candidates.sort(key=lambda c: -c.fitness)
    result.instant = candidates
    return candidates


def judge(score: float, refs: dict) -> str:
    """Where a decryption's fitness falls against English and shuffled text."""
    if score >= refs['english_fitness'].quantile(LOW_Q):
        return "reads as English"
    if score > refs['shuffled_fitness'].quantile(HIGH_Q):
        return "partly English"
    return "not English"


# ------------------------------------------------------------------ rules

def divisors(n: int, low: int = 2, high: int = 30) -> list:
    return [d for d in range(low, min(high, n - 1) + 1) if n % d == 0]


def derive_pathways(p: Profile):
    s, r, f, n = p.stats, p.refs, p.flags, p.length
    pathways, ruled_out = [], []
    english_ioc = r['english_ioc']
    ioc_line = (f"IoC {s['ioc']:.4f}: {describe_position(s['ioc'], english_ioc)} of {n}-letter English "
                f"(2nd-98th: {english_ioc.quantile(LOW_Q):.4f}-{english_ioc.quantile(HIGH_Q):.4f}); "
                f"random letters reach {r['random_ioc'].quantile(HIGH_Q):.4f} (98th)."
                + (" Slightly below the English range but within 3 SD of its mean, and no period was found, so "
                   "both a substitution/transposition and a polyalphabetic key are kept open."
                   if f['ioc_borderline'] else ""))
    chi_line = (f"Chi-squared vs English letters {s['chi']:.0f}: English samples reach "
                f"{r['english_chi'].quantile(HIGH_Q):.0f} (98th percentile).")
    adjacency_line = (f"Adjacent-pair structure {s['adjacency']:.2f}: English in order 2nd percentile "
                      f"{r['english_adjacency'].quantile(LOW_Q):.2f}, shuffled English 98th "
                      f"{r['shuffled_adjacency'].quantile(HIGH_Q):.2f}.")
    widths = divisors(n) or list(range(2, 13))
    width_hint = (f"widths that fill a complete rectangle ({', '.join(map(str, divisors(n)[:8]))}) first, then 2-20"
                  if divisors(n) else "widths 2-20 (the length is prime, so no width gives a full rectangle)")

    if f['reads_english']:
        which = "reversed" if s['fitness_reversed'] > s['fitness'] else "as written"
        pathways.append(Pathway(
            "Not enciphered (or only reversed)", "solved",
            [f"Read {which}, the text scores {max(s['fitness'], s['fitness_reversed']):.1f}; "
             f"English samples of this length score at least {r['english_fitness'].quantile(LOW_Q):.1f} "
             f"(2nd percentile)."],
            [("text_formatter", "Text Formatter, to clean or reverse it")]))

    # ---------------- letter counts kept: substitution and/or transposition
    if f['counts_kept']:
        if f['letters_english']:
            strength = "possible" if f['order_english'] else "strong"
            evidence = [ioc_line, chi_line + " The letters themselves are English, only their order is changed.",
                        adjacency_line + (" Adjacent pairs look like English, so the order is only partly changed "
                                          "(rail fence, route, or short blocks)." if f['order_english'] else
                                          " Adjacent letters are as independent as shuffled text.")]
            pathways.append(Pathway(
                "Transposition only (letters English, order scrambled)", strength, evidence,
                [("rail_fence", "Rail Fence: every rail count"), ("Scytale", "Scytale: every grid width"),
                 ("permutation_solver", f"Column-Order Solver: brute force to width 9, annealing above; try {width_hint}"),
                 ("permutation_solver", "Column-Order Solver: annealing for wider keys"),
                 ("columnar_transposition", "Keyed & Double Columnar: keyword dictionary and double columnar")],
                [AttackPlan("Columnar transposition (widths 2-8 were tried exhaustively)", ("trans",), 500_000, 1,
                            widths=list(range(9, 16)), modes=list(TRANSPOSITION_MODES))]))
        else:
            # Adjacency decides between the two; when it is in neither range
            # alone, both are listed as "possible", the nearer one first.
            ordered_only = f['order_english'] and not f['order_scrambled']
            scrambled_only = f['order_scrambled'] and not f['order_english']
            unclear_note = (" The value is not clearly in one range (at this length the ranges overlap or leave a gap); "
                            f"it is nearer to {'English in order' if f['order_leans_english'] else 'shuffled English'}.")
            substitution = Pathway(
                "Simple substitution (monoalphabetic)", "strong" if ordered_only else "possible",
                [ioc_line, chi_line + " The letters are not English letters, but their frequencies have "
                 "English's shape.", adjacency_line + (" Adjacent pairs still have English structure, so "
                                                     "no transposition." if ordered_only else unclear_note)],
                [("caesar", "Caesar, every shift"), ("affine", "Affine, every key"),
                 ("simulated_annealing", "Substitution Solver (the general attack)")]
                + ([("pattern_isomorphism", "Word Pattern Attack: the word boundaries look preserved")] if p.prepared.word_lengths else []),
                [AttackPlan("Simple substitution", ("sub",), 600_000, 6)])
            combined = Pathway(
                "Substitution + transposition", "strong" if scrambled_only else "possible",
                [ioc_line, chi_line, adjacency_line + (" Adjacent letters are as independent as shuffled text: "
                                                       "a transposition is present." if scrambled_only else unclear_note)]
                + ([f"At {n} letters this is hard: the Two-Layer Solver was measured on 300-600 letters."] if n < 250 else []),
                [("two_layer", f"Two-Layer Solver, combination 1; try {width_hint}")],
                [AttackPlan("Substitution + transposition, joint annealing", ("sub", "trans"), 1_500_000, 2,
                            widths=widths[:6])])
            if ordered_only:
                pathways.append(substitution)
            elif scrambled_only:
                pathways.append(combined)
            else:
                pathways += [substitution, combined] if f['order_leans_english'] else [combined, substitution]
        if not f['ioc_borderline']:
            ruled_out.append(("Periodic, autokey and running-key ciphers",
                              "they flatten letter frequencies, and the IoC is English-like."))
    if not f['counts_kept'] or f['ioc_borderline']:
        # ---------------- flattened frequencies
        periods = p.period_candidates
        if periods:
            period = periods[0]
            row = p.periods[period - 1]
            pathways.append(Pathway(
                f"Periodic polyalphabetic, key length {period}", "strong",
                [ioc_line,
                 f"Every {ordinal(period)} letter has IoC {row['ioc']:.4f}: above chance (shuffled copies reach "
                 f"{row['chance_high']:.4f}) and English-like (English split the same way: 2nd percentile "
                 f"{row['english_low']:.4f}). Other periods passing: {', '.join(map(str, periods[1:6])) or 'none'} "
                 f"(multiples of the key length also pass)."]
                + ([f"Kasiski: distances between repeats share the factors "
                    f"{', '.join(f'{k} ({v}x)' for k, v in p.kasiski[:4])}."] if p.kasiski else []),
                [("vigenere_auto_solver", f"Vigenere Auto-Solver (key length {period})"),
                 ("vigenere", f"Vigenere Workbench: anneal key length {period}, or a keyed alphabet such as KRYPTOS"),
                 ("beaufort", "Beaufort"), ("porta", "Porta"), ("Gronsfeld", "Gronsfeld, if the key shifts are all 0-9"),
                 ("keyword_periodic", f"Quagmire I-III: every dictionary word as the alphabet keyword, period {period}"),
                 ("two_layer", f"Two-Layer Solver combination 4 or 5 if the alphabets are mixed (Quagmire), period {period}")],
                [AttackPlan("Vigenere key (straight alphabet), annealing", ("periodic",), 300_000, 2, periods=[period]),
                 AttackPlan("Beaufort key (straight alphabet), annealing", ("periodic",), 300_000, 2, periods=[period],
                            variant="beaufort"),
                 AttackPlan("Mixed alphabet + periodic key (Quagmire-like: substitution, then Vigenere)",
                            ("sub", "periodic"), 600_000, 4, periods=[period]),
                 AttackPlan("Transposition, then Vigenere", ("trans", "periodic"), 600_000, 2,
                            widths=widths[:6], periods=[period])]))
        else:
            ruled_out.append((f"Periodic key of length 2-{len(p.periods)} on its own",
                              "no period gives columns that are both above chance and English-like."))
        friedman = friedman_estimate(s['ioc'])
        aperiodic = [ioc_line + " Letter frequencies are flattened, as by a polyalphabetic key.",
                     "Friedman estimate of the key length: "
                     + (f"{friedman:.1f}" if friedman else "unbounded (IoC at or below random)")
                     + " (a rough guide for short texts)."]
        pathways.append(Pathway(
            "Aperiodic or long key (autokey, running key, Gromark, long Vigenere)",
            "possible" if not periods and not f['ioc_borderline'] else "long shot", aperiodic,
            [("autoclave", "Autoclave: recover the primer of a plaintext or ciphertext autokey (no word list; tried above)"), ("running_key", "Running key: crib-drag a probable word"),
             ("gromark_solver", "Gromark Solver: every primer screened, then the mixed alphabet"), ("crib_drag", "Crib dragging, if you can guess a word"),
             ("vigenere", f"Vigenere with a key longer than {len(p.periods)} (annealing)")]))
        pathways.append(Pathway(
            "Periodic key combined with a transposition",
            "long shot" if periods or f['ioc_borderline'] else "possible",
            ["A transposition applied AFTER a periodic key moves letters out of their key columns, so no period "
             "shows, while the IoC stays low."],
            [("two_layer", "Two-Layer Solver, combination 3 (Vigenere-family, then transposition)")],
            [AttackPlan("Vigenere, then transposition, joint annealing", ("periodic", "trans"), 1_500_000, 2,
                        widths=widths[:3], periods=periods[:1] or [5, 7])]))

    # ---------------- structure: digraphic and fractionating ciphers
    even = n % 2 == 0
    if s['distinct'] <= 25 and even and s['aligned_doubles'] == 0:
        pathways.append(Pathway(
            "Digraphic 5x5 square (Playfair, Two-/Four-square)", "possible",
            [f"{s['distinct']} distinct letters (missing: {s['missing']}), even length, and no letter pair at "
             f"positions 1-2, 3-4, ... is a doubled letter, which a Playfair never outputs."
             + (" J missing is typical of a 5x5 square." if "J" in s['missing'] else "")],
            [("playfair", "Playfair: mode A anneals the square (no key needed)"), ("four_square", "Four-Square: annealing")],
            [AttackPlan("Playfair square, annealing (several runs in parallel)", ("playfair",), 1_000_000, 8)]))
    else:
        reasons = []
        if s['distinct'] > 25:
            reasons.append("all 26 letters occur (a 5x5 square has 25)")
        if not even:
            reasons.append(f"odd length {n} (digraphs need pairs)")
        if s['aligned_doubles']:
            reasons.append(f"{s['aligned_doubles']} doubled letter pair(s) at positions 1-2, 3-4, ... (Playfair never outputs one)")
        ruled_out.append(("Playfair applied directly", "; ".join(reasons) + "."))
    if s['distinct'] <= 25 and not f['counts_kept']:
        pathways.append(Pathway(
            "Bifid (Polybius fractionation)", "long shot",
            [f"{s['distinct']} distinct letters fit a 5x5 square, and fractionation flattens frequencies."],
            [("fractionation_solver", "Bifid / Trifid Solver: anneal the square for each period")]))
    hill_sizes = [m for m in (2, 3, 4) if n % m == 0]
    if hill_sizes and not f['counts_kept']:
        pathways.append(Pathway(
            "Hill cipher", "long shot",
            [f"The length {n} is a multiple of {', '.join(map(str, hill_sizes))}, the block sizes a Hill matrix of "
             f"that size needs."],
            [("hill", "Hill: ciphertext-only 2x2/3x3 attack, or known plaintext")]))
    elif not hill_sizes:
        ruled_out.append(("Hill cipher with 2x2, 3x3 or 4x4 blocks", f"the length {n} is not a multiple of 2, 3 or 4."))

    pathways.sort(key=lambda pathway: STRENGTH_ORDER[pathway.strength])
    return pathways, ruled_out
