"""Shared machinery for keyword dictionary attacks (Vigenere, Beaufort, Porta).

Each cipher module registers its ``decrypt(ciphertext, key, alphabet)`` with
its rule (``register_kernel``); run_batches then decrypts and scores every
word in C (scripts/native/periodic_dict.c, cct_periodic_dict) on several
threads, and Python only renders the rows that are kept.

What is scored is exactly what the Python decrypt returns: characters whose
upper case is in the alphabet are decrypted (the key advances on them) and
come out in lower case; every other character passes through in lower case.
Cost = ngram_scoring.score_text of that text (255 - mean n-gram score, lower
is more English-like), IoC = utils.calculate_ioc of it.

Any alphabet of 1 to 256 characters works (A-Z, keyed, I/J-merged, with
digits); the C kernel scores each plaintext symbol by the text it is shown as.
"""
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache

import compute
from theme import RED, RESET, YELLOW
from ngram_scoring import score_text
from utils.utils import calculate_ioc

from native import periodic_engine

BATCH_SIZE = 2_000
# Candidates kept per batch purely on n-gram score, in addition to phrase and
# IoC-window matches. English text frequently falls outside a narrow IoC
# window, so filtering on IoC alone can discard the correct key.
TOP_PER_BATCH = 25
MAX_ALPHABET = 256
_KERNELS = {}


def register_kernel(decrypt, rule):
    """Declare that ``decrypt(ciphertext, key, alphabet)`` is a periodic cipher
    with the Vigenere-family text rules described above and plaintext index
    ``rule(cipher_index, key_index, m)`` (alphabet indices, m = alphabet
    length), so run_batches can run it in C."""
    _KERNELS[decrypt] = rule
    return decrypt


@lru_cache(maxsize=4)
def read_word_list(file_path: str) -> tuple:
    """Read a word list once per process: stripped, uppercased, de-duplicated."""
    with open(file_path, "r", encoding="utf-8") as word_file:
        return tuple(dict.fromkeys(line.strip().upper() for line in word_file if line.strip()))


def read_ascii_keys(file_path: str):
    """The XOR and modular word-list attacks' keys: every non-empty stripped
    line that is pure ASCII, upper-cased, in file order (no de-duplication),
    as (list of words, periodic_engine.KeyList of their bytes). Cached per
    file and modification time."""
    return _read_ascii_keys(str(file_path), os.path.getmtime(file_path))


@lru_cache(maxsize=2)
def _read_ascii_keys(file_path, mtime):
    with open(file_path, "r", encoding="utf-8") as word_file:
        lines = word_file.read().splitlines()
    words = [word.upper() for word in map(str.strip, lines) if word and word.isascii()]
    return words, periodic_engine.KeyList.joined("".join(words).encode("ascii"), map(len, words))


def load_dictionary(file_path, alphabet_str, min_length=3, max_length=15, allowed_lengths=None):
    try:
        words = read_word_list(str(file_path))
    except FileNotFoundError:
        print(f"{RED}Error: {file_path} not found{RESET}")
        return []
    alphabet_set = set(alphabet_str.upper())
    lengths = set(allowed_lengths) if allowed_lengths else set(range(min_length, max_length + 1))
    return [word for word in words if len(word) in lengths and alphabet_set.issuperset(word)]


def contains_all_phrases(text: str, phrases) -> bool:
    """True if every phrase occurs in ``text``, ignoring case and spaces."""
    if not phrases:
        return False
    compact = text.upper().replace(" ", "")
    return all(phrase.upper().replace(" ", "") in compact for phrase in phrases)


def make_result(key, plaintext, ngram_model, phrases, is_phrase_match=None, ioc=None, score=None):
    if is_phrase_match is None:
        is_phrase_match = contains_all_phrases(plaintext, phrases)
    return {
        'key': key,
        'plaintext': plaintext,
        'ioc': calculate_ioc(plaintext) if ioc is None else ioc,
        'bigram_score': score_text(plaintext, ngram_model) if score is None else score,
        'is_phrase_match': is_phrase_match,
        'matched_phrases': list(phrases) if is_phrase_match else [],
    }


class _Prepared:
    """The ciphertext split for the C kernel, plus a fast renderer for kept rows."""

    def __init__(self, ciphertext, alphabet, rule, phrases, ngram_model):
        self.alphabet = alphabet
        m = len(alphabet)
        self.index_of = {char: i for i, char in enumerate(alphabet)}
        pieces, self.segments, run = [], [], 0
        for char in ciphertext:
            index = self.index_of.get(char.upper())
            if index is not None:
                pieces.append(index)
                run += 1
            else:
                pieces.append(char.lower())
                self.segments.append((run, char.lower()))
                run = 0
        self.tail = run
        self.symbols = bytes(piece for piece in pieces if isinstance(piece, int))
        rows = [bytes(rule(c, k, m) for c in range(m)) for k in range(m)]
        self.tables = [row + bytes(256 - m) for row in rows]          # 256-byte translate tables
        self.shown = [char.lower() for char in alphabet]                # what each plaintext symbol is shown as
        self.lower = None
        if all(len(text) == 1 and text.isascii() for text in self.shown):
            self.lower = bytes.maketrans(bytes(range(m)), "".join(self.shown).encode("ascii"))
        self.context = periodic_engine.TextContext(
            pieces, b"".join(rows), m, self.shown, ngram_model,
            phrases=[phrase.upper().replace(" ", "") for phrase in phrases], phrase_all=True,
            phrase_view=lambda text: text.upper().replace(" ", ""))

    def key_bytes(self, word):
        return bytes(self.index_of[char] for char in word.upper() if char in self.index_of)

    def render(self, key):
        """The decrypt function's output for this key (lower case, other characters kept)."""
        plain = bytearray(len(self.symbols))
        for column, k in enumerate(key):
            plain[column::len(key)] = self.symbols[column::len(key)].translate(self.tables[k])
        if self.lower is not None:
            letters = plain.translate(self.lower).decode("ascii")
            ends = None
        else:
            shown = [self.shown[p] for p in plain]
            letters = "".join(shown)
            ends = [0]
            for text in shown:
                ends.append(ends[-1] + len(text))
        if not self.segments:
            return letters
        parts, position = [], 0
        for run, char in self.segments:
            stop = position + run
            parts.append(letters[position:stop] if ends is None else letters[ends[position]:ends[stop]])
            parts.append(char)
            position = stop
        parts.append(letters[position:] if ends is None else letters[ends[position]:])
        return "".join(parts)


def _word_keys(words, prepared):
    """KeyList of the words' key indices; words with no alphabet letters get an
    empty key (the kernel skips them: the decrypt would return the text unchanged)."""
    joined = "".join(words).upper()
    alphabet = prepared.alphabet
    if alphabet.isascii() and joined.isascii() and sum(map(len, words)) == len(joined):
        alphabet_bytes = alphabet.encode("ascii")
        if not joined.encode("ascii").translate(None, alphabet_bytes):
            # bytes.maketrans keeps the last mapping of a repeated character, as {char: index} does
            translate = bytes.maketrans(alphabet_bytes, bytes(range(len(alphabet))))
            return periodic_engine.KeyList.joined(joined.encode("ascii").translate(translate), map(len, words))
    return periodic_engine.KeyList([prepared.key_bytes(word) for word in words])


def run_batches(decrypt, words, ciphertext, alphabet_str, phrases, ngram_model, min_ioc, max_ioc):
    """Score every word as a key (in C, on several threads). Per batch of
    BATCH_SIZE words, keeps phrase matches and IoC-window hits plus the
    TOP_PER_BATCH best others by n-gram cost. Returns result dicts (make_result)."""
    rule = _KERNELS.get(decrypt)
    if rule is None:
        raise ValueError(f"{getattr(decrypt, '__name__', decrypt)} has no C dictionary kernel; "
                         "register it with attack_support.register_kernel(decrypt, rule)")
    alphabet = alphabet_str.upper()
    if not 1 <= len(alphabet) <= MAX_ALPHABET:
        print(f"{RED}The dictionary attack needs an alphabet of 1 to {MAX_ALPHABET} characters.{RESET}")
        return []
    prepared = _Prepared(ciphertext, alphabet, rule, list(phrases or []), ngram_model)
    keys = _word_keys(words, prepared)
    batches = [(start, min(BATCH_SIZE, len(words) - start)) for start in range(0, len(words), BATCH_SIZE)]
    print(f"Processing {YELLOW}{len(words):,}{RESET} words with {YELLOW}{compute.workers(len(batches) or 1)}{RESET} "
          f"thread(s) (C engine)...")
    start_time = time.time()
    rows_by_batch = parallel_chunks(
        lambda batch: periodic_engine.dictionary_batch(prepared.context, keys, batch[0], batch[1], min_ioc, max_ioc,
                                                       TOP_PER_BATCH),
        batches, lambda done, total: print(f"Progress: {done / total:.1%}", end='\r') if total > 1 else None)
    results = []
    for rows in rows_by_batch:
        for index, cost, ioc, phrase in rows or ():
            word = words[index]
            plaintext = prepared.render(keys.key(index))
            results.append(make_result(word, plaintext, ngram_model, phrases, phrase, ioc, cost))
    print(f"\nDictionary search complete in {time.time() - start_time:.2f} seconds.")
    return results


def parallel_chunks(function, chunks, progress=None):
    """function(chunk) for every chunk on compute.workers() threads (the C
    engines release the GIL). Returns the results in chunk order; a chunk
    not finished when Ctrl+C is pressed gives None. progress(done, total) is
    called as chunks finish."""
    if not chunks:
        return []
    results = [None] * len(chunks)
    executor = ThreadPoolExecutor(max_workers=compute.workers(len(chunks)))
    futures = {executor.submit(function, chunk): number for number, chunk in enumerate(chunks)}
    try:
        for done, future in enumerate(as_completed(futures), start=1):
            results[futures[future]] = future.result()
            if progress is not None:
                progress(done, len(chunks))
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Interrupted; keeping the parts finished so far.{RESET}")
    finally:
        executor.shutdown(wait=True, cancel_futures=True)
    return results


def sort_results(results):
    """Phrase matches first, then best (lowest) n-gram cost."""
    results.sort(key=lambda result: (not result['is_phrase_match'], result['bigram_score'], -result['ioc']))
    return results
