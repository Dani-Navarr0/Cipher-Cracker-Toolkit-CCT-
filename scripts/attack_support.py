"""Shared machinery for keyword dictionary attacks (Vigenere, Beaufort, Porta).

Each cipher module supplies only its ``decrypt(ciphertext, key, alphabet)``
function; candidate generation, scoring, filtering and parallelism live here.
"""
import heapq
import os
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from functools import lru_cache

from ngram_scoring import score_text
from theme import RED, RESET, YELLOW
from utils.utils import calculate_ioc

# Starting a process pool on Windows (spawn) re-imports the launcher and every
# module in each worker, which costs seconds. Below this many words a single
# process finishes first (decrypt + score is roughly 50-100 us per word).
PARALLEL_THRESHOLD = 30_000
BATCH_SIZE = 2_000
# Candidates kept per batch purely on n-gram score, in addition to phrase and
# IoC-window matches. English text frequently falls outside a narrow IoC
# window, so filtering on IoC alone can discard the correct key.
TOP_PER_BATCH = 25


@lru_cache(maxsize=4)
def read_word_list(file_path: str) -> tuple:
    """Read a word list once per process: stripped, uppercased, de-duplicated."""
    with open(file_path, "r", encoding="utf-8") as word_file:
        return tuple(dict.fromkeys(line.strip().upper() for line in word_file if line.strip()))


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


def score_batch(args):
    """Decrypt and score one batch of keys. Must stay module-level (pickled)."""
    decrypt, words, ciphertext, alphabet_str, phrases, ngram_model, min_ioc, max_ioc = args
    kept, others = [], []
    for word in words:
        plaintext = decrypt(ciphertext, word, alphabet_str)
        score = score_text(plaintext, ngram_model)
        ioc = calculate_ioc(plaintext)
        is_phrase_match = contains_all_phrases(plaintext, phrases)
        entry = (score, word, plaintext, ioc, is_phrase_match)
        if is_phrase_match or min_ioc <= ioc <= max_ioc:
            kept.append(entry)
        else:
            others.append(entry)
    kept.extend(heapq.nsmallest(TOP_PER_BATCH, others, key=lambda entry: entry[0]))
    return [
        make_result(word, plaintext, ngram_model, phrases, is_phrase_match, ioc, score)
        for score, word, plaintext, ioc, is_phrase_match in kept
    ]


def run_batches(decrypt, words, ciphertext, alphabet_str, phrases, ngram_model, min_ioc, max_ioc):
    """Score every word as a key, in parallel only when that pays off."""
    batches = [words[index:index + BATCH_SIZE] for index in range(0, len(words), BATCH_SIZE)]
    tasks = [(decrypt, batch, ciphertext, alphabet_str, phrases, ngram_model, min_ioc, max_ioc) for batch in batches]
    workers = max(1, (os.cpu_count() or 1) - 1)
    parallel = len(words) >= PARALLEL_THRESHOLD and workers > 1
    print(f"Processing {YELLOW}{len(words):,}{RESET} words with "
          f"{YELLOW}{workers if parallel else 1}{RESET} process(es)...")
    start_time = time.time()
    results = []
    if parallel:
        with ProcessPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(score_batch, task) for task in tasks]
            for done, future in enumerate(as_completed(futures), start=1):
                results.extend(future.result())
                print(f"Progress: {done / len(futures):.1%}", end='\r')
    else:
        for done, task in enumerate(tasks, start=1):
            results.extend(score_batch(task))
            if len(tasks) > 1:
                print(f"Progress: {done / len(tasks):.1%}", end='\r')
    print(f"\nDictionary search complete in {time.time() - start_time:.2f} seconds.")
    return results


def sort_results(results):
    """Phrase matches first, then best (lowest) n-gram cost."""
    results.sort(key=lambda result: (not result['is_phrase_match'], result['bigram_score'], -result['ioc']))
    return results
