import glob
import gzip
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path


NGRAM_DIRECTORY = Path(__file__).resolve().parent.parent / "N-grams"
SPACES_DIRECTORY = NGRAM_DIRECTORY / "Spaces"
# Parsed text-format models are cached here as raw binary tables (git-ignored).
CACHE_DIRECTORY = NGRAM_DIRECTORY / ".cache"
DEFAULT_NGRAM_SIZE = 5
_NGRAM_FILES = {
    2: "2-grams_english_jarlve_reddit_v1912.gz",
    3: "3-grams_english_jarlve_reddit_v1912.gz",
    4: "4-grams_english_jarlve_reddit_v1912.gz",
    5: "5-grams_english_practicalcryptography_wortschatz.txt",
    6: "6-grams_english_jarlve_reddit_v1912.gz",
}
DEFAULT_NGRAM_PATH = NGRAM_DIRECTORY / _NGRAM_FILES[DEFAULT_NGRAM_SIZE]

# Byte-level tables: map ASCII 'A'-'Z' to codes 0-25 and drop every other byte.
_LETTER_CODES = bytes.maketrans(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ", bytes(range(26)))
_NON_LETTERS = bytes(byte for byte in range(256) if not 65 <= byte <= 90)
_CODES_TO_LETTERS = bytes.maketrans(bytes(range(26)), b"ABCDEFGHIJKLMNOPQRSTUVWXYZ")


def text_to_codes(text: str) -> bytes:
    """Return the A-Z letters of ``text`` (case-insensitive) as bytes of codes 0-25.

    Equivalent to keeping ``char for char in text.upper() if "A" <= char <= "Z"``
    but runs in C, which matters inside solver loops.
    """
    return text.upper().encode("ascii", "ignore").translate(_LETTER_CODES, _NON_LETTERS)


def codes_to_text(codes: bytes | bytearray) -> str:
    """Inverse of :func:`text_to_codes` for codes 0-25."""
    return bytes(codes).translate(_CODES_TO_LETTERS).decode("ascii")


def _native_ngram_total():
    """The C n-gram total, or None when the library is not built."""
    import os
    if os.environ.get("CCT_NATIVE", "1") == "0":
        return None
    try:
        import native
        from native import fast
        if not native.available():
            return None
        function, pointer = native.library().cct_ngram_total, fast._scores_pointer
    except Exception:
        return None

    def total(codes, scores, ngram_size):
        if not isinstance(codes, bytes):
            codes = bytes(codes)
        return function(codes, len(codes), pointer(scores), ngram_size)
    return total


_c_total = _native_ngram_total()


def ngram_total(codes: bytes | bytearray, scores: bytes | bytearray, ngram_size: int) -> int:
    """Sum of the table scores of every overlapping n-gram of ``codes`` (0-25
    letter codes), computed in C. The hot loop of every solver. Raises
    native.NativeUnavailable (with build instructions) when the C library is
    not built; it is looked up again on each call until it is, so building it
    from menu 91 works without a restart."""
    global _c_total
    if _c_total is None:
        _c_total = _native_ngram_total()
        if _c_total is None:
            import native
            native.require()
            raise native.NativeUnavailable(native.MISSING_MESSAGE)
    return _c_total(codes, scores, ngram_size)


@dataclass(frozen=True)
class NgramModel:
    size: int
    path: Path

    @property
    def scores(self) -> bytearray | bytes:
        return _load_model_data(str(self.path), self.size)


@dataclass(frozen=True)
class SpacingNgramModel:
    size: int
    alphabet: str
    path: Path

    @property
    def scores(self) -> bytes:
        return _load_spacing_model_data(str(self.path), self.size, self.alphabet)


def resolve_ngram_path(ngram_size: int = DEFAULT_NGRAM_SIZE) -> Path:
    try:
        filename = _NGRAM_FILES[ngram_size]
    except KeyError as exc:
        supported = ", ".join(map(str, sorted(_NGRAM_FILES)))
        raise ValueError(f"Unsupported n-gram size {ngram_size}; choose {supported}.") from exc
    return NGRAM_DIRECTORY / filename


def available_spacing_models() -> list[Path]:
    return sorted(
        (
            model_path.resolve()
            for model_path in SPACES_DIRECTORY.glob("*/*.gz")
            if model_path.with_suffix(".ini").is_file()
        ),
        key=lambda path: (path.parent.name.casefold(), path.name.casefold()),
    )


@lru_cache(maxsize=None)
def load_spacing_model(file_path: str | Path) -> SpacingNgramModel:
    path = Path(file_path).resolve()
    if not path.is_file():
        raise FileNotFoundError(f"Spacing n-gram data file not found: {path}")

    configuration_path = path.with_suffix(".ini")
    if not configuration_path.is_file():
        raise FileNotFoundError(f"Spacing n-gram configuration not found: {configuration_path}")

    configuration = {}
    with configuration_path.open("rt", encoding="ascii") as configuration_file:
        for line in configuration_file:
            key, separator, value = line.rstrip("\r\n").partition("=")
            if separator:
                configuration[key.strip()] = value

    try:
        ngram_size = int(configuration["N-gram size"].strip())
        alphabet = configuration["Alphabet"]
    except (KeyError, ValueError) as exc:
        raise ValueError(f"Invalid spacing n-gram configuration: {configuration_path}") from exc

    if ngram_size < 1 or not alphabet or len(set(alphabet)) != len(alphabet):
        raise ValueError(f"Invalid n-gram size or alphabet in {configuration_path}")
    if " " not in alphabet:
        raise ValueError(f"Spacing n-gram alphabet has no space symbol: {configuration_path}")

    return SpacingNgramModel(ngram_size, alphabet, path)


@lru_cache(maxsize=None)
def _load_spacing_model_data(file_path: str, ngram_size: int, alphabet: str) -> bytes:
    path = Path(file_path)
    with gzip.open(path, "rb") as ngram_file:
        scores = ngram_file.read()

    expected_size = len(alphabet) ** ngram_size
    if len(scores) != expected_size:
        raise ValueError(
            f"Expected {expected_size} binary scores for {ngram_size}-grams in {path}, "
            f"found {len(scores)}."
        )
    return scores


def add_spaces(text: str, model: SpacingNgramModel) -> str:
    """Insert word boundaries using the selected space-aware n-gram model."""
    alphabet_indices = {char: index for index, char in enumerate(model.alphabet)}
    letters = "".join(
        char for char in text.upper()
        if char in alphabet_indices and char != " "
    )
    if not letters:
        return ""

    scores = model.scores
    ngram_size = model.size
    alphabet_size = len(model.alphabet)
    space = alphabet_indices[" "]
    suffix_modulus = alphabet_size ** (ngram_size - 1)

    # The text is modelled as " " + letters (with optional spaces) + " ".
    # A suffix is the last (ngram_size - 1) symbols packed into an integer.
    # Its length is implied by the symbol count, which is fixed for every
    # state at a given position: 1 + letters consumed + spaces inserted.
    def append_symbol(suffix: int, symbol_count: int, symbol: int, score: int) -> tuple[int, int]:
        ngram_index = suffix * alphabet_size + symbol
        if symbol_count + 1 >= ngram_size:
            score += scores[ngram_index]
        return ngram_index % suffix_modulus, score

    # Keep separate paths by suffix and number of inserted spaces so each
    # state has the same eventual n-gram count and can be safely merged
    # (the final objective is a mean, so it does not decompose otherwise).
    # Each step stores a back-pointer instead of copying the output string,
    # which turns the O(n^3) character copying into O(n^2) state updates.
    initial_suffix, initial_score = append_symbol(0, 0, space, 0)
    paths: dict[tuple[int, int], int] = {(initial_suffix, 0): initial_score}
    # history[position][state] = (previous state, whether a space precedes the letter)
    history: list[dict[tuple[int, int], tuple[tuple[int, int], bool]]] = []
    for position, letter in enumerate(letters):
        letter_code = alphabet_indices[letter]
        next_paths: dict[tuple[int, int], int] = {}
        back_pointers: dict[tuple[int, int], tuple[tuple[int, int], bool]] = {}
        choices = (False, True) if position else (False,)
        for state, score in paths.items():
            suffix, space_count = state
            for insert_space in choices:
                symbol_count = 1 + position + space_count
                next_suffix, next_score = suffix, score
                next_space_count = space_count
                if insert_space:
                    next_suffix, next_score = append_symbol(next_suffix, symbol_count, space, next_score)
                    symbol_count += 1
                    next_space_count += 1
                next_suffix, next_score = append_symbol(next_suffix, symbol_count, letter_code, next_score)
                next_state = (next_suffix, next_space_count)
                current = next_paths.get(next_state)
                if current is None or next_score > current:
                    next_paths[next_state] = next_score
                    back_pointers[next_state] = (state, insert_space)
        paths = next_paths
        history.append(back_pointers)

    letter_count = len(letters)

    def path_quality(item: tuple[tuple[int, int], int]) -> tuple[float, int]:
        (suffix, space_count), score = item
        symbol_count = 1 + letter_count + space_count
        _, score_with_end_boundary = append_symbol(suffix, symbol_count, space, score)
        ngram_count = letter_count + space_count + 3 - ngram_size
        mean_score = score_with_end_boundary / ngram_count if ngram_count > 0 else 0.0
        return mean_score, -space_count

    state = max(paths.items(), key=path_quality)[0]
    output: list[str] = []
    for position in range(letter_count - 1, -1, -1):
        state, insert_space = history[position][state]
        output.append(letters[position])
        if insert_space:
            output.append(" ")
    return "".join(reversed(output))


@lru_cache(maxsize=None)
def load_ngram_scores(file_path: str | Path = DEFAULT_NGRAM_PATH) -> NgramModel:
    path = Path(file_path).resolve()
    size_match = re.match(r"(\d+)-grams_", path.name)
    if not size_match:
        raise ValueError(f"Cannot determine n-gram size from filename: {path.name}")
    ngram_size = int(size_match.group(1))
    if not path.is_file():
        raise FileNotFoundError(f"N-gram data file not found: {path}")
    return NgramModel(ngram_size, path)


@lru_cache(maxsize=None)
def _load_model_data(file_path: str, ngram_size: int) -> bytearray | bytes:
    path = Path(file_path)
    if path.suffix == ".gz":
        with gzip.open(path, "rb") as ngram_file:
            scores = ngram_file.read()
        expected_size = 26 ** ngram_size
        if len(scores) != expected_size:
            raise ValueError(
                f"Expected {expected_size} binary scores for {ngram_size}-grams in {path}, "
                f"found {len(scores)}."
            )
        return scores

    expected_size = 26 ** ngram_size
    stat = path.stat()
    cache_path = CACHE_DIRECTORY / f"{path.name}.{stat.st_size}.{stat.st_mtime_ns}.bin"
    try:
        cached = cache_path.read_bytes()
        if len(cached) == expected_size:
            return bytearray(cached)
    except OSError:
        pass

    scores = _parse_text_model(path, ngram_size)

    # Parsing the text format costs ~2 s for 5-grams; a raw table loads in ms.
    try:
        CACHE_DIRECTORY.mkdir(exist_ok=True)
        for stale in CACHE_DIRECTORY.glob(f"{glob.escape(path.name)}.*.bin"):
            stale.unlink(missing_ok=True)
        temporary_path = cache_path.with_suffix(".tmp")
        temporary_path.write_bytes(scores)
        temporary_path.replace(cache_path)
    except OSError:
        pass  # Read-only install: just parse every session.
    return scores


def _parse_text_model(path: Path, ngram_size: int) -> bytearray:
    with open(path, "rt", encoding="ascii") as ngram_file:
        contents = ngram_file.read()

    pattern = re.compile(rf"([A-Z]{{{ngram_size}}})\s*(\d{{1,3}})")
    scores = bytearray(26 ** ngram_size)
    entries_loaded = 0
    weights = [26 ** power for power in range(ngram_size - 1, -1, -1)]
    for ngram, score_text_value in pattern.findall(contents):
        score = int(score_text_value)
        if score > 255:
            raise ValueError(f"Invalid n-gram score {score} in {path}")
        ngram_index = 0
        for weight, code in zip(weights, ngram.encode("ascii")):
            ngram_index += weight * (code - 65)
        scores[ngram_index] = score
        entries_loaded += 1
    if not entries_loaded:
        raise ValueError(f"No {ngram_size}-gram scores found in {path}")
    return scores


def score_text(
    text: str,
    ngram_scores: NgramModel | dict[str, int],
    ngram_size: int | None = None,
) -> float:
    if not ngram_scores:
        raise ValueError("N-gram scores are required to score text.")
    if isinstance(ngram_scores, NgramModel):
        model = ngram_scores
        scores = model.scores
        ngram_size = model.size if ngram_size is None else ngram_size
    else:
        scores = ngram_scores
        ngram_size = len(next(iter(scores))) if ngram_size is None else ngram_size

    if isinstance(scores, (bytes, bytearray)):
        codes = text_to_codes(text)
        if len(codes) < ngram_size:
            return float("inf")
        total_score = ngram_total(codes, scores, ngram_size)
        return 255 - total_score / (len(codes) - ngram_size + 1)

    letters = "".join(char for char in text.upper() if "A" <= char <= "Z")
    if len(letters) < ngram_size:
        return float("inf")
    total_score = sum(
        scores.get(letters[index:index + ngram_size], 0)
        for index in range(len(letters) - ngram_size + 1)
    )
    # The source files assign larger byte scores to more likely n-grams;
    # convert their mean to a cost so existing solvers can keep minimizing.
    return 255 - total_score / (len(letters) - ngram_size + 1)
