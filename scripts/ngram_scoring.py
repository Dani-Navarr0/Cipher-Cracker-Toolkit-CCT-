import gzip
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path


NGRAM_DIRECTORY = Path(__file__).resolve().parent.parent / "N-grams"
SPACES_DIRECTORY = NGRAM_DIRECTORY / "Spaces"
DEFAULT_NGRAM_SIZE = 5
_NGRAM_FILES = {
    2: "2-grams_english_jarlve_reddit_v1912.gz",
    3: "3-grams_english_jarlve_reddit_v1912.gz",
    4: "4-grams_english_jarlve_reddit_v1912.gz",
    5: "5-grams_english_practicalcryptography_wortschatz.txt",
    6: "6-grams_english_jarlve_reddit_v1912.gz",
}
DEFAULT_NGRAM_PATH = NGRAM_DIRECTORY / _NGRAM_FILES[DEFAULT_NGRAM_SIZE]


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
    space = " "

    def append_symbol(suffix: str, symbol: str, score: int) -> tuple[str, int]:
        ngram = suffix + symbol
        if len(ngram) >= ngram_size:
            ngram_index = 0
            for char in ngram[-ngram_size:]:
                ngram_index = ngram_index * alphabet_size + alphabet_indices[char]
            score += scores[ngram_index]
        return ngram[-(ngram_size - 1):] if ngram_size > 1 else "", score

    # Keep separate paths by suffix and number of inserted spaces so each
    # state has the same eventual n-gram count and can be safely merged.
    initial_suffix, initial_score = append_symbol("", space, 0)
    paths: dict[tuple[str, int], tuple[int, str]] = {
        (initial_suffix, 0): (initial_score, "")
    }
    for position, letter in enumerate(letters):
        next_paths: dict[tuple[str, int], tuple[int, str]] = {}
        for (suffix, space_count), (score, output) in paths.items():
            choices = (False, True) if position else (False,)
            for insert_space in choices:
                next_suffix, next_score = suffix, score
                next_output = output
                next_space_count = space_count
                if insert_space:
                    next_suffix, next_score = append_symbol(next_suffix, space, next_score)
                    next_output += space
                    next_space_count += 1
                next_suffix, next_score = append_symbol(next_suffix, letter, next_score)
                next_output += letter
                state = (next_suffix, next_space_count)
                current = next_paths.get(state)
                if current is None or next_score > current[0]:
                    next_paths[state] = (next_score, next_output)
        paths = next_paths

    def path_quality(item: tuple[tuple[str, int], tuple[int, str]]) -> tuple[float, int]:
        (suffix, space_count), (score, _) = item
        _, score_with_end_boundary = append_symbol(suffix, space, score)
        ngram_count = len(letters) + space_count + 3 - ngram_size
        mean_score = score_with_end_boundary / ngram_count if ngram_count > 0 else 0.0
        return mean_score, -space_count

    return max(paths.items(), key=path_quality)[1][1]


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

    with open(path, "rt", encoding="ascii") as ngram_file:
        contents = ngram_file.read()

    pattern = re.compile(rf"([A-Z]{{{ngram_size}}})\s*(\d{{1,3}})")
    scores = bytearray(26 ** ngram_size)
    entries_loaded = 0
    for match in pattern.finditer(contents):
        score = int(match.group(2))
        if score > 255:
            raise ValueError(f"Invalid n-gram score {score} in {path}")
        ngram_index = 0
        for char in match.group(1):
            ngram_index = ngram_index * 26 + ord(char) - ord("A")
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

    letters = "".join(char for char in text.upper() if "A" <= char <= "Z")
    if len(letters) < ngram_size:
        return float("inf")

    if isinstance(scores, (bytes, bytearray)):
        total_score = 0
        for index in range(len(letters) - ngram_size + 1):
            ngram_index = 0
            for char in letters[index:index + ngram_size]:
                ngram_index = ngram_index * 26 + ord(char) - ord("A")
            total_score += scores[ngram_index]
    else:
        total_score = sum(
            scores.get(letters[index:index + ngram_size], 0)
            for index in range(len(letters) - ngram_size + 1)
        )
    # The source files assign larger byte scores to more likely n-grams;
    # convert their mean to a cost so existing solvers can keep minimizing.
    return 255 - total_score / (len(letters) - ngram_size + 1)
