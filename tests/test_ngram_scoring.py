import gzip
import pickle
import tempfile
import unittest
from pathlib import Path

from scripts.ngram_scoring import (
    DEFAULT_NGRAM_PATH,
    add_spaces,
    load_spacing_model,
    load_ngram_scores,
    resolve_ngram_path,
    score_text,
)


class NgramScoringTests(unittest.TestCase):
    def test_default_fivegram_model_loads(self):
        model = load_ngram_scores(DEFAULT_NGRAM_PATH)

        self.assertEqual(model.size, 5)
        self.assertIsInstance(model.scores, bytearray)
        self.assertEqual(len(model.scores), 26 ** 5)
        self.assertTrue(any(model.scores))
        index = ((((19 * 26 + 7) * 26 + 4) * 26 + 17) * 26) + 4
        self.assertEqual(score_text("THERE", model), 255 - model.scores[index])
        self.assertLess(len(pickle.dumps(model)), 1000)

    def test_larger_ngram_scores_produce_lower_cost(self):
        self.assertEqual(score_text("there", {"THERE": 220}), 35)
        self.assertEqual(score_text("there", {"THERE": 80}), 175)

    def test_compressed_ngrams_load(self):
        model = load_ngram_scores(resolve_ngram_path(3))

        self.assertEqual(model.size, 3)
        self.assertIsInstance(model.scores, bytes)
        self.assertEqual(len(model.scores), 26 ** 3)
        index = (19 * 26 + 7) * 26 + 4
        self.assertEqual(score_text("THE", model), 255 - model.scores[index])

    def test_unlisted_ngrams_receive_zero_source_score(self):
        self.assertEqual(score_text("zzzzz", {"AAAAA": 200}), 255)

    def test_spacing_uses_configured_space_ngram_scores(self):
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ "
        alphabet_indices = {char: index for index, char in enumerate(alphabet)}
        scores = bytearray(len(alphabet) ** 2)
        for bigram in ("C ", " D"):
            index = alphabet_indices[bigram[0]] * len(alphabet) + alphabet_indices[bigram[1]]
            scores[index] = 100

        with tempfile.TemporaryDirectory() as directory:
            model_path = Path(directory) / "2-grams_test+spaces.gz"
            with gzip.open(model_path, "wb") as model_file:
                model_file.write(scores)
            model_path.with_suffix(".ini").write_text(
                f"N-gram size=2\nAlphabet={alphabet}\n",
                encoding="ascii",
            )

            model = load_spacing_model(model_path)
            self.assertEqual(add_spaces("ABCDEF", model), "ABC DEF")


if __name__ == "__main__":
    unittest.main()
