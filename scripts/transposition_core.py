"""Shared transposition primitives: fast, verified decryptors for the four
write/read layouts used by the transposition solvers."""
import math
from collections import Counter


def make_decryptor(ciphertext, width: int, mode: str):
    """Return ``decrypt(key) -> bytearray`` for a fixed ciphertext, width and mode.

    Produces exactly ``[ciphertext[i] for i in get_decryption_indices(...)]``
    but with one C-level slice copy per column instead of a Python-level
    index table rebuilt on every call. ``ciphertext`` may be str or bytes.
    """
    source = ciphertext.encode("latin-1") if isinstance(ciphertext, str) else bytes(ciphertext)
    permute = make_permuter(len(source), width, mode)
    return lambda key: permute(source, key)


def make_permuter(length: int, width: int, mode: str):
    """Like make_decryptor, but the text is passed on each call:
    ``permute(source, key) -> bytearray`` for any bytes ``source`` of ``length``.
    Used when the transposition is one layer of a multi-layer cipher.
    """
    height = (length + width - 1) // width
    remainder = length % width or width
    full_rows = height if remainder == width else height - 1
    full_end = full_rows * width
    partial_base = (height - 1) * width
    column_lengths = [height if column < remainder else height - 1 for column in range(width)]

    if mode in ("write_rows_read_cols", "write_cols_read_cols"):
        row_major = mode == "write_rows_read_cols"

        def decrypt(source, key):
            output = bytearray(length)
            column_starts = [0] * width
            start = 0
            for column in key:
                column_starts[column] = start
                start += column_lengths[column]
            offset = 0
            for column in range(width):
                start = column_starts[column]
                end = start + column_lengths[column]
                if row_major:
                    output[column::width] = source[start:end]
                else:
                    output[offset:offset + end - start] = source[start:end]
                    offset += end - start
            return output
        return decrypt

    if mode in ("write_rows_read_rows", "write_cols_read_rows"):
        row_major = mode == "write_rows_read_rows"

        def decrypt(source, key):
            output = bytearray(length)
            full_position = [0] * width
            for position, column in enumerate(key):
                full_position[column] = position
            partial_position = [0] * width
            if remainder != width:
                for position, column in enumerate([column for column in key if column < remainder]):
                    partial_position[column] = position
            offset = 0
            for column in range(width):
                column_values = source[full_position[column]:full_end:width]
                if row_major:
                    output[column:full_end:width] = column_values
                    if remainder != width and column < remainder:
                        output[partial_base + column] = source[partial_base + partial_position[column]]
                else:
                    output[offset:offset + full_rows] = column_values
                    offset += full_rows
                    if remainder != width and column < remainder:
                        output[offset] = source[partial_base + partial_position[column]]
                        offset += 1
            return output
        return decrypt

    raise ValueError(f"Unknown transposition mode: {mode}")


def letter_entropy(letters) -> float:
    total = len(letters)
    return sum(abs(math.log2(count / total) * (count / total)) for count in Counter(letters).values())
