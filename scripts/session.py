"""The session ciphertext: set once, offered to every tool.

Tools read their ciphertext with ``input()``. When a session ciphertext is
set, ``install_input_hook`` makes every prompt that asks for a ciphertext show
``[Enter = session ciphertext]``; pressing Enter returns the stored text, and
typing anything else uses what was typed. Prompts about files, keys or
plaintext are left alone.

``read_text`` reads a pasted ciphertext over several lines (a single
``input()`` takes only the first line of a paste, and the rest would spill
into the following prompts) or the contents of a .txt file.
"""
import builtins
import os
import re

from theme import GREY, RESET

_state = {"ciphertext": None}
_original_input = builtins.input
_ANSI = re.compile(r"\033\[[0-9;?]*[A-Za-z]")
_ASKS_FOR_CIPHERTEXT = re.compile(
    r"cipher\s*-?\s*text|encrypted (text|message)|text to (decrypt|crack|analy[sz]e|solve|format)"
    r"|^\s*enter (the )?text\s*:", re.IGNORECASE)
_NOT_THE_TEXT = re.compile(r"\b(file|path|save|key|keyword|plaintext|crib|length|width|period|number|characters)\b"
                           r"|y/n|\[y\]", re.IGNORECASE)


def get_ciphertext():
    return _state["ciphertext"]


def set_ciphertext(text):
    text = " ".join(text.split()) if text else None
    _state["ciphertext"] = text or None


def summary(limit=40) -> str:
    text = _state["ciphertext"]
    if not text:
        return ""
    letters = sum(ch.isalpha() for ch in text)
    preview = text if len(text) <= limit else text[:limit - 3] + "..."
    return f"{preview} ({letters} letters)"


def asks_for_ciphertext(prompt) -> bool:
    plain = _ANSI.sub("", str(prompt))
    return bool(_ASKS_FOR_CIPHERTEXT.search(plain)) and not _NOT_THE_TEXT.search(
        _ASKS_FOR_CIPHERTEXT.sub("", plain))


def _pending_input(wait=0.08) -> bool:
    """True when more typed or pasted input is already waiting on the console.
    Only meaningful for an interactive terminal."""
    import sys
    import time
    if not sys.stdin.isatty():
        return False
    if os.name == "nt":
        import msvcrt
        deadline = time.time() + wait
        while time.time() < deadline:
            if msvcrt.kbhit():
                return True
            time.sleep(0.01)
        return False
    import select
    return bool(select.select([sys.stdin], [], [], wait)[0])


def _read_paste(first_line: str) -> str:
    """A pasted ciphertext arrives as several lines at once: after the first
    line, keep reading while more pasted input is waiting, so the extra lines
    do not answer the tool's next prompts."""
    lines = [first_line]
    while _pending_input():
        try:
            lines.append(_original_input())
        except EOFError:
            break
    return " ".join(line.strip() for line in lines if line.strip())


def _input(prompt=""):
    if not asks_for_ciphertext(prompt):
        return _original_input(prompt)
    text = _state["ciphertext"]
    hint = f"{GREY}[Enter = session ciphertext]{RESET} " if text else ""
    answer = _read_paste(_original_input(f"{prompt}{hint}"))
    return answer if answer.strip() or not text else text


def install_input_hook():
    builtins.input = _input


def read_text(prompt="Paste the ciphertext (several lines are fine; finish with an empty line),\n"
                     "or enter the path of a .txt file:"):
    """Multi-line paste (ended by an empty line) or a file path. Returns '' if nothing."""
    print(f"{GREY}{prompt}{RESET}")
    lines = []
    while True:
        try:
            line = _original_input()
        except EOFError:
            break
        if not line.strip():
            if lines:
                break
            continue
        candidate = line.strip().strip('"\'')
        if not lines and os.path.isfile(candidate):
            with open(candidate, encoding="utf-8", errors="ignore") as handle:
                return handle.read()
        lines.append(line)
    return "\n".join(lines)
