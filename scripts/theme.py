"""Single colour palette and layout helpers for the whole TUI.

Every module imports its colours from here, so the toolkit looks the same
everywhere and the palette can be changed in one place. Colours are from the
xterm 256-colour set and were picked to stay readable on both dark and light
terminal backgrounds (the previous dark grey 238 / dark red 88 were nearly
invisible on dark themes). Set the environment variable NO_COLOR to disable
colour output entirely (https://no-color.org).
"""
import os
import shutil

_ENABLED = "NO_COLOR" not in os.environ


def _code(sequence: str) -> str:
    return f"\033[{sequence}m" if _ENABLED else ""


RESET = _code("0")
BOLD = _code("1")
DIM = _code("2")
REVERSE = _code("7")

# Semantic palette (names kept compatible with the modules' existing usage).
RED = _code("38;5;203")      # errors, highlighted matches
GREEN = _code("38;5;78")     # success, results
YELLOW = _code("38;5;178")   # values, keys, options
BLUE = _code("38;5;75")      # section headings
CYAN = _code("38;5;80")      # secondary information
GREY = _code("38;5;245")     # hints, separators, prompts
WHITE = _code("39")          # terminal default foreground (works on light themes)
ACCENT = _code("38;5;209")   # titles and the selected menu item

MAX_WIDTH = 78


def width() -> int:
    """Usable line width: the terminal width capped for readability."""
    return max(40, min(shutil.get_terminal_size((80, 24)).columns - 1, MAX_WIDTH))


def rule(char: str = "─", color: str = GREY) -> None:
    print(f"{color}{char * width()}{RESET}")


def banner(title: str, subtitle: str = "") -> None:
    """Standard module title block."""
    line = "━" * width()
    print(f"{ACCENT}{line}{RESET}")
    print(f" {BOLD}{ACCENT}{title.upper()}{RESET}")
    if subtitle:
        print(f" {GREY}{subtitle}{RESET}")
    print(f"{ACCENT}{line}{RESET}")


def section(title: str) -> None:
    """Heading for a part of a module's output."""
    print(f"\n{BLUE}{BOLD}{title}{RESET}")
    rule()


def option(key, label: str, note: str = "") -> None:
    """One line of a numbered choice list."""
    extra = f" {GREY}{note}{RESET}" if note else ""
    print(f"  {YELLOW}[{key}]{RESET} {label}{extra}")
