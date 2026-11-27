import os
import re
import sys
import time
import random
import importlib
import traceback
from datetime import datetime

# Ensure console handles UTF-8 safely
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

# Add the 'scripts' directory to the Python path
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'scripts'))

from theme import (  # noqa: E402  (needs the scripts path above)
    ACCENT, BLUE, BOLD, CYAN, GREEN, GREY, RED, RESET, REVERSE, YELLOW,
    banner, option, section,
)
import session  # noqa: E402

session.install_input_hook()

VERSION = "2.1"

# --------------------------------------------------------------------------
# Menu definition: (number, title, module file, one-line description).
# The grid reads in attack order: START HERE (set the ciphertext, analyze,
# identify), then solve-by-family blocks numbered by tens, then encode/decode,
# utilities and setup. Tools are imported only when opened: start-up stays
# fast, a broken tool cannot stop the menu from loading, and worker processes
# (which re-import this file on Windows) stay light.
# --------------------------------------------------------------------------
CATEGORIES = [
    ("Start here · identify", [
        ("C", "Set ciphertext", "session", "Paste or load the ciphertext once; every tool then offers it"),
        (1, "Unknown Cipher Analyzer", "cipher_analyzer", "Ranks likely cipher types, quick solves, marks the tools to try"),
        (2, "Index of Coincidence", "ioc", "Mono or poly? English ~0.066, random letters ~0.038"),
        (3, "Frequency Analysis", "freq_analysis", "Letter, bigram and trigram counts vs English"),
        (4, "Kasiski Examination", "kasiski", "Distances between repeats point to a periodic key length"),
        (5, "Friedman Test", "friedman_test", "Estimate a periodic key length from the IoC"),
    ]),
    ("1x Monoalphabetic", [
        (11, "Caesar Cipher", "caesar", "Single shift: decrypt with a known shift or rank every shift"),
        (12, "Affine Cipher", "affine", "a*x + b mod m: rank every valid key by n-gram score"),
        (13, "Substitution Solver", "simulated_annealing", "Any simple substitution, no key needed: n-gram annealing"),
        (14, "Word Pattern Attack", "pattern_isomorphism", "Spaced text: word shapes give one consistent letter mapping"),
    ]),
    ("2x Periodic key", [
        (21, "Vigenere Auto-Solver", "vigenere_auto_solver", "Fast first try: key length and key by frequencies (+ Beaufort)"),
        (22, "Vigenere Workbench", "vigenere", "Known key, dictionary attack, or anneal the key"),
        (23, "Beaufort Cipher", "beaufort", "P = K - C: decrypt, dictionary attack, annealing"),
        (24, "Porta Cipher", "porta", "Reciprocal 13-alphabet cipher: decrypt, dictionary, annealing"),
        (25, "Gronsfeld Cipher", "Gronsfeld", "Vigenere with a digit key 0-9: exhaustive search or annealing"),
        (26, "Quagmire I-III", "keyword_periodic", "Periodic key on keyword alphabets: every dictionary word"),
    ]),
    ("3x Aperiodic / long key", [
        (31, "Autokey (Autoclave)", "autoclave", "Recover the primer of an autokey with no word list; decrypt"),
        (32, "Running Key", "running_key", "Book-text key: decrypt with the text, or crib-drag a word"),
        (33, "Crib Dragging", "crib_drag", "Slide a probable word; rank the key fragments it implies"),
        (34, "Gromark Solver", "gromark_solver", "Ciphertext only: screen every primer, climb the mixed alphabet"),
    ]),
    ("4x Transposition", [
        (41, "Rail Fence", "rail_fence", "Zig-zag: rank every rail count and offset; decrypt, encrypt"),
        (42, "Scytale", "Scytale", "Rod transposition: try every grid width"),
        (43, "Routes & Irregular", "transposition_screen", "Routes, spirals, double rotation, Myszkowski, AMSCO: ranked"),
        (44, "Column-Order Solver", "permutation_solver", "No key: brute force to width 9, annealing above; 4 layouts"),
        (45, "Keyed & Double Columnar", "columnar_transposition", "Keyword dictionary, double columnar, decrypt with a known key"),
    ]),
    ("5x Polygraphic & Bifid", [
        (51, "Playfair Cipher", "playfair", "5x5 digraphs: anneal the square (no key), or dictionary"),
        (52, "Four-Square Cipher", "four_square", "Two keyed squares: decrypt or anneal"),
        (53, "Bifid / Trifid Solver", "fractionation_solver", "Ciphertext only: anneal the square or cube, every period"),
        (54, "Hill Cipher", "hill", "2x2/3x3 matrix: ciphertext-only, known plaintext, decrypt"),
    ]),
    ("6x Two layers & cribs", [
        (61, "Two-Layer Solver", "two_layer", "Two stacked layers (sub / trans / Vigenere) solved jointly"),
        (62, "Crib Columnar Search", "crib_columnar_search", "Known letters at known spots: every column order + periodic key"),
    ]),
    ("7x Encode / decode", [
        (71, "Gromark (known key)", "Gromark_transposition", "Decrypt with a known keyword and primer; known-answer test"),
        (72, "Bifid (known key)", "bifid", "Encrypt or decrypt full-length Bifid with a keyed square"),
        (73, "Polybius Square", "polybius", "Letters to grid coordinates and back"),
        (74, "Modular Add / Subtract", "modular_add_sub", "Add or subtract a key mod n; word-list keys ranked by n-grams"),
        (75, "XOR Cipher", "xor", "XOR text with a key; try keys from a word list"),
    ]),
    ("8x Utilities", [
        (81, "Text Formatter", "text_formatter", "Clean, reshape or reverse ciphertext"),
        (82, "Keyword Alphabet", "keyword_alphabet", "Build mixed alphabets from a keyword"),
        (83, "Matrix Generator", "Matrix Generator", "Write a string into every n x m grid"),
    ]),
    ("9x Setup", [
        (91, "C Engines & GPU", "native_tools", "Build the C engines (needed by the solvers); enable OpenCL GPUs"),
        (92, "Compute Settings", "compute", "Worker processes and priority for searches (also key P)"),
    ]),
    # Hotkeys only (footer); must stay the LAST category.
    ("System", [
        ("H", "Help", "help", "Workflow, keys, tools by family, old-to-new number table"),
        ("A", "About", "about", "Version, credits and data sources"),
        ("Q", "Exit", "exit", "Leave the toolkit"),
    ]),
]

# Short family names for the footer breadcrumb (same order as CATEGORIES).
FAMILY = ["Start", "Mono", "Periodic", "Aperiodic", "Transposition", "Polygraphic", "Layers", "Encode",
          "Utilities", "Setup", "System"]

# Numbers before the v2.1 menu (shown as "(was NN)" and used to read old references).
OLD_TO_NEW = {39: 1, 40: 2, 41: 3, 35: 4, 36: 5, 8: 11, 10: 12, 31: 13, 33: 14, 30: 21, 1: 22, 13: 23, 14: 24,
              3: 25, 17: 26, 4: 31, 16: 32, 34: 33, 19: 34, 22: 41, 21: 42, 24: 43, 23: 44, 32: 44, 20: 45,
              9: 51, 15: 52, 18: 53, 5: 54, 37: 61, 38: 62, 2: 71, 12: 72, 11: 73, 7: 74, 6: 75, 43: 81,
              44: 82, 42: 83, 45: 91, 46: 92}
NEW_TO_OLD = {}
for _old, _new in OLD_TO_NEW.items():
    NEW_TO_OLD.setdefault(_new, []).append(_old)

ITEMS = [item for _, items in CATEGORIES for item in items]
# The tool grid; the System entries are hotkeys (H, A, Q) shown in the footer.
GRID_CATEGORIES = CATEGORIES[:-1]
NAV_ITEMS = [item for _, items in GRID_CATEGORIES for item in items]
FAMILY_OF = {id(item): FAMILY[index] for index, (_, items) in enumerate(CATEGORIES) for item in items}
FAMILY_STARTS = [NAV_ITEMS.index(items[0]) for _, items in GRID_CATEGORIES]
_loaded_modules = {}


def resolve_tool(reference, legacy_numbers=False):
    """A menu item from a module name or a menu number, else None. Old and new
    numbers overlap (old 1 was Vigenere, new 1 is the analyzer), so a caller
    holding pre-v2.1 numbers must pass legacy_numbers=True."""
    for item in NAV_ITEMS:
        if item[2] == reference:
            return item
    if isinstance(reference, str) and reference.strip().isdigit():
        reference = int(reference)
    if isinstance(reference, int):
        if legacy_numbers:
            reference = OLD_TO_NEW.get(reference)
        return next((item for item in NAV_ITEMS if item[0] == reference), None)
    if isinstance(reference, str):
        return next((item for item in NAV_ITEMS if str(item[0]).upper() == reference.strip().upper()), None)
    return None


def load_module(file_name):
    """Import a tool on first use; returns (module, error message)."""
    if file_name in _loaded_modules:
        return _loaded_modules[file_name], None
    try:
        module = importlib.import_module(file_name)
    except Exception as error:  # report it instead of crashing the menu
        return None, f"{type(error).__name__}: {error}"
    _loaded_modules[file_name] = module
    return module, None


# --------------------------------------------------------------------------
# Terminal helpers
# --------------------------------------------------------------------------

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


def terminal_size():
    try:
        size = os.get_terminal_size()
        return size.columns, size.lines
    except OSError:
        return 80, 24


def hide_cursor():
    sys.stdout.write('\033[?25l')
    sys.stdout.flush()


def show_cursor():
    sys.stdout.write('\033[?25h')
    sys.stdout.flush()


def get_key():
    """Reads a single keypress or arrow key (Windows & POSIX compatible)."""
    if os.name == 'nt':
        import msvcrt
        ch = msvcrt.getch()
        if ch in (b'\x00', b'\xe0'):
            mapping = {b'H': 'UP', b'P': 'DOWN', b'K': 'LEFT', b'M': 'RIGHT',
                       b'I': 'PAGE_UP', b'Q': 'PAGE_DOWN', b'G': 'HOME', b'O': 'END'}
            return mapping.get(msvcrt.getch(), None)
        if ch in (b'\r', b'\n'):
            return 'ENTER'
        if ch == b'\x1b':
            return 'ESC'
        if ch == b'\x08':
            return 'BACKSPACE'
        if ch == b'\x03':
            raise KeyboardInterrupt
        return ch.decode('utf-8', errors='ignore') or None
    import select, termios, tty
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        ch = sys.stdin.read(1)
        if ch == '\x1b':
            ready, _, _ = select.select([sys.stdin], [], [], 0.05)
            if ready and sys.stdin.read(1) == '[':
                ch3 = sys.stdin.read(1)
                mapping = {'A': 'UP', 'B': 'DOWN', 'C': 'RIGHT', 'D': 'LEFT',
                           'H': 'HOME', 'F': 'END', '5': 'PAGE_UP', '6': 'PAGE_DOWN'}
                if ch3 in ('5', '6'):
                    sys.stdin.read(1)  # trailing '~'
                return mapping.get(ch3, None)
            return 'ESC'
        if ch in ('\r', '\n'):
            return 'ENTER'
        if ch in ('\x7f', '\x08'):
            return 'BACKSPACE'
        if ch == '\x03':
            raise KeyboardInterrupt
        return ch
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)


def retro_effect(duration=0.5):
    columns, _ = terminal_size()
    chars = "█▓▒░ ░▒▓█"
    end_time = time.time() + duration
    while time.time() < end_time:
        print(f"{ACCENT}{''.join(random.choice(chars) for _ in range(columns - 1))}{RESET}", end="\r")
        time.sleep(0.05)
    print(" " * (columns - 1), end="\r")


LOGO = [
    " a88888b.           a88888b.          d888888P ",
    "d8'   `88          d8'   `88             88    ",
    "88                 88                    88    ",
    "88                 88                    88    ",
    "Y8.   .88    dP    Y8.   .88    dP       88    ",
    " Y88888P'    88     Y88888P'    88       dP    ",
]


# --------------------------------------------------------------------------
# Menu rendering
# --------------------------------------------------------------------------

_ANSI = re.compile(r"\033\[[0-9;?]*[A-Za-z]")


def pad(text, length):
    """Pad to a visible width, ignoring colour codes."""
    return text + " " * max(0, length - len(_ANSI.sub("", text)))


def build_columns(column_count):
    """Menu entries as ("header" | "item" | "blank", payload), per column.
    Blocks: 0 Start, 1-6 solve by family, 7 encode, 8 utilities, 9 setup."""
    blocks = [[("header", index)] + [("item", item) for item in items]
              for index, (_, items) in enumerate(GRID_CATEGORIES)]

    def stack(*indices):
        column = []
        for index in indices:
            column += blocks[index] + [("blank", None)]
        return column[:-1]

    if column_count >= 3:
        return [stack(0, 1, 2), stack(3, 4, 5), stack(6, 7, 8, 9)]
    if column_count == 2:
        return [stack(0, 1, 2, 3), stack(4, 5, 6, 7, 8, 9)]
    return [stack(*range(len(blocks)))]


def layout(columns_count):
    # Three columns need 31+ characters each: the longest title is 23 characters.
    count = 3 if columns_count >= 98 else 2 if columns_count >= 88 else 1
    cell = (columns_count - 2 * (count - 1) - 1) // count if count > 1 else max(30, min(columns_count - 2, 60))
    return build_columns(count), min(cell, 46)


def item_position(columns, item):
    for c, column in enumerate(columns):
        for r, entry in enumerate(column):
            if entry[0] == "item" and entry[1] is item:
                return c, r
    return 0, 0


def neighbour(columns, item, step):
    """The item in the next column (left or right) nearest to the same row."""
    c, r = item_position(columns, item)
    target = c + step
    if not 0 <= target < len(columns):
        return item
    rows = [(abs(row - r), entry[1]) for row, entry in enumerate(columns[target]) if entry[0] == "item"]
    return min(rows, key=lambda pair: pair[0])[1] if rows else item


def suggested_items():
    """The analyzer's suggestions for the session ciphertext as menu items, best first."""
    found = []
    for reference, note in session.get_suggestions():
        item = resolve_tool(reference, legacy_numbers=isinstance(reference, int))
        if item and all(item is not other for other, _ in found):
            found.append((item, note))
    return found


def needs_c(item):
    return item[2] not in NO_C_NEEDED


def render_menu(selected_index, number_buffer, scroll):
    columns_count, rows = terminal_size()
    columns, cell = layout(columns_count)
    rule_width = min(columns_count - 1, cell * len(columns) + 2 * (len(columns) - 1))
    selected_item = NAV_ITEMS[selected_index]
    suggestions = suggested_items()
    suggested = {id(item): note for item, note in suggestions}
    engines_ready = native_engines_built()
    has_text = bool(session.get_ciphertext())

    def render(entry):
        kind, payload = entry
        if kind == "header":
            colour = ACCENT if payload == 0 else BLUE
            name = GRID_CATEGORIES[payload][0]
            tag, _, rest = name.partition(" ")
            label = f"{tag} {rest.upper()}" if tag[:-1].isdigit() and tag.endswith("x") else name.upper()
            return pad(f" {colour}{BOLD}{label}{RESET}", cell)
        if kind == "item":
            label = f"{str(payload[0]):>2}"
            title = payload[1]
            if payload[2] == "session" and has_text:
                title = "Change ciphertext"
            title = title[:cell - 8]
            if payload is selected_item:
                return pad(f"{REVERSE}{BOLD} ▶ {label}  {title} ", cell) + RESET
            dot = f"{CYAN}•{RESET}" if id(payload) in suggested else " "
            dim = GREY if not engines_ready and needs_c(payload) else ""
            return pad(f"  {dot}{YELLOW}{label}{RESET}  {dim}{title}{RESET}", cell)
        return " " * cell

    # ---- header: title + engine status, then one line saying what to do next
    out = []
    body_rows = max(len(column) for column in columns)
    status = (f"{GREY}C engines ready{RESET}" if engines_ready else f"{YELLOW}C engines not built: open 91{RESET}")
    if rows >= body_rows + len(LOGO) + 8:
        out += [f"  {ACCENT}{line}{RESET}" for line in LOGO]
    title = f"  {ACCENT}{BOLD}CIPHER CRACKER TOOLKIT{RESET}  {GREY}v{VERSION}{RESET}"
    gap = max(2, rule_width - len(_ANSI.sub("", title)) - len(_ANSI.sub("", status)))
    out.append(title + " " * gap + status)
    if not has_text:
        guide = ("▶ Start: press C to paste your ciphertext, then 1 = Unknown Cipher Analyzer" if columns_count >= 92
                 else "▶ Start: C = ciphertext, then 1 = Analyzer")
        out.append(f"  {YELLOW}{guide}{RESET}")
    else:
        if suggestions:
            numbers = " ".join(f"•{item[0]}" for item, _ in suggestions)
            tail = f"Suggested: {numbers}  (N = next)"
        else:
            tail = "▶ Next: 1 Analyzer"
        letters = sum(ch.isalpha() for ch in session.get_ciphertext())
        # summary(room) is the preview (room characters) plus " (N letters)"
        room = columns_count - 1 - len("  Ciphertext: ") - 2 - len(tail) - len(f" ({letters} letters)")
        if room >= 8:
            out.append(f"  {GREY}Ciphertext:{RESET} {CYAN}{session.summary(room)}{RESET}  {YELLOW}{tail}{RESET}")
        else:
            out.append(f"  {YELLOW}{tail[:columns_count - 3]}{RESET}")
    out.append(f"{GREY}{'─' * rule_width}{RESET}")

    # ---- body
    available = rows - len(out) - 4
    if body_rows <= available:
        for row in range(body_rows):
            out.append("  ".join(render(column[row]) if row < len(column) else " " * cell for column in columns))
    else:  # too short: one scrolling column around the selection
        column = [entry for col in columns for entry in col]
        position = next(i for i, entry in enumerate(column) if entry[0] == "item" and entry[1] is selected_item)
        window = max(5, available - 2)
        scroll = min(max(scroll, position - window + 1), position)
        if scroll > 0:
            first = next((e[1] for e in column[scroll:] if e[0] == "item"), selected_item)
            out.append(f"   {GREY}↑ {scroll} more · {FAMILY_OF[id(first)]}{RESET}")
        out += [render(entry) for entry in column[scroll:scroll + window]]
        if len(column) > scroll + window:
            out.append(f"   {GREY}↓ {len(column) - scroll - window} more{RESET}")

    # ---- footer: family › title · description, then the keys
    out.append(f"{GREY}{'─' * rule_width}{RESET}")
    limit = columns_count - 2
    description = selected_item[3]
    if id(selected_item) in suggested:
        description = f"Analyzer: {suggested[id(selected_item)]}"
    if not engines_ready and needs_c(selected_item):
        description += " · needs C engines (91)"
    old = NEW_TO_OLD.get(selected_item[0])
    was = f" (was {'/'.join(map(str, old))})" if old else ""
    crumb = f" {GREY}{FAMILY_OF[id(selected_item)]} ›{RESET} {CYAN}{selected_item[1]}{RESET} {GREY}·{RESET} "
    room = max(0, limit - len(_ANSI.sub("", crumb)))
    text = description if len(description) + len(was) > room else description + was
    out.append(crumb + text[:room] + (f"{GREY}{was}{RESET}" if False else ""))
    nav = "↑↓←→ move" if len(columns) > 1 and body_rows <= available else "↑↓ move"
    next_key = " · N next suggested" if suggestions else ""
    if columns_count >= 110:
        hint = f"{nav} · PgUp/PgDn family · type a number · Enter open · C text{next_key} · P compute · H help · Q quit"
    elif columns_count >= 92:
        hint = f"{nav} · PgDn family · number = jump · Enter · C text{' · N next' if suggestions else ''} · H help · Q quit"
    else:
        hint = "↑↓ move · PgDn family · number = jump · Enter · C text · H help · Q quit"
    jump = f"Go to: {number_buffer}_" if number_buffer else ""
    if jump and len(hint) + len(jump) + 3 > limit:
        hint = ""
    out.append(f" {GREY}{hint[:limit]}{RESET}{'   ' if hint and jump else ''}{YELLOW}{jump}{RESET}")

    sys.stdout.write("\033[H" + "\n".join(line + "\033[K" for line in out) + "\033[J")
    sys.stdout.flush()
    return scroll


def initial_selection():
    """Cursor on C with no ciphertext, on the top suggestion after an analysis, else on 1."""
    suggestions = suggested_items()
    if suggestions:
        return NAV_ITEMS.index(suggestions[0][0])
    if not session.get_ciphertext():
        return NAV_ITEMS.index(find_item("session"))
    return NAV_ITEMS.index(find_item("cipher_analyzer"))


def select_menu_option(selected=None):
    """Interactive menu; returns (item, index of the selection in NAV_ITEMS)."""
    number_buffer, scroll = "", 0
    selected = initial_selection() if selected is None else min(selected, len(NAV_ITEMS) - 1)
    clear_screen()
    hide_cursor()
    try:
        while True:
            scroll = render_menu(selected, number_buffer, scroll)
            key = get_key()
            if not key:
                continue
            if len(key) == 1 and key.isdigit():
                # Multi-digit jump: "4" then "4" selects tool 44; 1-5 open the Start block.
                for candidate in (number_buffer + key, key):
                    matches = [i for i, item in enumerate(NAV_ITEMS) if str(item[0]).startswith(candidate)]
                    if matches:
                        number_buffer = candidate
                        exact = [i for i in matches if str(NAV_ITEMS[i][0]) == candidate]
                        selected = (exact or matches)[0]
                        break
                continue
            if key == 'BACKSPACE':
                number_buffer = number_buffer[:-1]
                continue
            number_buffer = ""
            columns, _ = layout(terminal_size()[0])
            order = [entry[1] for column in columns for entry in column if entry[0] == "item"]
            position = order.index(NAV_ITEMS[selected])
            if key in ('UP', 'w', 'W'):
                selected = NAV_ITEMS.index(order[(position - 1) % len(order)])
            elif key in ('DOWN', 's', 'S'):
                selected = NAV_ITEMS.index(order[(position + 1) % len(order)])
            elif key in ('LEFT', 'RIGHT'):
                selected = NAV_ITEMS.index(neighbour(columns, NAV_ITEMS[selected], -1 if key == 'LEFT' else 1))
            elif key in ('PAGE_UP', 'PAGE_DOWN'):
                block = max(i for i, start in enumerate(FAMILY_STARTS) if start <= selected)
                block = (block + (1 if key == 'PAGE_DOWN' else -1)) % len(FAMILY_STARTS)
                selected = FAMILY_STARTS[block]
            elif key == 'HOME':
                selected = 0
            elif key == 'END':
                selected = len(NAV_ITEMS) - 1
            elif key in ('n', 'N'):
                suggestions = [NAV_ITEMS.index(item) for item, _ in suggested_items()]
                if suggestions:
                    later = [i for i in suggestions if suggestions.index(i) > suggestions.index(selected)] \
                        if selected in suggestions else []
                    selected = (later or suggestions)[0]
            elif key == 'ENTER':
                return NAV_ITEMS[selected], selected
            elif key in ('ESC', 'q', 'Q', 'e', 'E'):
                return find_item('exit'), selected
            elif key in ('h', 'H', '?'):
                return find_item('help'), selected
            elif key in ('a', 'A'):
                return find_item('about'), selected
            elif key in ('c', 'C'):
                return find_item('session'), selected
            elif key in ('p', 'P'):
                return find_item('compute'), selected
    finally:
        show_cursor()


def find_item(action):
    return next(item for item in ITEMS if item[2] == action)


def select_menu_option_plain():
    """Fallback when stdin is not a terminal (piped input, IDLE)."""
    print(f"\n{ACCENT}{BOLD}CIPHER CRACKER TOOLKIT{RESET} {GREY}v{VERSION}{RESET}")
    for name, items in CATEGORIES:
        section(name)
        for key, title, _, description in items:
            option(key, title, description)
    choice = input(f"\n{GREEN}Enter your choice: {RESET}").strip().upper()
    return next((item for item in ITEMS if str(item[0]).upper() == choice), None)


# --------------------------------------------------------------------------
# Screens
# --------------------------------------------------------------------------

def pause(message="Press Enter to return to the menu..."):
    try:
        input(f"\n{GREY}{message}{RESET}")
    except (KeyboardInterrupt, EOFError):
        pass


def show_help():
    clear_screen()
    banner("Help", "How to use the Cipher Cracker Toolkit")
    Y, R = YELLOW, RESET
    print(f"""
{BOLD}The workflow for an unknown ciphertext{RESET}
  {Y}C{R}   Set the ciphertext once (paste several lines, or a .txt path). Every tool's
      ciphertext prompt then accepts Enter to use it.
  {Y}1{R}   Unknown Cipher Analyzer: measures the text against English and random text
      of the same length, ranks the cipher families, runs the instant attacks and
      can hill-climb a pathway. Its suggested tools get a {CYAN}•{R} in this menu;
      {Y}N{R} jumps from one suggestion to the next.
  {Y}2-5{R} The identification statistics by hand (IoC, frequencies, Kasiski, Friedman).
  Then open the family block that fits, and check a recovered key in {Y}7x{R}.

{BOLD}Which block?{RESET}  (what the analyzer's statistics say)
  English-like IoC, letters disguised, adjacent pairs English   -> {Y}1x{R} monoalphabetic
  English-like IoC, English letters, order scrambled             -> {Y}4x{R} transposition
  English-like IoC, letters disguised, order scrambled           -> {Y}61{R} two layers
  Flattened IoC with a clear key length                          -> {Y}2x{R} periodic key
  Flattened IoC, no key length                                   -> {Y}3x{R} aperiodic, {Y}61{R}
  25 letters, even length, no doubled pair at 1-2, 3-4, ...      -> {Y}5x{R} Playfair/Bifid
  Known letters at known positions                               -> {Y}62{R} crib search

{BOLD}Keys{RESET}
  Arrows (or W/S) move; Left/Right switch column; PgUp/PgDn jump between family
  blocks; typing a number jumps to it (e.g. {Y}44{R}); Enter opens. {Y}C{R} ciphertext,
  {Y}P{R} compute settings, {Y}N{R} next suggested tool, {Y}H{R} help, {Y}A{R} about, {Y}Q{R} quit.
  Inside a tool, {Y}Ctrl+C{R} stops the current step and returns to this menu.

{BOLD}Speed{RESET}
  Every annealing, dictionary and large brute-force search runs in the C engines
  (small keyspaces such as Caesar loop around C scoring). Build them once with
  {Y}91{R} (python -m pip install ziglang first). {Y}92{R} / {Y}P{R} sets how many worker processes
  searches may use and their priority, so the computer stays usable.

{BOLD}Scoring{RESET}
  Solvers rank candidate plaintexts with English n-gram statistics (5-grams by
  default, AZdecrypt data in N-grams/). "Fitness" is higher-is-better; "N-gram
  cost/score" is lower-is-better. Several independent runs that agree on the
  same plaintext are strong evidence of a real solution.""")
    for name, items in GRID_CATEGORIES:
        section(name)
        for key, title, _, description in items:
            print(f"  {YELLOW}{str(key):>2}{RESET}  {title:<24} {GREY}{description}{RESET}")
    section("Numbers before v2.1 -> now")
    pairs = sorted(OLD_TO_NEW.items())
    for start in range(0, len(pairs), 8):
        print("  " + "   ".join(f"{GREY}{old:>2}{RESET}->{YELLOW}{new:<2}{RESET}" for old, new in pairs[start:start + 8]))
    print(f"  {GREY}(old 23 and 32 are now one tool, 44){RESET}")
    pause()


def show_about():
    clear_screen()
    banner("About", f"Cipher Cracker Toolkit v{VERSION}")
    print(f"""
  A command-line toolkit for classical cryptanalysis: decrypt and break
  substitution, transposition and polyalphabetic ciphers, including
  two-layer combinations.

  {BOLD}Project{RESET}      github.com/hippie-cycling
  {BOLD}License{RESET}      MIT
  {BOLD}N-gram data{RESET}  AZdecrypt n-gram files (N-grams/), built from the Leipzig
               Wortschatz corpora (wortschatz.uni-leipzig.de), CC BY-NC 4.0
  {BOLD}Python{RESET}       {sys.version.split()[0]} · standard library only""")
    pause()


def edit_session():
    clear_screen()
    banner("Session ciphertext", "Set once; every tool's ciphertext prompt then accepts Enter to use it")
    current = session.get_ciphertext()
    if current:
        print(f"\n{GREY}Current session ciphertext:{RESET}\n{CYAN}{current}{RESET}\n")
        option(1, "Replace it")
        option(2, "Clear it")
        option(0, "Keep it and go back")
        choice = input("Select: ").strip()
        if choice == '2':
            session.set_ciphertext(None)
            return
        if choice != '1':
            return
    text = session.read_text()
    if text.strip():
        session.set_ciphertext(text)
        print(f"{GREEN}Session ciphertext set: {session.summary(60)}{RESET}")
        print(f"{GREY}Next: 1 Unknown Cipher Analyzer ranks the attack pathways for it.{RESET}")
        pause()


# Every solver runs its searches in the C engines (there is no Python fallback).
# These tools never use them, so they open without the build.
NO_C_NEEDED = {"polybius", "bifid", "kasiski", "friedman_test", "ioc", "freq_analysis", "Matrix Generator",
               "text_formatter", "keyword_alphabet", "native_tools", "compute", "help", "about", "session", "exit"}


def native_engines_built() -> bool:
    try:
        import native
        return native.available()
    except Exception:
        return False


def build_native_engines() -> bool:
    """Build the C engines in place (zig's C compiler from pip). Returns success."""
    try:
        import ziglang  # noqa: F401
    except ImportError:
        print(f"{RED}The compiler is missing. Run  {YELLOW}python -m pip install ziglang{RED}  and try again "
              f"(no Visual Studio or gcc needed).{RESET}")
        return False
    import native_tools
    return bool(native_tools.build())


def ensure_native(file_name) -> bool:
    """Tools that search need the C engines: offer to build them; False = do not open the tool."""
    if file_name in NO_C_NEEDED or native_engines_built():
        return True
    print(f"{YELLOW}This tool runs its searches in the C engines, which are not built yet.{RESET}\n"
          f"{GREY}They are built once per machine (a few seconds) with zig's C compiler from pip.{RESET}")
    if input(f"{YELLOW}B{RESET} = build them now, Enter = back to the menu: ").strip().lower() != "b":
        return False
    built = build_native_engines()
    if not built:
        pause("Press Enter to return to the menu...")
    return built


def run_module(item):
    _, title, file_name, _ = item
    clear_screen()
    if not ensure_native(file_name):
        return
    module, error = load_module(file_name)
    if module is None:
        banner("Tool unavailable", title)
        print(f"\n{RED}scripts/{file_name}.py could not be loaded:{RESET}\n  {error}")
        pause()
        return
    try:
        module.run()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Interrupted.{RESET}")
    except Exception as error:
        if type(error).__name__ == "NativeUnavailable":
            print(f"\n{RED}{error}{RESET}")
            pause()
            return
        print(f"\n{RED}The tool stopped with an error:{RESET}")
        traceback.print_exc()
    pause()


def startup_build_check(interactive):
    """The solvers need the C engines: on a machine without them, offer the build once at start."""
    if native_engines_built() or not interactive:
        return
    clear_screen()
    banner("C engines needed", "The toolkit's solvers run in C; build them once on this machine")
    print(f"\n  Every annealing, dictionary and large brute-force search runs in the\n"
          f"  toolkit's C library. It is built once per machine with zig's C compiler, a pip package:\n\n"
          f"    {YELLOW}python -m pip install ziglang{RESET}\n    {YELLOW}python scripts/native_tools.py build{RESET}"
          f"   {GREY}(or menu 91){RESET}\n")
    if input(f"{YELLOW}B{RESET} = build now, Enter = continue to the menu (utilities only): ").strip().lower() == "b":
        build_native_engines()
        pause("Press Enter to open the menu...")


def main():
    if 'idlelib' not in sys.modules and sys.stdout.isatty():
        retro_effect()
    interactive = sys.stdin.isatty()
    startup_build_check(interactive)
    import compute
    compute.startup_prompt(interactive)
    selected = None          # None = let the menu place the cursor (C, 1 or the top suggestion)
    while True:
        try:
            if interactive:
                item, selected = select_menu_option(selected)
            else:
                item = select_menu_option_plain()
                if item is None:
                    print(f"{RED}Invalid choice.{RESET}")
                    continue
            action = item[2]
            if action == 'exit':
                clear_screen()
                print(f"{GREEN}Goodbye!{RESET}")
                break
            if action == 'help':
                show_help()
            elif action == 'about':
                show_about()
            elif action == 'session':
                edit_session()
                if session.get_ciphertext():
                    selected = NAV_ITEMS.index(find_item('cipher_analyzer'))   # next step: analyze it
            else:
                run_module(item)
                if action == 'cipher_analyzer':
                    selected = None      # land on the analyzer's top suggestion
        except KeyboardInterrupt:
            clear_screen()
            print(f"{GREEN}Goodbye!{RESET}")
            break
        except EOFError:
            break


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
