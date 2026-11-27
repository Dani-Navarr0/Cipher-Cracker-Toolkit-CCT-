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

VERSION = "2.0"

# --------------------------------------------------------------------------
# Menu definition: (hotkey, title, module file, one-line description).
# Tools are imported only when opened: start-up stays fast, a broken tool
# cannot stop the menu from loading, and worker processes (which re-import
# this file on Windows) stay light.
# --------------------------------------------------------------------------
CATEGORIES = [
    ("Substitution ciphers", [
        (1, "Vigenere Cipher", "vigenere", "Decrypt, dictionary attack, or anneal a Vigenere key"),
        (2, "Gromark Cipher", "Gromark_transposition", "Keyed alphabet + numeric primer: decrypt and search"),
        (3, "Gronsfeld Cipher", "Gronsfeld", "Vigenere with a numeric key: exhaustive search or annealing"),
        (4, "Autoclave Cipher", "autoclave", "Autokey: recover the primer with no word list, decrypt, encrypt"),
        (5, "Hill Cipher", "hill", "Ciphertext-only 2x2/3x3 attack, known plaintext, decrypt, encrypt"),
        (6, "XOR", "xor", "XOR text with a key; try keys from a word list"),
        (7, "Modular ADD-SUB", "modular_add_sub", "Add or subtract a key modulo the alphabet"),
        (8, "Caesar Cipher", "caesar", "Single shift: decrypt or rank every shift"),
        (9, "Playfair Cipher", "playfair", "Digraph cipher: square annealing (no key needed), dictionary attack"),
        (10, "Affine Cipher", "affine", "a*x + b mod m: decrypt or try every valid key"),
        (11, "Polybius Square", "polybius", "Letters to grid coordinates and back"),
        (12, "Bifid Cipher", "bifid", "Polybius fractionation cipher (full length, no period)"),
        (13, "Beaufort Cipher", "beaufort", "P = K - C: decrypt, dictionary attack, annealing"),
        (14, "Porta Cipher", "porta", "Reciprocal 13-alphabet cipher: decrypt, dictionary, annealing"),
        (15, "Four-Square Cipher", "four_square", "Two keyed squares: decrypt or anneal"),
        (16, "Running Key Cipher", "running_key", "Book-text key: decrypt or crib-drag"),
        (17, "Quagmire (Keyword Alphabets)", "keyword_periodic", "Periodic key on keyword alphabets: every dictionary word, I-III"),
        (18, "Bifid / Trifid Solver", "fractionation_solver", "Ciphertext only: anneal the square or cube, every period"),
        (19, "Gromark Solver", "gromark_solver", "Ciphertext only: screen every primer, climb the mixed alphabet"),
    ]),
    ("Transposition ciphers", [
        (20, "Columnar Transposition", "columnar_transposition", "Dictionary, exhaustive and annealing attacks (single/double)"),
        (21, "Scytale Cipher", "Scytale", "Rod transposition: try every side count"),
        (22, "Rail Fence Cipher", "rail_fence", "Zig-zag: rank every rail count and offset, decrypt, encrypt"),
        (23, "Matrix Permutation Solver", "permutation_solver", "Keyless column order: brute force or annealing, 4 layouts"),
        (24, "Routes & Irregular", "transposition_screen", "Routes, spirals, double rotation, Myszkowski, AMSCO: ranked"),
    ]),
    ("Cryptanalysis", [
        (30, "Vigenere Auto-Solver", "vigenere_auto_solver", "Key length (tested) and key by frequencies; Vigenere and Beaufort"),
        (31, "Annealing: Substitution", "simulated_annealing", "Breaks simple (monoalphabetic) substitution with n-grams"),
        (32, "Annealing: Transposition", "simulated_annealing_transposition", "Finds the column order of a columnar transposition"),
        (33, "Word Pattern Isomorphism", "pattern_isomorphism", "Word shapes + one consistent mapping for a spaced substitution"),
        (34, "Crib Dragging", "crib_drag", "Slide a probable word; rank the key fragments it implies"),
        (35, "Kasiski Examination", "kasiski", "Repeated sequences point to likely key lengths"),
        (36, "Friedman Test", "friedman_test", "Estimate a polyalphabetic key length from the IoC"),
        (37, "Two-Layer Solver", "two_layer", "Two stacked layers (sub / trans / Vigenere) solved jointly"),
        (38, "Known-Plaintext Columnar", "crib_columnar_search", "Every column order + periodic key fitting known letters (C/GPU)"),
        (39, "Unknown Cipher Analyzer", "cipher_analyzer", "No clues? Statistics, ranked attack pathways, quick solves, hill-climb"),
    ]),
    ("Utilities", [
        (40, "Index of Coincidence", "ioc", "Monoalphabetic or polyalphabetic? English ~0.066"),
        (41, "Frequency Analysis", "freq_analysis", "Letter, bigram and trigram counts vs English"),
        (42, "Matrix Generator", "Matrix Generator", "Write a string into every n x m grid"),
        (43, "Text Formatter", "text_formatter", "Clean and reshape ciphertext"),
        (44, "Keyword Alphabet", "keyword_alphabet", "Build mixed alphabets from a keyword"),
        (45, "Native Engines", "native_tools", "Build the C engines; list, tune and enable GPUs (OpenCL)"),
    ]),
    ("System", [
        ("C", "Session ciphertext", "session", "Set the ciphertext once; every tool offers it (Enter = use it)"),
        ("H", "Help", "help", "How to use the toolkit, tool by tool"),
        ("A", "About", "about", "Version, credits and data sources"),
        ("Q", "Exit", "exit", "Leave the toolkit"),
    ]),
]

ITEMS = [item for _, items in CATEGORIES for item in items]
# The tool grid; the System entries are hotkeys (C, H, A, Q) shown in the footer.
GRID_CATEGORIES = [category for category in CATEGORIES if category[0] != "System"]
NAV_ITEMS = [item for _, items in GRID_CATEGORIES for item in items]
_loaded_modules = {}


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
    The System entries are hotkeys (C, H, A, Q) listed in the footer."""
    blocks = [[("header", name)] + [("item", item) for item in items] for name, items in GRID_CATEGORIES]

    def stack(*indices):
        column = []
        for index in indices:
            column += blocks[index] + [("blank", None)]
        return column[:-1]

    if column_count >= 3:
        return [stack(0), stack(1, 2), stack(3)]
    if column_count == 2:
        return [stack(0, 1), stack(2, 3)]
    return [stack(0, 1, 2, 3)]


def layout(columns_count):
    count = 3 if columns_count >= 132 else 2 if columns_count >= 88 else 1
    # Columns are joined by two spaces; keep one spare character at the right edge.
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


def render_menu(selected_index, number_buffer, scroll):
    columns_count, rows = terminal_size()
    columns, cell = layout(columns_count)
    rule_width = min(columns_count - 1, cell * len(columns) + 2 * (len(columns) - 1))
    selected_item = NAV_ITEMS[selected_index]

    def render(entry):
        kind, payload = entry
        if kind == "header":
            return pad(f" {BLUE}{BOLD}{payload.upper()}{RESET}", cell)
        if kind == "item":
            label = f"{str(payload[0]):>2}"
            title = payload[1][:cell - 8]
            if payload is selected_item:
                return pad(f"{REVERSE}{BOLD} ▶ {label}  {title} ", cell) + RESET
            return pad(f"   {YELLOW}{label}{RESET}  {title}", cell)
        return " " * cell

    out = []
    body_rows = max(len(column) for column in columns)
    if rows >= body_rows + len(LOGO) + 8:
        out += [f"  {ACCENT}{line}{RESET}" for line in LOGO]
        out.append(f"  {BOLD}CIPHER CRACKER TOOLKIT{RESET}  {GREY}v{VERSION} · classical cryptanalysis · {datetime.now():%Y-%m-%d %H:%M}{RESET}")
    else:
        out.append(f"  {ACCENT}{BOLD}CIPHER CRACKER TOOLKIT{RESET}  {GREY}v{VERSION}{RESET}")
    engines = "" if native_engines_built() else f"  {YELLOW}C engines not built: 45{RESET}"
    room = columns_count - (30 if engines else 0)
    if session.get_ciphertext():
        out.append(f"  {GREY}Session ciphertext:{RESET} {CYAN}{session.summary(max(20, room - 40))}{RESET}"
                   f"  {GREY}C change{RESET}{engines}")
    else:
        detail = ": every tool then offers it, or start with 39" if room >= 92 else ""
        out.append(f"  {GREY}No session ciphertext. Press {YELLOW}C{GREY} to set one{detail}.{RESET}{engines}")
    out.append(f"{GREY}{'─' * rule_width}{RESET}")

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
            out.append(f"   {GREY}↑ {scroll} more{RESET}")
        out += [render(entry) for entry in column[scroll:scroll + window]]
        if len(column) > scroll + window:
            out.append(f"   {GREY}↓ {len(column) - scroll - window} more{RESET}")

    out.append(f"{GREY}{'─' * rule_width}{RESET}")
    limit = columns_count - 2
    title = selected_item[1][:limit]
    description = selected_item[3][:max(0, limit - len(title) - 3)]
    out.append(f" {CYAN}{title}{RESET} {GREY}·{RESET} {description}")
    arrows = "↑↓←→ move" if len(columns) > 1 and body_rows <= available else "↑↓ move"
    hint = (f"{arrows} · type a number · Enter open · C session text · H help · A about · Q quit" if columns_count >= 92
            else f"{arrows} · number = jump · Enter · C text · H help · Q quit")
    jump = f"Go to: {number_buffer}_" if number_buffer else ""
    if jump and len(hint) + len(jump) + 3 > limit:
        hint = ""
    out.append(f" {GREY}{hint[:limit]}{RESET}{'   ' if hint and jump else ''}{YELLOW}{jump}{RESET}")

    sys.stdout.write("\033[H" + "\n".join(line + "\033[K" for line in out) + "\033[J")
    sys.stdout.flush()
    return scroll


def select_menu_option(selected=0):
    """Interactive menu; returns (item, index of the selection in NAV_ITEMS)."""
    number_buffer, scroll = "", 0
    selected = min(selected, len(NAV_ITEMS) - 1)
    clear_screen()
    hide_cursor()
    try:
        while True:
            scroll = render_menu(selected, number_buffer, scroll)
            key = get_key()
            if not key:
                continue
            if len(key) == 1 and key.isdigit():
                # Multi-digit jump: "3" then "7" selects tool 37.
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
            elif key == 'PAGE_UP':
                selected = NAV_ITEMS.index(order[max(0, position - 8)])
            elif key == 'PAGE_DOWN':
                selected = NAV_ITEMS.index(order[min(len(order) - 1, position + 8)])
            elif key == 'HOME':
                selected = NAV_ITEMS.index(order[0])
            elif key == 'END':
                selected = NAV_ITEMS.index(order[-1])
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
    print(f"""
{BOLD}Getting around{RESET}
  Arrow keys (or W/S) move, Left/Right switch column, typing a tool's number
  jumps to it (e.g. {YELLOW}37{RESET}), Enter opens it. Inside a tool, {YELLOW}Ctrl+C{RESET} stops
  the current step and returns to this menu.

{BOLD}Session ciphertext{RESET}
  {YELLOW}C{RESET} sets the ciphertext once (paste several lines, or a .txt path). Every
  tool's ciphertext prompt then accepts Enter to use it. Tool 39 sets it too.

{BOLD}A typical workflow for an unknown ciphertext{RESET}
  0. {YELLOW}39{RESET} Unknown Cipher Analyzer does steps 1-3 for you, ranks the attack
     pathways with the tools to open, runs the instant attacks and can
     hill-climb a pathway. The manual route:
  1. {YELLOW}40{RESET} Index of Coincidence: ~0.066 means letter frequencies are intact
     (substitution and/or transposition); ~0.04 suggests a polyalphabetic key.
  2. {YELLOW}41{RESET} Frequency Analysis: English-like frequencies point to transposition.
  3. {YELLOW}35{RESET}/{YELLOW}36{RESET} Kasiski / Friedman estimate a polyalphabetic key length.
  4. Solve: {YELLOW}31{RESET} substitution, {YELLOW}32{RESET}/{YELLOW}23{RESET} transposition, {YELLOW}30{RESET}/{YELLOW}1{RESET} Vigenere,
     or {YELLOW}37{RESET} when two layers were stacked. With known plaintext at known
     positions, {YELLOW}38{RESET} tests every column order + periodic key exhaustively.

{BOLD}Speed{RESET}
  {YELLOW}45{RESET} Native Engines builds the C engines (python -m pip install ziglang first)
  and enables a GPU. The transposition brute force and annealers (23, 32) and
  tool 38 then run in C or on the GPU, with the same results as the Python code.

{BOLD}Scoring{RESET}
  Solvers rank candidate plaintexts with English n-gram statistics (5-grams by
  default, AZdecrypt data in N-grams/). "Fitness" is higher-is-better; "N-gram
  cost/score" is lower-is-better. Several independent runs that agree on the
  same plaintext are strong evidence of a real solution.""")
    for name, items in CATEGORIES[:-1]:
        section(name)
        for key, title, _, description in items:
            print(f"  {YELLOW}{str(key):>2}{RESET}  {title:<26} {GREY}{description}{RESET}")
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
        print(f"{GREY}Tip: 39 Unknown Cipher Analyzer ranks the attack pathways for it.{RESET}")
        pause()


# Tools whose column-order searches have C (and GPU) engines, with the measured
# speed-up from the README (Python vs C, same results).
NATIVE_TOOLS = {
    "permutation_solver": "brute force ~9x faster (width 8: 47,000 -> 417,000 orders/s)",
    "simulated_annealing_transposition": "the annealing loop runs in C",
    "crib_columnar_search": "~80x faster (width 8, 97 letters: 11.6 s -> 0.14 s)",
}


def native_engines_built() -> bool:
    try:
        import native
        return native.available()
    except Exception:
        return False


def offer_native_build(file_name):
    """Before a tool with C engines runs in pure Python: say so and offer to build them."""
    if file_name not in NATIVE_TOOLS or native_engines_built():
        return
    print(f"{YELLOW}The C engines are not built: this tool will run in pure Python.{RESET} "
          f"{GREY}With them: {NATIVE_TOOLS[file_name]}.{RESET}")
    choice = input(f"{YELLOW}B{RESET} = build them now (a few seconds), Enter = continue in Python: ").strip().lower()
    if choice != "b":
        print()
        return
    try:
        import ziglang  # noqa: F401
    except ImportError:
        print(f"{RED}The compiler is missing. Run  python -m pip install ziglang  then press B again "
              f"(or use 45 Native Engines).{RESET}")
        pause("Press Enter to continue in Python...")
        return
    import native_tools
    native_tools.build()
    print()


def run_module(item):
    _, title, file_name, _ = item
    clear_screen()
    offer_native_build(file_name)
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
    except Exception:
        print(f"\n{RED}The tool stopped with an error:{RESET}")
        traceback.print_exc()
    pause()


def main():
    if 'idlelib' not in sys.modules and sys.stdout.isatty():
        retro_effect()
    interactive = sys.stdin.isatty()
    selected = 0
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
            else:
                run_module(item)
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
