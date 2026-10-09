import os
import time
import random
import sys
from datetime import datetime
import importlib

# Ensure console handles UTF-8 safely
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

# Add the 'scripts' directory to the Python path
sys.path.append(os.path.join(os.path.dirname(__file__), 'scripts'))

# Define a mapping from user-friendly names to module file names
MODULE_MAP = {
    'vigenere': 'vigenere',
    'beaufort': 'beaufort',                        
    'porta': 'porta',                              
    'four_square': 'four_square',                  
    'running_key': 'running_key',                  
    'gromark': 'Gromark_transposition',
    'gronsfeld': 'Gronsfeld',
    'autoclave': 'autoclave',
    'hill': 'hill',
    'xor': 'xor',
    'mod_add_sub': 'modular_add_sub',
    'caesar': 'caesar',
    'playfair': 'playfair',
    'affine': 'affine',
    'polybius': 'polybius',
    'bifid': 'bifid',
    'rail_fence': 'rail_fence',
    'columnar_transposition': 'columnar_transposition',
    'scytale': 'Scytale',
    'permutation_solver': 'permutation_solver',
    'matrix_generator': 'Matrix Generator',
    'ioc': 'ioc',
    'freq_analysis': 'freq_analysis',
    'kasiski': 'kasiski',                              
    'friedman_test': 'friedman_test',
    'pattern_isomorphism': 'pattern_isomorphism',
    'crib_drag': 'crib_drag',
    'simulated_annealing': 'simulated_annealing',      
    'simulated_annealing_transposition': 'simulated_annealing_transposition',
    'vigenere_auto_solver': 'vigenere_auto_solver',
    'text_formatter': 'text_formatter',
    'keyword_alphabet': 'keyword_alphabet'             
}

# Try to import the cipher and tool modules
CIPHER_MODULES = {name: None for name in MODULE_MAP.keys()}

for user_name, file_name in MODULE_MAP.items():
    try:
        module = importlib.import_module(file_name)
        CIPHER_MODULES[user_name] = module
    except ImportError as e:
        print(f"Warning: Module 'scripts/{file_name}.py' not found. Error: {e}")
        pass

# Style colors and effects
class Style:
    GREEN, YELLOW, RED, BLUE, CYAN, WHITE, GRAY = '\033[38;5;84m', '\033[33m', '\033[31m', '\033[34m', '\033[36m', '\033[37m', '\033[90m'
    BOLD, REVERSE, UNDERLINE, RESET = '\033[1m', '\033[7m', '\033[4m', '\033[0m'

def clear_screen(): os.system('cls' if os.name == 'nt' else 'clear')

def terminal_width():
    try: return os.get_terminal_size().columns
    except OSError: return 80

def terminal_height():
    try: return os.get_terminal_size().lines
    except OSError: return 24

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
            ch2 = msvcrt.getch()
            mapping = {
                b'H': 'UP',
                b'P': 'DOWN',
                b'K': 'LEFT',
                b'M': 'RIGHT',
                b'I': 'PAGE_UP',
                b'Q': 'PAGE_DOWN',
                b'G': 'HOME',
                b'O': 'END',
            }
            return mapping.get(ch2, None)
        elif ch in (b'\r', b'\n'):
            return 'ENTER'
        elif ch == b'\x1b':
            return 'ESC'
        elif ch == b'\x08':
            return 'BACKSPACE'
        elif ch == b'\x03':
            raise KeyboardInterrupt
        try:
            return ch.decode('utf-8', errors='ignore')
        except Exception:
            return None
    else:
        import select, termios, tty
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            ch = sys.stdin.read(1)
            if ch == '\x1b':
                r, _, _ = select.select([sys.stdin], [], [], 0.05)
                if r:
                    ch2 = sys.stdin.read(1)
                    if ch2 == '[':
                        ch3 = sys.stdin.read(1)
                        mapping = {
                            'A': 'UP',
                            'B': 'DOWN',
                            'C': 'RIGHT',
                            'D': 'LEFT',
                            'H': 'HOME',
                            'F': 'END',
                            '5': 'PAGE_UP',
                            '6': 'PAGE_DOWN',
                        }
                        return mapping.get(ch3, None)
                return 'ESC'
            elif ch in ('\r', '\n'):
                return 'ENTER'
            elif ch == '\x03':
                raise KeyboardInterrupt
            return ch
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

def print_centered(text, color=Style.WHITE): print(f"{color}{text.center(terminal_width())}{Style.RESET}")
def print_divider(char='=', color=Style.GRAY): print(f"{color}{char * terminal_width()}{Style.RESET}")

def fancy_box(text, color=Style.YELLOW, padding=1):
    lines = text.split('\n')
    width = max(len(line) for line in lines) + padding * 2
    print(f"{color}┌{'─' * width}┐{Style.RESET}")
    for line in lines:
        plain_line = ''.join(c for c in line if c.isprintable() and ord(c) < 128)
        padding_needed = width - len(plain_line)
        left_padding = padding_needed // 2
        right_padding = padding_needed - left_padding
        print(f"{color}│{' ' * left_padding}{Style.RESET}{line}{color}{' ' * right_padding}│{Style.RESET}")
    print(f"{color}└{'─' * width}┘{Style.RESET}")

def retro_effect(duration=1.0):
    width = terminal_width()
    chars = "█▓▒░ ░▒▓█"
    end_time = time.time() + duration
    while time.time() < end_time:
        line = "".join(random.choice(chars) for _ in range(width))
        print(f"{Style.GREEN}{line}{Style.RESET}", end="\r")
        time.sleep(0.05)
    print(" " * width, end="\r")

def display_logo():
    logo = f"""
    {Style.RED}
 a88888b.           a88888b.          d888888P 
d8'   `88          d8'   `88             88    
88                 88                    88    
88                 88                    88    
Y8.   .88    dP    Y8.   .88    dP       88    
 Y88888P'    88     Y88888P'    88       dP                                                                                                                               
    {Style.RESET}
    """
    print(logo)
    print_centered(f"{Style.BOLD}{Style.REVERSE} CIPHER CRACKER TOOLKIT {Style.RESET}", Style.RED)
    print_divider()
    print_centered(f"github.com/hippie-cycling", Style.GRAY)
    print_centered(f"Session started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", Style.BLUE)
    print_divider()

MENU_OPTIONS = [
    (0, "Help & Documentation", Style.WHITE, 'help'),
    (-1, "SUBSTITUTION CIPHER OPTIONS", Style.CYAN, None),
    (1, "Vigenere Cipher", Style.GREEN, 'vigenere'),
    (2, "Gromark Cipher", Style.GREEN, 'gromark'),
    (3, "Gronsfeld Cipher", Style.GREEN, 'gronsfeld'),
    (4, "Autoclave Cipher", Style.GREEN, 'autoclave'),
    (5, "Hill Cipher", Style.GREEN, 'hill'),
    (6, "XOR", Style.GREEN, 'xor'),
    (7, "Modular ADD-SUB", Style.GREEN, 'mod_add_sub'),
    (8, "Caesar Cipher", Style.GREEN, 'caesar'),
    (9, "Playfair Cipher", Style.GREEN, 'playfair'),
    (10, "Affine Cipher", Style.GREEN, 'affine'),
    (11, "Polybius Square", Style.GREEN, 'polybius'),
    (12, "Bifid Cipher", Style.GREEN, 'bifid'),
    (13, "Beaufort Cipher", Style.GREEN, 'beaufort'),
    (14, "Porta Cipher", Style.GREEN, 'porta'),
    (15, "Four-Square Cipher", Style.GREEN, 'four_square'),
    (16, "Running Key Cipher", Style.GREEN, 'running_key'),
    (-2, "TRANSPOSITION CIPHER OPTIONS", Style.CYAN, None),
    (20, "Columnar Transposition Cipher", Style.GREEN, 'columnar_transposition'),
    (21, "Scytale Cipher", Style.GREEN, 'scytale'),
    (22, "Rail Fence Cipher", Style.GREEN, 'rail_fence'),
    (23, "Matrix Permutation Solver", Style.GREEN, 'permutation_solver'),
    (-3, "CRYPTANALYSIS TOOLS", Style.CYAN, None),
    (30, "Vigenere Auto-Solver", Style.YELLOW, 'vigenere_auto_solver'),
    (31, "Simulated Annealing (Substitution)", Style.YELLOW, 'simulated_annealing'),
    (32, "Simmulated Annealing (Transposition)", Style.YELLOW, 'simulated_annealing_transposition'),
    (33, "Word Pattern Isomorphism", Style.YELLOW, 'pattern_isomorphism'),
    (34, "Automated Crib Dragging", Style.YELLOW, 'crib_drag'),
    (35, "Kasiski Examination", Style.YELLOW, 'kasiski'),
    (36, "Friedman Test (Key Length Estimator)", Style.YELLOW, 'friedman_test'),
    (-4, "UTILITIES", Style.CYAN, None),
    (40, "Calculate IoC", Style.GRAY, 'ioc'),
    (41, "Frequency Analysis", Style.GRAY, 'freq_analysis'),
    (42, "Matrix Generator", Style.GRAY, 'matrix_generator'),
    (43, "Text Formatter", Style.GRAY, 'text_formatter'),
    (44, "Keyword Alphabet Generator", Style.GRAY, 'keyword_alphabet'), 
    (-5, "SYSTEM", Style.CYAN, None),
    ('A', "About", Style.WHITE, 'about'),
    ('E', "Exit", Style.RED, 'exit')
]

def display_menu():
    print(f"\n{Style.BOLD}{Style.WHITE}Select an option:{Style.RESET}")
    print_divider('-', Style.GRAY)
    
    for number, name, color, _ in MENU_OPTIONS:
        if isinstance(number, int) and number < 0:
            print()
            print(f" {color}{Style.BOLD}{name}{Style.RESET}")
            print_divider('-', Style.GRAY)
        else:
            print(f" {color}[{number}]{Style.RESET} {Style.BOLD}{name}{Style.RESET}")
    
    print_divider('-', Style.GRAY)
    
    return {
        str(number): name for number, name, _, _ in MENU_OPTIONS 
        if isinstance(number, (int, str)) and (isinstance(number, int) and number >= 0 or isinstance(number, str))
    }

def select_menu_option(options):
    selectable = [opt for opt in options if opt[3] is not None]
    if not selectable:
        return None
    
    selected_idx = 0
    hide_cursor()
    first_render = True
    
    try:
        while True:
            term_w = terminal_width()
            term_h = terminal_height()
            
            show_full_logo = (term_h >= len(options) + 18)
            
            if first_render:
                clear_screen()
                first_render = False
            else:
                sys.stdout.write('\033[H')
                sys.stdout.flush()
                
            if show_full_logo:
                display_logo()
                header_lines = 15
            else:
                print_centered(f"{Style.BOLD}{Style.REVERSE} CIPHER CRACKER TOOLKIT {Style.RESET}", Style.RED)
                print_divider('-', Style.GRAY)
                header_lines = 3
                
            footer_lines = 3
            available_lines = term_h - header_lines - footer_lines
            
            cur_opt = selectable[selected_idx]
            cur_idx = options.index(cur_opt)
            
            if len(options) <= available_lines:
                window = options
                start = 0
                end = len(options)
            else:
                w_size = max(5, available_lines - 2)
                start = max(0, min(cur_idx - w_size // 2, len(options) - w_size))
                end = min(len(options), start + w_size)
                window = options[start:end]
                
            if start > 0:
                print(f"   {Style.GRAY}^ ... ({start} more options above) ...{Style.RESET}\033[K")
                
            for item in window:
                number, name, color, target = item
                if target is None:
                    print(f" {color}{Style.BOLD}--- {name} ---{Style.RESET}\033[K")
                else:
                    is_active = (item == cur_opt)
                    num_str = str(number).rjust(2)
                    if is_active:
                        print(f" {Style.BOLD}{Style.REVERSE} > [{num_str}] {name:<35} {Style.RESET}\033[K")
                    else:
                        print(f"   {color}[{num_str}]{Style.RESET} {Style.BOLD}{name:<35}{Style.RESET}\033[K")
                        
            if end < len(options):
                print(f"   {Style.GRAY}v ... ({len(options) - end} more options below) ...{Style.RESET}\033[K")
                
            print_divider('-', Style.GRAY)
            print(f" {Style.GRAY}Controls: [Up/Down] or [W/S] Navigate | [Enter] Select | [0-9/A/E] Hotkey | [Q/Esc] Exit{Style.RESET}\033[K")
            sys.stdout.write('\033[J')
            sys.stdout.flush()
            
            key = get_key()
            if not key:
                continue
                
            if key in ('UP', 'w', 'W'):
                selected_idx = (selected_idx - 1) % len(selectable)
            elif key in ('DOWN', 's', 'S'):
                selected_idx = (selected_idx + 1) % len(selectable)
            elif key in ('LEFT', 'PAGE_UP'):
                selected_idx = max(0, selected_idx - 5)
            elif key in ('RIGHT', 'PAGE_DOWN'):
                selected_idx = min(len(selectable) - 1, selected_idx + 5)
            elif key == 'HOME':
                selected_idx = 0
            elif key == 'END':
                selected_idx = len(selectable) - 1
            elif key == 'ENTER':
                return cur_opt
            elif key in ('ESC', 'q', 'Q'):
                return next(opt for opt in options if opt[3] == 'exit')
            elif isinstance(key, str):
                key_upper = key.upper()
                if key_upper in ('A', 'E', '0'):
                    return next((opt for opt in selectable if str(opt[0]).upper() == key_upper), cur_opt)
                for i, opt in enumerate(selectable):
                    if str(opt[0]).upper() == key_upper:
                        selected_idx = i
                        break
    finally:
        show_cursor()

def run_module(module_name):
    module = CIPHER_MODULES.get(module_name)
    name = module_name.replace('_', ' ').title()
    if module:
        clear_screen()
        print(f"{Style.YELLOW}Running {name} module...{Style.RESET}\n")
        module.run()
        print(f"\n{Style.GREEN}[{name} process completed]{Style.RESET}")
    else:
        fancy_box(f" ERROR: {name} MODULE NOT FOUND ", Style.RED)
        print(f"\n{Style.RED}The {name} module could not be imported.{Style.RESET}")
    input(f"\n{Style.YELLOW}Press Enter to return to the main menu...{Style.RESET}")

def main():
    if 'idlelib' not in sys.modules: retro_effect()
    clear_screen()
    while True:
        try:
            if sys.stdin.isatty():
                selected = select_menu_option(MENU_OPTIONS)
            else:
                display_logo()
                options_dict = display_menu()
                choice = input(f"\n{Style.GREEN}Enter your choice: {Style.RESET}").strip().upper()
                selected = next((opt for opt in MENU_OPTIONS if str(opt[0]).upper() == choice), None)
                if not selected:
                    print(f"\n{Style.RED}Invalid choice!{Style.RESET}")
                    time.sleep(1)
                    continue

            if not selected:
                continue

            choice_num, choice_name, _, module_key = selected
            choice_str = str(choice_num).upper()

            if module_key == 'help' or choice_str == '0':
                clear_screen()
                print("Scoring-enabled tools use the bundled 5-gram model by default. See README.md or individual tools for exact parameters.")
                input("\nPress Enter to return...")
            elif module_key == 'about' or choice_str == 'A':
                clear_screen()
                print("Cipher Cracker Toolkit. A comprehensive powerful cryptanalysis and heuristic decryption suite.")
                input("\nPress Enter to return...")
            elif module_key == 'exit' or choice_str == 'E':
                clear_screen()
                print(f"\n{Style.GREEN}Goodbye!{Style.RESET}")
                break
            elif module_key in CIPHER_MODULES:
                run_module(module_key)
            else:
                clear_screen()
                print(f"\n{Style.RED}Module '{module_key}' not found!{Style.RESET}")
                time.sleep(1)
        except KeyboardInterrupt:
            clear_screen()
            print(f"\n{Style.GREEN}Goodbye!{Style.RESET}")
            break
        except Exception as e:
            clear_screen()
            print(f"\n{Style.RED}Error: {str(e)}{Style.RESET}")
            time.sleep(2)

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: sys.exit(0)