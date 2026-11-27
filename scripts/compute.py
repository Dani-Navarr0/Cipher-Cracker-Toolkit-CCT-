"""Compute settings: how many worker processes the toolkit's searches may use,
and at what priority, so a long search does not make the computer unusable.

The setting is chosen at launch (Enter keeps the saved one) and can be changed
from the menu (46 Compute Settings, or P). Every parallel search asks
``workers()`` for its process count. Saved in cct_settings.json at the
repository root (git-ignored).
"""
import json
import os
import platform
import sys

from theme import BOLD, CYAN, GREEN, GREY, RED, RESET, YELLOW, banner, option

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SETTINGS_PATH = os.path.join(ROOT, "cct_settings.json")
PRIORITIES = {"low": "Below normal: other programs stay responsive (recommended)",
              "normal": "Normal: searches compete equally with other programs"}
_cache = {}


# ---------------------------------------------------------------- hardware

def available_cpus() -> int:
    """Logical CPUs this process may run on (respects affinity limits)."""
    if hasattr(os, "process_cpu_count"):
        count = os.process_cpu_count()
    elif hasattr(os, "sched_getaffinity"):
        count = len(os.sched_getaffinity(0))
    else:
        count = os.cpu_count()
    return max(1, count or 1)


def memory() -> tuple:
    """(total bytes, available bytes), or (None, None) if unknown."""
    if os.name == "nt":
        import ctypes

        class MemoryStatus(ctypes.Structure):
            _fields_ = [("length", ctypes.c_ulong), ("load", ctypes.c_ulong), ("total", ctypes.c_ulonglong),
                        ("available", ctypes.c_ulonglong), ("page_total", ctypes.c_ulonglong),
                        ("page_available", ctypes.c_ulonglong), ("virtual_total", ctypes.c_ulonglong),
                        ("virtual_available", ctypes.c_ulonglong), ("extended", ctypes.c_ulonglong)]
        status = MemoryStatus()
        status.length = ctypes.sizeof(MemoryStatus)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            return status.total, status.available
        return None, None
    try:
        page = os.sysconf("SC_PAGE_SIZE")
        return page * os.sysconf("SC_PHYS_PAGES"), page * os.sysconf("SC_AVPHYS_PAGES")
    except (ValueError, OSError, AttributeError):
        return None, None


def cpu_name() -> str:
    name = platform.processor() or platform.machine()
    if os.name == "nt":
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0") as key:
                name = winreg.QueryValueEx(key, "ProcessorNameString")[0].strip()
        except OSError:
            pass
    return name


def load_average():
    """1-minute load average (POSIX), or None (Windows has no standard-library equivalent)."""
    try:
        return os.getloadavg()[0]
    except (AttributeError, OSError):
        return None


def presets(cpus=None) -> dict:
    cpus = cpus or available_cpus()
    return {
        "light": max(1, cpus // 4),
        "balanced": max(1, cpus // 2),
        "heavy": max(1, cpus - 2),
    }


# ---------------------------------------------------------------- settings

def load() -> dict:
    if "settings" not in _cache:
        try:
            with open(SETTINGS_PATH, encoding="utf-8") as handle:
                _cache["settings"] = json.load(handle)
        except (OSError, ValueError):
            _cache["settings"] = {}
    return _cache["settings"]


def save(settings: dict):
    _cache["settings"] = dict(settings)
    with open(SETTINGS_PATH, "w", encoding="utf-8") as handle:
        json.dump(settings, handle, indent=2)


def workers(jobs=None) -> int:
    """Worker processes a parallel search may use: the saved setting (default:
    half the CPUs), never more than the CPUs available or the number of jobs."""
    cpus = available_cpus()
    chosen = load().get("workers") or presets(cpus)["balanced"]
    chosen = max(1, min(int(chosen), cpus))
    return max(1, min(chosen, jobs)) if jobs else chosen


def apply_priority(priority=None):
    """Set this process's priority. Child processes started afterwards (the
    search workers) inherit 'below normal' on Windows and the nice value on POSIX."""
    priority = priority or load().get("priority", "low")
    if priority != "low":
        return
    try:
        if os.name == "nt":
            import ctypes
            BELOW_NORMAL_PRIORITY_CLASS = 0x00004000
            kernel32 = ctypes.windll.kernel32
            # Declare the handle type: without it ctypes truncates the 64-bit
            # pseudo-handle and the call silently fails.
            kernel32.GetCurrentProcess.restype = ctypes.c_void_p
            kernel32.SetPriorityClass.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
            kernel32.SetPriorityClass.restype = ctypes.c_int
            kernel32.SetPriorityClass(kernel32.GetCurrentProcess(), BELOW_NORMAL_PRIORITY_CLASS)
        elif not _cache.get("niced"):
            os.nice(5)
            _cache["niced"] = True
    except (OSError, AttributeError):
        pass


# ---------------------------------------------------------------- screens

def _gb(value):
    return f"{value / 1024 ** 3:.1f} GB" if value else "unknown"


def describe_hardware():
    cpus, logical = available_cpus(), os.cpu_count() or 0
    total, free = memory()
    load = load_average()
    print(f"  {BOLD}CPU{RESET}        {cpu_name()}")
    print(f"  {BOLD}Threads{RESET}    {YELLOW}{cpus}{RESET} available to the toolkit"
          f"{f' ({logical} logical in the machine)' if logical and logical != cpus else ''}")
    print(f"  {BOLD}Memory{RESET}     {_gb(free)} free of {_gb(total)}")
    if load is not None:
        print(f"  {BOLD}Load{RESET}       {load:.1f} (1-minute average: about how many threads are busy now)")
    try:
        import native
        if native.available():
            from native import gpu
            for line in gpu.describe():
                print(f"  {BOLD}GPU{RESET}        {line}")
    except Exception:
        pass


def configure(first_time=False):
    """Interactive choice of worker count and priority. Returns the settings."""
    settings = dict(load())
    cpus = available_cpus()
    options = presets(cpus)
    total, free = memory()
    print()
    describe_hardware()
    current = workers()
    print(f"\n  {GREY}Searches run several independent processes at once; each one uses a whole CPU thread "
          f"while it runs.\n  Using every thread makes the computer sluggish for anything else. Each worker "
          f"also holds its own\n  copy of the n-gram table (about 12 MB for the default 5-grams, 300 MB for "
          f"6-grams).{RESET}\n")
    option(1, f"Light     {options['light']:>3} worker(s)", "(the computer stays fully usable)")
    option(2, f"Balanced  {options['balanced']:>3} worker(s)", "(default)")
    option(3, f"Heavy     {options['heavy']:>3} worker(s)", "(fastest; leaves 2 threads for everything else)")
    option(4, "Custom", f"(1-{cpus})")
    keep = "" if first_time and "workers" not in settings else f", Enter = keep {current}"
    choice = input(f"Workers{keep}: ").strip()
    if choice in ("1", "2", "3"):
        settings["workers"] = options[("light", "balanced", "heavy")[int(choice) - 1]]
    elif choice == "4":
        text = input(f"Number of workers (1-{cpus}): ").strip()
        if text.isdigit() and 1 <= int(text) <= cpus:
            settings["workers"] = int(text)
        else:
            print(f"{RED}Not a number from 1 to {cpus}; keeping {current}.{RESET}")
            settings["workers"] = current
    elif choice.isdigit() and 1 <= int(choice) <= cpus:
        settings["workers"] = int(choice)
    else:
        settings["workers"] = current
    if total and free:
        need = settings["workers"] * 12 * 1024 ** 2
        if need > free * 0.8:
            print(f"{YELLOW}{settings['workers']} workers need about {_gb(need)} for 5-gram tables; only "
                  f"{_gb(free)} is free.{RESET}")
    priority = settings.get("priority", "low")
    print()
    for key, text in PRIORITIES.items():
        option("L" if key == "low" else "N", text, "(current)" if key == priority else "")
    answer = input(f"Priority (Enter = keep {priority}): ").strip().lower()
    settings["priority"] = "low" if answer == "l" else "normal" if answer == "n" else priority
    save(settings)
    apply_priority(settings["priority"])
    print(f"{GREEN}Searches will use up to {settings['workers']} worker process(es) at "
          f"{'below-normal' if settings['priority'] == 'low' else 'normal'} priority.{RESET}")
    return settings


def startup_prompt(interactive=True):
    """At launch: on the first run (no saved setting) show the hardware and ask;
    later, show the saved setting in one line (Enter keeps it, C changes it)."""
    apply_priority()
    if not interactive:
        return
    settings = load()
    if "workers" in settings:
        cpus = available_cpus()
        print(f"\n{CYAN}Compute:{RESET} up to {YELLOW}{workers()}{RESET} of {cpus} threads, "
              f"{'below-normal' if settings.get('priority', 'low') == 'low' else 'normal'} priority.")
        if input(f"{GREY}Enter = keep, C = change: {RESET}").strip().lower() != "c":
            return
        configure()
    else:
        banner("Compute settings", "How much of this computer the toolkit's searches may use")
        configure(first_time=True)


def run():
    banner("Compute Settings", "Worker processes and priority for the toolkit's searches")
    configure()


if __name__ == "__main__":
    run()
