"""C Engines & GPU: build the C engines, check their status, tune and enable the GPU.

Command line:  python scripts/native_tools.py build | status | gpu
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from theme import BLUE, GREEN, GREY, RED, RESET, YELLOW, banner  # noqa: E402

import native  # noqa: E402


def install_compiler():
    """Offer to install zig's C compiler (the pip package ziglang) into the
    Python that is running the toolkit. Returns True when it is importable."""
    import importlib
    import subprocess
    print(f"{YELLOW}zig's C compiler (the pip package ziglang) is not installed for the Python running the "
          f"toolkit:{RESET}\n  {sys.executable}\n{GREY}(Each Python installation has its own packages; it may be "
          f"installed for another one.){RESET}")
    command = [sys.executable, "-m", "pip", "install", "ziglang"]
    if input(f"I = install it now into this Python ({GREY}{' '.join(command)}{RESET}), Enter = cancel: "
             ).strip().lower() != "i":
        print(f"{GREY}To install it yourself:  \"{sys.executable}\" -m pip install ziglang{RESET}")
        return False
    if subprocess.run(command).returncode != 0:
        print(f"{RED}pip could not install ziglang (see its message above).{RESET}")
        return False
    importlib.invalidate_caches()
    try:
        import ziglang  # noqa: F401
    except ImportError:
        print(f"{RED}ziglang installed but cannot be imported yet: restart the toolkit and build again.{RESET}")
        return False
    return True


def build():
    """Build the C engines. Returns True when the new engines are in use or
    will be at the next start (Windows keeps a loaded library locked)."""
    try:
        import ziglang  # noqa: F401
    except ImportError:
        if not install_compiler():
            return False
    try:
        outcome = native.build()
    except Exception as error:      # show the compiler's message
        print(f"{RED}Build failed: {error}{RESET}")
        return False
    if outcome == "pending":
        print(f"{GREEN}Built.{RESET} {YELLOW}This toolkit session still has the previous engines loaded (Windows "
              f"locks a library while it is in use): restart the toolkit to use the new build.{RESET}")
        return True
    print(f"{GREEN}Native engines built: {native.available()}{RESET}")
    return native.available()


def status():
    print(f"C engines: {GREEN + 'on' if native.available() else YELLOW + 'off (build them)'}{RESET}")
    from native import gpu
    for line in gpu.describe():
        print(f"GPU: {line}")
    print(f"GPU search: {GREEN + 'on' if gpu.enabled() else GREY + 'off'}{RESET} (environment variable CCT_GPU=1)")


def gpu_menu():
    from native import gpu, opencl
    found = opencl.devices()
    if not found:
        print(f"{YELLOW}No OpenCL GPU found (the runtime ships with the graphics driver).{RESET}")
        return
    for line in gpu.describe():
        print(line)
    print(f"{GREY}Tuning each GPU once (cached in scripts/native/build/gpu_tuning.json)...{RESET}")
    for _, _, props in found:
        os.environ["CCT_GPU_DEVICE"] = props["name"]
        gpu._contexts.clear()
        for kernel in ("perm_score", "crib_periodic"):
            best = gpu.tuned_per_item(kernel, retune=True)
            print(f"{props['name']}: {kernel}: {best} column orders per work-item")
    os.environ.pop("CCT_GPU_DEVICE", None)
    gpu._contexts.clear()
    choice = input("Use the GPU for wide searches in this session? (Y/N): ").strip().upper()
    if choice == "Y":
        os.environ["CCT_GPU"] = "1"
        name = input("GPU name contains (Enter for a discrete GPU first): ").strip()
        if name:
            os.environ["CCT_GPU_DEVICE"] = name
        print(f"{GREEN}GPU search on (set CCT_GPU=1 in the environment to make it permanent).{RESET}")


def run():
    banner("C Engines & GPU", "Build the C engines every solver needs; OpenCL GPUs for the columnar searches")
    status()
    print(f"\n  {BLUE}1{RESET} Build the C engines   {BLUE}2{RESET} GPU: list, tune, enable   {BLUE}0{RESET} Back")
    choice = input("Select: ").strip()
    if choice == "1":
        build()
    elif choice == "2":
        gpu_menu()


if __name__ == "__main__":
    command = sys.argv[1] if len(sys.argv) > 1 else "status"
    if command == "build":
        sys.exit(0 if build() else 1)
    elif command == "gpu":
        gpu_menu()
    else:
        status()
