"""Native Engines: build the C engines, check their status, tune and enable the GPU.

Command line:  python scripts/native_tools.py build | status | gpu
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from theme import BLUE, GREEN, GREY, RED, RESET, YELLOW, banner  # noqa: E402

import native  # noqa: E402


def build():
    try:
        import ziglang  # noqa: F401
    except ImportError:
        print(f"{RED}zig's C compiler is missing: run  python -m pip install ziglang  and try again.{RESET}")
        return False
    try:
        native.build()
    except Exception as error:      # show the compiler's message
        print(f"{RED}Build failed: {error}{RESET}")
        return False
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
    banner("Native Engines", "C engines and GPU (OpenCL) for the columnar searches")
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
