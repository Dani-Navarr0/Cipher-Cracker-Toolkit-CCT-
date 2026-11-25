"""Minimal OpenCL binding through ctypes (no pyopencl, no CUDA toolkit).

The OpenCL runtime ships with the graphics driver on Windows and Linux (NVIDIA,
AMD, Intel) and with macOS, so GPU search needs nothing else installed. Kernels
are compiled by the driver at run time for whichever device is present.
"""
import ctypes
import ctypes.util
import sys

_c = ctypes
_vp, _u32, _i32, _sz = _c.c_void_p, _c.c_uint32, _c.c_int32, _c.c_size_t
CL_DEVICE_TYPE_GPU = 1 << 2
CL_DEVICE_TYPE_ALL = 0xFFFFFFFF
INFO = {"name": 0x102B, "vendor": 0x102C, "version": 0x102F, "compute_units": 0x1002, "clock_mhz": 0x100C,
        "global_mem": 0x101F, "unified_memory": 0x1035, "type": 0x1000}
CL_MEM_READ_WRITE, CL_MEM_READ_ONLY, CL_MEM_COPY_HOST_PTR = 1, 4, 32
CL_PROGRAM_BUILD_LOG = 0x1183

_lib = None


class OpenCLError(RuntimeError):
    pass


def library():
    """The OpenCL runtime, or None if this machine has none."""
    global _lib
    if _lib is None:
        candidates = ["/System/Library/Frameworks/OpenCL.framework/OpenCL"] if sys.platform == "darwin" else \
            [ctypes.util.find_library("OpenCL") or "OpenCL", "libOpenCL.so.1"]
        for path in candidates:
            try:
                _lib = _c.CDLL(path)
                break
            except OSError:
                continue
        else:
            _lib = False
            return None
        L = _lib
        for name, restype in (("clCreateContext", _vp), ("clCreateCommandQueue", _vp),
                              ("clCreateProgramWithSource", _vp), ("clCreateKernel", _vp), ("clCreateBuffer", _vp)):
            getattr(L, name).restype = restype
    return _lib or None


def _check(code, what):
    if code != 0:
        raise OpenCLError(f"{what} failed with OpenCL error {code}")


def _info(fn, obj, key, size=512):
    buf = _c.create_string_buffer(size)
    fn(_vp(obj), _u32(key), _sz(size), buf, None)
    return buf.raw


def devices():
    """[(platform name, device handle, properties)] for every GPU."""
    L = library()
    if L is None:
        return []
    n = _u32()
    if L.clGetPlatformIDs(0, None, _c.byref(n)) != 0 or not n.value:
        return []
    platforms = (_vp * n.value)()
    L.clGetPlatformIDs(n.value, platforms, None)
    found = []
    for platform in platforms:
        count = _u32()
        if L.clGetDeviceIDs(_vp(platform), _c.c_uint64(CL_DEVICE_TYPE_GPU), 0, None, _c.byref(count)) != 0:
            continue
        handles = (_vp * count.value)()
        L.clGetDeviceIDs(_vp(platform), _c.c_uint64(CL_DEVICE_TYPE_GPU), count.value, handles, None)
        platform_name = _info(L.clGetPlatformInfo, platform, 0x0902).split(b"\0")[0].decode(errors="replace")
        for handle in handles:
            raw = lambda key, size=8: _info(L.clGetDeviceInfo, handle, key, size)
            props = {"name": raw(INFO["name"], 256).split(b"\0")[0].decode(errors="replace").strip(),
                     "vendor": raw(INFO["vendor"], 256).split(b"\0")[0].decode(errors="replace").strip(),
                     "compute_units": int.from_bytes(raw(INFO["compute_units"], 4), "little"),
                     "clock_mhz": int.from_bytes(raw(INFO["clock_mhz"], 4), "little"),
                     "global_mem": int.from_bytes(raw(INFO["global_mem"], 8), "little"),
                     "unified_memory": bool(int.from_bytes(raw(INFO["unified_memory"], 4), "little"))}
            found.append((platform_name, handle, props))
    return found


def pick_device(preference=None):
    """A GPU: the one whose name contains ``preference`` if given, else a discrete GPU
    (own memory) before an integrated one, largest memory first."""
    found = devices()
    if preference:
        found = [d for d in found if preference.lower() in (d[2]["name"] + " " + d[0]).lower()]
    if not found:
        return None
    return sorted(found, key=lambda d: (d[2]["unified_memory"], -d[2]["global_mem"]))[0]


class Buffer:
    def __init__(self, context, size, data=None, read_only=False):
        self.size = max(1, size)
        flags = (CL_MEM_READ_ONLY if read_only else CL_MEM_READ_WRITE) | (CL_MEM_COPY_HOST_PTR if data is not None else 0)
        err = _i32()
        self.keep = data
        self.handle = library().clCreateBuffer(_vp(context.handle), _c.c_uint64(flags), _sz(self.size),
                                              data, _c.byref(err))
        _check(err.value, "clCreateBuffer")

    def release(self):
        if self.handle:
            library().clReleaseMemObject(_vp(self.handle))
            self.handle = None


class Context:
    """One device, one command queue, one compiled program."""

    def __init__(self, source, device=None, options=""):
        L = library()
        if L is None:
            raise OpenCLError("no OpenCL runtime on this machine")
        chosen = device or pick_device()
        if chosen is None:
            raise OpenCLError("no OpenCL GPU found")
        self.platform_name, self.device, self.properties = chosen
        err = _i32()
        dev = (_vp * 1)(self.device)
        self.handle = L.clCreateContext(None, 1, dev, None, None, _c.byref(err))
        _check(err.value, "clCreateContext")
        self.queue = L.clCreateCommandQueue(_vp(self.handle), _vp(self.device), _c.c_uint64(0), _c.byref(err))
        _check(err.value, "clCreateCommandQueue")
        text = source.encode()
        strings, lengths = (_c.c_char_p * 1)(text), (_sz * 1)(len(text))
        self.program = L.clCreateProgramWithSource(_vp(self.handle), 1, strings, lengths, _c.byref(err))
        _check(err.value, "clCreateProgramWithSource")
        code = L.clBuildProgram(_vp(self.program), 1, dev, options.encode(), None, None)
        if code != 0:
            size = _sz()
            L.clGetProgramBuildInfo(_vp(self.program), _vp(self.device), _u32(CL_PROGRAM_BUILD_LOG), _sz(0), None,
                                    _c.byref(size))
            log = _c.create_string_buffer(size.value + 1)
            L.clGetProgramBuildInfo(_vp(self.program), _vp(self.device), _u32(CL_PROGRAM_BUILD_LOG), size, log, None)
            raise OpenCLError(f"kernel build failed ({code}):\n{log.value.decode(errors='replace')}")
        self.kernels = {}

    def kernel(self, name):
        if name not in self.kernels:
            err = _i32()
            self.kernels[name] = library().clCreateKernel(_vp(self.program), name.encode(), _c.byref(err))
            _check(err.value, f"clCreateKernel({name})")
        return self.kernels[name]

    def buffer(self, data=None, size=None, read_only=False):
        if data is not None and not isinstance(data, _c.Array):
            data = (_c.c_uint8 * len(data)).from_buffer_copy(bytes(data))
        return Buffer(self, size if size is not None else _c.sizeof(data), data, read_only)

    def run(self, name, args, global_size):
        """args: Buffer, or a ctypes scalar (c_int32, c_uint64, ...)."""
        L, kernel = library(), self.kernel(name)
        for index, arg in enumerate(args):
            if isinstance(arg, Buffer):
                handle = _vp(arg.handle)
                _check(L.clSetKernelArg(_vp(kernel), _u32(index), _sz(_c.sizeof(_vp)), _c.byref(handle)),
                       f"clSetKernelArg({index})")
            else:
                _check(L.clSetKernelArg(_vp(kernel), _u32(index), _sz(_c.sizeof(arg)), _c.byref(arg)),
                       f"clSetKernelArg({index})")
        size = (_sz * 1)(global_size)
        _check(L.clEnqueueNDRangeKernel(_vp(self.queue), _vp(kernel), _u32(1), None, size, None, _u32(0), None, None),
               "clEnqueueNDRangeKernel")

    def write(self, buffer, data):
        data = (_c.c_uint8 * len(data)).from_buffer_copy(bytes(data))
        _check(library().clEnqueueWriteBuffer(_vp(self.queue), _vp(buffer.handle), _u32(1), _sz(0), _sz(len(data)),
                                              data, _u32(0), None, None), "clEnqueueWriteBuffer")

    def read(self, buffer, size=None):
        size = size if size is not None else buffer.size
        out = (_c.c_uint8 * size)()
        _check(library().clEnqueueReadBuffer(_vp(self.queue), _vp(buffer.handle), _u32(1), _sz(0), _sz(size), out,
                                             _u32(0), None, None), "clEnqueueReadBuffer")
        return bytes(out)

    def finish(self):
        library().clFinish(_vp(self.queue))
