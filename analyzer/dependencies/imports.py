"""Standard library and runtime module registries for Python and Node.js."""

import sys
from typing import Set

# Python Standard Library Modules:
# Prefer authoritative sys.stdlib_module_names (available in Python 3.10+)
if hasattr(sys, "stdlib_module_names"):
    PYTHON_STDLIB_MODULES: Set[str] = set(sys.stdlib_module_names)
else:
    # Fallback builtin module set
    PYTHON_STDLIB_MODULES = set(sys.builtin_module_names) | {
        "os", "sys", "pathlib", "json", "time", "datetime", "re", "math",
        "random", "collections", "itertools", "functools", "typing",
        "subprocess", "shutil", "glob", "hashlib", "hmac", "uuid",
        "unittest", "doctest", "logging", "threading", "multiprocessing",
        "asyncio", "socket", "http", "urllib", "email", "sqlite3", "io",
    }

# Maintained Node.js / JavaScript Built-in Modules
NODE_BUILTIN_MODULES: Set[str] = {
    "assert",
    "async_hooks",
    "buffer",
    "child_process",
    "cluster",
    "console",
    "constants",
    "crypto",
    "dgram",
    "diagnostics_channel",
    "dns",
    "domain",
    "events",
    "fs",
    "fs/promises",
    "http",
    "http2",
    "https",
    "inspector",
    "module",
    "net",
    "os",
    "path",
    "path/posix",
    "path/win32",
    "perf_hooks",
    "process",
    "punycode",
    "querystring",
    "readline",
    "repl",
    "stream",
    "stream/promises",
    "stream/consumers",
    "string_decoder",
    "timers",
    "timers/promises",
    "tls",
    "trace_events",
    "tty",
    "url",
    "util",
    "util/types",
    "v8",
    "vm",
    "wasi",
    "worker_threads",
    "zlib",
}


def is_python_stdlib(module_name: str) -> bool:
    """Check if the root module identifier belongs to Python's standard library."""
    root_module = module_name.split(".")[0].lstrip(".")
    return root_module in PYTHON_STDLIB_MODULES


def is_node_builtin(module_name: str) -> bool:
    """Check if the import targets a Node.js built-in runtime module."""
    clean = module_name.strip()
    if clean.startswith("node:"):
        return True
    return clean in NODE_BUILTIN_MODULES
