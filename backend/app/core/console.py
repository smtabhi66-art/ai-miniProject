"""Console helpers for the command-line demos."""
import sys


def utf8_output() -> None:
    """Print logic symbols (∧ ⊢ ¬ →) even on Windows consoles that default to cp1252."""
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
