"""Command line interface package for CodeSentinel."""

def main(argv=None):
    from analyzer.cli.main import main as _main
    return _main(argv)

__all__ = ["main"]
