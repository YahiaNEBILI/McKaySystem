"""Compatibility wrapper for worker runner entrypoint."""

from apps.worker.runner import main

__all__ = ["main"]


if __name__ == "__main__":
    import sys

    raise SystemExit(main(sys.argv[1:]))
