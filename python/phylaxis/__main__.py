"""Console-script entry point: ``phylaxis ...`` and ``python -m phylaxis ...``."""

import sys

from ._native import cli_main


def main() -> int:
    return cli_main(sys.argv)


if __name__ == "__main__":
    sys.exit(main())
