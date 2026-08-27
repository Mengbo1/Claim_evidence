from __future__ import annotations

import sys
from pathlib import Path

from .pipeline import DEFAULT_INPUT, DEFAULT_OUTPUT, run_pipeline


def main() -> None:
    input_path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_INPUT
    output_path = Path(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_OUTPUT
    print(run_pipeline(input_path, output_path))


if __name__ == "__main__":
    main()
