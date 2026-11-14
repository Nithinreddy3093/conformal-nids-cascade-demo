#!/usr/bin/env python3
"""Validate notebook JSON and syntax of its Python code cells for CI."""
from __future__ import annotations

import json
from pathlib import Path

NOTEBOOK = Path(__file__).with_name("CICIDS2017_Colab.ipynb")


def main():
    notebook = json.loads(NOTEBOOK.read_text(encoding="utf-8"))
    if notebook.get("nbformat") != 4 or not notebook.get("cells"):
        raise ValueError("Notebook is empty or not nbformat v4.")
    compiled = 0
    for index, cell in enumerate(notebook["cells"]):
        if cell.get("cell_type") != "code":
            continue
        source = cell.get("source", [])
        code = "".join(source) if isinstance(source, list) else str(source)
        # Strip IPython shell lines; remaining code must be valid Python.
        python_lines = [line for line in code.splitlines() if not line.lstrip().startswith("!")]
        compile("\n".join(python_lines), f"{NOTEBOOK.name}:cell-{index}", "exec")
        compiled += 1
    print(f"Validated notebook JSON and {compiled} Python code cells.")


if __name__ == "__main__":
    main()
