# tooling/dsl_parser.py
from pathlib import Path
from typing import Dict, List, Union

def parse_dsl(path: Path) -> Dict[str, Union[str, List[str]]]:
    """
    Parses an OT/ICS firmware fingerprint DSL.

    Returns a dict where:
      - Blocks (DETECT, INDICATOR, etc.) become lists of lines
      - Key-value lines outside blocks become str values
      - Single-token lines outside blocks become key with None
    """
    data: Dict[str, Union[str, List[str]]] = {}
    current_block: str | None = None

    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # Start of block
        if line.endswith("{"):
            current_block = line[:-1].strip()
            data[current_block] = []
            continue

        # End of block
        if line == "}":
            current_block = None
            continue

        # Inside a block
        if current_block:
            data[current_block].append(line)
        else:
            parts = line.split(" ", 1)
            if len(parts) == 2:
                key, value = parts
                data[key] = value.strip().strip('"')
            else:
                # Single-token line outside block
                data[parts[0]] = None

    return data
