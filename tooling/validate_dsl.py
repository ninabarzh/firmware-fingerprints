import sys
from pathlib import Path
from dsl_parser import parse_dsl

# Required blocks
REQUIRED = {"FINGERPRINT", "VULNERABILITY", "DETECT", "CONFIDENCE"}
CONFIDENCE_VALUES = {"low", "medium", "high"}

# Protocol rules
PROTOCOL_RULES = {
    "modbus": {
        "PORTS": range(1, 65536),
        "FUNCTION_CODES": range(1, 0x11),
        "STEPS": {"FUNCTION", "SAFE", "PORT"}  # allowed first tokens
    },
    "s7": {
        "PORTS": [102],
        "STEPS": {"S7_SETUP_COMM", "S7_READ_SZL", "S7_WRITE_REG", "SAFE", "PORT"}
    },
    "opcua": {
        "PORTS": [4840],
        "STEPS": {"OPCUA_CONNECT", "OPCUA_READ", "OPCUA_WRITE", "SAFE", "PORT"}
    },
    "dnp3": {
        "PORTS": [20000],
        "STEPS": {"DNP3_READ", "DNP3_WRITE", "SAFE", "PORT"}
    }
}

# Allowed evidence types
ALLOWED_EVIDENCE = {"firmware:file", "firmware:string", "firmware:regex", "firmware:sha256", "firmware:offset"}

# CI mode flag
CI_MODE = True  # If True, unsafe steps raise an error


def validate_protocol_step(protocol, step_line, path):
    rules = PROTOCOL_RULES.get(protocol, {})
    parts = step_line.split()
    if not parts:
        return

    first_token = parts[0]

    # If first token is not in the protocol's allowed steps, treat as protocol-neutral
    if rules and first_token not in rules.get("STEPS", {}):
        return

    # Port check
    if "PORT" in parts:
        try:
            port = int(parts[1])
        except ValueError:
            raise ValueError(f"{path}: PORT must be numeric, got '{parts[1]}'")
        if "PORTS" in rules and port not in rules["PORTS"]:
            raise ValueError(f"{path}: PORT {port} invalid for protocol {protocol}")

    # Modbus function code
    if protocol == "modbus" and first_token == "FUNCTION":
        try:
            code = int(parts[1], 16)
        except ValueError:
            raise ValueError(f"{path}: Modbus FUNCTION code must be hex, got '{parts[1]}'")
        if code not in rules["FUNCTION_CODES"]:
            raise ValueError(f"{path}: Modbus function code 0x{code:X} invalid")

    # Safe flag
    if first_token == "SAFE":
        val = parts[1].lower()
        if val not in {"true", "false"}:
            raise ValueError(f"{path}: SAFE must be true/false, got '{parts[1]}'")
        if CI_MODE and val == "false":
            raise ValueError(f"{path}: Unsafe step (SAFE false) not allowed in CI mode")
        return {"unsafe": val == "false"}


def validate_multi_step(detect_block, path):
    """
    Ensure each step is well-formed and no mixed unsafe/safe steps.
    Returns metadata about unsafe steps for scanners if needed.
    """
    steps = [l for l in detect_block if l.strip() and not l.strip().startswith("#")]
    metadata = {"unsafe_steps": []}

    for step in steps:
        protocol = step.split()[0].lower()
        result = validate_protocol_step(protocol, step, path)
        if result and result.get("unsafe"):
            metadata["unsafe_steps"].append(step)

    return metadata


def validate_evidence(evidence_block, path):
    for ev in evidence_block:
        parts = ev.strip().split(None, 1)  # split on first whitespace
        if len(parts) < 2:
            raise ValueError(f"{path}: EVIDENCE line incomplete: {ev}")
        typ_token, _ = parts
        if typ_token not in ALLOWED_EVIDENCE:
            raise ValueError(f"{path}: Unsupported evidence type '{typ_token}' in line: {ev}")


def validate(path: Path, ci_mode: bool = True):
    global CI_MODE
    CI_MODE = ci_mode

    data = parse_dsl(path)

    # 1. Required blocks
    missing = REQUIRED - data.keys()
    if missing:
        raise ValueError(f"{path}: missing required blocks: {missing}")

    # 2. Confidence
    if data["CONFIDENCE"].lower() not in CONFIDENCE_VALUES:
        raise ValueError(f"{path}: invalid CONFIDENCE '{data['CONFIDENCE']}'")

    # 3. DETECT validation
    detect_block = data.get("DETECT")
    if detect_block is None:
        raise ValueError(f"{path}: DETECT block missing")
    if isinstance(detect_block, str):
        detect_block = detect_block.splitlines()
    elif not isinstance(detect_block, list):
        detect_block = [str(detect_block)]

    metadata = validate_multi_step(detect_block, path)

    # 4. EVIDENCE validation
    evidence_block = data.get("EVIDENCE", [])
    validate_evidence(evidence_block, path)

    return metadata  # could be used by scanner


if __name__ == "__main__":
    for p in map(Path, sys.argv[1:]):
        try:
            meta = validate(p, ci_mode=True)
            print(f"{p}: OK")
            if meta.get("unsafe_steps"):
                print(f"  Unsafe steps detected: {meta['unsafe_steps']}")
        except Exception as e:
            print(f"{p}: ERROR -> {e}")
