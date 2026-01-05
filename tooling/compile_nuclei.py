from pathlib import Path
import json
from dsl_parser import parse_dsl
from validate_dsl import validate

# Output folder for compiled fingerprints
OUTPUT_DIR = Path("output/nuclei")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def compile_ot(fp: dict, metadata: dict | None = None):
    """
    Compile an OT/ICS fingerprint for scanners (Modbus, S7, OPC UA, DNP3).

    Parameters:
        fp: dict parsed from DSL
        metadata: dict from validate_dsl, may include 'unsafe_steps'

    Returns:
        dict suitable for scanner ingestion
    """
    # Get DETECT steps as list of lines
    detect_steps = fp.get("DETECT", [])
    if isinstance(detect_steps, str):
        detect_steps = detect_steps.splitlines()

    # Remove unsafe steps, but preserve inline comments
    if metadata and "unsafe_steps" in metadata:
        detect_steps = [
            s for s in detect_steps
            if s.split('#')[0].strip() not in metadata["unsafe_steps"]
        ]

    # Determine protocol (explicit PROTOCOL block preferred)
    proto = fp.get("PROTOCOL", "").upper()
    if not proto and detect_steps:
        proto = detect_steps[0].split()[0].upper()  # fallback

    # Default ports per protocol
    default_ports = {
        "MODBUS": 502,
        "S7COMM": 102,
        "OPCUA": 4840,
        "DNP3": 20000
    }
    port = int(fp.get("PORT", default_ports.get(proto, 102)))

    # Return compiled fingerprint
    return {
        "id": fp["FINGERPRINT"],
        "info": {
            "name": fp["VULNERABILITY"],
            "severity": fp["CONFIDENCE"]
        },
        "protocol": proto,
        "port": port,
        "inputs": detect_steps
    }


def compile_fingerprint(fp: dict, metadata: dict | None = None):
    """
    Dispatcher for OT/ICS fingerprints.
    Supports known OT/ICS protocols.
    """
    # Use explicit PROTOCOL first
    proto = fp.get("PROTOCOL", "").upper()

    # Fallback: infer from first DETECT step if PROTOCOL missing
    if not proto:
        detect_steps = fp.get("DETECT", [])
        if isinstance(detect_steps, str):
            detect_steps = detect_steps.splitlines()
        if not detect_steps:
            raise ValueError(f"Cannot compile {fp.get('FINGERPRINT')}: DETECT block empty")
        proto = detect_steps[0].split()[0].upper()

    if proto in ("MODBUS", "S7COMM", "OPCUA", "DNP3"):
        return compile_ot(fp, metadata)

    raise ValueError(f"Unsupported protocol {proto} in {fp.get('FINGERPRINT')}")


if __name__ == "__main__":
    import sys

    path = Path(sys.argv[1])

    # Parse the DSL into a dictionary
    fp = parse_dsl(path)

    # Validate DSL, get metadata about unsafe steps
    meta = validate(path, ci_mode=False)

    # Compile fingerprint into scanner-ready JSON
    compiled = compile_fingerprint(fp, metadata=meta)

    # Write output to output/nuclei/<FINGERPRINT>.json
    out_file = OUTPUT_DIR / f"{fp['FINGERPRINT']}.json"
    with open(out_file, "w") as f:
        json.dump(compiled, f, indent=2)

    print(f"Wrote compiled fingerprint to {out_file}")
