from pathlib import Path
import json
from dsl_parser import parse_dsl
from validate_dsl import validate

# Output folder for canonical JSON
OUTPUT_DIR = Path("output/json")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

def compile_json(fp: dict, metadata: dict | None = None) -> dict:
    """
    Compile a canonical JSON representation of an OT/ICS fingerprint.

    Parameters:
        fp: dict parsed from DSL
        metadata: dict from validate_dsl, may include 'unsafe_steps'

    Returns:
        dict suitable for storage or further compilation into scanner formats
    """
    # DETECT steps as list of lines
    detect_steps = fp.get("DETECT", [])
    if isinstance(detect_steps, str):
        detect_steps = detect_steps.splitlines()
    elif not isinstance(detect_steps, list):
        detect_steps = [str(detect_steps)]

    # Determine PROTOCOL: explicit first, else infer from first DETECT line
    proto = fp.get("PROTOCOL")
    if not proto and detect_steps:
        proto = detect_steps[0].split()[0].upper()

    # Determine PORT: explicit first, else default per protocol
    port = fp.get("PORT")
    default_ports = {
        "MODBUS": 502,
        "S7COMM": 102,
        "OPCUA": 4840,
        "DNP3": 20000
    }
    if port is None:
        port = default_ports.get(proto.upper(), 102)

    # Preserve metadata
    meta = metadata or {}
    compiled = {
        "FINGERPRINT": fp["FINGERPRINT"],
        "VULNERABILITY": fp.get("VULNERABILITY", ""),
        "CONFIDENCE": fp.get("CONFIDENCE", "medium"),
        "PROTOCOL": proto.upper() if proto else "",
        "PORT": port,
        "DETECT": detect_steps,
        "_metadata": meta
    }

    # Optional: copy extra fields if present
    for k in ("SCOPE", "NOTES", "VENDOR", "PRODUCT", "FIRMWARE", "CWE", "INDICATOR", "IMPACT"):
        if k in fp:
            compiled[k] = fp[k]

    return compiled

if __name__ == "__main__":
    import sys

    for path_str in sys.argv[1:]:
        path = Path(path_str)
        try:
            # Parse DSL
            fp = parse_dsl(path)

            # Validate, record unsafe steps metadata
            meta = validate(path, ci_mode=False)

            # Compile canonical JSON
            compiled = compile_json(fp, metadata=meta)

            # Write to output/json/<FINGERPRINT>.json
            out_file = OUTPUT_DIR / f"{fp['FINGERPRINT']}.json"
            with open(out_file, "w") as f:
                json.dump(compiled, f, indent=2)

            print(f"Wrote canonical JSON to {out_file}")

        except Exception as e:
            print(f"{path}: ERROR -> {e}")
