from pathlib import Path
import json

# Output folder for compiled nuclei fingerprints
OUTPUT_DIR = Path("output/nuclei")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def compile_ot(fp: dict) -> dict:
    """
    Compile an OT/ICS fingerprint for scanners (Modbus, S7, OPC UA, DNP3),
    tagging unsafe steps instead of removing them.
    """
    detect_steps = fp.get("DETECT", [])
    if isinstance(detect_steps, str):
        detect_steps = detect_steps.splitlines()

    unsafe_steps = set(fp.get("_metadata", {}).get("unsafe_steps", []))

    compiled_inputs = []
    for line in detect_steps:
        # Strip comments for matching against unsafe_steps
        code_part = line.split("#")[0].strip()
        step_entry = {"line": line}
        if code_part in unsafe_steps:
            step_entry["unsafe"] = True
        compiled_inputs.append(step_entry)

    proto = fp.get("PROTOCOL", "").upper()
    port = fp.get("PORT", 102)

    return {
        "id": fp["FINGERPRINT"],
        "info": {
            "name": fp["VULNERABILITY"],
            "severity": fp["CONFIDENCE"]
        },
        "protocol": proto,
        "port": port,
        "inputs": compiled_inputs
    }


def compile_fingerprint(fp: dict):
    proto = fp.get("PROTOCOL", "").upper()
    if proto in ("MODBUS", "S7COMM", "OPCUA", "DNP3"):
        return compile_ot(fp)
    raise ValueError(f"Unsupported protocol '{proto}' in {fp.get('FINGERPRINT')}")


if __name__ == "__main__":
    import sys

    for json_path_str in sys.argv[1:]:
        path = Path(json_path_str)
        try:
            with open(path) as f:
                fp = json.load(f)

            compiled = compile_fingerprint(fp)

            # Write output
            out_file = OUTPUT_DIR / f"{fp['FINGERPRINT']}.json"
            with open(out_file, "w") as f:
                json.dump(compiled, f, indent=2)

            print(f"Wrote compiled fingerprint to {out_file}")

        except Exception as e:
            print(f"{path}: ERROR -> {e}")
