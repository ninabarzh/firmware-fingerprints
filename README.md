# Firmware fingerprints

Translate DSL to scanner edible output (Human-readable OT/ICS fingerprints (Modbus, S7, OPC UA, DNP3), compiled for scanners).

## Structure

- `fingerprints/`: DSL definitions  
- `output/json/`: canonical JSON from DSL  
- `output/nuclei/`: scanner-ready nuclei JSON  
- `tooling/`: validation and compilation scripts

## Workflow

1. Validate DSL  
   
```bash
python tooling/validate_dsl.py fingerprints/ics/<name>.dsl
```

2. Compile JSON

```bash
python tooling/compile_json.py fingerprints/ics/<name>.dsl
```

3. Compile for scanners

```bash
python tooling/compile_nuclei.py output/json/<name>.json
```

Unsafe steps are tagged in the JSON; they are not removed.

## Requirements

* Python 3.12+
* Standard library only
