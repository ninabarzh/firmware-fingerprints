# DSL authoring

## Purpose

DSL (Domain Specific Language) files describe OT/ICS fingerprints in a human-readable form. They are used for:

* Identifying vulnerable firmware or unsafe operations.
* Feeding scanners without hardcoding protocol logic.

## Structure

1. Header Blocks

```dsl
FINGERPRINT fp-ics-example
VULNERABILITY "Description of issue"
CONFIDENCE high
SCOPE plc industrial_lan
NOTES "Optional descriptive text"
```

2. Evidence

```dsl
EVIDENCE {
   firmware:file /usr/bin/modbusd "No authentication"
   firmware:string "process_write_single_register"
}
```

3. Detection Steps

```dsl
DETECT {
   MODBUS PORT 502
   MODBUS FUNCTION 0x03
   MODBUS EXPECT response VALID
}
```

4. Optional Metadata

   * `VENDOR`, `PRODUCT`, `FIRMWARE`, `CWE`
   * `INDICATOR`, `IMPACT`

## Lab/Human notes

* Use consistent naming for fingerprints.
* Annotate unsafe steps with `SAFE false` if needed (for tagging only, not removal).
* Keep steps atomic: one action per line.
* Include comments inline using `#` for clarity in lab experiments.

## Workflow

1. Author `.dsl` file describing detection logic.
2. Validate using `validate_dsl.py`.
3. Compile to canonical JSON using `compile_json.py`.
4. Compile for scanner ingestion using `compile_nuclei.py`.