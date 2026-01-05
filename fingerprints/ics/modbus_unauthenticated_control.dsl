FINGERPRINT fp-ics-modbus-unauth-control
VULNERABILITY DIVD-2026-ICS-0003

EVIDENCE {
    firmware:file /usr/bin/modbusd "Modbus TCP daemon without authentication checks"
    firmware:string "process_write_single_register" "No access control before register write"
    firmware:string "0x06" "Write Single Register function enabled"
}

DETECT {
    MODBUS PORT 502
    MODBUS FUNCTION 0x03
    MODBUS EXPECT response VALID

    MODBUS FUNCTION 0x06
    MODBUS REGISTER 40001
    MODBUS VALUE 0x0001
    MODBUS EXPECT response ACCEPTED
}

CONFIDENCE high
SCOPE plc industrial_lan
NOTES Firmware allows unauthenticated Modbus register writes, enabling process manipulation or unsafe state changes
