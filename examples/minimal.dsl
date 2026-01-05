FINGERPRINT fp-example-ping
VULNERABILITY DIVD-2026-0000

DETECT tcp
    PORT 80
    EXPECT open

CONFIDENCE low
NOTES Sanity check example
