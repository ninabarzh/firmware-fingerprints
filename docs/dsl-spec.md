Fingerprint DSL v1

Required blocks:
- FINGERPRINT <id>
- VULNERABILITY <internal_id> [CVE-XXXX-YYYY optional]
- DETECT <protocol>
- CONFIDENCE <low|medium|high>

Optional blocks:
- EVIDENCE
- SCOPE
- NOTES

Block rules:
- Blocks start with uppercase keyword
- Indentation is semantic inside blocks
- Lines starting with # are comments
