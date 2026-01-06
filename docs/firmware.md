# Firmware Extraction (BIN / ELF)

## Overview

Firmware comes in different formats—commonly raw binaries (`.bin`) or Executable and Linkable 
Format (`.elf`). Extracting firmware is the first step for reverse engineering, vulnerability 
research, or creating fingerprints.

## Methods

1. From devices

   * Use JTAG, SWD, UART, or SPI to read memory directly.
   * Some PLCs or embedded devices allow firmware downloads via maintenance ports.

2. From firmware images

   * Manufacturers often provide update packages.
   * `.bin` files may contain raw flash contents.
   * `.elf` files contain symbols, sections, and debug info if not stripped.

3. Tools

   * `binwalk` – detect embedded files, compressions, and extract components.
   * `readelf` / `objdump` – inspect ELF sections, symbols, and headers.
   * `hexdump` / `xxd` – basic binary inspection.
   * `strings` – find readable text such as function names or constants.

## Notes

* Work on copies; never modify the original firmware.
* Record MD5/SHA256 hashes for integrity.
* Document offsets of interesting sections (register maps, strings, routines).
* Note endianness and processor architecture before analysis.

## Resources

### Tools

* [Binwalk](https://github.com/ReFirmLabs/binwalk) – scan and extract firmware images.
* [Firmware Mod Kit](https://github.com/rampageX/firmware-mod-kit) – modify and analyze firmware.
* [Radare2](https://rada.re/n/) – reverse engineering and binary analysis.
* [Ghidra](https://ghidra-sre.org/) – free reverse engineering suite, ELF/BIN support.
* `readelf` / `objdump` – inspect ELF headers, symbols, and sections.
* `hexdump` / `xxd` / `strings` – basic binary inspection.

### Guides

* ReFirm Labs: [Firmware Analysis & Extraction](https://www.refirmlabs.com/) (blog & whitepapers)
* Offensive Security: [Firmware Analysis Cheat Sheet](https://www.offensive-security.com/)
* Embedded Security Learning: [JTAG / SWD Tutorials](https://www.embedded.com/)
* [Foraging for secrets in binaries](https://red.tymyrddin.dev/docs/through/reverse-engineering/)
