# Offensive Security Lab

Personal penetration-testing / security-research lab scripts.

## Scope and intent

This repository contains small, convenience scripts I wrote while learning wireless security workflows and basic automation. The goal is to understand the tooling and data formats involved (captures → conversion → offline analysis), not to provide a polished “one-click” solution.

**Authorized use only.** Run these scripts only on networks you own or where you have explicit written permission to test. Anything else may be illegal and harmful.

## What’s in this repo

- `capture_handshake.py`  
  A guided, “handshake-first” capture helper for **authorized** wireless testing. It orchestrates common wireless tooling to:
  - monitor traffic to help you identify a target,
  - capture traffic for a specific AP/channel,
  - verify whether a capture likely contains a usable authentication exchange,
  - convert captures to Hashcat’s modern `*.22000` format,
  - optionally capture a parallel radiotap `*.pcapng` and produce basic CSV artifacts for later analysis.

- `merge_list.py`  
  A wordlist merge/cleanup helper:
  - combines multiple `.txt` lists from a folder,
  - prioritizes “seed*” and “cupp*” style lists first,
  - filters to WPA(2/3)-PSK length constraints (8–63),
  - de-duplicates while preserving first-seen order,
  - prints basic merge statistics.

- `cracking_wifi.py`  
  A Windows-oriented Hashcat runner with simple file dialogs that helps you select:
  - your `hashcat.exe`,
  - a capture artifact (`*.22000` or legacy formats),
  - a wordlist,
  - an optional rule file,
  then runs an offline attack and writes recovered keys to an output file.

## Dependencies (high level)

These scripts are thin wrappers around existing tooling; they do not replace learning the underlying commands and concepts.

### `capture_handshake.py` (Linux / Kali-style environment)

- Python 3
- Sudo privileges
- Wireless adapter compatible with monitor mode (and, depending on your test case, injection)
- Common tools used by the script:
  - Aircrack-ng suite (e.g., monitoring/capture/validation utilities)
  - `iw`
  - HCX tools for conversion (`hcxpcapngtool`) and optional PMKID capture (`hcxdumptool`)
  - Optional for parallel capture and analysis:
    - `dumpcap` or `tshark` (for radiotap `pcapng`)
    - `tshark` (for CSV exports)

### `merge_list.py` (cross-platform)

- Python 3 with Tkinter support

### `cracking_wifi.py` (Windows)

- Python 3 with Tkinter support
- Hashcat installed (and correct GPU drivers for your system)
- A capture artifact in a Hashcat-compatible format (recommended: `*.22000`)

## Output artifacts (what to expect)

Depending on the script and options selected, you may see:

- Wireless capture artifacts: `*.cap`, optional `*.pcapng`
- Converted Hashcat artifacts: `*.22000`
- Optional analysis artifacts (when enabled): CSV exports summarizing EAPOL frames, beacon/RSN flags, and signal over time
- Hashcat results: a “found” output file containing recovered keys (format depends on the Hashcat outfile settings)

## Known limitations (current state)

These are early-stage scripts. Some limitations are expected:

- Minimal input validation and error handling (many commands are “best effort”).
- Environment assumptions (paths, installed tools, interface naming).
- The Windows Hashcat runner is intentionally basic and may require manual troubleshooting for driver/backend issues.
- The codebase is not yet structured as a package and does not include automated tests.

## Imperfection / learning note

These scripts reflect my understanding at the time I wrote them, and that understanding is still limited. They are not production-ready tooling. Some behavior may be unreliable across different adapters, drivers, and network configurations. Over time, I plan to:
- tighten safety checks,
- improve correctness and logging,
- make the workflows more reproducible,
- document assumptions more clearly.

## Roadmap / future improvements

Planned directions (subject to change):

- Better preflight checks (tool availability, permissions, interface sanity checks).
- Clearer logging, structured output folders, and consistent naming.
- More robust parsing/validation of capture quality and artifact conversion.
- Optional “dry run” mode and safer defaults for lab use.
- Integration experiments with AI tooling via MCP (e.g., agent-driven orchestration, guided checklists, smarter artifact triage), while keeping strict permission and safety boundaries.

## Non-goals

- Encouraging unauthorized access or misuse.
- Replacing foundational learning of wireless standards, tooling, and legal/ethical constraints.
- “Guaranteed cracking” or anything implying success outside an authorized lab context.
