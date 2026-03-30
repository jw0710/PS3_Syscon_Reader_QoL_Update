# PS3 RSX Advanced Patching Tool - SysconDiag

> **A modern GUI for PS3 Syscon operations, RSX patching, fan curve management, and built-in knowledge base**

[![License](https://img.shields.io/badge/license-Educational-blue.svg)](https://github.com/jw0710/PS3_Syscon_Reader_QoL_Update/blob/main/LICENSE)
[![Status](https://img.shields.io/badge/status-Early%20Access-orange.svg)](https://github.com/jw0710/PS3_Syscon_Reader_QoL_Update)
[![Python](https://img.shields.io/badge/python-3.x-blue.svg)](https://github.com/jw0710/PS3_Syscon_Reader_QoL_Update)

> ⚠️ **PRE-RELEASE — Use with care. Always authenticate before patching. No warranty provided.**

---

## Overview

SysconDiag is a professional GUI tool for PS3 hardware work — specifically designed for technicians doing RSX chip swaps, Syscon EEPROM modifications, and fan curve management on FAT consoles. It replaces tedious manual command entry with a clean, validated interface that keeps you from bricking your board.

**Requires:** A UART-TTL adapter (CP2102, CH340, FT232, etc.) connected to the PS3 Syscon testpads.

---

## Features at a Glance

| Feature | Description |
|---|---|
| CXR → CXRF Patcher | One-click switch between external/internal mode — fully automatic |
| RSX Patcher (40nm/65nm) | Model-aware one-click RSX patching after chip swaps |
| Fan Curve Editor | Multi-preset fan management, writes directly to Syscon — no CFW needed |
| Quick Commands | Fast access to common Syscon commands without typing |
| Undervolt | CELL & RSX voltage control via presets or manual sliders |
| Sysko Helper | Clippy-style assistant with UART pinout maps and error code reference |
| Sandbox Mode | Full simulation mode — test everything without real hardware |

---

## Screenshots

### CXR → CXRF Patcher

Fully automatic one-click switcher between external (CXR) and internal (CXRF/Mullion) mode on FAT consoles. No more manual EEPROM digging — select, authenticate, click.

![CXR Patcher](https://github.com/jw0710/PS3_Syscon_Reader_QoL_Update/raw/main/Screenshots/CRXPatcher.PNG)

---

### Quick Commands Tab

All the day-to-day Syscon commands in one place — error log, firmware checksum, temperatures, RTC, boot/error count. Hit the button, get the output. No manual typing needed.

![Quick Commands](https://github.com/jw0710/PS3_Syscon_Reader_QoL_Update/raw/main/Screenshots/quick_commands_Tab.PNG)

---

### Fan Curve Editor with Presets

Interactive fan curve editor with live graph visualization and drag-and-drop editing. Includes Stock, Quiet, and Performance presets. Writes directly to the Syscon EEPROM — **no CFW required, works on OFW.**

![Fan Curve Editor](https://github.com/jw0710/PS3_Syscon_Reader_QoL_Update/raw/main/Screenshots/FanCurve_with_PreSets.PNG)

---

### RSX Patcher (40nm / 65nm)

One-click RSX patch solution after RSX chip swaps (40nm or 65nm). Model-aware: separately handles AGB/BGB/CGB/DGB vs. GGB variants. No more manually looking up values — select, authenticate, patch.

![RSX Patcher](https://github.com/jw0710/PS3_Syscon_Reader_QoL_Update/raw/main/Screenshots/RSXPatcher40nm.PNG)

---

### Light Mode + Sysko Helper

Toggle between dark and light mode via the Apple-style switch in the top-right corner. Enabling the Sysko helper activates light mode automatically and places the Chippy mascot in the corner.

![Light Mode with Helper](https://github.com/jw0710/PS3_Syscon_Reader_QoL_Update/raw/main/Screenshots/lightmode_with_helper.PNG)

---

### Sysko Context Menu

Right-click (or left-click) Sysko to open the context menu. Gives quick access to serial connection point maps, the error code reference, and the setup guide — all without leaving the tool.

![Sysko Menu](https://github.com/jw0710/PS3_Syscon_Reader_QoL_Update/raw/main/Screenshots/SysKo_Menu.PNG)

---

### Sysko — UART Connection Points

From the Sysko menu, pull up model-specific UART testpad maps for every PS3 FAT and Slim variant. Images open in a built-in viewer — no browser, no external files to hunt down.

![Sysko UART Points](https://github.com/jw0710/PS3_Syscon_Reader_QoL_Update/raw/main/Screenshots/sysko_uart_points.PNG)

---

### Error Code Reference (Early Build)

Built-in error code knowledge base, accessible from Sysko. Currently an early build — the goal is a fully integrated, searchable all-in-one reference tool for PS3 Syscon diagnostics.

![Early Wiki](https://github.com/jw0710/PS3_Syscon_Reader_QoL_Update/raw/main/Screenshots/early_wiki.PNG)

---

## Requirements

### Hardware

- PS3 console (FAT or Slim)
- UART-TTL adapter (CP2102, CH340, FT232, or similar)
- USB cable

### Software

- Windows 10/11
- Python 3.10+ (source version)

### Python Dependencies

```
pip install pyserial customtkinter pycryptodome pillow matplotlib
```

---

## Installation

### From Source

```bash
git clone https://github.com/jw0710/PS3_Syscon_Reader_QoL_Update.git
cd PS3_Syscon_Reader_QoL_Update
pip install -r requirments.txt
python SysconDiag_PS3_v1_00.py
```

---

## Quick Start

1. **Connect** your UART adapter to the PS3 Syscon testpads (TX→RX, RX→TX, GND→GND)
2. **Select** the correct COM port and SC Type (CXR / CXRF / SW)
3. **Authenticate** — click `AUTH PS3` in the Advanced Patching tab before any patching
4. **Enable Sandbox Mode** if you want to test without real hardware

> Use the **Sysko** helper to find the correct UART testpads for your specific PS3 model.

---

## SC Type Reference

| Type | Console | Fan Control |
|---|---|---|
| **CXR** | FAT — standard Syscon | ❌ |
| **CXRF** | FAT — Mullion-patched Syscon | ✅ |
| **SW** | Slim consoles | ❌ |

Fan curve editing is only available in **CXRF** mode.

---

## Safety Features

- **AUTH gate** — RSX patching buttons are locked until authentication succeeds
- **Sandbox mode** — full dry-run simulation, no UART traffic sent
- **Checksum correction** — auto-detect and fix EEPROM checksum after writes
- **Temperature validation** — fan curve phases must be ascending, TMax > TMin enforced
- **T-Shutdown warning** — alerts on values above safe thresholds

---

## Credits

Built on community reverse engineering work:

- **M4j0r** (PSX-Place) — Syscon RE contributions
- **PSX-Place Community** — Frankenstein mod documentation and RSX swap research
- Reference thread: [Frankenstein PHAT PS3 CECHA with 40nm RSX](https://www.psx-place.com/threads/frankenstein-phat-ps3-cecha-with-40nm-rsx.28069/)

---

## Disclaimer

- Educational and private use only — no commercial use
- No affiliation with Sony Interactive Entertainment
- All trademarks belong to their respective owners
- **Use at your own risk** — no warranty, no liability

> If you use this tool or code in your own project, please credit back to this repository.

---

## License

See [LICENSE](LICENSE) for details.

---

*Made with care for the PS3 modding community — NostaMods*
