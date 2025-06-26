# NT(dll) Unhooker

A Windows security tool demonstrating a method to detect and remove inline hooks and IAT (Import Address Table) hooks from NTDLL.dll. This tool is particularly useful for security researchers, penetration testers, and malware analysts who need to restore the integrity of system DLLs that may have been hooked by security solutions or malicious software.

## Features

- **Inline Hook Detection**: Identifies and removes inline hooks in NTDLL.dll functions
- **IAT Hook Detection**: Detects and cleans Import Address Table hooks
- **Clean NTDLL Restoration**: Downloads and uses a clean version of NTDLL for comparison
- **Critical Function Protection**: Safely skips critical functions to prevent system instability

## How It Works

The tool works by:

1. **Loading NTDLL**: Dynamically loads NTDLL.dll using Windows API functions
2. **PE Analysis**: Parses the PE headers to extract function information
3. **Clean Comparison**: Downloads a clean version of NTDLL for comparison
4. **Hook Detection**: Compares the current NTDLL with the clean version to identify hooks
5. **Unhooking**: Restores original function code by overwriting hooked functions
6. **IAT Cleaning**: Removes any IAT hooks that redirect function calls

## Prerequisites

- Rust toolchain (latest stable version)
- Windows development environment

## Installation

```bash
# For development
cargo build

# For release (recommended)
cargo build --release

# For static linking
cargo rustc --release --bin ntdll-unhooker -- -C target-feature=+crt-static
```
