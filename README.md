# Memory Forensics Mini-Toolkit (Volatility 3 Wrapper)

A small Python wrapper that runs common **Volatility 3** plugins against a memory image and saves outputs into a structured **case folder**.

> For **training and authorized DFIR use only**. This tool is read-only—no execution or sample modification.

## Requirements
- Volatility 3 installed or available in PATH as `vol`, `vol.py`, or `volatility3`
- Python 3.9+

## Usage
```bash
# basic triage
python3 mf_triage.py -f mem.raw -o cases/CASE001

# choose specific plugins
python3 mf_triage.py -f mem.raw -o cases/CASE001 --plugins windows.pslist windows.netscan
