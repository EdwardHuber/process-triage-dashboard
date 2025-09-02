#!/usr/bin/env python3
"""
Memory Forensics Mini-Toolkit (Volatility 3 wrapper)
Focus: Memory forensics triage for DFIR (safe)

Runs a set of common Volatility 3 plugins against a memory image and
saves raw outputs + an index summary into a case folder.

Usage:
  python3 mf_triage.py -f mem.raw -o cases/CASE001
  python3 mf_triage.py -f mem.raw -o cases/CASE001 --plugins windows.pslist windows.netscan

Requires:
  - Volatility 3 in PATH (e.g., 'vol', 'vol.py', or 'volatility3')
  - Python 3.9+
"""
import argparse, os, subprocess, pathlib, sys, time, textwrap

DEFAULT_PLUGINS = [
    "windows.pslist",
    "windows.pstree",
    "windows.netscan",
    "windows.dlllist",
    "windows.cmdline",
    "windows.malfind"
]

CANDIDATE_CMDS = ["vol", "vol.py", "volatility3"]

def find_vol():
    for c in CANDIDATE_CMDS:
        try:
            r = subprocess.run([c, "-h"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if r.returncode in (0,1):
                return c
        except FileNotFoundError:
            continue
    return None

def run_plugin(volcmd, img, plugin, outpath, kargs=None):
    args = [volcmd, "-f", img, plugin]
    if kargs: args += kargs
    with open(outpath, "w", encoding="utf-8", errors="ignore") as f:
        subprocess.run(args, stdout=f, stderr=subprocess.STDOUT, text=True)

def main():
    ap = argparse.ArgumentParser(description="Volatility 3 wrapper for quick triage")
    ap.add_argument("-f","--file", required=True, help="Memory image (e.g., mem.raw)")
    ap.add_argument("-o","--outdir", required=True, help="Case output directory (e.g., cases/CASE001)")
    ap.add_argument("--plugins", nargs="*", default=DEFAULT_PLUGINS,
                    help="Plugins to run (e.g., windows.pslist windows.netscan)")
    args = ap.parse_args()

    vol = find_vol()
    if not vol:
        print("[!] Could not find Volatility 3 (tried: vol, vol.py, volatility3). Add it to PATH.", file=sys.stderr)
        sys.exit(2)

    outdir = pathlib.Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir/"raw").mkdir(exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")

    summary = [f"# Memory Forensics Triage — {stamp}",
               f"- Image: `{args.file}`",
               f"- Volatility: `{vol}`",
               f"- Plugins: {', '.join(args.plugins)}",
               "", "## Outputs"]

    for plg in args.plugins:
        safe = plg.replace(".","_")
        target = outdir/"raw"/f"{safe}.txt"
        print(f"[*] Running {plg} → {target}")
        run_plugin(vol, args.file, plg, target)
        summary.append(f"- `{target}`")

    hints = textwrap.dedent("""
    ## Quick Review Hints
    - pslist / pstree: odd parent-child pairs, short-lived procs, unusual names.
    - netscan: unexpected outbound connections, high ports, shells with net.
    - dlllist: unsigned or unusual DLL paths in user-writable dirs.
    - cmdline: suspicious flags, base64 strings, LOLBins.
    - malfind: injected code regions (follow up only in a lab environment).
    """).strip()

    (outdir/"INDEX.md").write_text("\n".join(summary)+ "\n\n" + hints + "\n", encoding="utf-8")
    print(f"[✓] Case saved to: {outdir}")

if __name__ == "__main__":
    main()
