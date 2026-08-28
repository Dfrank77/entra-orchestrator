"""Run all three scanners, correlate, and render the report.

Each scanner is a sibling repo that authenticates independently and
writes findings to the shared entra_security_report store. This
script launches them as subprocesses so each one keeps its own
virtual environment and entry point. After all three finish, it
runs the correlation and opens the HTML report.

Usage:
    python orchestrate.py          # run all three, then correlate
    python orchestrate.py --only workload attack-path zt-policy
    python orchestrate.py --skip workload
"""

import argparse
import subprocess
import sys
import os
import time

# Paths are relative to the parent of this repo (sibling repos)
BASE = os.path.dirname(os.path.abspath(__file__))
PROJECTS = os.path.dirname(BASE)

SCANNERS = {
    "workload": {
        "label": "Workload Identity Scanner",
        "cwd": os.path.join(PROJECTS, "entra-workload-identity-scanner"),
        "cmd": [os.path.join(".venv", "bin", "python"), "scan.py"],
    },
    "attack-path": {
        "label": "Attack Path Visualizer",
        "cwd": os.path.join(PROJECTS, "entra-attack-path-visualizer"),
        "cmd": [os.path.join("venv", "bin", "python"), "entra_scanner.py"],
    },
    "zt-policy": {
        "label": "Zero Trust Policy Engine",
        "cwd": os.path.join(PROJECTS, "entra-zt-policy-engine", "audit"),
        "cmd": [os.path.join("..", "venv", "bin", "python"), "audit.py"],
    },
}

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"


def run_scanner(key, info):
    """Run one scanner as a subprocess, streaming output in real time."""
    print(f"\n{CYAN}{'=' * 60}{RESET}")
    print(f"{CYAN}  {info['label']}{RESET}")
    print(f"{CYAN}{'=' * 60}{RESET}\n")

    if not os.path.isdir(info["cwd"]):
        print(f"{RED}  Directory not found: {info['cwd']}{RESET}")
        print(f"{RED}  Skipping {info['label']}.{RESET}")
        return False

    start = time.time()
    try:
        result = subprocess.run(
            info["cmd"],
            cwd=info["cwd"],
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        )
        elapsed = time.time() - start

        if result.returncode == 0:
            print(f"\n{GREEN}  {info['label']} completed in {elapsed:.1f}s{RESET}")
            return True
        else:
            print(f"\n{RED}  {info['label']} exited with code {result.returncode} ({elapsed:.1f}s){RESET}")
            return False
    except FileNotFoundError:
        print(f"{RED}  Could not find Python interpreter for {info['label']}.{RESET}")
        print(f"{RED}  Make sure the virtual environment is set up.{RESET}")
        return False
    except KeyboardInterrupt:
        print(f"\n{YELLOW}  {info['label']} interrupted.{RESET}")
        return False


def run_correlation():
    """Run correlate.py to join findings and render the report."""
    print(f"\n{CYAN}{'=' * 60}{RESET}")
    print(f"{CYAN}  Correlating findings across tools{RESET}")
    print(f"{CYAN}{'=' * 60}{RESET}\n")

    result = subprocess.run(
        [os.path.join("venv", "bin", "python"), "correlate.py"],
        cwd=BASE,
    )
    return result.returncode == 0


def main():
    parser = argparse.ArgumentParser(
        description="Run Entra ID security scanners and correlate findings."
    )
    parser.add_argument(
        "--only",
        nargs="+",
        choices=list(SCANNERS.keys()),
        help="Run only these scanners (then correlate).",
    )
    parser.add_argument(
        "--skip",
        nargs="+",
        choices=list(SCANNERS.keys()),
        help="Skip these scanners (run the rest, then correlate).",
    )
    parser.add_argument(
        "--no-correlate",
        action="store_true",
        help="Run scanners but skip correlation.",
    )
    args = parser.parse_args()

    # Decide which scanners to run
    if args.only:
        keys = args.only
    elif args.skip:
        keys = [k for k in SCANNERS if k not in args.skip]
    else:
        keys = list(SCANNERS.keys())

    print(f"{CYAN}Entra Orchestrator{RESET}")
    print(f"Running: {', '.join(SCANNERS[k]['label'] for k in keys)}")

    results = {}
    for key in keys:
        results[key] = run_scanner(key, SCANNERS[key])

    # Summary
    print(f"\n{CYAN}{'=' * 60}{RESET}")
    print(f"{CYAN}  Scanner Summary{RESET}")
    print(f"{CYAN}{'=' * 60}{RESET}")
    for key in keys:
        status = f"{GREEN}OK{RESET}" if results[key] else f"{RED}FAILED{RESET}"
        print(f"  {SCANNERS[key]['label']:40s} {status}")

    if args.no_correlate:
        print(f"\n{YELLOW}  Skipping correlation (--no-correlate).{RESET}")
        sys.exit(0)

    # Correlate
    if not run_correlation():
        print(f"\n{RED}  Correlation failed.{RESET}")
        sys.exit(1)

    # Generate unified report across all tools
    print(f"\n{CYAN}{'=' * 60}{RESET}")
    print(f"{CYAN}  Generating unified report{RESET}")
    print(f"{CYAN}{'=' * 60}{RESET}\n")

    result = subprocess.run(
        [os.path.join("venv", "bin", "python"), "unified_report.py"],
        cwd=BASE,
    )
    if result.returncode != 0:
        print(f"{RED}  Unified report failed.{RESET}")

    print(f"\n{GREEN}Done.{RESET}")
    print(f"  Correlation report: orchestrator_report.html")
    print(f"  Unified report:     unified_report.html")


if __name__ == "__main__":
    main()
