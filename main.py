import argparse
import hashlib
import hmac
import re
import subprocess
import sys
from pathlib import Path

BASE = Path("/home/user")
JOBS = {
    "ro_mount": "ro_mount.py",
    "file inventory": "file_inventory_disk.py",
    "metadata": "metadata_collector.py",
    "binary copy": "binary_copy.py",
    "verify": None,  # built-in job
}

LINE_RE = re.compile(r"^(MD5|SHA1|SHA224|SHA256|SHA384|SHA512)\s*\((.+)\)\s*=\s*([0-9a-fA-F]+)\s*$")


def job_verify(job_args):
    p = argparse.ArgumentParser(prog="main.py --job verify")
    p.add_argument("--file", required=True, help="path to the file to verify")
    p.add_argument("--hashes", required=True, help="path to the txt file with hashes")
    a = p.parse_args(job_args)

    target, hash_file = Path(a.file), Path(a.hashes)
    for f in (target, hash_file):
        if not f.is_file():
            print(f"[!] File not found: {f}")
            return 2

    expected = {}
    for line in hash_file.read_text().splitlines():
        m = LINE_RE.match(line.strip())
        if m:
            algo, name, digest = m.groups()
            expected[algo.lower()] = (name, digest.lower())
    if not expected:
        print("[!] No valid hash lines found in the hash file")
        return 2

    hashers = {algo: hashlib.new(algo) for algo in expected}
    with open(target, "rb") as fh:
        while chunk := fh.read(1024 * 1024):
            for h in hashers.values():
                h.update(chunk)

    ok = True
    for algo, (name, exp) in expected.items():
        got = hashers[algo].hexdigest()
        match = hmac.compare_digest(got, exp)
        ok &= match
        print(f"[{'OK' if match else 'FAIL'}] {algo.upper():7} {name}")
        if not match:
            print(f"         expected: {exp}\n         got:      {got}")
    if Path(next(iter(expected.values()))[0]).name != target.name:
        print(f"[i] Note: name in hash file differs from {target.name}")

    print("\nVERIFIED" if ok else "\nVERIFICATION FAILED")
    return 0 if ok else 1


parser = argparse.ArgumentParser(description="Launcher. Remaining args go to the selected job.")
parser.add_argument("--job", required=True, choices=JOBS)
args, job_args = parser.parse_known_args()

if args.job == "verify":
    sys.exit(job_verify(job_args))

cmd = [sys.executable, str(BASE / JOBS[args.job]), *job_args]
sys.exit(subprocess.run(cmd, cwd=BASE).returncode)