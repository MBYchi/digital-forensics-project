import argparse
import getpass
import hashlib
import os
import platform
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("[!] PyYAML is missing. Install it with: pip install pyyaml")

HASH_ALGOS = ("md5", "sha1", "sha256", "sha512")
CHUNK = 4 * 1024 * 1024


class ReportDumper(yaml.SafeDumper):
    """Lists are indented under their key (foldable in an editor); no aliases."""

    def increase_indent(self, flow=False, indentless=False):
        return super().increase_indent(flow, False)

    def ignore_aliases(self, data):
        return True


def _str_representer(dumper, data):
    style = "|" if "\n" in data else None
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style=style)


ReportDumper.add_representer(str, _str_representer)


def dump_yaml(obj) -> str:
    return yaml.dump(obj, Dumper=ReportDumper, sort_keys=False, allow_unicode=True,
                     default_flow_style=False, indent=2, width=1_000_000)


def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def require_root():
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        sys.exit("[!] Root privileges required (sudo).")


def hash_bytes(data: bytes) -> dict:
    hs = {a: hashlib.new(a) for a in HASH_ALGOS}
    for h in hs.values():
        h.update(data)
    return {a: h.hexdigest() for a, h in hs.items()}


def hash_file(path, chunk_size=CHUNK, limit=None):
    """Reads a file/device once, computing all hashes at the same time. Returns (hashes, bytes)."""
    hs, total = {a: hashlib.new(a) for a in HASH_ALGOS}, 0
    with open(path, "rb") as f:
        while True:
            to_read = chunk_size if limit is None else min(chunk_size, limit - total)
            if to_read <= 0:
                break
            block = f.read(to_read)
            if not block:
                break
            for h in hs.values():
                h.update(block)
            total += len(block)
    return {a: h.hexdigest() for a, h in hs.items()}, total


def hash_device(dev, expected_bytes) -> dict:
    hashes, total = hash_file(dev, limit=expected_bytes)
    return {
        "path": str(dev),
        "scope": "entire block device as given, bytes 0 .. capacity-1 (sysfs size * 512)",
        "bytes_hashed": total, "expected_bytes": expected_bytes,
        "complete": (total == expected_bytes) if expected_bytes is not None else None,
        "hashes": hashes,
    }


def sysfs_path(device) -> Path:
    return Path("/sys/class/block") / Path(os.path.realpath(device)).name


def read_text(path):
    try:
        return Path(path).read_text().strip()
    except Exception:  # noqa: BLE001
        return None


def read_int(path):
    try:
        return int(read_text(path))
    except (TypeError, ValueError):
        return None


def device_size(dev):
    sectors = read_int(sysfs_path(dev) / "size")
    return sectors * 512 if sectors is not None else None


def is_read_only(dev):
    """sysfs ro flag. None = not applicable / unknown."""
    v = read_int(sysfs_path(dev) / "ro")
    return None if v is None else v == 1


def script_info() -> dict:
    h = hash_file(__file__)[0]
    return {"name": Path(__file__).name, **h}


def workstation_info() -> dict:
    u = platform.uname()
    return {"hostname": u.node, "user": getpass.getuser(),
            "os": platform.platform(), "kernel": f"{u.release} {u.version}",
            "machine": u.machine, "python": platform.python_version(),
            "script": script_info()}


def write_hashes_txt(path: Path):
    """Writes <file>.hashes.txt; returns (hashes_path, hashes)."""
    fh, _ = hash_file(path)
    hpath = path.with_name(path.name + ".hashes.txt")
    hpath.write_text("".join(f"{a.upper()} ({path.name}) = {fh[a]}\n" for a in HASH_ALGOS),
                     encoding="utf-8")
    return hpath, fh


def write_report(path: Path, report: dict):
    """Atomic YAML write + .hashes.txt. Returns (hashes_path, hashes)."""
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(dump_yaml(report), encoding="utf-8")
    tmp.replace(path)
    return write_hashes_txt(path)


def finish_case(report: dict, status: str, t0: float):
    report["case"]["finished_utc"] = now_utc()
    report["case"]["duration_s"] = round(time.monotonic() - t0, 2)
    report["case"]["status"] = status


def print_summary(status, files: dict, hashes: dict):
    print(f"\n[{'+' if status == 'COMPLETED' else '!'}] Status: {status}")
    for label, p in files.items():
        print(f"    {label:<7}: {p}")
    for a in HASH_ALGOS:
        print(f"    {a.upper():<7}: {hashes[a]}")


def clone(src_path, dst_path, chunk_size=CHUNK):
    total = 0
    with open(src_path, "rb") as src, open(dst_path, "wb") as dst:
        while True:
            block = src.read(chunk_size)
            if not block:
                break
            dst.write(block)
            total += len(block)
        dst.flush()
        os.fsync(dst.fileno())
    return total


def source_size(path):
    with open(path, "rb") as f:
        return f.seek(0, os.SEEK_END)


def main():
    ap = argparse.ArgumentParser(description="Binary copy of media -> image + YAML report + hashes.")
    ap.add_argument("--device", required=True, help="block device, e.g. /dev/sdb")
    ap.add_argument("--case-dir", required=True, help="case directory (NOT on the examined media)")
    ap.add_argument("--evidence-id", required=True)
    ap.add_argument("--examiner", required=True)
    ap.add_argument("--rehash-source", action="store_true",
                    help="additionally compute the source hash AFTER imaging")
    a = ap.parse_args()
    require_root()

    src = a.device
    out_dir = Path(a.case_dir) / "binary_copy"
    out_dir.mkdir(parents=True, exist_ok=True)
    dst = out_dir / f"{a.evidence_id}_{Path(src).name}.img"
    if os.path.abspath(src) == os.path.abspath(dst):
        sys.exit("[!] Source and destination are the same file.")
    yaml_path = dst.with_name(dst.name + ".yaml")
    total_steps = 5 if a.rehash_source else 4

    report = {
        "case": {"evidence_id": a.evidence_id, "examiner": a.examiner,
                 "device": src, "started_utc": now_utc(), "finished_utc": None,
                 "status": "IN_PROGRESS"},
        "workstation": {
            **workstation_info(),
            "algorithms": list(HASH_ALGOS), "chunk_size_bytes": CHUNK,
            "workflow": ["hash source BEFORE imaging",
                         "imaging (copy source -> image)",
                         "hash image"]
                        + (["hash source AFTER imaging"] if a.rehash_source else []),
        },
        "source": {"path": src, "read_only": is_read_only(src)},
        "image": {"path": str(dst)},
        "result": {}, "warnings": [],
    }
    w = report["warnings"]
    if report["source"]["read_only"] is False:
        w.append("Source is NOT read-only (sysfs ro=0) - no write protection.")
    elif report["source"]["read_only"] is None:
        w.append("Cannot verify read-only status (not a block device or sysfs unavailable).")

    status, t0 = "COMPLETED", time.monotonic()
    try:
        report["source"]["size_bytes"] = source_size(src)

        print(f"[1/{total_steps}] Hashing source BEFORE imaging...")
        before, n_before = hash_file(src)
        report["source"]["hashes_before"] = before
        report["source"]["bytes_hashed_before"] = n_before

        print(f"[2/{total_steps}] Imaging...")
        n_copied = clone(src, dst)
        report["image"]["bytes_written"] = n_copied

        print(f"[3/{total_steps}] Hashing image...")
        img_hash, n_img = hash_file(dst)
        report["image"]["size_bytes"] = n_img
        report["image"]["hashes"] = img_hash

        checks = {
            "before_equals_image": before == img_hash,
            "size_match": n_before == n_copied == n_img,
        }
        if a.rehash_source:
            print(f"[4/{total_steps}] Hashing source AFTER imaging...")
            after, _ = hash_file(src, limit=n_copied)
            report["source"]["hashes_after"] = after
            checks["before_equals_after"] = before == after

        report["result"] = {"all_checks_passed": all(checks.values()), "checks": checks}

        if not checks.get("before_equals_after", True):
            w.append("Source changed between hashing and/or imaging!")
            status = "FAILED_SOURCE_CHANGED"
        elif not (checks["before_equals_image"] and checks["size_match"]):
            status = "FAILED_HASH_MISMATCH"
    except PermissionError:
        status = "FAILED_PERMISSION"
        w.append("Permission denied (run as root/Administrator).")
    except Exception as exc:  # noqa: BLE001
        status = "FAILED_ERROR"
        w.append(f"{type(exc).__name__}: {exc}")

    finish_case(report, status, t0)
    print(f"[{total_steps}/{total_steps}] Writing report...")
    hpath, fh = write_report(yaml_path, report)
    print_summary(status, {"Image": dst, "YAML": yaml_path, "Hashes": hpath}, fh)
    sys.exit(0 if status == "COMPLETED" else 1)


if __name__ == "__main__":
    main()
