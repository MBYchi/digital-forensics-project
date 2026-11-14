import argparse
import csv
import getpass
import hashlib
import os
import platform
import re
import stat
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


def iso(ts):
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="seconds")


def unescape(s):
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), s)


def mount_info(mp):
    found = (None, None, None)
    with open("/proc/self/mountinfo") as f:
        for line in f:
            p = line.split()
            if unescape(p[4]) == mp:
                sep = p.index("-")
                found = (p[5].split(","), p[sep + 1], unescape(p[sep + 2]))
    return found


def ftype(m):
    for name, fn in (("file", stat.S_ISREG), ("dir", stat.S_ISDIR),
                     ("symlink", stat.S_ISLNK), ("other", lambda x: True)):
        if fn(m):
            return name


def walk(root, writer, stats, errors):
    stack = [root]
    while stack:
        d = stack.pop()
        try:
            with os.scandir(d) as it:
                entries = sorted(it, key=lambda e: e.name)
        except OSError as e:
            errors.append({"path": os.path.relpath(d, root), "op": "scandir", "error": str(e)})
            continue
        for e in entries:
            rel = os.path.relpath(e.path, root)
            try:
                st = e.stat(follow_symlinks=False)
            except OSError as ex:
                errors.append({"path": rel, "op": "stat", "error": str(ex)})
                continue
            t = ftype(st.st_mode)
            hs = {a: "" for a in HASH_ALGOS}
            target = ""
            if t == "dir":
                stack.append(e.path)
                stats["dirs"] += 1
            elif t == "symlink":
                target = os.readlink(e.path)
                stats["symlinks"] += 1
            elif t == "file":
                stats["files"] += 1
                stats["bytes"] += st.st_size
                try:
                    hs, _ = hash_file(e.path)
                except OSError as ex:
                    errors.append({"path": rel, "op": "read", "error": str(ex)})
            else:
                stats["other"] += 1
            writer.writerow([rel, t, st.st_size, iso(st.st_mtime), iso(st.st_atime),
                             iso(st.st_ctime), oct(stat.S_IMODE(st.st_mode)), st.st_uid,
                             st.st_gid, st.st_ino, st.st_nlink, target,
                             *[hs[a] for a in HASH_ALGOS]])


def main():
    ap = argparse.ArgumentParser(description="File inventory of a mounted disk")
    ap.add_argument("--device", required=True, help="block device, e.g. /dev/sdb")
    ap.add_argument("--case-dir", required=True, help="case directory (NOT on the examined media)")
    ap.add_argument("--evidence-id", required=True)
    ap.add_argument("--examiner", required=True)
    ap.add_argument("--mountpoint", required=True, help="e.g. /mnt/evidence (must be mounted from --device)")
    a = ap.parse_args()
    require_root()

    root = os.path.realpath(a.mountpoint)
    opts, fstype, mount_source = mount_info(root)
    if opts is None:
        sys.exit(f"[!] ABORT: {root} is not a mount point (check: findmnt {root})")
    dev = os.path.realpath(a.device)
    if mount_source is None or os.path.realpath(mount_source) != dev:
        sys.exit(f"[!] ABORT: --device {a.device} is not the source of {root} "
                 f"(mount source: {mount_source})")
    ro = "ro" in opts
    if not ro:
        sys.exit(f"[!] ABORT: {root} is not mounted read-only (options: {','.join(opts)})")

    out_dir = (Path(a.case_dir) / "file_inventory").resolve()
    if str(out_dir).startswith(root + os.sep) or str(out_dir) == root:
        sys.exit("[!] ABORT: the case directory is on the examined disk")
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = f"{a.evidence_id}_{Path(a.device).name}"
    csv_path = out_dir / f"{stem}_files.csv"
    yaml_path = out_dir / f"{stem}.yaml"

    report = {
        "case": {"evidence_id": a.evidence_id, "examiner": a.examiner,
                 "device": a.device, "started_utc": now_utc(), "finished_utc": None,
                 "status": "IN_PROGRESS"},
        "workstation": {**workstation_info(), "algorithms": list(HASH_ALGOS),
                        "chunk_size_bytes": CHUNK},
        "source": {"mountpoint": root, "device": mount_source, "fstype": fstype,
                   "mount_options": opts, "read_only": ro},
        "device_hashes": {}, "result": {}, "warnings": [],
    }
    w = report["warnings"]
    stats = {"files": 0, "dirs": 0, "symlinks": 0, "other": 0, "bytes": 0}
    errors = []
    status, t0 = "COMPLETED", time.monotonic()
    try:
        print("[1/3] Walking and hashing files...")
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["path", "type", "size", "mtime_utc", "atime_utc", "ctime_utc",
                             "mode", "uid", "gid", "inode", "nlink", "symlink_target",
                             *HASH_ALGOS])
            walk(root, writer, stats, errors)

        print("[2/3] Device hash (full read)...")
        try:
            dh = hash_device(dev, device_size(dev))
            report["device_hashes"]["target"] = dh
            if dh["complete"] is False:
                w.append(f"device hash incomplete: {dh['bytes_hashed']} of "
                         f"{dh['expected_bytes']} bytes read")
            elif dh["complete"] is None:
                w.append("device hash: capacity unknown, hashed until EOF")
        except Exception as exc:  # noqa: BLE001
            w.append(f"device hash {dev}: {type(exc).__name__}: {exc}")
        csv_hpath, csv_hashes = write_hashes_txt(csv_path)
        report["result"] = {"stats": stats, "errors_count": len(errors), "errors": errors,
                            "inventory_csv": {"file": csv_path.name, "hashes": csv_hashes}}
    except PermissionError:
        status = "FAILED_PERMISSION"
        w.append("Permission denied (run as root).")
    except Exception as exc:  # noqa: BLE001
        status = "FAILED_ERROR"
        w.append(f"{type(exc).__name__}: {exc}")

    finish_case(report, status, t0)
    print("[3/3] Writing report...")
    hpath, fh = write_report(yaml_path, report)
    print(f"[i] Files: {stats['files']}, directories: {stats['dirs']}, errors: {len(errors)}")
    print_summary(status, {"CSV": csv_path, "YAML": yaml_path, "Hashes": hpath}, fh)
    sys.exit(0 if status == "COMPLETED" else 1)


if __name__ == "__main__":
    main()