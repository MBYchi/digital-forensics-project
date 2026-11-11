import argparse, csv, hashlib, os, platform, re, stat, sys, time
from datetime import datetime, timezone
from pathlib import Path
import yaml


ALGS = ("md5", "sha1", "sha256", "sha512")
CHUNK = 4 * 1024 * 1024


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def iso(ts):
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="seconds")


def hash_path(p):
    hs = {a: hashlib.new(a) for a in ALGS}
    with open(p, "rb") as f:
        while chunk := f.read(CHUNK):
            for h in hs.values():
                h.update(chunk)
    return {a: h.hexdigest() for a, h in hs.items()}


def write_hashes(path):
    h = hash_path(path)
    Path(str(path) + ".hashes.txt").write_text(
        "".join(f"{a.upper()}  {h[a]}  {Path(path).name}\n" for a in ALGS))
    return h


def device_size(dev):
    try:
        name = Path(os.path.realpath(dev)).name
        return int((Path("/sys/class/block") / name / "size").read_text()) * 512
    except Exception:
        return None


def hash_device(dev, expected_bytes):
    hs = {a: hashlib.new(a) for a in ALGS}
    total, started, t0 = 0, now(), time.monotonic()
    with open(dev, "rb") as f:
        while True:
            n = CHUNK if expected_bytes is None else min(CHUNK, expected_bytes - total)
            if n <= 0:
                break
            block = f.read(n)
            if not block:
                break
            for h in hs.values():
                h.update(block)
            total += len(block)
    return {
        "path": dev,
        "scope": "entire block device as given, bytes 0 .. capacity-1 (sysfs size * 512)",
        "bytes_hashed": total, "expected_bytes": expected_bytes,
        "complete": (total == expected_bytes) if expected_bytes is not None else None,
        "started_utc": started, "finished_utc": now(),
        "duration_s": round(time.monotonic() - t0, 2),
        "hashes": {a: h.hexdigest() for a, h in hs.items()},
    }


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
            hs = {a: "" for a in ALGS}
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
                    hs = hash_path(e.path)
                except OSError as ex:
                    errors.append({"path": rel, "op": "read", "error": str(ex)})
            else:
                stats["other"] += 1
            writer.writerow([rel, t, st.st_size, iso(st.st_mtime), iso(st.st_atime),
                             iso(st.st_ctime), oct(stat.S_IMODE(st.st_mode)), st.st_uid,
                             st.st_gid, st.st_ino, st.st_nlink, target,
                             *[hs[a] for a in ALGS]])


def main():
    ap = argparse.ArgumentParser(description="File inventory of a mounted disk")
    ap.add_argument("mountpoint", help="e.g. /mnt/evidence")
    ap.add_argument("--device", required=True,
                    help="block device to hash, e.g. /dev/sda3 (must be the source of the mountpoint)")
    ap.add_argument("--out-dir", required=True, help="output directory (NOT on the examined disk)")
    ap.add_argument("--name", default="inventory", help="prefix for output files")
    ap.add_argument("--allow-rw", action="store_true", help="allow a mount without ro")
    a = ap.parse_args()

    root = os.path.realpath(a.mountpoint)
    opts, fstype, source = mount_info(root)
    if opts is None:
        sys.exit(f"ABORT: {root} is not a mount point (check: findmnt {root})")
    dev = os.path.realpath(a.device)
    if source is None or os.path.realpath(source) != dev:
        sys.exit(f"ABORT: --device {a.device} is not the source of {root} "
                 f"(mount source: {source})")
    ro = "ro" in opts
    if not ro and not a.allow_rw:
        sys.exit(f"ABORT: {root} is not mounted read-only (options: {','.join(opts)})")

    out = Path(a.out_dir).resolve()
    if str(out).startswith(root + os.sep) or str(out) == root:
        sys.exit("ABORT: the output directory is on the examined disk")
    out.mkdir(parents=True, exist_ok=True)
    csv_path = out / f"{a.name}_files.csv"
    yaml_path = out / f"{a.name}_inventory.yaml"

    started = now()
    stats = {"files": 0, "dirs": 0, "symlinks": 0, "other": 0, "bytes": 0}
    errors = []
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["path", "type", "size", "mtime_utc", "atime_utc", "ctime_utc",
                    "mode", "uid", "gid", "inode", "nlink", "symlink_target", *ALGS])
        walk(root, w, stats, errors)

    warnings, device_hashes = [], {}
    try:
        dh = hash_device(dev, device_size(dev))
        device_hashes["target"] = dh
        if dh["complete"] is False:
            warnings.append(f"device hash incomplete: {dh['bytes_hashed']} of "
                            f"{dh['expected_bytes']} bytes read")
        elif dh["complete"] is None:
            warnings.append("device hash: capacity unknown, hashed until EOF")
    except Exception as ex:
        warnings.append(f"device hash {dev}: {type(ex).__name__}: {ex}")
    finished = now()

    csv_h = write_hashes(csv_path)
    report = {
        "device_hashes": device_hashes,
        "time": {"started_utc": started, "finished_utc": finished},
        "workstation": {"host": platform.node(), "os": platform.platform(),
                        "python": platform.python_version()},
        "source": {"mountpoint": root, "device": source, "fstype": fstype,
                   "mount_options": opts, "mounted_read_only": ro},
        "result": {"stats": stats, "errors_count": len(errors), "errors": errors,
                   "inventory_csv": {"file": csv_path.name, "hashes": csv_h}},
        "warnings": warnings,
    }
    with open(yaml_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(report, f, sort_keys=False, allow_unicode=True, indent=2)
    write_hashes(yaml_path)

    print(f"[i] Files: {stats['files']}, directories: {stats['dirs']}, errors: {len(errors)}")


if __name__ == "__main__":
    main()