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



# ---------------------------------------------------------------- YAML
class ReportDumper(yaml.SafeDumper):
    def increase_indent(self, flow=False, indentless=False):
        return super().increase_indent(flow, False)


    def ignore_aliases(self, data):
        return True



def dump_yaml(obj) -> str:
    return yaml.dump(obj, Dumper=ReportDumper, sort_keys=False, allow_unicode=True,
                     default_flow_style=False, indent=2, width=1_000_000)



def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"



def new_hashers():
    return {a: hashlib.new(a) for a in HASH_ALGOS}



def digest(hs) -> dict:
    return {a: h.hexdigest() for a, h in hs.items()}



def hash_file(path, chunk_size=CHUNK, limit=None):
    """Reads a file/device once, computing all hashes at the same time. Returns (hashes, bytes)."""
    hs, total = new_hashers(), 0
    with open(path, "rb") as f:
        while True:
            to_read = chunk_size if limit is None else min(chunk_size, limit - total)
            if to_read <= 0:
                break
            chunk = f.read(to_read)
            if not chunk:
                break
            for h in hs.values():
                h.update(chunk)
            total += len(chunk)
    return digest(hs), total



def clone_and_hash(src_path, dst_path, chunk_size=CHUNK):
    """Copies src -> dst and, in the same pass, hashes what was read."""
    hs, total = new_hashers(), 0
    with open(src_path, "rb") as src, open(dst_path, "wb") as dst:
        while True:
            chunk = src.read(chunk_size)
            if not chunk:
                break
            for h in hs.values():
                h.update(chunk)
            dst.write(chunk)
            total += len(chunk)
        dst.flush()
        os.fsync(dst.fileno())
    return digest(hs), total



def source_size(path):
    with open(path, "rb") as f:
        return f.seek(0, os.SEEK_END)



def source_readonly(path):
    """Checks sysfs ro for block devices. None = not applicable / unknown."""
    p = Path("/sys/class/block") / Path(path).name / "ro"
    try:
        return p.read_text().strip() == "1"
    except Exception:
        return None



def file_hashes_txt(path: Path):
    fh, _ = hash_file(path)
    hpath = path.with_name(path.name + ".hashes.txt")
    hpath.write_text("".join(f"{a.upper()} ({path.name}) = {fh[a]}\n" for a in HASH_ALGOS),
                     encoding="utf-8")
    return hpath, fh



def main():
    ap = argparse.ArgumentParser(description="Binary copy of media -> image + YAML report + hashes.")
    ap.add_argument("--disk-path", required=True)
    ap.add_argument("--dest-path", required=True,
                    help="case directory; the image goes to <dest-path>/Binary_copy/")
    ap.add_argument("--examiner", required=True)
    ap.add_argument("--evidence-id", required=True)
    ap.add_argument("--rehash-source", action="store_true",
                    help="additionally compute the source hash AFTER imaging")
    a = ap.parse_args()


    if hasattr(os, "geteuid") and os.geteuid() != 0:
        sys.exit("[!] Root privileges required (sudo).")


    chunk = CHUNK
    src = a.disk_path
    out_dir = Path(a.dest_path) / "Binary_copy"
    out_dir.mkdir(parents=True, exist_ok=True)
    dst = str(out_dir / f"{a.evidence_id}_{Path(src).name}.img")
    if os.path.abspath(src) == os.path.abspath(dst):
        sys.exit("[!] Source and destination are the same file.")


    total_steps = 5 if a.rehash_source else 4


    report = {
        "case": {"evidence_id": a.evidence_id, "examiner": a.examiner,
                 "started_utc": now_utc(), "finished_utc": None, "status": "IN_PROGRESS"},
        "workstation": {
            "hostname": platform.node(), "user": getpass.getuser(),
            "os": f"{platform.system()} {platform.release()}", "machine": platform.machine(),
            "python": sys.version.split()[0],
            "script": {"name": Path(__file__).name,
                       "sha256": hash_file(__file__)[0]["sha256"]},
            "algorithms": list(HASH_ALGOS), "chunk_size_bytes": chunk,
            "workflow": ["hash source BEFORE imaging",
                         "imaging (hash computed on the same bytes written)",
                         "hash image"]
                        + (["hash source AFTER imaging"] if a.rehash_source else []),
        },
        "source": {"path": src, "read_only": source_readonly(src)},
        "image": {"path": dst},
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
        before, n_before = hash_file(src, chunk)
        report["source"]["hashes_before"] = before
        report["source"]["bytes_hashed_before"] = n_before


        print(f"[2/{total_steps}] Imaging...")
        during, n_copied = clone_and_hash(src, dst, chunk)
        report["source"]["hashes_during_imaging"] = during
        report["image"]["bytes_written"] = n_copied


        print(f"[3/{total_steps}] Hashing image...")
        img_hash, n_img = hash_file(dst, chunk)
        report["image"]["size_bytes"] = n_img
        report["image"]["hashes"] = img_hash


        checks = {
            "before_equals_during": before == during,
            "before_equals_image": before == img_hash,
            "during_equals_image": during == img_hash,
            "size_match": n_before == n_copied == n_img,
        }


        if a.rehash_source:
            print(f"[4/{total_steps}] Hashing source AFTER imaging...")
            after, n_after = hash_file(src, chunk, limit=n_copied)
            report["source"]["hashes_after"] = after
            checks["before_equals_after"] = before == after


        report["result"] = {"all_checks_passed": all(checks.values()), "checks": checks}


        if not checks["before_equals_during"] or not checks.get("before_equals_after", True):
            w.append("Source changed between hashing and/or imaging!")
            status = "FAILED_SOURCE_CHANGED"
        elif not (checks["before_equals_image"] and checks["during_equals_image"]
                  and checks["size_match"]):
            status = "FAILED_HASH_MISMATCH"
    except PermissionError:
        status = "FAILED_PERMISSION"
        w.append("Permission denied (run as root/Administrator).")
    except Exception as exc:
        status = "FAILED_ERROR"
        w.append(f"{type(exc).__name__}: {exc}")


    report["case"]["finished_utc"] = now_utc()
    report["case"]["duration_s"] = round(time.monotonic() - t0, 2)
    report["case"]["status"] = status


    print(f"[{total_steps}/{total_steps}] Writing report...")
    rpath = Path(dst + ".yaml")
    tmp = rpath.with_name(rpath.name + ".tmp")
    tmp.write_text(dump_yaml(report), encoding="utf-8")
    tmp.replace(rpath)
    hpath, fh = file_hashes_txt(rpath)


    print(f"\n[{'+' if status == 'COMPLETED' else '!'}] Status: {status}")
    print(f"    Image : {dst}")
    print(f"    YAML  : {rpath}")
    print(f"    Hashes: {hpath}")
    for x in HASH_ALGOS:
        print(f"    {x.upper():<7}: {fh[x]}")
    sys.exit(0 if status == "COMPLETED" else 1)



if __name__ == "__main__":
    main()