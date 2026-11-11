from __future__ import annotations
import time
import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path


try:
    import yaml
except ImportError:
    sys.exit("[!] PyYAML library is missing. Install it with: pip install pyyaml")


CMD_TIMEOUT = 120
HASH_ALGOS = ("md5", "sha1", "sha256", "sha512")
MAX_INLINE_BYTES = 5 * 1024 * 1024
KEEP_RAW = False
LSBLK_COLS = ("NAME,KNAME,PATH,TYPE,SIZE,MODEL,SERIAL,WWN,VENDOR,REV,TRAN,RO,RM,FSTYPE,"
              "FSVER,UUID,LABEL,PTTYPE,PARTUUID,PARTLABEL,MOUNTPOINTS")



# ----------------------------------------------------------------- YAML
class ReportDumper(yaml.SafeDumper):
    """Lists are indented under their key (allows folding in an editor); no aliases."""


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



def tool(name):
    return shutil.which(name)



def hashes_of(data: bytes) -> dict:
    hs = {a: hashlib.new(a) for a in HASH_ALGOS}
    for h in hs.values():
        h.update(data)
    return {a: h.hexdigest() for a, h in hs.items()}



def hashes_of_file(path: Path, chunk: int = 1 << 20) -> dict:
    hs = {a: hashlib.new(a) for a in HASH_ALGOS}
    with open(path, "rb") as fh:
        while block := fh.read(chunk):
            for h in hs.values():
                h.update(block)
    return {a: h.hexdigest() for a, h in hs.items()}



def hash_device(dev, expected_bytes, chunk: int = 4 * 1024 * 1024) -> dict:
    """Reads the whole device once (read-only) and computes all hashes at the same time."""
    hs = {a: hashlib.new(a) for a in HASH_ALGOS}
    total, started, t0 = 0, now_utc(), time.monotonic()
    with open(dev, "rb") as fh:
        while True:
            to_read = chunk if expected_bytes is None else min(chunk, expected_bytes - total)
            if to_read <= 0:
                break
            block = fh.read(to_read)
            if not block:
                break
            for h in hs.values():
                h.update(block)
            total += len(block)
    return {
        "scope": "entire block device as given, bytes 0 .. capacity-1 (sysfs size * 512)",
        "bytes_hashed": total, "expected_bytes": expected_bytes,
        "complete": (total == expected_bytes) if expected_bytes is not None else None,
        "started_utc": started, "finished_utc": now_utc(),
        "duration_s": round(time.monotonic() - t0, 2),
        "hashes": {a: h.hexdigest() for a, h in hs.items()},
    }



def encode_bytes(data: bytes) -> dict:
    truncated = len(data) > MAX_INLINE_BYTES
    chunk = data[:MAX_INLINE_BYTES]
    try:
        return {"encoding": "utf-8", "truncated": truncated,
                "lines": chunk.decode("utf-8").split("\n")}
    except UnicodeDecodeError:
        return {"encoding": "base64", "truncated": truncated,
                "data": base64.b64encode(chunk).decode("ascii")}



def decode_text(d: dict) -> bytes:
    if d["encoding"] == "base64":
        return base64.b64decode(d["data"])
    return "\n".join(d["lines"]).encode("utf-8")



def try_cmd(cmd):
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=30)
        return p.returncode, (p.stdout or p.stderr).decode(errors="replace").strip()
    except Exception:  # noqa: BLE001
        return None, ""



def sysfs_path(device):
    return Path("/sys/class/block") / Path(device).name



def read_text(path):
    try:
        return path.read_text().strip()
    except Exception:  # noqa: BLE001
        return None



def read_int(path):
    t = read_text(path)
    try:
        return int(t)
    except (TypeError, ValueError):
        return None



def base_disk_of(device):
    name = Path(device).name
    if sysfs_path(name).exists() and not (sysfs_path(name) / "partition").exists():
        return name
    m = re.match(r"^(nvme\d+n\d+)p\d+$", name)
    if m:
        return m.group(1)
    m = re.match(r"^(.*?)(p?\d+)$", name)
    if m and sysfs_path(m.group(1)).exists():
        return m.group(1)
    return name



def list_partitions(base):
    try:
        return sorted(p.name for p in sysfs_path(base).iterdir()
                      if p.is_dir() and re.match(rf"^{re.escape(base)}(p?\d+)$", p.name))
    except Exception:  # noqa: BLE001
        return []



def read_at(device, offset, length):
    try:
        with open(device, "rb") as fh:
            fh.seek(offset)
            return fh.read(length)
    except Exception:  # noqa: BLE001
        return b""



def hexdump_lines(data: bytes) -> list:
    out = []
    for i in range(0, len(data), 16):
        c = data[i:i + 16]
        hx = " ".join(f"{b:02x}" for b in c)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in c)
        out.append(f"{i:08x}  {hx:<47}  {asc}")
    return out



def blob(data: bytes, with_hexdump=True) -> dict:
    d = {"bytes": len(data), "hashes": hashes_of(data),
         "base64": base64.b64encode(data).decode("ascii")}
    if with_hexdump:
        d["hexdump"] = hexdump_lines(data)
    return d



def udev_unescape(s: str) -> str:
    """\\x20 -> space etc.; invalid UTF-8 stays as \\xNN; strips padding."""
    b = s.encode("utf-8")
    out, pos = bytearray(), 0
    for m in re.finditer(rb"\\x([0-9a-fA-F]{2})", b):
        out += b[pos:m.start()]
        out.append(int(m.group(1), 16))
        pos = m.end()
    out += b[pos:]
    return bytes(out).decode("utf-8", errors="backslashreplace").strip()



def parse_kv(text):
    out = {}
    for ln in text.splitlines():
        if "=" in ln:
            k, v = ln.split("=", 1)
            k = k.strip()
            out[k] = udev_unescape(v) if k.endswith("_ENC") else v
    return out



def parse_generic(text):
    """Any text: 'key: value' -> fields; the rest -> other_lines (nothing is lost)."""
    fields, other = {}, []
    for ln in text.splitlines():
        if not ln.strip():
            continue
        m = re.match(r"^\s*([^:]{1,80}?)\s*:\s+(\S.*?)\s*$", ln) or \
            re.match(r"^\s*([A-Za-z][\w .()/-]{0,60}?)\s+=\s+(\S.*?)\s*$", ln)
        if m:
            k, v = m.group(1), m.group(2)
            if k in fields:
                if not isinstance(fields[k], list):
                    fields[k] = [fields[k]]
                fields[k].append(v)
            else:
                fields[k] = v
        else:
            other.append(ln.strip())
    out = {"fields": fields}
    if other:
        out["other_lines"] = other
    return out



def parse_blkid(text):
    res = []
    for ln in text.splitlines():
        m = re.match(r"^(\S+):\s+(.*)$", ln)
        if m:
            res.append({"device": m.group(1),
                        **dict(re.findall(r'(\w+)="([^"]*)"', m.group(2)))})
    return res



_UDEV_MATCH = {"KERNEL": "kernel", "KERNELS": "kernel", "SUBSYSTEM": "subsystem",
               "SUBSYSTEMS": "subsystem", "DRIVER": "driver", "DRIVERS": "driver"}



def parse_udev_attrs(text):
    devs, cur = [], None
    for ln in text.splitlines():
        m = re.match(r"\s*looking at (parent )?device '(.+)':", ln)
        if m:
            cur = {"level": len(devs), "role": "parent" if m.group(1) else "device",
                   "devpath": m.group(2), "match": {}, "attributes": {}}
            devs.append(cur)
            continue
        if cur is None:
            continue
        m = re.match(r'\s+ATTRS?\{(.+?)\}=="(.*)"$', ln)
        if m:
            cur["attributes"][m.group(1)] = m.group(2)
            continue
        m = re.match(r'\s+(KERNELS?|SUBSYSTEMS?|DRIVERS?)=="(.*)"$', ln)
        if m:
            cur["match"][_UDEV_MATCH[m.group(1)]] = m.group(2)
    return devs



def parse_fdisk(text):
    d, hdr = {"disk": {}, "partitions": []}, False
    for ln in text.splitlines():
        m = re.match(r"Disk (/dev/\S+): ([\d.]+ \w+), (\d+) bytes, (\d+) sectors", ln)
        if m:
            d["disk"].update(device=m.group(1), size_human=m.group(2),
                             bytes=int(m.group(3)), sectors=int(m.group(4)))
            continue
        m = re.match(r"(Disk model|Disklabel type|Disk identifier|Units|"
                     r"Sector size.*|I/O size.*): (.*)", ln)
        if m:
            d["disk"][m.group(1)] = m.group(2).strip()
            continue
        if ln.startswith("Device"):
            hdr = True
            continue
        if hdr and ln.strip():
            p = ln.split(None, 8)
            boot = len(p) > 1 and p[1] == "*"
            if boot:
                p.pop(1)
            d["partitions"].append({
                "device": p[0], "bootable": boot, "start": int(p[1]), "end": int(p[2]),
                "sectors": int(p[3]), "size": p[4], "type_id": p[5], "type": " ".join(p[6:])})
    return d



def parse_sgdisk(text):
    d = {"disk": {}, "partitions": [], "messages": []}
    for ln in text.splitlines():
        s = ln.strip()
        if not s or set(s) == {"*"}:
            continue
        m = re.match(r"^\s+(\d+)\s+(\d+)\s+(\d+)\s+(\S+ \S+)\s+(\S+)\s*(.*)$", ln)
        if m:
            d["partitions"].append({"number": int(m.group(1)), "start_sector": int(m.group(2)),
                                    "end_sector": int(m.group(3)), "size": m.group(4),
                                    "code": m.group(5), "name": m.group(6).strip()})
            continue
        m = re.match(r"^Disk (/dev/\S+): (\d+) sectors, (.+)$", s)
        if m:
            d["disk"].update(device=m.group(1), sectors=int(m.group(2)), size_human=m.group(3))
            continue
        m = re.match(r"^([A-Za-z][^:]{1,60}):\s+(.+)$", s)
        if m:
            d["disk"][m.group(1)] = m.group(2)
        elif not s.startswith("Number"):
            d["messages"].append(s)
    return d



def parse_file_s(text):
    t = text.strip()
    m = re.match(r"^(\S+):\s+(.*)$", t, re.S)
    d = {"target": m.group(1) if m else None, "description": m.group(2) if m else t}
    m = re.search(r"disk signature (0x[0-9a-fA-F]+)", t)
    if m:
        d["disk_signature"] = m.group(1)
    d["partitions"] = [
        {"index": int(i), "id": pid, "start_chs": sc, "end_chs": ec,
         "start_sector": int(ss), "sectors": int(n)}
        for i, pid, sc, ec, ss, n in re.findall(
            r"partition (\d+) : ID=(0x[0-9a-fA-F]+), start-CHS \(([^)]*)\), "
            r"end-CHS \(([^)]*)\), startsector (\d+), (\d+) sectors", t)]
    d["boot_messages"] = re.findall(r'"([^"]+)" at offset', t)
    return d



def parse_mmls(text):
    d = {"fields": {}, "slots": []}
    for ln in text.splitlines():
        m = re.match(r"^(\d+):\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(.*)$", ln.strip())
        if m:
            d["slots"].append({"slot": m.group(1), "meta": m.group(2),
                                "start": int(m.group(3)), "end": int(m.group(4)),
                                "length": int(m.group(5)), "description": m.group(6)})
        elif ":" in ln:
            k, v = ln.split(":", 1)
            d["fields"][k.strip()] = v.strip()
    return d



def parse_mmstat(text):
    return {"volume_system": text.strip()}



def parse_hdparm_n(text):
    m = re.search(r"max sectors\s*=\s*(\d+)/(\d+),\s*HPA is (\w+)", text)
    return ({"visible_sectors": int(m.group(1)), "native_sectors": int(m.group(2)),
             "hpa_reported": m.group(3)} if m else None)



def parse_json(text):
    return json.loads(text)



STAT_FIELDS = [
    "read_ios", "read_merges", "read_sectors", "read_ticks_ms",
    "write_ios", "write_merges", "write_sectors", "write_ticks_ms",
    "in_flight", "io_ticks_ms", "time_in_queue_ms",
    "discard_ios", "discard_merges", "discard_sectors", "discard_ticks_ms",
    "flush_ios", "flush_ticks_ms",
]



def parse_stat(text):
    vals = [int(x) for x in text.split()]
    d = dict(zip(STAT_FIELDS, vals))
    d["_fields_present"] = len(vals)
    if "read_sectors" in d:
        d["read_bytes"] = d["read_sectors"] * 512
    if "write_sectors" in d:
        d["write_bytes"] = d["write_sectors"] * 512
        d["no_writes_seen"] = d["write_ios"] == 0 and d["write_sectors"] == 0
    return d



def parse_ntfs_boot(sec: bytes, partition_byte_offset: int = 0) -> dict:
    if len(sec) < 512:
        return {"error": "sector too short"}
    le = lambda a, b: int.from_bytes(sec[a:b], "little")  # noqa: E731
    bps, spc = le(0x0B, 0x0D), sec[0x0D]
    cluster = bps * spc
    total = le(0x28, 0x30)


    def rec_size(v):
        s = v - 256 if v > 127 else v
        return s * cluster if s > 0 else 2 ** (-s)


    mft = le(0x30, 0x38)
    return {
        "oem_id": sec[3:11].decode("ascii", errors="replace").strip(),
        "bytes_per_sector": bps, "sectors_per_cluster": spc,
        "cluster_size_bytes": cluster, "media_descriptor": f"0x{sec[0x15]:02x}",
        "sectors_per_track": le(0x18, 0x1A), "heads": le(0x1A, 0x1C),
        "hidden_sectors": le(0x1C, 0x20),
        "total_sectors": total, "volume_size_bytes": total * bps,
        "mft_cluster": mft, "mft_offset_in_partition_bytes": mft * cluster,
        "mft_offset_on_disk_bytes": partition_byte_offset + mft * cluster,
        "mftmirr_cluster": le(0x38, 0x40),
        "mft_record_size_bytes": rec_size(sec[0x40]),
        "index_buffer_size_bytes": rec_size(sec[0x44]),
        "volume_serial_number": f"{le(0x48, 0x50):016X}",
        "boot_signature_valid": sec[510:512] == b"\x55\xaa",
    }



PARSERS = {"udev_properties": parse_kv, "udev_attributes": parse_udev_attrs,
           "fdisk": parse_fdisk, "sgdisk": parse_sgdisk, "file_s": parse_file_s,
           "mmls": parse_mmls, "mmstat": parse_mmstat, "hpa_check": parse_hdparm_n,
           "smart_json": parse_json}



def parser_for(art_id):
    return parse_blkid if art_id.startswith("blkid_") else PARSERS.get(art_id, parse_generic)



FS_SIGNATURES = [
    ("NTFS", 3, b"NTFS ", "Windows", "MFT - details in the ntfs / fsstat field"),
    ("BitLocker", 3, b"-FVE-FS-", "Windows", "NTFS encrypted with BitLocker - DO NOT decrypt"),
    ("exFAT", 3, b"EXFAT ", "Windows / universal", "typical for USB flash drives"),
    ("FAT12/16/32", 3, b"MSDOS", "Windows / universal", "distinguished by BPB fields"),
    ("LUKS1/LUKS2", 0, b"LUKS", "Linux", "LUKS volume - the image preserves the encryption"),
    ("XFS", 0, b"XFSB", "Linux (RHEL)", ""),
    ("Btrfs", 0x10040, b"_BHRfS_M", "Linux", "superblock @ 64 KiB"),
    ("HFS+", 1024, b"H+", "macOS", "volume header @ 1024"),
    ("HFSX", 1024, b"HX", "macOS", "case-sensitive variant"),
    ("APFS", 32, b"NXSB", "macOS", "NXSB container @ 32"),
    ("ext2/3/4", 1080, b"\x53\xef", "Linux", "superblock @ 1024, magic @ 1080"),
    ("UFS1", 8192 + 1372, b"\x54\x19\x01\x00", "BSD (UFS1)", "superblock @ 8192"),
    ("UFS2", 65536 + 1372, b"\x19\x01\x54\x19", "BSD (UFS2)", "superblock @ 65536"),
]
ZFS_SCAN_BYTES = 262144
MBR_TYPES = {
    0x07: "NTFS/exFAT (Windows)", 0x0B: "FAT32", 0x0C: "FAT32 (LBA)",
    0x0E: "FAT16 (LBA)", 0x83: "Linux (ext/xfs/btrfs/luks)", 0x82: "Linux swap",
    0x8E: "Linux LVM", 0xA5: "FreeBSD (UFS/ZFS)", 0xA9: "NetBSD (UFS)",
    0xA6: "OpenBSD (UFS)", 0xAF: "HFS/HFS+ (macOS)", 0xAB: "boot (macOS)",
    0xEE: "GPT (protective MBR)", 0xFD: "Linux RAID (md)",
}



def scan_fs_signatures(data):
    found = []
    for name, off, magic, osys, note in FS_SIGNATURES:
        if len(data) >= off + len(magic) and data[off:off + len(magic)] == magic:
            found.append({"fs": name, "offset": off, "os": osys, "note": note})
    head = data[:ZFS_SCAN_BYTES]
    if b"\x00\xba\xb1\x0c" in head or b"\x0c\xb1\xba\x00" in head:
        found.append({"fs": "ZFS", "offset": "uberblock (vdev label)",
                      "os": "BSD/illumos (OpenZFS)",
                      "note": "vdev labels at the start and end of the disk"})
    return found



def parse_mbr(sector0: bytes, ss: int = 512) -> dict:
    if len(sector0) < 512 or sector0[510:512] != b"\x55\xaa":
        return {"signature_valid": False, "partitions": [],
                "note": "no 0xAA55 signature (GPT without protective MBR? other format?)"}
    parts = []
    for i in range(4):
        e = sector0[446 + 16 * i: 446 + 16 * (i + 1)]
        ptype = e[4]
        start = int.from_bytes(e[8:12], "little")
        n = int.from_bytes(e[12:16], "little")
        if ptype == 0 and n == 0:
            continue
        parts.append({"index": i + 1, "bootable": e[0] == 0x80,
                      "type_hex": f"0x{ptype:02X}",
                      "type_desc": MBR_TYPES.get(ptype, "unknown"),
                      "start_lba": start, "sectors": n, "bytes": n * ss})
    sig = int.from_bytes(sector0[440:444], "little")
    return {"signature_valid": True, "partitions": parts, "disk_signature": f"0x{sig:08x}"}



def fmt_guid(raw):
    return str(uuid.UUID(bytes_le=raw)) if len(raw) == 16 else "?"



def parse_gpt(dev, ss: int = 512) -> dict:
    hdr = read_at(dev, ss, ss)
    if len(hdr) < 92 or hdr[0:8] != b"EFI PART":
        return {"present": False}
    num = int.from_bytes(hdr[80:84], "little")
    size = int.from_bytes(hdr[84:88], "little")
    out = {"present": True, "disk_guid": fmt_guid(hdr[56:72]),
           "entries_declared": num, "entry_size": size,
           "header": blob(hdr[:92], with_hexdump=False), "partitions": []}
    if size < 128 or size > 4096:
        out["note"] = "unusual entry size - parsing skipped"
        return out
    entries = read_at(dev, 2 * ss, min(num * size, 16384))
    for i in range(min(num, 128)):
        e = entries[i * size:(i + 1) * size]
        if len(e) < 128 or e[:16] == b"\x00" * 16:
            continue
        s = int.from_bytes(e[32:40], "little")
        t = int.from_bytes(e[40:48], "little")
        out["partitions"].append({
            "index": i + 1, "type_guid": fmt_guid(e[:16]),
            "unique_guid": fmt_guid(e[16:32]), "start_lba": s, "end_lba": t,
            "bytes": (t - s + 1) * ss,
            "name": e[56:128].decode("utf-16-le", errors="replace").rstrip("\x00")})
    return out



class Session:
    def __init__(self, device, base, case_dir: Path, evidence_id, examiner):
        self.device, self.base = device, base
        self.dev_base = f"/dev/{base}"
        self.out_dir = case_dir / "metadata"
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.evidence_id = evidence_id
        self.doc = {
            "case": {"evidence_id": evidence_id, "examiner": examiner,
                     "device": device, "base_disk": self.dev_base,
                     "started_utc": now_utc(), "finished_utc": None,
                     "status": "IN_PROGRESS"},
            "device_hashes": {},
            "workstation": {}, "safety": {}, "device": {}, "partitioning": {},
            "filesystems": {}, "hidden_areas": {}, "artifacts": {}, "warnings": [],
        }


    def warn(self, msg):
        self.doc["warnings"].append(msg)


    def run_cmd(self, art_id, title, cmd, version_cmd=None):
        art = {"title": title, "command": cmd}
        if version_cmd:
            art["tool_version"] = try_cmd(version_cmd)[1][:200]
        try:
            p = subprocess.run(cmd, capture_output=True, timeout=CMD_TIMEOUT)
            art["returncode"] = p.returncode
            text = p.stdout.decode("utf-8", errors="replace")
            parsed_ok = False
            if text.strip():
                try:
                    res = parser_for(art_id)(text)
                    if res is not None:
                        art["parsed"] = res
                        parsed_ok = True
                except Exception as exc:  # noqa: BLE001
                    art["parse_error"] = str(exc)
            if text.strip() and not parsed_ok:
                art["unparsed_text"] = text.split("\n")
            if p.stderr.strip():
                art["stderr_lines"] = p.stderr.decode("utf-8", errors="replace").rstrip("\n").split("\n")
            if KEEP_RAW:
                art["raw"] = {"stdout": {"bytes": len(p.stdout), "hashes": hashes_of(p.stdout),
                                          **encode_bytes(p.stdout)}}
        except subprocess.TimeoutExpired:
            art["error"] = "timeout"
            self.warn(f"{art_id}: timeout after {CMD_TIMEOUT}s")
        except Exception as exc:  # noqa: BLE001
            art["error"] = str(exc)
            self.warn(f"{art_id}: {exc}")
        self.doc["artifacts"][art_id] = art
        return art


    def collect_lsblk(self, dev):
        """lsblk -J -> device.lsblk (no separate artifact)."""
        try:
            p = subprocess.run(["lsblk", "-J", "-o", LSBLK_COLS, dev],
                               capture_output=True, timeout=CMD_TIMEOUT)
            if p.returncode != 0:
                self.warn(f"lsblk -J: return code {p.returncode}")
                return
            self.doc["device"]["lsblk"] = json.loads(p.stdout.decode("utf-8", errors="replace"))
        except Exception as exc:  # noqa: BLE001
            self.warn(f"lsblk -J: {exc}")


    def finish(self, status):
        d = self.doc
        d["case"]["finished_utc"] = now_utc()
        d["case"]["status"] = status
        name = f"{self.evidence_id}_{self.base}.yaml"
        path = self.out_dir / name
        tmp = path.with_name(name + ".tmp")
        tmp.write_text(dump_yaml(d), encoding="utf-8")
        tmp.replace(path)
        fh = hashes_of_file(path)
        hpath = path.with_name(name + ".hashes.txt")
        hpath.write_text("".join(f"{a.upper()} ({name}) = {fh[a]}\n" for a in HASH_ALGOS),
                         encoding="utf-8")
        return path, hpath, fh



def verify_read_only(s: Session) -> bool:
    checks, ok = [], True


    def add(name, value, good):
        nonlocal ok
        checks.append({"check": name, "value": value, "result": "OK" if good else "FAILED"})
        ok = ok and good


    ro = read_int(sysfs_path(s.base) / "ro")
    add("sysfs ro (disk)", ro, ro == 1)
    if tool("blockdev"):
        rc, out = try_cmd(["blockdev", "--getro", s.dev_base])
        add("blockdev --getro (disk)", out.strip() if rc == 0 else f"rc={rc}",
            rc == 0 and out.strip() == "1")
    else:
        checks.append({"check": "blockdev --getro", "value": None, "result": "SKIPPED"})
    parts = list_partitions(s.base)
    for p in parts:
        v = read_int(sysfs_path(p) / "ro")
        add(f"sysfs ro (partition {p})", v, v == 1)
    s.doc["safety"] = {"read_only_verified": ok, "partitions_detected": parts,
                       "checks": checks}
    return ok



TOOLS = [("smartctl", ["smartctl", "--version"]), ("hdparm", ["hdparm", "-V"]),
         ("nvme", ["nvme", "version"]), ("fdisk", ["fdisk", "--version"]),
         ("sgdisk", ["sgdisk", "--version"]), ("blkid", ["blkid", "--version"]),
         ("file", ["file", "--version"]), ("mmls", ["mmls", "-V"]),
         ("fsstat", ["fsstat", "-V"]), ("blockdev", ["blockdev", "--version"]),
         ("udevadm", ["udevadm", "--version"]), ("lsblk", ["lsblk", "--version"])]



def assess_hpa(s: Session, size_sectors):
    art = s.doc["artifacts"].get("hpa_check", {})
    parsed = art.get("parsed")
    stderr = "\n".join(art.get("stderr_lines", []))
    hpa = {"read_only_commands": True, "sysfs_sectors": size_sectors}
    if not parsed:
        return {**hpa, "hpa_detected": None, "reliable": False,
                "reason": "no hdparm -N result (USB/SAS/NVMe without ATA?)"}
    hpa.update(parsed)
    vis, nat = parsed["visible_sectors"], parsed["native_sectors"]
    if "SG_IO" in stderr or art.get("returncode") not in (0, None) or vis == 0 or nat <= 1:
        s.warn("HPA/DCO not verified: hdparm returned an error/illogical numbers "
               "(a USB bridge does not pass through ATA commands). Do not draw HPA conclusions from this data.")
        return {**hpa, "hpa_detected": None, "reliable": False,
                "reason": "hdparm unreliable (SG_IO / zero capacity) - "
                          "the USB bridge does not support ATA passthrough"}
    detected = vis < nat
    hpa.update(reliable=True, hpa_detected=detected,
               hidden_sectors=max(nat - vis, 0),
               hidden_mib=round(max(nat - vis, 0) * 512 / 1024 ** 2, 1))
    if detected:
        s.warn("HPA detected - the image must include the hidden area (examiner's decision).")
    return hpa



def collect(device, case_dir, evidence_id, examiner):
    base = base_disk_of(device)
    s = Session(device, base, case_dir, evidence_id, examiner)
    dev = s.dev_base
    print(f"[i] Media: {device} (base disk: {dev})")


    u = os.uname()
    versions = {}
    for name, vcmd in TOOLS:
        if tool(name):
            out = try_cmd(vcmd)[1]
            versions[name] = out.splitlines()[0][:120] if out else "unknown"
        else:
            versions[name] = None
            s.warn(f"tool unavailable: {name}")
    s.doc["workstation"] = {
        "hostname": u.nodename, "kernel": f"{u.release} {u.version}",
        "machine": u.machine, "python": sys.version.split()[0],
        "script": {"name": "metadata_collector.py",
                   "sha256": hashes_of_file(Path(__file__))["sha256"],
                   "keep_raw": KEEP_RAW},
        "tool_versions": versions}


    print("[*] Verifying write protection (read-only)...")
    if not verify_read_only(s):
        s.warn("ABORT: media or partition is NOT read-only - aborted before reading.")
        path, hpath, _ = s.finish("ABORTED_NOT_READ_ONLY")
        print(f"[!] ABORT: not read-only. Report: {path}")
        print("    Run: sudo python3 ro_mount.py --prepare and reconnect the media AGAIN.")
        sys.exit(2)
    print("[+] Write protection confirmed.")


    sb = sysfs_path(base)
    ss = read_int(sb / "queue/logical_block_size") or 512


    print("[1/7] Device hash (full read)...")
    hash_targets = [("target", device)]
    if device != dev:
        hash_targets.append(("base_disk", dev))
    for label, path in hash_targets:
        sz = read_int(sysfs_path(path) / "size")
        try:
            dh = hash_device(path, sz * 512 if sz else None)
            dh["path"] = path
            s.doc["device_hashes"][label] = dh
            if dh["complete"] is False:
                s.warn(f"device hash {path} incomplete: {dh['bytes_hashed']} of "
                       f"{dh['expected_bytes']} bytes read")
            elif dh["complete"] is None:
                s.warn(f"device hash {path}: capacity unknown, hashed until EOF")
        except Exception as exc:  # noqa: BLE001
            s.warn(f"device hash {path}: {type(exc).__name__}: {exc}")


    print("[2/7] Device identification...")
    if tool("lsblk"):
        s.collect_lsblk(dev)
    if tool("udevadm"):
        s.run_cmd("udev_properties", "udev: properties", ["udevadm", "info", "--query=property", "--name", dev])
        s.run_cmd("udev_attributes", "udev: attributes", ["udevadm", "info", "--attribute-walk", "--name", dev])
    keys = ["size", "ro", "rm", "stat", "queue/logical_block_size", "queue/physical_block_size",
            "queue/rotational", "queue/write_cache", "queue/discard_max_bytes",
            "device/model", "device/serial", "device/rev", "device/vendor", "wwid", "dm/uuid", "start"]
    sysfs = {k: read_text(sb / k) for k in keys if (sb / k).exists()}
    raw_stat = sysfs.get("stat")
    if raw_stat:
        try:
            sysfs["stat"] = parse_stat(raw_stat)
            sysfs["stat_raw"] = raw_stat
        except ValueError:
            s.warn("sysfs stat: could not parse, text left as is")
    s.doc["device"]["sysfs"] = sysfs
    size = read_int(sb / "size")
    s.doc["device"]["capacity"] = {"sectors_512": size, "bytes": size * 512 if size else None,
                                   "logical_sector_size": ss}


    print("[3/7] SMART...")
    if tool("smartctl"):
        art = s.run_cmd("smart_json", "SMART: JSON", ["smartctl", "-x", "--json", dev], ["smartctl", "--version"])
        if "parsed" not in art:
            s.run_cmd("smart_full", "SMART: full (-x)", ["smartctl", "-x", dev])
        s.run_cmd("smart_identify", "SMART: identification (-i)", ["smartctl", "-i", dev])


    print("[4/7] HPA/DCO...")
    if tool("hdparm"):
        s.run_cmd("hpa_check", "HPA: hdparm -N (read)", ["hdparm", "-N", dev], ["hdparm", "-V"])
        s.run_cmd("dco_check", "DCO: hdparm --dco-identify", ["hdparm", "--dco-identify", dev])
        s.run_cmd("ata_identify", "ATA IDENTIFY: hdparm -I", ["hdparm", "-I", dev])
    s.doc["hidden_areas"] = assess_hpa(s, size)


    if base.startswith("nvme") and tool("nvme"):
        ctrl = base.split("n")[0]
        s.run_cmd("nvme_list", "NVMe: list", ["nvme", "list"], ["nvme", "version"])
        s.run_cmd("nvme_id_ctrl", "NVMe: id-ctrl", ["nvme", "id-ctrl", f"/dev/{ctrl}"])
        s.run_cmd("nvme_id_ns", "NVMe: id-ns", ["nvme", "id-ns", dev])
        s.run_cmd("nvme_smart_log", "NVMe: smart-log", ["nvme", "smart-log", dev])


    print("[5/7] Partition table...")
    if tool("fdisk"):
        s.run_cmd("fdisk", "fdisk -l", ["fdisk", "-l", dev], ["fdisk", "--version"])
    if tool("sgdisk"):
        s.run_cmd("sgdisk", "sgdisk -p", ["sgdisk", "-p", dev], ["sgdisk", "--version"])
    if tool("mmls"):
        s.run_cmd("mmls", "mmls", ["mmls", dev], ["mmls", "-V"])
        s.run_cmd("mmstat", "mmstat", ["mmstat", dev])
    sector0 = read_at(dev, 0, 512)
    part = {"sector0": blob(sector0) if sector0 else None}
    if sector0:
        part["mbr"] = parse_mbr(sector0, ss)
    else:
        s.warn("could not read sector 0")
    part["gpt"] = parse_gpt(dev, ss)
    s.doc["partitioning"] = part


    print("[6/7] Filesystems...")
    if tool("blkid"):
        s.run_cmd("blkid_disk", "blkid -p (disk)", ["blkid", "-p", "-c", "/dev/null", dev], ["blkid", "--version"])
        for p in list_partitions(base):
            s.run_cmd(f"blkid_{p}", f"blkid -p ({p})", ["blkid", "-p", "-c", "/dev/null", f"/dev/{p}"])
    if tool("file"):
        s.run_cmd("file_s", "file -s", ["file", "-s", dev], ["file", "--version"])


    targets = []
    for p in list_partitions(base):
        st = read_int(sysfs_path(p) / "start")
        if st is not None:
            targets.append((p, st * 512))
    whole = not targets
    if whole:
        targets.append((f"{base}_whole_disk", 0))
    vols, os_guess = [], set()
    for tname, off in targets:
        data = read_at(dev, off, ZFS_SCAN_BYTES)
        v = {"target": tname, "byte_offset": off}
        if not data:
            v["error"] = "read error"
            s.warn(f"signature scan {tname}: read not possible")
        else:
            v["boot_sector"] = blob(data[:512])
            v["signatures"] = scan_fs_signatures(data)
            for h in v["signatures"]:
                os_guess.add(h["os"])
                if h["fs"] == "NTFS":
                    v["ntfs"] = parse_ntfs_boot(data[:512], off)
                if h["fs"].startswith("LUKS"):
                    v["luks_header_4k"] = blob(data[:4096])
        vols.append(v)
    s.doc["filesystems"] = {
        "scanned_whole_disk_no_partitions": whole, "volumes": vols,
        "conclusion_write_systems": sorted(os_guess),
        "conclusion_text": ("write system: " + ", ".join(sorted(os_guess))) if os_guess else
        "not recognized by signatures; compare with fdisk/sgdisk/blkid (artifacts)"}


    print("[7/7] fsstat...")
    if tool("fsstat"):
        for p in list_partitions(base):
            st = (read_int(sysfs_path(p) / "start") or 0) * 512 // ss
            s.run_cmd(f"fsstat_{p}", f"fsstat {p}", ["fsstat", "-b", str(ss), "-o", str(st), dev])
    else:
        s.warn("fsstat unavailable - get FS details later from the IMAGE (recommended)")


    path, hpath, fh = s.finish("COMPLETED")
    print("\n[+] DONE")
    print(f"    YAML  : {path}")
    print(f"    Hashes: {hpath}")
    for a in HASH_ALGOS:
        print(f"    {a.upper():<7}: {fh[a]}")



def _walk_blobs(node, path=""):
    if isinstance(node, dict):
        if "hashes" in node and ("lines" in node or "data" in node or "base64" in node):
            yield path, node
        for k, v in node.items():
            yield from _walk_blobs(v, f"{path}.{k}" if path else str(k))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _walk_blobs(v, f"{path}[{i}]")



def load_report(path: Path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))



def verify(report_path: Path) -> int:
    ok = True
    raw = hashes_of_file(report_path)
    hp = report_path.with_name(report_path.name + ".hashes.txt")
    if hp.exists():
        for line in hp.read_text(encoding="utf-8").splitlines():
            m = re.match(r"(\w+) \((.+)\) = ([0-9a-f]+)", line)
            if m:
                a = m.group(1).lower()
                good = raw.get(a) == m.group(3)
                ok &= good
                print(f"[{'OK' if good else 'FAIL'}] file {a}")
    else:
        print("[!] .hashes.txt file is missing")
        ok = False
    try:
        doc = load_report(report_path)
    except yaml.YAMLError as exc:
        print(f"[FAIL] file is not valid YAML: {exc}")
        return 1
    n_bad = n = 0
    for p, b in _walk_blobs(doc):
        if "base64" in b:
            data = base64.b64decode(b["base64"])
        elif b.get("truncated"):
            continue
        else:
            data = decode_text(b)
        n += 1
        if hashes_of(data) != b["hashes"]:
            n_bad += 1
            print(f"[FAIL] {p}")
    print(f"[{'OK' if n_bad == 0 else 'FAIL'}] internal hashes (sectors, raw text): {n - n_bad}/{n} match")
    ok &= n_bad == 0
    print("RESULT:", "INTEGRITY CONFIRMED" if ok else "VIOLATED!")
    return 0 if ok else 1



def show(report_path: Path, art_id=None) -> int:
    doc = load_report(report_path)
    arts = doc.get("artifacts", {})
    if not art_id:
        for k, v in arts.items():
            print(f"{k:<20} rc={v.get('returncode')}  {v.get('title')}")
        return 0
    if art_id not in arts:
        print(f"no such artifact: {art_id}")
        return 1
    print(dump_yaml(arts[art_id].get("parsed", arts[art_id])), end="")
    return 0



def main():
    global KEEP_RAW
    ap = argparse.ArgumentParser(description="Passive acquisition of media metadata -> a single YAML + hashes.")
    ap.add_argument("device", nargs="?")
    ap.add_argument("--case-dir")
    ap.add_argument("--evidence-id")
    ap.add_argument("--examiner")
    ap.add_argument("--keep-raw", action="store_true",
                    help="additionally save the raw stdout of commands (default: parsed fields only)")
    ap.add_argument("--verify", metavar="FILE.yaml")
    ap.add_argument("--show", nargs="+", metavar=("FILE.yaml", "ARTIFACT"))
    a = ap.parse_args()
    if a.verify:
        sys.exit(verify(Path(a.verify)))
    if a.show:
        sys.exit(show(Path(a.show[0]), a.show[1] if len(a.show) > 1 else None))
    if not (a.device and a.case_dir and a.evidence_id and a.examiner):
        ap.error("required: device, --case-dir, --evidence-id, --examiner")
    if os.geteuid() != 0:
        sys.exit("[!] Root privileges required (sudo).")
    KEEP_RAW = a.keep_raw
    dev = a.device if a.device.startswith("/dev/") else "/dev/" + a.device
    if not Path(dev).exists():
        sys.exit(f"[!] Device {dev} does not exist (check lsblk).")
    collect(dev, Path(a.case_dir), a.evidence_id, a.examiner)



if __name__ == "__main__":
    main()