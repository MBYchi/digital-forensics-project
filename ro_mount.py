#!/usr/bin/env python3
import os, re, json, hashlib, subprocess, time, pathlib, shutil, glob, sys

DEV_RE = re.compile(r"^/dev/(sd[a-z]+\d*|nvme\d+n\d+(p\d+)?|loop\d+(p\d+)?|mmcblk\d+(p\d+)?)$")
PARENT_RE = re.compile(r"^(/dev/(?:sd[a-z]+|nvme\d+n\d+|mmcblk\d+|loop\d+))p?\d+$")
RULE_PATH = "/etc/udev/rules.d/99-forensic-noautomount.rules"
RULE = ('SUBSYSTEM=="block", ACTION=="add|change", ENV{UDISKS_IGNORE}="1", '
        'ENV{UDISKS_AUTO}="0", RUN+="/sbin/blockdev --setro %N"\n')

def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode:
        raise RuntimeError(f"{' '.join(cmd)}\n{r.stderr.strip()}")
    return r.stdout.strip()

def disable_automount(stop_udisks=True):
    if os.geteuid() != 0:
        raise PermissionError("wymagany root")
    with open(RULE_PATH, "w") as f:
        f.write(RULE)
    run(["udevadm", "control", "--reload-rules"])
    run(["udevadm", "trigger", "--subsystem-match=block", "--action=change"])
    run(["udevadm", "settle"])
    if stop_udisks and shutil.which("systemctl"):
        subprocess.run(["systemctl", "stop", "udisks2.service"], capture_output=True)
    user = os.environ.get("SUDO_USER")
    if user and shutil.which("gsettings"):
        uid = run(["id", "-u", user])
        env = {**os.environ, "DBUS_SESSION_BUS_ADDRESS": f"unix:path=/run/user/{uid}/bus"}
        for key in ("automount", "automount-open"):
            r = subprocess.run(["runuser", "-u", user, "--", "gsettings", "set",
                                "org.gnome.desktop.media-handling", key, "false"],
                               env=env, capture_output=True, text=True)
            if r.returncode:
                print(f"[warn] gsettings {key}: {r.stderr.strip()}")

def mounts_of(dev):
    with open("/proc/mounts") as f:
        return [l.split()[1] for l in f if l.split()[0].startswith(dev)]

def unmount_if_mounted(dev):
    for t in mounts_of(dev):
        run(["umount", t])

def sys_ro(dev):
    return int((pathlib.Path("/sys/class/block") / os.path.basename(dev) / "ro").read_text())

def set_ro(dev):
    if not DEV_RE.match(dev):
        raise ValueError("niedozwolone urządzenie")
    run(["blockdev", "--setro", dev])
    m = PARENT_RE.match(dev)
    if m and os.path.exists(m.group(1)):
        run(["blockdev", "--setro", m.group(1)])
    if sys_ro(dev) != 1 or run(["blockdev", "--getro", dev]) != "1":
        raise RuntimeError("nie udało się ustawić RO")

def fs_type(dev):
    return run(["blkid", "-o", "value", "-s", "TYPE", dev])

def mount_opts(fs):
    opts = ["ro", "noexec", "nosuid", "nodev", "noatime"]
    if fs in ("ext3", "ext4"):
        opts.append("noload")
    elif fs == "xfs":
        opts.append("norecovery")
    elif fs == "ntfs":
        opts.append("show_sys_files")
    elif fs == "btrfs":
        opts.append("rescue=nologreplay")
    return ",".join(opts)

_prev = "0" * 64
def log(path, entry):
    global _prev
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                if line.strip():
                    _prev = json.loads(line)["hash"]
    entry = {**entry, "ts": time.time(), "prev": _prev}
    _prev = hashlib.sha256(json.dumps(entry, sort_keys=True).encode()).hexdigest()
    entry["hash"] = _prev
    with open(path, "a") as f:
        f.write(json.dumps(entry) + "\n")

def ro_mount(dev, mnt, case_log="custody.jsonl", force=False):
    pre = mounts_of(dev)
    if pre:
        log(case_log, {"event": "WARNING_premounted", "dev": dev, "mounts": pre})
        if not force:
            raise RuntimeError(f"{dev} było już zamontowane w {pre}. "
                               "Dowód mógł zostać zmodyfikowany. Użyj --force.")
        unmount_if_mounted(dev)
    set_ro(dev)
    fs = fs_type(dev)
    os.makedirs(mnt, exist_ok=True)
    cmd = ["mount", "-o", mount_opts(fs), "-t", {"ntfs": "ntfs3"}.get(fs, fs), dev, mnt]
    run(cmd)
    opts = run(["findmnt", "-no", "OPTIONS", mnt])
    if "ro" not in opts.split(","):
        run(["umount", mnt])
        raise RuntimeError("mount nie jest RO")
    log(case_log, {"event": "ro_mount", "dev": dev, "fs": fs, "mnt": mnt, "cmd": cmd})
    return fs

def mount_image(img, mnt, case_log="custody.jsonl"):
    if not os.path.isfile(img):
        raise FileNotFoundError(img)
    src = img
    if img.lower().endswith((".e01", ".ex01")):
        raw_dir = mnt + "_ewf"
        os.makedirs(raw_dir, exist_ok=True)
        run(["ewfmount", img, raw_dir])
        src = raw_dir + "/ewf1"
    loop = run(["losetup", "--find", "--show", "--read-only", "--partscan", src])
    run(["udevadm", "settle"])
    set_ro(loop)
    for part in sorted(glob.glob(loop + "p[0-9]*")):
        unmount_if_mounted(part)
        set_ro(part)
    log(case_log, {"event": "mount_image", "img": img, "loop": loop})
    return loop

def sha256_dev(dev, bs=1 << 20):
    h = hashlib.sha256()
    with open(dev, "rb", buffering=0) as f:
        while chunk := f.read(bs):
            h.update(chunk)
    return h.hexdigest()

USAGE = ("użycie:\n"
         "  ro_mount.py --prepare\n"
         "  ro_mount.py [--force] /dev/sdXN /mnt/punkt\n"
         "  ro_mount.py --image obraz.E01 /mnt/punkt")

if __name__ == "__main__":
    a = sys.argv[1:]
    force = "--force" in a
    a = [x for x in a if x != "--force"]
    if a == ["--prepare"]:
        disable_automount()
        print("automount wyłączony, możesz podłączyć nośnik")
    elif len(a) == 3 and a[0] == "--image":
        print(mount_image(a[1], a[2]))
    elif len(a) == 2:
        print(ro_mount(a[0], a[1], force=force))
    else:
        sys.exit(USAGE)