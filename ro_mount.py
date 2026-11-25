#!/usr/bin/env python3

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from zoneinfo import ZoneInfo


RULE_PATH = Path(
    "/etc/udev/rules.d/99-forensic-noautomount.rules"
)

# Disable UDisks automount handling without setting all disks read-only.
RULE = (
    'SUBSYSTEM=="block", ACTION=="add|change", '
    'ENV{UDISKS_IGNORE}="1", ENV{UDISKS_AUTO}="0"\n'
)

# Recognize the rule installed by an earlier version of this script.
OLD_RULE = (
    'SUBSYSTEM=="block", ACTION=="add|change", '
    'ENV{UDISKS_IGNORE}="1", ENV{UDISKS_AUTO}="0", '
    'RUN+="/sbin/blockdev --setro %N"\n'
)

GUM_SERVERS = (
    "tempus1.gum.gov.pl",
    "tempus2.gum.gov.pl",
)

NTP_TIMEOUT = 2.0

SUPPORTED_FS = {
    "ext2",
    "ext3",
    "ext4",
    "xfs",
    "btrfs",
    "ntfs",
    "vfat",
    "exfat",
    "iso9660",
    "udf",
    "hfs",
    "hfsplus",
}


def run(cmd):
    """Run a command and return its standard output."""
    result = subprocess.run(
        [str(arg) for arg in cmd],
        capture_output=True,
        text=True,
    )

    if result.returncode:
        raise RuntimeError(
            f"Command failed: {' '.join(map(str, cmd))}\n"
            f"{result.stderr.strip() or result.stdout.strip()}"
        )

    return result.stdout.strip()


def utc_iso(timestamp):
    """Format a Unix timestamp as an ISO 8601 UTC string."""
    return (
        datetime.fromtimestamp(timestamp, timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


class Journal:
    """Append session events to a hash-chained JSONL audit log.

    Only log records are hashed. Disk contents are not hashed.

    The hash chain is not a digital signature and does not independently
    authenticate the log. Existing records are not verified by this class.
    """

    def __init__(self, path, session_id):
        self.path = path
        self.session_id = session_id

    def write(self, event, **data):
        with open(self.path, "a+", encoding="utf-8") as handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            handle.seek(0)

            previous = "0" * 64

            for line in handle:
                if line.strip():
                    previous = json.loads(line)["hash"]

            record = {
                **data,
                "event": event,
                "session_id": self.session_id,
                "ts": time.time(),
                "prev": previous,
            }

            payload = json.dumps(
                record,
                sort_keys=True,
                ensure_ascii=True,
            ).encode("utf-8")

            record["hash"] = hashlib.sha256(payload).hexdigest()

            handle.seek(0, os.SEEK_END)
            handle.write(json.dumps(record) + "\n")
            handle.flush()
            os.fsync(handle.fileno())


def reference_time():
    """Obtain an NTP sample without changing the system clock."""
    errors = []

    try:
        import ntplib

    except ImportError:
        errors.append({
            "error": (
                "The ntplib module is unavailable; "
                "using the local system clock"
            )
        })

    else:
        client = ntplib.NTPClient()

        for server in GUM_SERVERS:
            try:
                response = client.request(
                    server,
                    version=4,
                    timeout=NTP_TIMEOUT,
                )

                if response.leap == 3:
                    raise ValueError(
                        "The server reports an unsynchronized clock"
                    )

                if not 1 <= response.stratum <= 15:
                    raise ValueError(
                        f"Invalid NTP stratum: {response.stratum}"
                    )

                if response.mode != 4:
                    raise ValueError(
                        f"Invalid NTP response mode: {response.mode}"
                    )

                if response.recv_time <= 0 or response.tx_time <= 0:
                    raise ValueError("Invalid server timestamps")

                timestamp = response.dest_time + response.offset

                return {
                    "source": "gum_ntp",
                    "server": server,
                    "fallback": False,
                    "time_verified": False,
                    "authentication": "unauthenticated_ntp",
                    "utc": utc_iso(timestamp),
                    "unix": timestamp,
                    "local_unix": response.dest_time,
                    "local_utc": utc_iso(response.dest_time),
                    "offset_seconds": response.offset,
                    "round_trip_delay_seconds": response.delay,
                    "stratum": response.stratum,
                    "leap": response.leap,
                    "server_receive_utc": utc_iso(response.recv_time),
                    "server_transmit_utc": utc_iso(response.tx_time),
                    "monotonic_ns": time.monotonic_ns(),
                    "errors": errors,
                }

            except Exception as exc:
                errors.append({
                    "server": server,
                    "error": f"{type(exc).__name__}: {exc}",
                })

    timestamp = time.time()

    return {
        "source": "local_clock",
        "fallback": True,
        "time_verified": False,
        "authentication": "none",
        "utc": utc_iso(timestamp),
        "unix": timestamp,
        "monotonic_ns": time.monotonic_ns(),
        "errors": errors,
    }


def time_event(journal, event, **data):
    """Record UTC and Polish local representations of the same instant."""
    sample = reference_time()

    sample["poland_iso"] = datetime.fromtimestamp(
        sample["unix"],
        tz=ZoneInfo("Europe/Warsaw"),
    ).isoformat(timespec="microseconds")

    journal.write(
        event,
        time_reference=sample,
        **data,
    )

    print(
        f"[time] {event}: "
        f"utc={sample['utc']} "
        f"poland={sample['poland_iso']} "
        f"source={sample['source']} "
        f"fallback={sample['fallback']}",
        file=sys.stderr,
    )

    for error in sample["errors"]:
        print(
            f"[warn] Time reference: {error}",
            file=sys.stderr,
        )


def prepare(journal):
    """Disable UDisks automount handling before mounting the source.

    Changes are not restored automatically. This does not protect
    the interval before the script was started.
    """
    print(
        "[prepare] Disabling automount handling...",
        file=sys.stderr,
    )

    if not Path("/run/systemd/system").exists():
        raise RuntimeError(
            "This preparation procedure requires systemd. "
            "Refusing to continue without environment preparation."
        )

    if not shutil.which("systemctl"):
        raise RuntimeError(
            "Required executable not found: systemctl"
        )

    if RULE_PATH.exists():
        existing = RULE_PATH.read_text()

        if existing not in (RULE, OLD_RULE):
            raise RuntimeError(
                f"{RULE_PATH} contains an unrecognized rule. "
                "Review it manually before continuing."
            )

    RULE_PATH.write_text(RULE)

    run(["udevadm", "control", "--reload-rules"])

    # Do not trigger block-device events globally.
    # Read-only mode is set separately on the selected disk.
    run([
        "systemctl",
        "mask",
        "--runtime",
        "--now",
        "udisks2.service",
    ])

    user = os.environ.get("SUDO_USER")

    if user and shutil.which("gsettings"):
        uid = run(["id", "-u", user])

        for key in ("automount", "automount-open"):
            cmd = [
                "runuser",
                "-u",
                user,
                "--",
                "env",
                (
                    "DBUS_SESSION_BUS_ADDRESS="
                    f"unix:path=/run/user/{uid}/bus"
                ),
                "gsettings",
                "set",
                "org.gnome.desktop.media-handling",
                key,
                "false",
            ]

            try:
                run(cmd)

            except RuntimeError as exc:
                print(
                    f"[warn] GNOME settings: {exc}",
                    file=sys.stderr,
                )

    journal.write("prepare_complete")

    print(
        "[prepare] Environment preparation completed.",
        file=sys.stderr,
    )


def block_path(value):
    """Resolve and validate a block-device path."""
    path = Path(value).resolve(strict=True)

    if not stat.S_ISBLK(path.stat().st_mode):
        raise ValueError(
            f"{path} is not a block device"
        )

    return str(path)


def parent_disk(dev):
    """Return the parent disk of a partition, or the device itself."""
    node = (
        Path("/sys/class/block") / Path(dev).name
    ).resolve()

    if (node / "partition").exists():
        return "/dev/" + node.parent.name

    return dev


def block_tree(dev):
    """Return the device and its descendants as a flat list."""
    data = json.loads(run([
        "lsblk",
        "--json",
        "--paths",
        "--output",
        "NAME,TYPE",
        dev,
    ]))

    result = []

    def visit(node):
        result.append(node)

        for child in node.get("children", []):
            visit(child)

    for node in data["blockdevices"]:
        visit(node)

    return result


def assert_unused(dev):
    """Reject mounted devices, active block swap, and active holders.

    Mount checks cover the current mount namespace.
    This is not an exhaustive check for every possible device user.
    """
    nodes = block_tree(dev)
    device_ids = set()

    for node in nodes:
        path = node["name"]
        number = os.stat(path).st_rdev

        device_ids.add(
            f"{os.major(number)}:{os.minor(number)}"
        )

        holders = (
            Path("/sys/class/block")
            / Path(path).name
            / "holders"
        )

        if holders.exists() and any(holders.iterdir()):
            raise RuntimeError(
                f"{path} has active dependent devices "
                "(for example LVM, RAID, or dm-crypt)."
            )

    with open("/proc/self/mountinfo") as handle:
        for line in handle:
            fields = line.split()

            if fields[2] in device_ids:
                raise RuntimeError(
                    f"{dev} or one of its partitions is "
                    f"already mounted at {fields[4]}. "
                    "Automatic unmounting is disabled."
                )

    with open("/proc/swaps") as handle:
        next(handle, None)

        for line in handle:
            source = line.split()[0]

            try:
                info = os.stat(source)

            except OSError:
                continue

            if stat.S_ISBLK(info.st_mode):
                identity = (
                    f"{os.major(info.st_rdev)}:"
                    f"{os.minor(info.st_rdev)}"
                )

                if identity in device_ids:
                    raise RuntimeError(
                        f"{source} is an active swap device."
                    )


def set_ro(dev):
    """Set and verify the block-device read-only flag."""
    run(["blockdev", "--setro", dev])

    sysfs = (
        Path("/sys/class/block")
        / Path(dev).name
        / "ro"
    )

    if (
        run(["blockdev", "--getro", dev]) != "1"
        or sysfs.read_text().strip() != "1"
    ):
        raise RuntimeError(
            f"Failed to verify read-only mode: {dev}"
        )


def probe(dev):
    """Read filesystem signatures and metadata using blkid."""
    result = subprocess.run(
        ["blkid", "-p", "-o", "export", dev],
        capture_output=True,
        text=True,
    )

    if result.returncode not in (0, 2):
        raise RuntimeError(
            f"blkid failed for {dev}: "
            f"{result.stderr.strip() or result.stdout.strip()}"
        )

    return dict(
        line.split("=", 1)
        for line in result.stdout.splitlines()
        if "=" in line
    )


def mount_options(fs):
    """Build read-only mount options for a supported filesystem."""
    options = [
        "ro",
        "noexec",
        "nosuid",
        "nodev",
        "noatime",
    ]

    if fs in ("ext3", "ext4"):
        options.append("noload")

    elif fs == "xfs":
        options.append("norecovery")

    elif fs == "btrfs":
        options.append("nologreplay")

    return ",".join(options)


def make_empty_target(path):
    """Create an empty destination directory or validate an existing one."""
    path = Path(path).resolve()

    if path.exists() and not path.is_dir():
        raise RuntimeError(
            f"{path} is not a directory"
        )

    path.mkdir(parents=True, exist_ok=True)

    if os.path.ismount(path):
        raise RuntimeError(
            f"{path} is already a mount point"
        )

    if any(path.iterdir()):
        raise RuntimeError(
            f"{path} is not empty"
        )

    return str(path)


def mount_one(dev, target, fs, journal, mounted):
    """Mount one filesystem and verify its source and read-only option."""
    target = make_empty_target(target)

    driver = "ntfs3" if fs == "ntfs" else fs

    cmd = [
        "mount",
        "-t",
        driver,
        "-o",
        mount_options(fs),
        dev,
        target,
    ]

    run(cmd)
    mounted.append(target)

    info = json.loads(run([
        "findmnt",
        "--json",
        "--mountpoint",
        target,
        "--output",
        "TARGET,SOURCE,FSTYPE,OPTIONS,MAJ:MIN",
    ]))["filesystems"][0]

    number = os.stat(dev).st_rdev
    expected = (
        f"{os.major(number)}:{os.minor(number)}"
    )

    if info["maj:min"] != expected:
        raise RuntimeError(
            f"Unexpected mount source at {target}"
        )

    if "ro" not in info["options"].split(","):
        raise RuntimeError(
            f"The filesystem is not mounted read-only: {target}"
        )

    journal.write(
        "ro_mount",
        dev=dev,
        fs=fs,
        target=target,
        command=cmd,
        verified=info,
    )

    print(
        f"[OK] {dev} ({fs}) -> {target}"
    )


def mount_filesystems(dev, target, journal, mounted):
    """Mount supported partitions, or a filesystem directly on the device."""
    nodes = block_tree(dev)

    partitions = [
        node["name"]
        for node in nodes
        if node["type"] == "part"
        and node["name"] != dev
    ]

    candidates = partitions or [dev]
    mountable = []

    for candidate in candidates:
        set_ro(candidate)

        metadata = probe(candidate)
        fs = metadata.get("TYPE")

        journal.write(
            "filesystem_probe",
            dev=candidate,
            metadata=metadata,
        )

        if fs in SUPPORTED_FS:
            mountable.append((candidate, fs))

        else:
            reason = (
                fs or "No recognized filesystem signature"
            )

            print(
                f"[skip] {candidate}: {reason}",
                file=sys.stderr,
            )

            journal.write(
                "filesystem_skipped",
                dev=candidate,
                reason=reason,
            )

    if not mountable:
        raise RuntimeError(
            "No supported filesystem was found. "
            "The source may be encrypted, unsupported, "
            "or have an unrecognized partition layout."
        )

    for candidate, fs in mountable:
        destination = (
            str(Path(target) / Path(candidate).name)
            if partitions
            else target
        )

        mount_one(
            candidate,
            destination,
            fs,
            journal,
            mounted,
        )


def unmount_all(mounted, journal):
    """Unmount all mount points tracked by this script.

    This function is provided for explicit use.
    It is not called automatically.
    """
    errors = []

    for target in reversed(mounted.copy()):
        try:
            run(["umount", target])

        except Exception as exc:
            errors.append({
                "target": target,
                "error": f"{type(exc).__name__}: {exc}",
            })

            print(
                f"[warn] Failed to unmount {target}: {exc}",
                file=sys.stderr,
            )
            continue

        mounted.remove(target)

        try:
            journal.write(
                "filesystem_unmounted",
                target=target,
            )

        except Exception as exc:
            errors.append({
                "target": target,
                "error": (
                    "Failed to log successful unmount: "
                    f"{exc}"
                ),
            })

        print(
            f"[unmount] Unmounted: {target}",
            file=sys.stderr,
        )

    journal.write(
        "unmount_all_complete",
        success=not errors,
        remaining_mounts=list(mounted),
        errors=errors,
    )

    return not errors


def cleanup(mounted, journal):
    """Attempt to unmount tracked filesystems after an operation failure.

    This error-recovery function is separate from unmount_all().
    It does not restore automount settings or device read-only flags.
    """
    errors = []

    for target in reversed(mounted.copy()):
        try:
            run(["umount", target])
            mounted.remove(target)

        except Exception as exc:
            errors.append({
                "target": target,
                "error": f"{type(exc).__name__}: {exc}",
            })

    try:
        journal.write(
            "cleanup",
            remaining_mounts=list(mounted),
            errors=errors,
        )

    except Exception as exc:
        errors.append({
            "error": f"Failed to write cleanup log: {exc}"
        })

    for error in errors:
        print(
            f"[warn] Cleanup: {error}",
            file=sys.stderr,
        )


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Automatically prepare the environment and mount "
            "a physical disk or partition in read-only mode. "
            "Full-disk hashing is currently disabled."
        ),
        epilog=(
            "Successful mounts remain mounted. "
            "Automount settings and block-device read-only "
            "flags are not restored automatically."
        ),
    )

    parser.add_argument(
        "--log",
        default="custody.jsonl",
        help="path to the JSONL audit log",
    )

    parser.add_argument(
        "source",
        help="physical block device, e.g. /dev/sdb or /dev/sdb1",
    )

    parser.add_argument(
        "target",
        help="empty destination directory",
    )

    return parser.parse_args()


def main():
    args = parse_args()

    if os.geteuid() != 0:
        sys.exit(
            "Root privileges are required. Run with sudo."
        )

    required = [
        "mount",
        "umount",
        "lsblk",
        "blkid",
        "blockdev",
        "findmnt",
        "udevadm",
    ]

    for command in required:
        if not shutil.which(command):
            sys.exit(
                f"Required executable not found: {command}"
            )

    source = block_path(args.source)
    disk = parent_disk(source)

    disk_sysfs = (
        Path("/sys/class/block") / Path(disk).name
    )

    # This is a source-type restriction, not hardware authentication.
    if not (disk_sysfs / "device").exists():
        sys.exit(
            "The source is not supported as a physical disk. "
            "Loop and virtual block devices are outside "
            "the scope of this version."
        )

    # Validate the display timezone before changing system settings.
    ZoneInfo("Europe/Warsaw")

    target = make_empty_target(args.target)

    journal = Journal(
        str(Path(args.log).resolve()),
        str(uuid.uuid4()),
    )

    mounted = []
    status = "error"
    error = None
    started_ns = time.monotonic_ns()

    # Prevent concurrent execution of this script.
    with open("/run/lock/ro_mount.lock", "a") as lock:
        fcntl.flock(
            lock,
            fcntl.LOCK_EX | fcntl.LOCK_NB,
        )

        try:
            journal.write(
                "session_start",
                source=source,
                disk=disk,
                target=target,
                disk_hashing_enabled=False,
                argv=sys.argv[1:],
            )

            prepare(journal)

            # Check the entire parent disk even when only
            # one partition was requested.
            assert_unused(disk)

            set_ro(disk)

            if source != disk:
                set_ro(source)

            time_event(
                journal,
                "reference_start",
            )

            journal.write(
                "disk_integrity_check_skipped",
                reason="Full-disk hashing is temporarily disabled",
            )

            mount_filesystems(
                source,
                target,
                journal,
                mounted,
            )

            time_event(
                journal,
                "reference_end",
            )

            journal.write(
                "resources",
                source=source,
                disk=disk,
                mounts=list(mounted),
                integrity_status="not_checked",
            )

            print("\nRead-only mounting completed.")
            print(f"Source device: {source}")
            print(f"Audit log: {journal.path}")
            print("Full-disk hashing is disabled.")
            print(
                "Filesystems remain mounted. "
                "unmount_all() has not been called."
            )
            print(
                "Automount settings and device read-only "
                "flags have not been restored."
            )

            status = "success"

        except BaseException as exc:
            status = (
                "interrupted"
                if isinstance(exc, KeyboardInterrupt)
                else "error"
            )

            error = f"{type(exc).__name__}: {exc}"

            cleanup(
                mounted,
                journal,
            )

            raise

        finally:
            try:
                journal.write(
                    "session_end",
                    status=status,
                    error=error,
                    integrity_status="not_checked",
                    remaining_mounts=list(mounted),
                    duration_ns=(
                        time.monotonic_ns() - started_ns
                    ),
                )

            except Exception as exc:
                print(
                    "[ERROR] Failed to record session end: "
                    f"{exc}",
                    file=sys.stderr,
                )

                if status == "success":
                    raise


if __name__ == "__main__":
    try:
        main()

    except KeyboardInterrupt:
        print(
            "\nOperation interrupted.",
            file=sys.stderr,
        )
        sys.exit(130)

    except Exception as exc:
        print(
            f"[ERROR] {type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        sys.exit(1)