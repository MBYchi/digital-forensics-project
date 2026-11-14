# digital-forensics-project
 A system for the passive acquisition of data and metadata from storage media, utilizing tools dedicated to digital forensics


# User guide
## Automount turning off and disk mount

```bash
sudo python3 main.py --job ro_mount --prepare
sudo python3 main.py --job ro_mount /dev/sda3 /mnt/evidence_sda3
```

## Binary copy

```bash
sudo python3 main.py --job "binary copy" --device <path to the disk> --case-dir <directory where all will be saved> --evidence-id <evidence id> --examiner <"Name Surname"> --rehash-source
```

--rehash-source is optional. It will calculate source hashes again to be sure that it wasn't chaged after making copy

## Metadata collector

```bash
sudo python3 main.py --job metadata --device <path to the disk> --case-dir <directory where all will be saved> --evidence-id <evidence id> --examiner <"Name Surname"> --keep-raw
```

--keep-raw is optional. It will add raw output of tolls to the raport.

## File inventory
```bash
sudo python3 main.py --job "file inventory" --device <path to the partition on device> --case-dir <directory where all will be saved> --evidence-id <evidence id> --examiner <"Name Surname"> --mountpoint <path to the partition mountpoint>
```
