# Dokumentacja metadanych: `Alpine-EV-001_sda.yaml`

> Dokument wyjaśnia po kolei, co jest w raporcie, co to znaczy i na co uważać.
> Zakłada, że czytelnik **nie zna** informatyki śledczej. Na końcu jest porównanie z poprzednim raportem `linux-001_sda.yaml`.

---

## 1. Co to za plik?

To **raport techniczny z zabezpieczenia dysku** (informatyka śledcza, *digital forensics*).
Skrypt `metadata_collector.py` zapytał system o dysk `/dev/sda`, zapisał odpowiedzi różnych narzędzi i policzył **sumy kontrolne całego dysku**.

- Plik **nie zawiera** zawartości plików z dysku - tylko opis dysku i dowody, że go nie zmieniono.
- Format **YAML** to tekst w układzie `klucz: wartość`. Wcięcia oznaczają zagnieżdżenie.
- Raport jest nowszy i pełniejszy niż `linux-001`: dodano **hash całego dysku**, a testy ukrytych obszarów są tym razem **wiarygodne**.

## 2. Streszczenie (30 sekund)

| Pytanie | Odpowiedź |
|---|---|
| Co badano? | Dysk `/dev/sda`, wirtualny (VMware SATA), 20 GiB |
| Numer dowodu | `Alpine-EV-001` |
| Kto badał? | Ruslan Hedz |
| Kiedy? | 2026-11-11, 18:03:00 - 18:04:24 UTC (19:03 - 19:04 czasu polskiego) |
| Czy zakończono? | Tak, `COMPLETED` |
| Czy dysk był tylko do odczytu? | Tak - 5/5 testów `OK`, zapisano 0 bajtów |
| Czy policzono hash całego dysku? | Tak, 21 474 836 480 bajtów, `complete: true` |
| Układ dysku | Tablica MBR, 3 partycje: ext4 (`/boot`), swap, ext4 (`/`) |
| Ukryte obszary (HPA/DCO)? | Nie wykryto, wynik wiarygodny |
| Główne zastrzeżenie | Systemy plików ext4 mają flagę *Needs Recovery* (patrz 8.1) |

## 3. Słowniczek

| Pojęcie | Wyjaśnienie |
|---|---|
| **Dysk / urządzenie blokowe** | Całe urządzenie, tu `sda`. |
| **Partycja** | Wydzielony kawałek dysku: `sda1`, `sda2`, `sda3`. |
| **Sektor** | Najmniejsza porcja dysku; tu 512 bajtów. |
| **LBA** | Numer sektora liczony od 0. |
| **MBR** | Starszy typ tablicy partycji, zapisany w sektorze 0 (pierwsze 512 bajtów). |
| **GPT** | Nowszy typ tablicy partycji. Tu go nie ma. |
| **System plików** | Sposób zapisu danych na partycji (ext4, swap). |
| **Hash (skrót)** | "Odcisk palca" danych. Zmiana choćby jednego bitu zmienia cały skrót. |
| **MD5 / SHA-1 / SHA-256 / SHA-512** | Cztery algorytmy hashujące; SHA-256 i SHA-512 są najmocniejsze. |
| **Write blocker / read-only** | Zabezpieczenie, które uniemożliwia zapis na badany dysk. |
| **HPA / DCO** | Ukryte obszary dysku, mogące skrywać dane. |
| **SMART** | Wbudowana diagnostyka zdrowia dysku. |
| **UUID** | Unikalny identyfikator partycji / systemu plików. |
| **Journal (dziennik)** | Mechanizm ext4 zapisujący zamiary operacji, by po awarii odzyskać spójność. |
| **Inode** | Rekord systemu plików opisujący jeden plik lub katalog. |
| **Sleuth Kit** | Zestaw narzędzi śledczych (`mmls`, `fsstat`). |
| **UTC** | Czas uniwersalny. W Polsce: +1 h zimą (CET), +2 h latem (CEST). |

## 4. Budowa pliku - przegląd

```
case              dane sprawy, czas, status
device_hashes     hash CAŁEGO dysku              <- NOWOŚĆ
workstation       komputer badającego
script            użyty skrypt + jego hash
tool_versions     wersje narzędzi
safety            dowody trybu tylko-do-odczytu
device            opis dysku (lsblk, statystyki I/O, pojemność)
partitioning      sektor 0 (MBR) + hashe
filesystems       pierwsze sektory partycji + sygnatury
hidden_areas      kontrola HPA/DCO
artifacts         surowe wyniki poleceń (udev, SMART, fdisk, fsstat ...)
```

## 5. Sekcje szczegółowo

### 5.1 `case` - sprawa
| Pole | Wartość | Znaczenie |
|---|---|---|
| `evidence_id` | `Alpine-EV-001` | Numer dowodu. Nazwa sugeruje system Alpine Linux (to mój wniosek, patrz 7.2) |
| `examiner` | Ruslan Hedz | Osoba badająca |
| `device` | `/dev/sda` | Badane urządzenie |
| `base_disk` | `/dev/sda` | Dysk bazowy. W `linux-001` badano `/dev/sda3`, tu cały dysk |
| `started_utc` | 2026-11-11 18:03:00.444 | Początek |
| `finished_utc` | 2026-11-11 18:04:24.461 | Koniec (łącznie ok. 84 s) |
| `status` | `COMPLETED` | Zakończone |

### 5.2 `device_hashes` - hash całego dysku (najważniejsza nowość)
Skrypt przeczytał **każdy bajt dysku** od 0 do końca i policzył z niego skróty.

| Pole | Wartość | Znaczenie |
|---|---|---|
| `scope` | cały dysk, bajty 0 .. pojemność-1 | Zakres hashowania |
| `bytes_hashed` | 21 474 836 480 | Ile bajtów przeczytano |
| `expected_bytes` | 21 474 836 480 | Ile powinno być (rozmiar z sysfs x 512) |
| `complete` | `true` | Oba liczby się zgadzają, więc nic nie pominięto |
| `duration_s` | 83,54 | Czas; to ok. 257 MB/s |

Skróty całego dysku:

| Algorytm | Wartość |
|---|---|
| MD5 | `0be018a3193097b398bb65c29db679ba` |
| SHA-1 | `3c0f8bc15e6a48b2ac6d6c2ce7d222d57cee91d4` |
| SHA-256 | `1dc92bd531f38e2a69f9aa0675cd93b988703f267d3a52ab3542ce459d398fc4` |
| SHA-512 | `a156f784ec80c39a5a8118b788236d95e6183ebd4f842f76a38e1d41d537c04764b8908c2458ca38a3db3ac983091165fc1b3c991ba37c4740766a93cd830a73` |

**Po co to?** To główny dowód integralności. Jeśli za tydzień obraz dysku da ten sam SHA-256, to nic się nie zmieniło.
**Uwaga:** w raporcie jest tylko jedno przejście. Dobra praktyka to drugie, niezależne policzenie i porównanie.

### 5.3 `workstation` - stanowisko
| Pole | Wartość |
|---|---|
| hostname | `user-VMware-Virtual-Platform` |
| kernel | `7.0.0-43-generic` (Ubuntu) |
| architektura | `x86_64` |
| Python | `3.14.4` |

Badanie wykonano z maszyny wirtualnej VMware. Informacje te pozwalają odtworzyć środowisko.

### 5.4 `script` - skrypt
Nazwa `metadata_collector.py` i jego SHA-256 `80da4f97...81bd`. Dzięki temu da się wykazać, której wersji skryptu użyto.
`keep_raw: false` znaczy, że surowe wyjścia nie są zapisane osobno, tylko wewnątrz tego pliku.

### 5.5 `tool_versions` - narzędzia

| Narzędzie | Wersja | Do czego |
|---|---|---|
| `lsblk`, `blkid`, `blockdev`, `fdisk`, `udevadm` | util-linux 2.41.3 / udev 259 | Lista dysków, identyfikatory, flaga RO, partycje |
| `sgdisk` | 1.0.10 | Odczyt GPT/MBR |
| `mmls`, `fsstat` | Sleuth Kit 4.12.1 | Układ partycji i statystyki ext4 |
| `smartctl` | 7.5 | SMART |
| `hdparm` | 9.65 | Parametry ATA, HPA, DCO |
| `file` | 5.46 | Rozpoznanie typu danych |
| `nvme` | 2.16 | Dyski NVMe (tu nieużywane) |

### 5.6 `safety` - ochrona przed zapisem
Pięć testów flagi "tylko do odczytu":

| Test | Wynik |
|---|---|
| sysfs ro (dysk) | 1 -> `OK` |
| `blockdev --getro` (dysk) | 1 -> `OK` |
| sysfs ro (`sda1`, `sda2`, `sda3`) | 1 -> `OK` x3 |

`read_only_verified: true` to wniosek zbiorczy. Potwierdza to licznik I/O: `write_ios: 0`, `write_bytes: 0`, `no_writes_seen: true`.

### 5.7 `device` - opis dysku

**Dysk**
- Model `VMware Virtual SATA Hard Drive`, vendor `ATA`, magistrala `sata`.
- Numer seryjny `00000000000000000001` (wartość sztuczna, nadana przez VMware).
- Rozmiar: 20 GiB = 21 474 836 480 B = 41 943 040 sektorów po 512 B.
- Tablica partycji: `dos` (MBR), ID dysku `0x72cef442`.

**Partycje**

| Partycja | Rozmiar | Start (sektor) | Typ MBR | System plików | Zamontowanie | Rola (wniosek) |
|---|---|---|---|---|---|---|
| `sda1` | 300 MiB | 2048 | 0x83 Linux, *bootable* | ext4 | - (wcześniej `/mnt/boot`) | `/boot`, w sektorze startowym jest SYSLINUX |
| `sda2` | 924 MiB | 616448 | 0x82 swap | swap | - | Pamięć wymiany |
| `sda3` | 18,8 GiB | 2508800 | 0x83 Linux | ext4 | `/mnt/evidence` | System główny `/` |

**Statystyki I/O (`sysfs.stat`)**
- Odczyty: 110 963 operacji, 606 215 484 sektory = **310 382 327 808 B (ok. 289 GiB)**.
- Zapisy: **0**.
- Uwaga: 289 GiB to ok. 14-krotność rozmiaru dysku. Liczniki są **skumulowane od chwili podłączenia dysku**, więc obejmują też wcześniejsze odczyty (np. inne próby hashowania), a nie tylko ten przebieg. Raport nie podaje dokładnej przyczyny.

### 5.8 `partitioning` - sektor 0 (MBR)
Zapisano pierwsze 512 bajtów dysku jako `hexdump`, `base64` oraz cztery hashe.
- `signature_valid: true` - na końcu stoi poprawna sygnatura `55 AA`.
- `gpt.present: false` - brak GPT.
- Tablica MBR zawiera trzy wpisy zgodne z tabelą z punktu 5.7.
- W kodzie rozruchowym widać komunikaty "Missing operating system" itp. - to standardowy kod MBR, nie błąd.

SHA-256 sektora 0: `0a0d83a30695998219926bafade180182b8ee0df464ff8ff6252463094363d4c`.

### 5.9 `filesystems` - początki partycji
Dla każdej partycji zapisano pierwsze 512 bajtów, ich hashe i wykryte sygnatury.

| Partycja | Offset (bajty) | Zawartość sektora | Sygnatura |
|---|---|---|---|
| `sda1` | 1 048 576 | Kod SYSLINUX | ext2/3/4 (superblok @1024, magic @1080) |
| `sda2` | 315 621 376 | Same zera | brak (to swap) |
| `sda3` | 1 284 505 600 | Same zera | ext2/3/4 |

`sda2` i `sda3` mają ten sam hash, bo oba sektory to zera. To normalne.
`conclusion_text: 'write system: Linux'` - wniosek: dysk zapisał system Linux.

### 5.10 `hidden_areas` - HPA/DCO (tym razem wiarygodne)

| Pole | Wartość | Znaczenie |
|---|---|---|
| `sysfs_sectors` | 41 943 040 | Rozmiar widziany przez jądro |
| `visible_sectors` | 41 943 040 | Rozmiar widoczny dla użytkownika |
| `native_sectors` | 41 943 040 | Rozmiar "fabryczny" dysku |
| `hpa_reported` | `disabled` | HPA wyłączone |
| `hpa_detected` | `false` | Nie wykryto |
| `hidden_sectors` | 0 (0,0 MiB) | Brak ukrytych sektorów |
| `reliable` | **`true`** | Test można uznać za wiarygodny |

Trzy liczby są równe, więc nikt nie "przyciął" dysku. W `linux-001` ten test był niewiarygodny (patrz 9).
Zastrzeżenie: `dco_check` zwrócił dziwne `Real max sectors: 1` i błąd `SG_IO: bad/missing sense data`. Wirtualny dysk nie wspiera DCO w pełni, więc **to wynik DCO jest niepewny**, a wniosek o braku HPA opiera się na zgodności trzech liczb.

## 6. Sekcja `artifacts` - surowe wyniki poleceń

Każdy wpis zawiera `command` (co uruchomiono), `returncode` (0 = sukces) i `parsed` (wynik).

| Artefakt | Co pokazuje | Wynik |
|---|---|---|
| `udev_properties`, `udev_attributes` | Gdzie dysk jest w systemie: kontroler SATA/AHCI (`ata3`, sterownik `ahci`), magistrala PCI | OK |
| `smart_json`, `smart_identify` | SMART niedostępny (`device lacks SMART capability`); `returncode: 4` jest tu oczekiwany | OK / brak SMART |
| `hpa_check` | HPA wyłączone, 41 943 040 = 41 943 040 | OK |
| `dco_check` | Niepewne (patrz 5.10) | Ostrzeżenie |
| `ata_identify` | Pełne dane ATA: LBA48, NCQ, SATA Gen1/Gen2, cache 32 KB | OK |
| `fdisk`, `sgdisk`, `mmls`, `mmstat` | Trzy niezależne potwierdzenia układu partycji | OK |
| `blkid_*` | UUID-y i typy systemów plików | OK |
| `file_s` | Rozpoznanie sektora MBR | OK |
| `fsstat_sda1` | Statystyki ext4 | OK (rc 0) |
| `fsstat_sda2` | `Cannot determine file system type` | rc 1 - **oczekiwane**, bo to swap |
| `fsstat_sda3` | Statystyki ext4 | OK (rc 0) |

### 6.1 Co mówi `fsstat` o systemach plików

| Cecha | `sda1` (`/boot`) | `sda3` (`/`) |
|---|---|---|
| Typ | Ext4 | Ext4 |
| Rozmiar bloku | 1024 B | 4096 B |
| Liczba bloków | 307 200 | 4 929 280 |
| Wolne bloki | 237 685 (ok. 77%) | 4 405 365 (ok. 89%) |
| Zajęte (obliczone) | ok. 68 MiB | ok. 2,0 GiB |
| Wolne i-węzły | 76 887 z 76 912 | 1 221 141 z 1 234 577 |
| Grupy bloków | 38 | 151 |
| Ostatnio zapisany | 2026-11-11 12:55:36 CET | 2026-08-31 20:36:06 CEST |
| Ostatnio zamontowany | 2026-11-11 12:55:36 CET | 2026-11-11 12:55:36 CET |
| Zamontowany jako | `/mnt/boot` | `/` |
| Ostatnie sprawdzenie (fsck) | 2026-08-31 18:59:38 CEST | 2026-08-31 18:59:38 CEST |
| Flagi | Journal, Extents, *Needs Recovery* | Journal, Extents, 64bit, *Needs Recovery* |

Wartości "zajęte" to różnica *wszystkie - wolne* i są moim wyliczeniem.

## 7. Wnioski z raportu

### 7.1 Co jest potwierdzone
- Dysk ma 20 GiB, tablicę MBR i trzy partycje o podanych rozmiarach (potwierdzone przez `lsblk`, `fdisk`, `sgdisk`, `mmls`, `file`).
- Dysk był chroniony przed zapisem; liczniki pokazują 0 zapisów.
- Cały dysk został zhashowany w całości.
- Brak ukrytych sektorów HPA.

### 7.2 Co jest wnioskiem (nie wprost z pliku)
- Nazwa `Alpine` oraz układ `/boot` + swap + `/` sugerują instalację Alpine Linux. Plik nie podaje dystrybucji wprost; potwierdzi to dopiero analiza zawartości `/etc/os-release` na `sda3`.
- `sda1` to partycja rozruchowa (flaga *bootable*, SYSLINUX).

## 8. Uwagi i ostrzeżenia

### 8.1 Flaga *Needs Recovery*
Obie partycje ext4 mają ustawioną flagę, że dziennik zawiera niezatwierdzone operacje. Zwykle znaczy to, że system plików **nie został czysto odmontowany** (np. nagłe wyłączenie VM).
Skutek dla śledztwa: przy zwykłym montowaniu Linux mógłby próbować odtworzyć dziennik, czyli zapisać na dysk. Dlatego montuj z opcjami `ro,noload` (albo pracuj na kopii obrazu).

### 8.2 Znaczniki czasu wymagają ostrożności
`sda3` ma "Last Written" z 31 sierpnia, a "Last Mounted" z 11 listopada. To nie jest sprzeczność: zamontowanie nie musi oznaczać zapisu danych (zwłaszcza w trybie RO). Strefy czasowe są różne: CET (zima) i CEST (lato).

### 8.3 Dziwne wartości, które nie są błędem
- **`rotational: 1`, a SMART pisze "Solid State Device"** - skutek wirtualizacji.
- **`sgdisk`: "invalid GPT and valid MBR; converting in memory"** - narzędzie tylko w pamięci przekonwertowało MBR, aby go wyświetlić. Ostrzeżenie o nakładaniu się o 33 bloki i GUID `D9633741-C145-4A2F-897D-BBF5DE8D4D0C` pochodzą z tej tymczasowej konwersji. **To nie jest prawdziwy identyfikator dysku** (w `linux-001` GUID był inny, mimo że dysk ma ten sam MBR).
- **`ioerr_cnt: 0xa` (10) i `iotmo_cnt: 0x4` (4)** - 10 błędów I/O i 4 timeouty w warstwie SCSI. Najpewniej to skutek odrzuconych poleceń ATA (DCO). Plik tego nie potwierdza, więc to hipoteza.
- **`sda2` i `fsstat` zwrócił błąd** - swap nie jest systemem plików.

### 8.4 Ograniczenia
- Brak SMART: nie ocenimy zdrowia dysku.
- Numer seryjny jest sztuczny, więc dysk identyfikują UUID-y i hashe, nie sprzęt.
- W widocznej dla mnie części pliku nie zobaczyłem końcowej sekcji ostrzeżeń `warnings`; jeśli istnieje, sprawdź ją ręcznie.
- Raport to stan z jednej chwili.

## 9. Porównanie z `linux-001_sda.yaml`

| Cecha | `linux-001` (wcześniej) | `Alpine-EV-001` (teraz) |
|---|---|---|
| Data | 2026-11-10 | 2026-11-11 |
| Badany obiekt | partycja `sda3` | cały dysk `sda` |
| Hash całego dysku | brak | **jest** (SHA-256 `1dc92bd5...8fc4`) |
| Typ kontrolera | SCSI (`mptspi`), model `VMware Virtual S` | SATA/AHCI, `VMware Virtual SATA Hard Drive` |
| Numer seryjny | brak | `00000000000000000001` |
| Kernel | 7.3.0-10 | 7.0.0-43 |
| Sleuth Kit | 4.14.0 | 4.12.1 |
| HPA/DCO | **niewiarygodne** (`reliable: false`) | **wiarygodne** (`reliable: true`, 0 ukrytych) |
| SMART | brak | brak |
| `fsstat` | awaria (rc -11) na wszystkich partycjach | działa dla `sda1`, `sda3`; `sda2` (swap) rc 1 |
| Odczytane dane (I/O) | ok. 20 MB | ok. 289 GiB (skumulowane) |
| Zapisane dane | 0 | 0 |
| Komunikaty | po polsku | po angielsku |
| MBR, UUID partycji | identyczne | identyczne |

**Wniosek z porównania:** sektor 0, UUID-y partycji i hashe początków partycji są **identyczne** w obu raportach. To ten sam układ dysku (ten sam obraz lub sklonowana maszyna) zaobserwowany w dwóch konfiguracjach sprzętu wirtualnego. Dlatego zmiana kontrolera z SCSI na SATA dała lepsze wyniki narzędzi.

## 10. Jak weryfikować raport (praktycznie)

```bash
# 1. podgląd kluczowych sekcji
yq '.case, .safety, .device_hashes, .hidden_areas' Alpine-EV-001_sda.yaml

# 2. ponowne policzenie hasha całego dysku (dysk musi być RO)
sudo blockdev --getro /dev/sda            # oczekiwane: 1
sudo sha256sum /dev/sda
# oczekiwane: 1dc92bd531f38e2a69f9aa0675cd93b988703f267d3a52ab3542ce459d398fc4

# 3. kontrola sektora 0
sudo dd if=/dev/sda bs=512 count=1 2>/dev/null | sha256sum
# oczekiwane: 0a0d83a30695998219926bafade180182b8ee0df464ff8ff6252463094363d4c

# 4. bezpieczne montowanie ext4 (bez odtwarzania dziennika)
sudo mount -o ro,noload,noexec,nodev /dev/sda3 /mnt/evidence
```

## 11. Checklista czytania raportu

1. `status: COMPLETED`.
2. `device_hashes.complete: true` i `bytes_hashed == expected_bytes`.
3. `safety.read_only_verified: true`, `write_bytes: 0`.
4. Zapisz SHA-256 dysku i sektora 0 jako odciski dowodu.
5. Układ partycji zgodny w `fdisk`, `mmls`, `lsblk`.
6. `hidden_areas.reliable: true` i `hidden_sectors: 0`.
7. Odnotuj flagę *Needs Recovery* oraz błędy I/O (`ioerr_cnt`, `iotmo_cnt`).
8. Powtórz hash i porównaj.
