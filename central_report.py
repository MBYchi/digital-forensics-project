#!/usr/bin/env python3
"""central_report.py - forensic central report (PDF): what was done + MD5/SHA-1/SHA-256/SHA-512
hashes of all module reports in the case dir + evidence and ZIP hashes + GUM (NTP) time reference
+ PEM digital signature + optional TSA timestamp + ZIP with reports (and optionally the image).

Usage:
  python central_report.py --case-dir case-001 --evidence-id case-001 --examiner "Ruslan Hedz" \
      --key key.pem --cert cert.pem --tsa-url http://timestamp.digicert.com --include-image

Requires: pip install pyyaml reportlab pyhanko ntplib
"""
import argparse, getpass, hashlib, os, re, shutil, sys, zipfile
from datetime import datetime, timezone
from pathlib import Path
import yaml
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak

NA = "n/a"
JSON_YAML = (".json", ".jsonl", ".yaml", ".yml")
ALGOS = ("md5", "sha1", "sha256", "sha512")
LABEL = {"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256", "sha512": "SHA-512"}
GUM_SERVERS = ("tempus1.gum.gov.pl", "tempus2.gum.gov.pl")
HLINE = re.compile(r"^(MD5|SHA1|SHA224|SHA256|SHA384|SHA512)\s*\((.+)\)\s*=\s*([0-9a-fA-F]+)\s*$")


def fonts():
    dirs = ["/usr/share/fonts/truetype/dejavu"]
    try:
        import matplotlib
        dirs.append(os.path.join(os.path.dirname(matplotlib.__file__), "mpl-data/fonts/ttf"))
    except ImportError:
        pass
    for d in dirs:
        if Path(d, "DejaVuSans.ttf").exists():
            for n, f in (("D", "DejaVuSans"), ("DB", "DejaVuSans-Bold"), ("M", "DejaVuSansMono")):
                pdfmetrics.registerFont(TTFont(n, f"{d}/{f}.ttf"))
            return
    sys.exit("! DejaVu font missing (apt install fonts-dejavu-core)")


def hashes(p):
    """MD5, SHA-1, SHA-256, SHA-512 in a single pass."""
    hs = {a: hashlib.new(a) for a in ALGOS}
    with open(p, "rb") as f:
        while c := f.read(1 << 20):
            for h in hs.values():
                h.update(c)
    return {a: h.hexdigest() for a, h in hs.items()}


def g(d, *ks, default=NA):
    for k in ks:
        if not isinstance(d, dict) or k not in d:
            return default
        d = d[k]
    return default if d in (None, "") else d


def classify(doc):
    if not isinstance(doc, dict):
        return None
    if "partitioning" in doc or "hidden_areas" in doc:
        return "metadata"
    if "image" in doc or "workflow" in doc:
        return "binary_copy"
    if "inventory_csv" in str(doc.get("result", "")) or "algorithms" in doc:
        return "file_inventory"
    return None


def companion(p):
    """Values from <file>.hashes.txt as {algo: hex} (empty when the file is missing)."""
    h = p.with_name(p.name + ".hashes.txt")
    out = {}
    if h.is_file():
        for line in h.read_text(encoding="utf-8", errors="replace").splitlines():
            m = HLINE.match(line.strip())
            if m:
                out[m.group(1).lower()] = m.group(3).lower()
    return out


def ntp_reference(timeout=2.0):
    """Time measurement from GUM without changing the system clock. Returns (text, offset_s or None)."""
    try:
        import ntplib
    except ImportError:
        return "ntplib missing - local clock only", None
    cl = ntplib.NTPClient()
    for srv in GUM_SERVERS:
        try:
            r = cl.request(srv, version=4, timeout=timeout)
            if r.leap == 3 or not 1 <= r.stratum <= 15:
                continue
            utc = datetime.fromtimestamp(r.tx_time, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            return (f"{srv}: {utc} UTC, offset {r.offset:+.3f} s, stratum {r.stratum} "
                    f"(unauthenticated NTP, not part of the signature)"), r.offset
        except Exception:
            continue
    return "GUM unreachable - local clock only", None


def sign_pdf(src, dst, key_pem, cert_pem, passphrase, reason, examiner, tsa_url=None):
    from pyhanko.sign import signers
    from pyhanko.sign.fields import SigFieldSpec
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.stamp import TextStampStyle
    signer = signers.SimpleSigner.load(
        key_file=key_pem, cert_file=cert_pem,
        key_passphrase=passphrase.encode() if passphrase else None)
    if signer is None:
        sys.exit("! Could not load the PEM key/certificate")
    meta = signers.PdfSignatureMetadata(field_name="ExaminerSignature", reason=reason, location="Wrocław, PL")
    spec = SigFieldSpec("ExaminerSignature", on_page=-1, box=(300, 40, 560, 100))
    style = TextStampStyle(
        stamp_text=f"Digitally signed by: {examiner}\nReason: {reason}\nCertificate: see report page 1",
        border_width=1)
    tsa = None
    if tsa_url:
        from pyhanko.sign import timestamps
        tsa = timestamps.HTTPTimeStamper(tsa_url)
    with open(src, "rb") as f:
        w = IncrementalPdfFileWriter(f)
        ps = signers.PdfSigner(meta, signer=signer, new_field_spec=spec, stamp_style=style, timestamper=tsa)
        with open(dst, "wb") as o:
            ps.sign_pdf(w, output=o)


def key_is_encrypted(path):
    return "ENCRYPTED" in Path(path).read_text(errors="replace")


def find_images(cdir, found):
    """Disk image paths: taken from the binary copy YAML, otherwise any *.img in the case dir."""
    imgs = []
    for p, d in found.get("binary_copy", []):
        ref = g(d, "image", "path", default=None)
        if ref:
            q = Path(ref) if Path(ref).is_absolute() else p.parent / Path(ref).name
            if q.is_file():
                imgs.append(q.resolve())
    if not imgs:
        imgs = [q.resolve() for q in sorted(cdir.rglob("*.img")) if q.is_file()]
    return list(dict.fromkeys(imgs))


def make_zip(zip_path, cdir, include_image, found):
    """ZIP with all report files (JSON/YAML) from the case dir (+ the image only if include_image)."""
    cdir = cdir.resolve()
    files = [p.resolve() for p in sorted(cdir.rglob("*")) if p.is_file() and p.suffix.lower() in JSON_YAML]
    images = find_images(cdir, found) if include_image else []
    if include_image and not images:
        print("warn: --include-image given but no image file was found")
    need = sum(i.stat().st_size for i in images)
    free = shutil.disk_usage(zip_path.parent).free
    if need and free < need * 1.05:
        sys.exit(f"! Not enough free space for the image in the ZIP (need {need} B, free {free} B)")

    def arc(p):
        try:
            return str(p.relative_to(cdir))
        except ValueError:
            return p.name

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as z:
        for p in files:
            z.write(p, arcname=arc(p))
        for img in images:
            z.write(img, arcname=arc(img), compress_type=zipfile.ZIP_STORED)
    return len(files), len(images)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--case-dir", required=True)
    ap.add_argument("--evidence-id", required=True)
    ap.add_argument("--examiner", required=True)
    ap.add_argument("--version", default="1.0")
    ap.add_argument("--out", default=None)
    ap.add_argument("--key", default=None, help="private key PEM (key.pem)")
    ap.add_argument("--cert", default=None, help="signer certificate PEM (cert.pem)")
    ap.add_argument("--tsa-url", default=None, help="RFC 3161 TSA, e.g. http://timestamp.digicert.com")
    ap.add_argument("--reason", default="Forensic report approval")
    ap.add_argument("--extra", nargs="*", default=[], help="additional report files (JSON/YAML) to hash")
    ap.add_argument("--include-image", action="store_true",
                    help="also put the disk image (.img) into the ZIP archive")
    a = ap.parse_args()
    if bool(a.key) != bool(a.cert):
        sys.exit("! --key and --cert must be given together")
    if a.tsa_url and not a.key:
        sys.exit("! --tsa-url requires --key and --cert")
    fonts()
    cdir = Path(a.case_dir)
    out = Path(a.out) if a.out else cdir / f"{a.evidence_id}_central_report.pdf"

    B = ParagraphStyle("b", fontName="D", fontSize=9, leading=12.5)
    H1 = ParagraphStyle("h1", parent=B, fontName="DB", fontSize=13, leading=17, spaceBefore=10, spaceAfter=5,
                        textColor=colors.HexColor("#1F3A5F"))
    T = ParagraphStyle("t", parent=B, fontName="DB", fontSize=19, leading=25, alignment=1)
    C = ParagraphStyle("c", parent=B, fontSize=8, leading=10.5)
    CM = ParagraphStyle("cm", parent=C, fontName="M", fontSize=6.3, leading=8)
    esc = lambda x: str(x).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    GREEN, RED = colors.HexColor("#2E7D32"), colors.HexColor("#B00020")

    def tbl(rows, w, mono=(), status_col=None):
        data = [[Paragraph(esc(c), CM if (i and j in mono) else C) for j, c in enumerate(r)]
                for i, r in enumerate(rows)]
        t = Table(data, colWidths=[x * mm for x in w], repeatRows=1)
        st = [("GRID", (0, 0), (-1, -1), .4, colors.grey), ("VALIGN", (0, 0), (-1, -1), "TOP"),
              ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#DCE6F1"))]
        col = status_col if status_col is not None else len(rows[0]) - 1
        for i, r in enumerate(rows[1:], 1):
            v = str(r[col])
            if v.startswith(("MISMATCH", "FAILED", "BROKEN", "PROBLEM", "file missing", "NO REPORT")):
                st.append(("TEXTCOLOR", (col, i), (col, i), RED))
            elif v.startswith("OK"):
                st.append(("TEXTCOLOR", (col, i), (col, i), GREEN))
        t.setStyle(TableStyle(st))
        return t

    def hash_block(label, hs, check=None):
        """4 rows: Object, Algorithm, Value, Check."""
        rows = []
        for i, al in enumerate(ALGOS):
            res = NA
            if check is not None:
                res = ("OK - matches" if check.get(al) == hs[al] else "MISMATCH - file changed!") if al in check else "no stored value"
            rows.append([label if i == 0 else "", LABEL[al], hs[al], res])
        return rows

    found = {}
    for y in sorted(p for p in cdir.rglob("*") if p.is_file() and p.suffix.lower() in (".yaml", ".yml")):
        try:
            doc = yaml.safe_load(y.read_text(encoding="utf-8"))
        except Exception:
            continue
        k = classify(doc)
        if k:
            found.setdefault(k, []).append((y, doc))
    tref, toff = ntp_reference()

    zpath = cdir / f"{a.evidence_id}_reports{'_with_image' if a.include_image else ''}.zip"
    nf, ni = make_zip(zpath, cdir, a.include_image, found)
    zhs = hashes(zpath)
    print(f"zip: {zpath} ({nf} report files, {ni} image(s))")

    NAMES = {
        "metadata": ("Metadata", "metadata_collector.py",
                     "Collected lsblk/fdisk/sgdisk/mmls/fsstat/hdparm/SMART data, verified read-only state, checked HPA/DCO, hashed the whole device."),
        "binary_copy": ("Binary copy", "binary_copy.py",
                        "Hashed source, wrote bit-for-bit image, hashed image, compared hashes."),
        "file_inventory": ("File inventory", "file_inventory_disk.py",
                           "Walked the read-only mounted filesystem; recorded metadata and MD5/SHA-1/SHA-256/SHA-512 for each file."),
    }

    hash_rows = [["File", "Algorithm", "Hash (computed now)", "Check vs .hashes.txt"]]
    state = {"missing": False, "mismatch": False}

    def addfile(label, p):
        p = Path(p)
        if not p.is_file():
            hash_rows.append([f"{label}: {p.name}", "-", NA, "file missing"])
            state["missing"] = True
            return
        hs = hashes(p)
        chk = companion(p) or None
        blk = hash_block(f"{label}: {p.name}", hs, chk)
        if any(r[3].startswith("MISMATCH") for r in blk):
            state["mismatch"] = True
        hash_rows.extend(blk)

    kind = {str(p): NAMES[k][0] + " report" for k, lst in found.items() for p, _ in lst}
    seen = set()
    for p in sorted(cdir.rglob("*")):
        if p.is_file() and p.suffix.lower() in JSON_YAML:
            seen.add(p.resolve())
            in_ro = "ro_mount" in [x.lower() for x in p.relative_to(cdir).parts[:-1]]
            label = "RO mount report" if in_ro else kind.get(str(p), "Report")
            addfile(label, p)
    for ex in a.extra:
        if Path(ex).suffix.lower() in JSON_YAML and Path(ex).resolve() not in seen:
            addfile("Report", ex)

    all_ok = not state["missing"] and not state["mismatch"] and len(hash_rows) > 1

    s = [Spacer(1, 22 * mm), Paragraph("CENTRAL FORENSIC REPORT", T), Spacer(1, 8 * mm)]
    first = next((d for k in ("metadata", "binary_copy", "file_inventory") for _, d in found.get(k, [])), {})
    rows = [["Field", "Value"], ["Evidence ID", a.evidence_id], ["Device", g(first, "case", "device")],
            ["Examiner", a.examiner],
            ["Generated (UTC)", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")],
            ["Version", a.version],
            ["Time reference (GUM)", tref]]
    if toff is not None and abs(toff) > 1:
        rows.append(["Clock warning", f"System clock differs from GUM by {toff:+.1f} s"])
    rows.append(["Trusted timestamp (TSA)", a.tsa_url or "none - signature time comes from the signer's clock"])
    s.append(tbl(rows, [45, 125], mono=(1,), status_col=0))
    s.append(Spacer(1, 4 * mm))
    s.append(Paragraph("Hashes of the generator script and signing certificate", H1))
    hrows = [["Object", "Algorithm", "Hash", "Check"]]
    hrows += hash_block("central_report.py", hashes(__file__))
    if a.cert:
        hrows += hash_block("Signing certificate " + Path(a.cert).name, hashes(a.cert))
    s.append(tbl(hrows, [38, 20, 100, 12], mono=(2,)))
    s.append(PageBreak())

    vt = Table([[Paragraph(
        "<font color='white'><b>INTEGRITY CHECK: " + ("PASSED" if all_ok else "ATTENTION REQUIRED") + "</b><br/>" +
        ("All module report hashes match their companion files."
         if all_ok else "A hash mismatch or a missing file was found - see section 2.") +
        "</font>", B)]], colWidths=[170 * mm])
    vt.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), GREEN if all_ok else RED),
                            ("LEFTPADDING", (0, 0), (-1, -1), 8), ("TOPPADDING", (0, 0), (-1, -1), 6),
                            ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
    s += [vt, Spacer(1, 3 * mm)]

    s.append(Paragraph("1. What was done", H1))
    rows = [["Module", "Script", "Action", "Status", "Start (UTC)", "End (UTC)"]]
    for k in ("metadata", "binary_copy", "file_inventory"):
        n, sc, act = NAMES[k]
        if k not in found:
            rows.append([n, sc, act, "NO REPORT FOUND", NA, NA])
            continue
        for p, d in found[k]:
            rows.append([n, sc, act, g(d, "case", "status"), g(d, "case", "started_utc"), g(d, "case", "finished_utc")])
    s.append(tbl(rows, [24, 28, 58, 22, 19, 19]))

    s.append(Paragraph("2. Hashes of module reports", H1))
    s.append(Paragraph("MD5, SHA-1, SHA-256 and SHA-512 computed now over every module report in the case directory and compared with the values stored in its companion .hashes.txt (if present). MD5 and SHA-1 are listed for compatibility; rely on SHA-256/SHA-512.", C))
    s.append(tbl(hash_rows, [38, 18, 100, 14], mono=(2,)))

    s.append(Paragraph("3. Evidence and archive hashes", H1))
    rows = [["Evidence", "Algorithm", "Hash"]]

    def ev_rows(label, node):
        for i, al in enumerate(ALGOS):
            rows.append([label if i == 0 else "", LABEL[al], g(node, al)])

    for p, d in found.get("binary_copy", []):
        dev = g(d, "source", "path")
        ev_rows(f"Disk {dev}", g(d, "source", "hashes_before", default={}))
        ev_rows("Disk image", g(d, "image", "hashes", default={}))
    if not found.get("binary_copy"):
        for p, d in found.get("metadata", []):
            ev_rows("Disk " + str(g(d, "case", "device")), g(d, "device_hashes", "hashes", default={}))
    ev_rows(f"ZIP archive {zpath.name}", zhs)
    s.append(tbl(rows, [45, 20, 105], mono=(2,), status_col=1))
    s.append(Paragraph("The ZIP contains the module reports" + (" and the disk image" if a.include_image else "") +
                       ". The PDF report is not inside the ZIP.", C))

    s.append(Paragraph("4. Warnings and limitations", H1))
    s.append(Paragraph("• Software read-only protection is not a hardware write blocker.", B))

    def pg(c, doc):
        c.saveState()
        c.setFillColor(colors.HexColor("#1F3A5F"))
        c.rect(0, 285 * mm, 210 * mm, 12 * mm, stroke=0, fill=1)
        c.setFillColor(colors.white)
        c.setFont("DB", 9)
        c.drawString(20 * mm, 289 * mm, "CENTRAL FORENSIC REPORT")
        c.drawRightString(190 * mm, 289 * mm, a.evidence_id)
        c.setFillColor(colors.grey)
        c.setFont("D", 7)
        c.line(20 * mm, 14 * mm, 190 * mm, 14 * mm)
        c.drawString(20 * mm, 10 * mm, f"v{a.version} | Examiner: {a.examiner}")
        c.drawRightString(190 * mm, 10 * mm, f"Page {doc.page}")
        c.restoreState()

    SimpleDocTemplate(str(out), pagesize=A4, leftMargin=20 * mm, rightMargin=20 * mm,
                      topMargin=24 * mm, bottomMargin=20 * mm).build(s, onFirstPage=pg, onLaterPages=pg)

    final = out
    if a.key:
        pw = None
        if key_is_encrypted(a.key):
            pw = os.environ.get("FORENSIC_KEY_PASS") or getpass.getpass("Key passphrase: ")
        final = out.with_name(out.stem + "_signed.pdf")
        sign_pdf(str(out), str(final), a.key, a.cert, pw, a.reason, a.examiner, a.tsa_url)
        print("signed:", final, "(with TSA token)" if a.tsa_url else "(no TSA token)")
    print("OK", final)


if __name__ == "__main__":
    main()