import os
import math
import sys
import yara
import pefile
from collections import Counter
from pathlib import Path

CONFIG = {
    'score_thresholds': {
        'suspicious': 10,
        'critical': 50
    },
}

SUSPICIOUS_EXTENSIONS = {".locked", ".enc", ".pay"}
SUSPICIOUS_KEYFILES = {"vault", ".key", "secret.key"}
EXPECTED_MAGIC = {
    ".jpg": b"\xff\xd8\xff",
    ".png": b"\x89PNG",
    ".pdf": b"%PDF",
    ".zip": b"PK\x03\x04",
    ".exe": b"MZ"
}
SUSPICIOUS_SECTIONS = {".upx", ".asdf", ".textbss", ".packed", ".encsec", ".xyz", ".lol"}


def load_named_yara_rules():
    rules = yara.compile(filepath='./rules/index.yara', includes=True)
    return rules


def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0
    counter = Counter(data)
    total = len(data)
    entropy = -sum((count / total) * math.log2(count / total) for count in counter.values())
    return entropy


def has_suspicious_extension(file_path):
    return Path(file_path).suffix.lower() in SUSPICIOUS_EXTENSIONS


def is_key_file(file_path):
    name = Path(file_path).name.lower()
    return any(key in name for key in SUSPICIOUS_KEYFILES)


def mismatched_magic_bytes(file_path):
    ext = Path(file_path).suffix.lower()
    expected = EXPECTED_MAGIC.get(ext)
    if not expected:
        return False
    try:
        with open(file_path, "rb") as f:
            header = f.read(len(expected))
            return not header.startswith(expected)
    except:
        return False


def suspicious_pe_sections(file_path):
    try:
        pe = pefile.PE(file_path)
        for section in pe.sections:
            name = section.Name.decode(errors="ignore").strip("\x00").lower()
            print(f"[PE] Section found: {name}")
            if name in SUSPICIOUS_SECTIONS:
                return True
    except (pefile.PEFormatError, IOError) as e:
        print(f"Warning: {file_path} - {str(e)}", file=sys.stderr)
    return False


def analyze_file(file_path, rules):
    print("analyze file")
    try:
        with open(file_path, "rb") as f:
            data = f.read()
    except Exception as e:
        return None

    flags = []
    score = 0

    matches = rules.match(data=data)
    yara_score = 0
    for match in matches:
        rule_score = int(match.meta.get('score', 0))
        yara_score += rule_score
        flags.append(f"YARA Rule: {match.rule} ({rule_score})")

    score += yara_score

    # === Manual checks ===
    if calculate_entropy(data) > 7.5:
        flags.append("High Entropy")
        score += 3

    # Check overlay entropy (tail section)
    try:
        with open(file_path, 'rb') as f:
            f.seek(-4096, os.SEEK_END)
            tail = f.read(4096)
            if calculate_entropy(tail) > 7.5:
                flags.append("High Entropy Overlay")
                score += 2
    except Exception:
        pass

    if has_suspicious_extension(file_path):
        flags.append("Suspicious Extension")
        score += 2

    if is_key_file(file_path):
        flags.append("Suspicious Filename")
        score += 2

    if mismatched_magic_bytes(file_path):
        flags.append("Mismatched Magic Bytes")
        score += 2

    if file_path.lower().endswith(".exe") and suspicious_pe_sections(file_path):
        flags.append("Suspicious PE Sections")
        score += 3

    # Static string heuristics
    try:
        decoded = data.decode(errors='ignore')
        if "vssadmin delete shadows" in decoded:
            flags.append("Shadow Copy Deletion Command")
            score += 5
        if "Your files have been encrypted" in decoded:
            flags.append("Ransom Note Text")
            score += 7
        if "AES_encrypt" in decoded or "EVP_aes_256" in decoded:
            flags.append("Encryption API Found")
            score += 5
    except:
        pass

    if score >= CONFIG["score_thresholds"]["critical"]:
        verdict = "Critical"
    elif score >= CONFIG["score_thresholds"]["suspicious"]:
        verdict = "Suspicious"
    else:
        verdict = "Clean"

    return {
        "file": file_path,
        "verdict": verdict,
        "score": score,
        "reasons": flags
    }


def scan_directory(folder, rules):
    print("scanning directory")
    results = []
    for root, _, files in os.walk(folder):
        for file in files:
            full_path = os.path.join(root, file)
            result = analyze_file(full_path, rules)
            if result:
                results.append(result)
    return results


def main():
    try:
        print("Starting scanner...")
        rules = load_named_yara_rules()
        print("YARA rules loaded successfully")

        folder = r"./File-Populator/populated"
        print(f"Scanning folder: {folder}")
        print(f"Folder exists: {os.path.exists(folder)}")

        results = scan_directory(folder, rules)
        print(f"Scan completed. Found {len(results)} files")

        for res in results:
            print(f"{res['verdict']}: {res['file']}")
            print(f"    Score: {res['score']}")
            if res["reasons"]:
                print(f"    Reasons: {', '.join(res['reasons'])}")

    except Exception as e:
        print(f"Fatal error: {str(e)}", file=sys.stderr)
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
