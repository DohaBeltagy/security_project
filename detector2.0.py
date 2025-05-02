import os
import math
import sys
import yara
import pefile
from collections import Counter
from pathlib import Path
import re 

CONFIG = {
    'score_thresholds': {
        'suspicious': 10,
        'critical': 30
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
SUSPICIOUS_IMPORTS = [
    "CryptEncrypt", "CryptGenKey", "CryptAcquireContextA",
    "DeleteFileW", "MoveFileW", "SHEmptyRecycleBinA",
    "VssAdmin", "NetUserDel", "SystemFunction032"
]

def check_suspicious_imports(pe):
    try:
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name and any(s in imp.name.decode(errors="ignore") for s in SUSPICIOUS_IMPORTS):
                    return True
    except:
        pass
    return False


def load_named_yara_rules():
    rules_dir = './rules'
    filepaths = {
        'mass': os.path.join(rules_dir, 'massopeartions.yara'),
        'aes': os.path.join(rules_dir, 'aes.yara'),
        'note': os.path.join(rules_dir, 'note.yara'),
        'system_destruct': os.path.join(rules_dir, 'system_destructive_command.yara'),
        'base64': os.path.join(rules_dir, 'base64_Overflow.yara')
    }
    for name, path in filepaths.items():
        print(f"{name} path exists:", os.path.exists(path))  # Debug each path
    return yara.compile(filepaths=filepaths)

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
def has_large_overlay(file_path):
    try:
        pe = pefile.PE(file_path)
        last_section = pe.sections[-1]
        end_of_sections = last_section.PointerToRawData + last_section.SizeOfRawData
        actual_size = os.path.getsize(file_path)
        overlay_size = actual_size - end_of_sections
        return overlay_size > 50 * 1024  # >50KB overlay = suspicious
    except:
        return False

def detect_embedded_payloads(data):
    suspicious_embeds = []
    embedded_signatures = {
        "PE EXE": b"MZ",
        "ZIP Archive": b"PK\x03\x04",
        "PowerShell": b"powershell",
        "CMD": b"cmd.exe",
        "WScript": b"wscript",
    }
    for label, sig in embedded_signatures.items():
        if sig in data:
            suspicious_embeds.append(label)
    base64_blobs = re.findall(rb"[A-Za-z0-9+/]{200,}={0,2}", data)
    if len(base64_blobs) >= 3:
        suspicious_embeds.append("Multiple Base64 Blobs")
    return suspicious_embeds


def analyze_file(file_path, rules):
    print(f"Analyzing: {file_path}")
    try:
        with open(file_path, "rb") as f:
            data = f.read()
    except Exception as e:
        print(f"Failed to read {file_path}: {e}", file=sys.stderr)
        return None

    flags = []
    score = 0

    # === YARA Matching ===
    matches = rules.match(data=data)
    yara_score = 0
    for match in matches:
        rule_score = int(match.meta.get('score', 0))
        yara_score += rule_score
        flags.append(f"YARA Rule: {match.rule} ({rule_score})")
    score += yara_score

    # === Mutex keywords ===
    mutex_keywords = ["mutex", "global\\", "session", "mtx"]

    # === Entropy Checks ===
    if calculate_entropy(data) > 7.5:
        flags.append("High Entropy")
        score += 2

    try:
        with open(file_path, 'rb') as f:
            f.seek(-4096, os.SEEK_END)
            tail = f.read(4096)
            if calculate_entropy(tail) > 7.5:
                flags.append("High Entropy Overlay")
                score += 2
    except Exception:
        pass

    # === PE Analysis ===
    if file_path.lower().endswith(".exe"):
        try:
            pe = pefile.PE(file_path)

            if check_suspicious_imports(pe):
                flags.append("Suspicious Imports")
                score += 5

            if suspicious_pe_sections(file_path):
                flags.append("Suspicious PE Sections")
                score += 3

            if has_large_overlay(file_path):
                flags.append("Large Overlay Detected")
                score += 3

        except pefile.PEFormatError:
            pass

    # === Static Heuristics ===
    if has_suspicious_extension(file_path):
        flags.append("Suspicious Extension")
        score += 2

    if is_key_file(file_path):
        flags.append("Suspicious Filename")
        score += 2

    if mismatched_magic_bytes(file_path):
        flags.append("Mismatched Magic Bytes")
        score += 2

    # === Embedded payload indicators ===
    embedded_flags = detect_embedded_payloads(data)
    for label in embedded_flags:
        flags.append(f"Embedded Signature: {label}")
        score += 2

    obfuscation_patterns = ["-e ", "iex", "frombase64string", "invoke-expression"]
    note_patterns = [
        r"your files have been encrypted",
        r"encrypted",
        r"decrypt.*bitcoin",
        r"decrypt.*wallet",
        r"contact.*(support|email)",]
    # === String-based Heuristics ===
    try:
        decoded = data.decode(errors='ignore')
        if "vssadmin delete shadows" in decoded:
            flags.append("Shadow Copy Deletion Command")
            score += 15
        if "Your files have been encrypted" in decoded:
            flags.append("Ransom Note Text")
            score += 7
        if "AES_encrypt" in decoded or "EVP_aes_256" in decoded:
            flags.append("Encryption API Found")
            score += 10
        for keyword in mutex_keywords:
            if keyword in decoded.lower():
                flags.append("Suspicious Mutex Name")
                score += 2
                break
        for pattern in note_patterns:
            if re.search(pattern, decoded, re.IGNORECASE):
                flags.append("Ransom Note Pattern")
                score += 30
                break
        if any(p in decoded.lower() for p in obfuscation_patterns):
            flags.append("Script Obfuscation Detected")
            score += 3
    except:
        pass

    try:
        utf16_decoded = data.decode('utf-16', errors='ignore')
        if "Your files have been encrypted" in utf16_decoded:
            flags.append("Ransom Note (UTF-16)")
            score += 7
        if "AES_encrypt" in utf16_decoded or "EVP_aes_256_cbc" in utf16_decoded:
            flags.append("Encryption API (UTF-16)")
            score += 5
        if "vssadmin delete shadows" in utf16_decoded:
            flags.append("Shadow Copy Delete (UTF-16)")
            score += 5
        for keyword in mutex_keywords:
            if keyword in utf16_decoded.lower():
                flags.append("Suspicious Mutex Name (UTF-16)")
                score += 2
                break
        for pattern in note_patterns:
            if re.search(pattern, utf16_decoded, re.IGNORECASE):
                flags.append("Ransom Note Pattern")
                score += 30
                break
        if any(p in utf16_decoded.lower() for p in obfuscation_patterns):
            flags.append("Script Obfuscation (UTF-16)")
            score += 4
    except:
        pass
    
    
    # === Final Verdict ===
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
