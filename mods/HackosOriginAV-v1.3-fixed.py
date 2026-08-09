# mods/HackosOriginAV.py
# -*- coding: utf-8 -*-

"""
HackosOriginAV v1.3 FIXED

HackOS v5.x mod API uyumlu antivirus.
- setup(api) kullanir
- @api.add_command() kullanir
- AST statik analiz
- Risk puanlama
- Dinamik kod / encoded veri korelasyonu
- Supheli metin sinyalleri
- Karantina
- Tarama gecmisi
- Kendi dosyasini yanlis pozitif olarak taramaz
"""

import ast
import base64
import hashlib
import math
import re
import time
from pathlib import Path


META = {
    "name": "HackosOriginAV",
    "version": "1.3",
    "author": "HackOS Security",
    "description": "Davranis korelasyonlu Python guvenlik analizoru.",
    "permissions": [
        "dosya_okuma",
        "dosya_yazma",
        "yeniden_adlandirma"
    ]
}

AV_DIR = ".HackosOriginAV"
QUARANTINE_DIR = AV_DIR + "/quarantine"
MAX_SOURCE_SIZE = 2 * 1024 * 1024

IMPORT_SCORES = {
    "socket": 5,
    "requests": 5,
    "urllib": 5,
    "urllib3": 5,
    "ftplib": 8,
    "subprocess": 8,
    "ctypes": 10,
}

DYNAMIC_CALLS = {
    "eval": 18,
    "exec": 22,
    "compile": 12,
    "__import__": 10,
}

HACKOS_OPERATIONS = {
    "delete_file": 8,
    "rename_file": 5,
    "write_file": 3,
    "read_file": 2,
    "run": 8,
}

SUSPICIOUS_TEXT = {
    "rm -rf": 18,
    "powershell": 12,
    "cmd.exe": 12,
    "wget": 8,
    "curl": 8,
    "chmod +x": 10,
    "base64 -d": 12,
}

def clamp(value, low=0, high=100):
    return max(low, min(high, value))

def sha256_text(text):
    return hashlib.sha256(
        text.encode("utf-8", errors="ignore")
    ).hexdigest()

def entropy(text):
    if not text:
        return 0.0
    counts = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    length = len(text)
    result = 0.0
    for count in counts.values():
        p = count / length
        result -= p * math.log2(p)
    return result

def get_call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parts = []
        current = node
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
            return ".".join(reversed(parts))
    return ""

class OriginScanner(ast.NodeVisitor):

    def __init__(self, source):
        self.source = source
        self.score = 0
        self.findings = []
        self.imports = set()
        self.calls = set()
        self.file_operations = 0
        self.network_operations = 0
        self.dynamic_operations = 0
        self.encoded_strings = 0

    def add(self, score, level, message, line=0):
        self.score += score
        self.findings.append({
            "score": score,
            "level": level,
            "message": message,
            "line": line
        })

    def visit_Import(self, node):
        for item in node.names:
            root = item.name.split(".")[0]
            self.imports.add(root)
            if root in IMPORT_SCORES:
                self.add(
                    IMPORT_SCORES[root],
                    "INFO",
                    f"Supheli kutuphane: {item.name}",
                    node.lineno
                )
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        module = node.module or ""
        root = module.split(".")[0]
        self.imports.add(root)
        if root in IMPORT_SCORES:
            self.add(
                IMPORT_SCORES[root],
                "INFO",
                f"Supheli kutuphane: {module}",
                node.lineno
            )
        self.generic_visit(node)

    def visit_Call(self, node):
        name = get_call_name(node.func)
        self.calls.add(name)

        if name in DYNAMIC_CALLS:
            self.dynamic_operations += 1
            self.add(
                DYNAMIC_CALLS[name],
                "HIGH",
                f"Supheli kod calistirma: {name}",
                getattr(node, "lineno", 0)
            )

        short = name.split(".")[-1]
        if short in HACKOS_OPERATIONS:
            self.file_operations += 1
            self.add(
                HACKOS_OPERATIONS[short],
                "INFO",
                f"HackOS islemi: {name}",
                getattr(node, "lineno", 0)
            )

        if name in (
            "socket.socket",
            "requests.get",
            "requests.post",
            "urllib.request.urlopen"
        ):
            self.network_operations += 1

        self.generic_visit(node)

    def visit_Constant(self, node):
        if not isinstance(node.value, str):
            self.generic_visit(node)
            return

        text = node.value
        compact = re.sub(r"\s+", "", text)

        if len(text) >= 500 and entropy(text) >= 4.7:
            self.encoded_strings += 1
            self.add(
                10,
                "MEDIUM",
                "Yuksek entropili uzun string",
                getattr(node, "lineno", 0)
            )

        if (
            len(compact) >= 80
            and re.fullmatch(r"[A-Za-z0-9+/=]+", compact)
        ):
            try:
                base64.b64decode(compact, validate=True)
                self.encoded_strings += 1
                self.add(
                    8,
                    "MEDIUM",
                    "Base64 benzeri encoded veri",
                    getattr(node, "lineno", 0)
                )
            except Exception:
                pass

        self.generic_visit(node)

    def correlate(self):
        if self.dynamic_operations and self.encoded_strings:
            self.add(
                25,
                "CRITICAL",
                "Dinamik kod + encoded veri kombinasyonu"
            )

        if self.dynamic_operations and self.file_operations >= 2:
            self.add(
                20,
                "HIGH",
                "Dinamik kod + coklu dosya islemi"
            )

        if self.network_operations and self.dynamic_operations:
            self.add(
                20,
                "HIGH",
                "Ag islemi + dinamik kod kombinasyonu"
            )

        if self.network_operations and self.file_operations >= 3:
            self.add(
                15,
                "MEDIUM",
                "Ag + coklu dosya islemi"
            )

        # Kaynak kod icindeki supheli komut/metinleri sinyal olarak say.
        lower = self.source.lower()
        for text, points in SUSPICIOUS_TEXT.items():
            if text in lower:
                self.add(
                    points,
                    "HIGH",
                    f"Supheli komut/metin: {text}"
                )

class HackosOriginAV:

    def __init__(self, api):
        self.api = api
        self.scanned = 0
        self.threats = 0
        self.last_scan = None
        self.history = []

    def read_file(self, path):
        try:
            source = self.api.read_file(path)
            if source is None or len(source) > MAX_SOURCE_SIZE:
                return None
            return source
        except Exception:
            return None

    def scan_file(self, path):
        source = self.read_file(path)

        if source is None:
            return {
                "path": path,
                "score": 50,
                "status": "OKUNAMADI",
                "findings": [{
                    "level": "MEDIUM",
                    "message": "Dosya okunamadi.",
                    "line": 0
                }]
            }

        if Path(path).name.lower() == "hackosoriginav.py":
            return {
                "path": path,
                "score": 0,
                "status": "TEMIZ",
                "findings": [{
                    "level": "INFO",
                    "message": "Antivirus kendi dosyasi; self-scan bypass.",
                    "line": 0
                }]
            }

        self.scanned += 1

        try:
            tree = ast.parse(source, filename=path)
        except SyntaxError as error:
            return {
                "path": path,
                "score": 20,
                "status": "SUPHELI",
                "findings": [{
                    "level": "INFO",
                    "message": "Syntax hatasi: " + str(error),
                    "line": getattr(error, "lineno", 0)
                }]
            }

        scanner = OriginScanner(source)
        scanner.visit(tree)
        scanner.correlate()

        score = clamp(scanner.score)

        if score >= 90:
            status = "KRITIK"
        elif score >= 70:
            status = "YUKSEK"
        elif score >= 50:
            status = "SUPHELI"
        elif score >= 25:
            status = "DUSUK_RISK"
        else:
            status = "TEMIZ"

        return {
            "path": path,
            "score": score,
            "status": status,
            "hash": sha256_text(source),
            "findings": scanner.findings
        }

    def scan_directory(self, directory):
        results = []
        try:
            files = self.api.list_dir(directory)
        except Exception:
            return results

        for name in files:
            if name.endswith(".py"):
                results.append(
                    self.scan_file(f"{directory}/{name}")
                )
        return results

    def full_scan(self):
        self.scanned = 0
        self.threats = 0

        print("\n==========================================")
        print("       HACKOSORIGINAV v1.3")
        print("==========================================")
        print("\n  [1/2] Modlar taraniyor...")
        results = self.scan_directory("mods")

        print("  [2/2] Eklentiler taraniyor...")
        results += self.scan_directory("eklentiler")

        print()

        for result in results:
            score = result["score"]
            status = result["status"]

            if status in ("KRITIK", "YUKSEK"):
                symbol = "!"
                self.threats += 1
            elif status == "SUPHELI":
                symbol = "?"
            elif status == "DUSUK_RISK":
                symbol = "~"
            else:
                symbol = "✓"

            print(
                f"  [{symbol}] {result['path']}"
                f"  Risk: {score}/100"
                f"  [{status}]"
            )

            for finding in result["findings"]:
                if finding["level"] in ("HIGH", "CRITICAL"):
                    print(
                        "       └─ "
                        + finding["message"]
                    )

        self.last_scan = time.strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        self.history.append({
            "time": self.last_scan,
            "files": len(results),
            "threats": self.threats
        })
        self.history = self.history[-20:]

        print("\n------------------------------------------")
        print(f"  Dosya: {len(results)}")
        print(f"  Tehdit: {self.threats}")
        print(f"  Zaman: {self.last_scan}")
        print("------------------------------------------\n")
        return results

    def single_scan(self):
        path = input("\n  Dosya yolu: ").strip()
        if not path:
            return

        result = self.scan_file(path)

        print(f"\n  Dosya : {result['path']}")
        print(f"  Risk  : {result['score']}/100")
        print(f"  Durum : {result['status']}\n")

        for finding in result["findings"]:
            print(
                f"  [{finding['level']}] "
                f"{finding['message']}"
            )
        print()

    def quarantine(self):
        path = input("\n  Karantinaya alinacak dosya: ").strip()
        if not path:
            return

        result = self.scan_file(path)

        if result["score"] < 70:
            print("\n  [!] Risk 70'in altinda; karantina yapilmadi.\n")
            return

        print(f"\n  TEHDIT: {result['status']}")
        print(f"  Risk: {result['score']}/100")

        answer = input(
            "  Karantinaya al? [e/h]: "
        ).strip().lower()

        if answer != "e":
            print("  Islem iptal edildi.")
            return

        try:
            self.api.write_file(
                QUARANTINE_DIR + "/.keep",
                ""
            )

            filename = Path(path).name
            target = (
                QUARANTINE_DIR
                + "/"
                + filename
                + ".quarantined"
            )

            self.api.rename_file(path, target)

            print("\n  KARANTINA BASARILI")
            print(f"  -> {target}\n")

        except Exception as error:
            print(f"\n  [!] Karantina hatasi: {error}\n")

    def show_history(self):
        print("\n========== HACKOSORIGINAV GECMIS ==========")

        if not self.history:
            print("  Henuz tarama yapilmadi.")
        else:
            for item in self.history:
                print(
                    f"  {item['time']} | "
                    f"Dosya: {item['files']} | "
                    f"Tehdit: {item['threats']}"
                )

        print("============================================\n")

    def status(self):
        print("\n========== HACKOSORIGINAV DURUM ==========")
        print(f"  Surum        : v{META['version']}")
        print(f"  Son tarama   : {self.last_scan or 'Yok'}")
        print(f"  Son taranan  : {self.scanned}")
        print(f"  Tehdit sayisi: {self.threats}")
        print("===========================================\n")

    def menu(self):
        while True:
            print("\n╔════════════════════════════════════╗")
            print("║       HACKOSORIGINAV v1.3          ║")
            print("╠════════════════════════════════════╣")
            print("║  1. 🔍 Hizli Tarama                ║")
            print("║  2. 🔎 Derin Tarama                ║")
            print("║  3. 📄 Dosya Tara                  ║")
            print("║  4. 🛡️ Karantina                   ║")
            print("║  5. 📋 Tarama Gecmisi              ║")
            print("║  6. ℹ️ Durum                       ║")
            print("║  0. 🚪 Cikis                       ║")
            print("╚════════════════════════════════════╝")

            secim = input("\n  HackOSAV > ").strip()

            if secim == "1":
                self.full_scan()
            elif secim == "2":
                self.full_scan()
            elif secim == "3":
                self.single_scan()
            elif secim == "4":
                self.quarantine()
            elif secim == "5":
                self.show_history()
            elif secim == "6":
                self.status()
            elif secim == "0":
                break
            else:
                print("  [!] Gecersiz secim.")

def setup(api):
    av = HackosOriginAV(api)

    @api.add_command(
        name="hackosav",
        description="HackosOriginAV antivirus menusu"
    )
    def hackosav(*args):
        av.menu()
