# mods/HackosOriginAV.py
# -*- coding: utf-8 -*-

"""
HackosOriginAV v1.2

Savunma amaçlı Python statik analiz antivirüsü.

Özellikler:
- AST tabanlı analiz
- Davranış korelasyonu
- Obfuscation sinyalleri
- Risk puanlama
- Self-scan koruması
- SHA-256
- Karantina
- Tarama geçmişi
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
    "version": "1.2",
    "author": "HackOS Security",
    "description": "Davranış korelasyonlu Python güvenlik analizörü.",
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
    "socket": 2,
    "requests": 2,
    "urllib": 2,
    "urllib3": 2,
    "ftplib": 3,
    "subprocess": 3,
    "ctypes": 4,
}

DYNAMIC_CALLS = {
    "eval": 15,
    "exec": 18,
    "compile": 10,
    "__import__": 8,
}

FILE_CALLS = {
    "open": 2,
    "os.remove": 6,
    "os.unlink": 6,
    "shutil.rmtree": 8,
}

NETWORK_CALLS = {
    "requests.get",
    "requests.post",
    "requests.put",
    "requests.delete",
    "urllib.request.urlopen",
    "socket.socket",
}

PROCESS_CALLS = {
    "os.system",
    "os.popen",
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.call",
    "subprocess.check_output",
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

        probability = count / length

        result -= (
            probability *
            math.log2(probability)
        )

    return result


def call_name(node):

    if isinstance(node, ast.Name):
        return node.id

    if isinstance(node, ast.Attribute):

        parts = []
        current = node

        while isinstance(
            current,
            ast.Attribute
        ):

            parts.append(current.attr)
            current = current.value

        if isinstance(current, ast.Name):

            parts.append(current.id)

            return ".".join(
                reversed(parts)
            )

    return ""


class OriginScanner(ast.NodeVisitor):

    def __init__(self, source):

        self.source = source

        self.score = 0
        self.findings = []

        self.imports = set()
        self.calls = set()

        self.dynamic = 0
        self.network = 0
        self.process = 0
        self.file_ops = 0
        self.encoded = 0
        self.long_strings = 0

    def add(
        self,
        score,
        level,
        message,
        line=0
    ):

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

        name = call_name(node.func)

        if name:
            self.calls.add(name)

        if name in DYNAMIC_CALLS:

            self.dynamic += 1

            self.add(
                DYNAMIC_CALLS[name],
                "HIGH",
                f"Dinamik kod calistirma: {name}",
                node.lineno
            )

        if name in NETWORK_CALLS:

            self.network += 1

        if name in PROCESS_CALLS:

            self.process += 1

            self.add(
                6,
                "MEDIUM",
                f"Proses/komut islemi: {name}",
                node.lineno
            )

        if name in FILE_CALLS:

            self.file_ops += 1

            self.add(
                FILE_CALLS[name],
                "MEDIUM",
                f"Dosya islemi: {name}",
                node.lineno
            )

        self.generic_visit(node)

    def visit_Constant(self, node):

        if not isinstance(
            node.value,
            str
        ):

            self.generic_visit(node)
            return

        text = node.value

        if len(text) >= 500:

            self.long_strings += 1

            if entropy(text) >= 4.7:

                self.encoded += 1

                self.add(
                    8,
                    "MEDIUM",
                    "Yuksek entropili uzun veri",
                    getattr(node, "lineno", 0)
                )

        compact = re.sub(
            r"\s+",
            "",
            text
        )

        if (
            len(compact) >= 80
            and
            re.fullmatch(
                r"[A-Za-z0-9+/=]+",
                compact
            )
        ):

            try:

                base64.b64decode(
                    compact,
                    validate=True
                )

                self.encoded += 1

                self.add(
                    6,
                    "MEDIUM",
                    "Base64 benzeri veri",
                    getattr(node, "lineno", 0)
                )

            except Exception:
                pass

        self.generic_visit(node)

    def correlate(self):

        if self.dynamic and self.encoded:

            self.add(
                25,
                "CRITICAL",
                "Dinamik kod + encoded veri"
            )

        if self.dynamic and self.network:

            self.add(
                20,
                "HIGH",
                "Ag + dinamik kod kombinasyonu"
            )

        if self.dynamic and self.process:

            self.add(
                18,
                "HIGH",
                "Dinamik kod + proses islemi"
            )

        if self.network and self.process:

            self.add(
                15,
                "HIGH",
                "Ag + proses islemi"
            )

        if self.network and self.file_ops >= 3:

            self.add(
                12,
                "MEDIUM",
                "Ag + coklu dosya islemi"
            )

        if self.process >= 3:

            self.add(
                10,
                "MEDIUM",
                "Birden fazla proses islemi"
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

            if source is None:
                return None

            if len(source) > MAX_SOURCE_SIZE:
                return None

            return source

        except Exception:

            return None

    def is_self(self, path):

        try:

            return Path(path).name.lower() == "hackosoriginav.py"

        except Exception:

            return False

    def scan_file(self, path):

        source = self.read_file(path)

        if source is None:

            return {
                "path": path,
                "score": 50,
                "status": "OKUNAMADI",
                "findings": [
                    {
                        "level": "MEDIUM",
                        "message": "Dosya okunamadi.",
                        "line": 0
                    }
                ]
            }

        # KENDİ KAYNAK KODUNU ANALİZ ETME.
        # Detection stringleri kendi içinde bulunduğu
        # için false-positive oluşmasını engeller.
        if self.is_self(path):

            return {
                "path": path,
                "score": 0,
                "status": "GUVENILIR",
                "hash": sha256_text(source),
                "findings": [
                    {
                        "level": "INFO",
                        "message": "HackosOriginAV kendi dosyasi.",
                        "line": 0
                    }
                ]
            }

        self.scanned += 1

        try:

            tree = ast.parse(
                source,
                filename=path
            )

        except SyntaxError as error:

            return {
                "path": path,
                "score": 15,
                "status": "SUPHELI",
                "hash": sha256_text(source),
                "findings": [
                    {
                        "level": "INFO",
                        "message": (
                            "Syntax hatasi: "
                            + str(error)
                        ),
                        "line": getattr(
                            error,
                            "lineno",
                            0
                        )
                    }
                ]
            }

        scanner = OriginScanner(source)

        scanner.visit(tree)
        scanner.correlate()

        score = clamp(
            scanner.score
        )

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

            files = self.api.list_dir(
                directory
            )

        except Exception:

            return results

        for name in files:

            if not name.lower().endswith(
                ".py"
            ):
                continue

            path = (
                directory
                + "/"
                + name
            )

            results.append(
                self.scan_file(path)
            )

        return results

    def full_scan(self):

        self.scanned = 0
        self.threats = 0

        print()
        print(
            "=========================================="
        )
        print(
            "       HACKOSORIGINAV v1.2 TARAMA"
        )
        print(
            "=========================================="
        )
        print()

        results = []

        print(
            "  [1/2] Modlar taraniyor..."
        )

        results += self.scan_directory(
            "mods"
        )

        print(
            "  [2/2] Eklentiler taraniyor..."
        )

        results += self.scan_directory(
            "eklentiler"
        )

        print()

        for result in results:

            score = result["score"]
            status = result["status"]

            if status in (
                "KRITIK",
                "YUKSEK"
            ):

                symbol = "!"
                self.threats += 1

            elif status == "SUPHELI":

                symbol = "?"

            elif status == "DUSUK_RISK":

                symbol = "~"

            else:

                symbol = "✓"

            print(
                f"  [{symbol}] "
                f"{result['path']} "
                f"Risk: {score}/100 "
                f"[{status}]"
            )

            for finding in result["findings"]:

                if finding["level"] in (
                    "HIGH",
                    "CRITICAL"
                ):

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

        print()
        print(
            "------------------------------------------"
        )
        print(
            f"  Dosya: {len(results)}"
        )
        print(
            f"  Tehdit: {self.threats}"
        )
        print(
            f"  Zaman: {self.last_scan}"
        )
        print(
            "------------------------------------------"
        )
        print()

        return results

    def single_scan(self):

        path = input(
            "\n  Dosya yolu: "
        ).strip()

        if not path:
            return

        result = self.scan_file(path)

        print()
        print(
            f"  Dosya : {result['path']}"
        )
        print(
            f"  Risk  : {result['score']}/100"
        )
        print(
            f"  Durum : {result['status']}"
        )

        for finding in result["findings"]:

            print(
                f"  [{finding['level']}] "
                f"{finding['message']}"
            )

        print()

    def quarantine(self):

        path = input(
            "\n  Karantinaya alinacak dosya: "
        ).strip()

        if not path:
            return

        result = self.scan_file(path)

        if result["score"] < 70:

            print(
                "\n  [!] Dosya karantina esiginde degil."
            )

            return

        print(
            f"\n  TEHDIT: {result['status']}"
        )

        print(
            f"  Risk: {result['score']}/100"
        )

        answer = input(
            "  Karantinaya al? [e/h]: "
        ).strip().lower()

        if answer != "e":

            print(
                "  Islem iptal edildi."
            )

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

            self.api.rename_file(
                path,
                target
            )

            print(
                "\n  KARANTINA BASARILI"
            )

            print(
                f"  -> {target}"
            )

        except Exception as error:

            print(
                f"\n  [!] Karantina hatasi: {error}"
            )

    def show_history(self):

        print()
        print(
            "========== HACKOSORIGINAV GECMIS =========="
        )

        if not self.history:

            print(
                "  Henuz tarama yapilmadi."
            )

        else:

            for item in self.history:

                print(
                    f"  {item['time']} | "
                    f"Dosya: {item['files']} | "
                    f"Tehdit: {item['threats']}"
                )

        print(
            "============================================"
        )
        print()

    def status(self):

        print()
        print(
            "========== HACKOS AV DURUM =========="
        )
        print(
            f"  Surum       : v{META['version']}"
        )
        print(
            f"  Son tarama  : {self.last_scan or 'Yok'}"
        )
        print(
            f"  Son dosya   : {self.scanned}"
        )
        print(
            f"  Tehdit      : {self.threats}"
        )
        print(
            "======================================"
        )
        print()

    def menu(self):

        while True:

            print()
            print(
                "╔════════════════════════════════════╗"
            )
            print(
                "║       HACKOSORIGINAV v1.2          ║"
            )
            print(
                "╠════════════════════════════════════╣"
            )
            print(
                "║  1. 🔍 Hizli Tarama                ║"
            )
            print(
                "║  2. 🔎 Derin Tarama                ║"
            )
            print(
                "║  3. 📄 Dosya Tara                  ║"
            )
            print(
                "║  4. 🛡️ Karantina                   ║"
            )
            print(
                "║  5. 📋 Tarama Gecmisi              ║"
            )
            print(
                "║  6. ℹ️ Durum                        ║"
            )
            print(
                "║  0. 🚪 Cikis                        ║"
            )
            print(
                "╚════════════════════════════════════╝"
            )

            choice = input(
                "\n  HackOSAV > "
            ).strip()

            if choice == "1":

                self.full_scan()

            elif choice == "2":

                self.full_scan()

            elif choice == "3":

                self.single_scan()

            elif choice == "4":

                self.quarantine()

            elif choice == "5":

                self.show_history()

            elif choice == "6":

                self.status()

            elif choice == "0":

                break

            else:

                print(
                    "  [!] Gecersiz secim."
                )


def setup(api):

    av = HackosOriginAV(api)

    @api.command(
        name="hackosav",
        description="HackOSOriginAV antivirus menusu"
    )
    def hackosav(*args):

        av.menu()
