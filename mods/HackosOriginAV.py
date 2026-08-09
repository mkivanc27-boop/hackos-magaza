# mods/HackosOriginAV.py
# -*- coding: utf-8 -*-

"""
HackosOriginAV v1.1
Savunma odakli HackOS antivirus modu.

Komut:
    hackosav

Ozellikler:
    - AST tabanli statik analiz
    - Risk puanlama
    - Davranis korelasyonu
    - Obfuscation tespiti
    - Supheli dosya/komut analizi
    - Karantina
    - Tarama gecmisi

Not:
Bu antivirus tek bir import veya kelimeyi otomatik olarak
"virus" kabul etmez. Birden fazla supheli belirtiyi birlikte
degerlendirir.
"""

import ast
import base64
import hashlib
import json
import math
import re
import time
from pathlib import Path


META = {
    "name": "HackosOriginAV",
    "version": "1.1",
    "author": "HackOS Security",
    "description": "Gelismis davranis ve statik analiz antivirusu.",
    "permissions": [
        "dosya_okuma",
        "dosya_yazma",
        "yeniden_adlandirma"
    ]
}


# =========================================================
# AYARLAR
# =========================================================

AV_DIR = ".HackosOriginAV"
QUARANTINE_DIR = AV_DIR + "/quarantine"

MAX_SOURCE_SIZE = 2 * 1024 * 1024

RISK_CLEAN = 25
RISK_LOW = 49
RISK_SUSPICIOUS = 69
RISK_HIGH = 89


# Tek basina virus anlamina GELMEYEN importlar.
IMPORT_SCORES = {
    "socket": 5,
    "requests": 5,
    "urllib": 5,
    "urllib3": 5,
    "ftplib": 8,
    "subprocess": 8,
    "ctypes": 10,
}


# Dinamik kod calistirma daha ciddi.
DYNAMIC_CALLS = {
    "eval": 18,
    "exec": 22,
    "compile": 12,
    "__import__": 10,
}


# HackOS API'leri tek basina zararli degildir.
HACKOS_OPERATIONS = {
    "delete_file": 8,
    "rename_file": 5,
    "write_file": 3,
    "read_file": 2,
    "run": 8,
}


# =========================================================
# YARDIMCI
# =========================================================

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


def get_call_name(node):

    if isinstance(node, ast.Name):
        return node.id

    if isinstance(node, ast.Attribute):

        parts = []

        current = node

        while isinstance(
            current,
            ast.Attribute
        ):

            parts.append(
                current.attr
            )

            current = current.value

        if isinstance(
            current,
            ast.Name
        ):

            parts.append(
                current.id
            )

            return ".".join(
                reversed(parts)
            )

    return ""


# =========================================================
# ANALIZCI
# =========================================================

class OriginScanner(ast.NodeVisitor):

    def __init__(self, source):

        self.source = source
        self.lines = source.splitlines()

        self.score = 0
        self.findings = []

        self.imports = set()
        self.calls = set()

        self.file_operations = 0
        self.network_operations = 0
        self.dynamic_operations = 0

        self.long_strings = 0
        self.encoded_strings = 0

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

    # -----------------------------------------------------
    # IMPORT
    # -----------------------------------------------------

    def visit_Import(self, node):

        for item in node.names:

            root = item.name.split(".")[0]

            self.imports.add(root)

            if root in IMPORT_SCORES:

                self.add(
                    IMPORT_SCORES[root],
                    "INFO",
                    f"Supheli import: {item.name}",
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
                f"Supheli import: {module}",
                node.lineno
            )

        self.generic_visit(node)

    # -----------------------------------------------------
    # CALL
    # -----------------------------------------------------

    def visit_Call(self, node):

        name = get_call_name(
            node.func
        )

        self.calls.add(name)

        if name in DYNAMIC_CALLS:

            value = DYNAMIC_CALLS[name]

            self.dynamic_operations += 1

            self.add(
                value,
                "HIGH",
                f"Dinamik kod calistirma: {name}",
                node.lineno
            )

        if name in HACKOS_OPERATIONS:

            self.file_operations += 1

            self.add(
                HACKOS_OPERATIONS[name],
                "INFO",
                f"HackOS islemi: {name}",
                node.lineno
            )

        if name in (
            "socket.socket",
            "requests.get",
            "requests.post",
            "urllib.request.urlopen"
        ):

            self.network_operations += 1

        self.generic_visit(node)

    # -----------------------------------------------------
    # STRING
    # -----------------------------------------------------

    def visit_Constant(self, node):

        if not isinstance(
            node.value,
            str
        ):

            self.generic_visit(node)
            return

        text = node.value

        # Cok uzun stringler bazen encoded/obfuscated
        # payloadlarda gorulebilir.
        if len(text) >= 500:

            self.long_strings += 1

            ent = entropy(text)

            if ent >= 4.7:

                self.encoded_strings += 1

                self.add(
                    10,
                    "MEDIUM",
                    "Yuksek entropili uzun string",
                    getattr(
                        node,
                        "lineno",
                        0
                    )
                )

        # Base64 benzeri stringleri sadece
        # suphe sinyali olarak ele al.
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

                self.encoded_strings += 1

                self.add(
                    8,
                    "MEDIUM",
                    "Base64 benzeri encoded veri",
                    getattr(
                        node,
                        "lineno",
                        0
                    )
                )

            except Exception:
                pass

        self.generic_visit(node)

    # -----------------------------------------------------
    # KORELASYON
    # -----------------------------------------------------

    def correlate(self):

        # Dinamik kod + encoded veri
        if (
            self.dynamic_operations > 0
            and
            self.encoded_strings > 0
        ):

            self.add(
                25,
                "CRITICAL",
                "Dinamik kod + encoded veri kombinasyonu"
            )

        # Dinamik kod + dosya islemleri
        if (
            self.dynamic_operations > 0
            and
            self.file_operations >= 2
        ):

            self.add(
                20,
                "HIGH",
                "Dinamik kod + coklu dosya islemi"
            )

        # Ag + dinamik kod
        if (
            self.network_operations > 0
            and
            self.dynamic_operations > 0
        ):

            self.add(
                20,
                "HIGH",
                "Ag islemi + dinamik kod kombinasyonu"
            )

        # Ag + coklu dosya islemi
        if (
            self.network_operations > 0
            and
            self.file_operations >= 3
        ):

            self.add(
                15,
                "MEDIUM",
                "Ag + coklu dosya islemi"
            )

        # Cok fazla HackOS dosya islemi
        if self.file_operations >= 8:

            self.add(
                15,
                "MEDIUM",
                "Yuksek miktarda dosya islemi"
            )


# =========================================================
# ANTIVIRUS
# =========================================================

class HackosOriginAV:

    def __init__(self, api):

        self.api = api

        self.scanned = 0
        self.threats = 0

        self.last_scan = None

        self.history = []

    # -----------------------------------------------------
    # OKUMA
    # -----------------------------------------------------

    def read_file(self, path):

        try:

            source = self.api.read_file(
                path
            )

            if source is None:
                return None

            if len(source) > MAX_SOURCE_SIZE:

                return None

            return source

        except Exception:

            return None

    # -----------------------------------------------------
    # TEK DOSYA
    # -----------------------------------------------------

    def scan_file(
        self,
        path
    ):

        source = self.read_file(
            path
        )

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

        # AV'nin kendisini tararken
        # kendi detection listelerini analiz etme.
        if (
            Path(path).name.lower()
            == "hackosoriginav.py"
        ):

            return {
                "path": path,
                "score": 0,
                "status": "GUVENILIR",
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
                "score": 20,
                "status": "SUPHELI",
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

        scanner = OriginScanner(
            source
        )

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

    # -----------------------------------------------------
    # KLASOR
    # -----------------------------------------------------

    def scan_directory(
        self,
        directory
    ):

        results = []

        try:

            files = self.api.list_dir(
                directory
            )

        except Exception:

            return results

        for name in files:

            if not name.endswith(
                ".py"
            ):

                continue

            path = (
                directory
                + "/"
                + name
            )

            result = self.scan_file(
                path
            )

            results.append(
                result
            )

        return results

    # -----------------------------------------------------
    # TAM TARAMA
    # -----------------------------------------------------

    def full_scan(self):

        self.scanned = 0
        self.threats = 0

        print()
        print(
            "╔══════════════════════════════════════╗"
        )
        print(
            "║      🛡️ HACKOSORIGINAV v1.1          ║"
        )
        print(
            "║         DERIN TARAMA                ║"
        )
        print(
            "╚══════════════════════════════════════╝"
        )
        print()

        results = []

        print(
            "  [1/2] Modlar analiz ediliyor..."
        )

        results += self.scan_directory(
            "mods"
        )

        print(
            "  [2/2] Eklentiler analiz ediliyor..."
        )

        results += self.scan_directory(
            "eklentiler"
        )

        print()

        for result in results:

            score = result[
                "score"
            ]

            status = result[
                "status"
            ]

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
                f"{result['path']}"
                f"  Risk: {score}/100"
                f"  [{status}]"
            )

            for finding in result[
                "findings"
            ]:

                if finding[
                    "level"
                ] in (
                    "HIGH",
                    "CRITICAL"
                ):

                    print(
                        "       └─ "
                        + finding[
                            "message"
                        ]
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
            "----------------------------------------"
        )
        print(
            f"  Taranan dosya : {len(results)}"
        )
        print(
            f"  Yuksek/Kritik : {self.threats}"
        )
        print(
            f"  Tarama zamani : {self.last_scan}"
        )
        print(
            "----------------------------------------"
        )
        print()

        return results

    # -----------------------------------------------------
    # DOSYA TARA
    # -----------------------------------------------------

    def single_scan(self):

        path = input(
            "\n  Dosya yolu: "
        ).strip()

        if not path:

            return

        result = self.scan_file(
            path
        )

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

        print()

        for finding in result[
            "findings"
        ]:

            print(
                f"  [{finding['level']}] "
                f"{finding['message']}"
            )

        print()

    # -----------------------------------------------------
    # KARANTINA
    # -----------------------------------------------------

    def quarantine(self):

        path = input(
            "\n  Dosya yolu: "
        ).strip()

        if not path:

            return

        result = self.scan_file(
            path
        )

        if result["score"] < 70:

            print(
                "\n  [!] Bu dosya karantina esiginde degil."
            )

            return

        print()
        print(
            f"  TEHDIT: {result['status']}"
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
                QUARANTINE_DIR
                + "/.keep",
                ""
            )

            filename = Path(
                path
            ).name

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

            print()
            print(
                "  🛡️ KARANTINA BASARILI"
            )
            print(
                f"  -> {target}"
            )
            print()

        except Exception as error:

            print(
                f"\n  [!] Karantina hatasi: {error}\n"
            )

    # -----------------------------------------------------
    # GECMIS
    # -----------------------------------------------------

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

    # -----------------------------------------------------
    # MENU
    # -----------------------------------------------------

    def menu(self):

        while True:

            print()
            print(
                "╔════════════════════════════════════╗"
            )
            print(
                "║       🛡️ HACKOSORIGINAV v1.1       ║"
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

                print(
                    "\n  [*] Hizli tarama baslatiliyor..."
                )

                results = []

                results += self.scan_directory(
                    "mods"
                )

                results += self.scan_directory(
                    "eklentiler"
                )

                threats = 0

                for result in results:

                    if result["score"] >= 70:

                        threats += 1

                    print(
                        f"  [{result['status']}] "
                        f"{result['path']} "
                        f"Risk: {result['score']}/100"
                    )

                self.scanned = len(results)
                self.threats = threats
                self.last_scan = time.strftime(
                    "%Y-%m-%d %H:%M:%S"
                )

                self.history.append({
                    "time": self.last_scan,
                    "files": len(results),
                    "threats": threats
                })

                self.history = self.history[-20:]

                print()
                print(
                    f"  [✓] Hizli tarama tamamlandi."
                )
                print(
                    f"  Dosya: {len(results)} | "
                    f"Yuksek/Kritik: {threats}"
                )
                print()

            elif choice == "2":

                self.full_scan()

            elif choice == "3":

                self.single_scan()

            elif choice == "4":

                self.quarantine()

            elif choice == "5":

                self.show_history()

            elif choice == "6":

                print()
                print(
                    "  🛡️ HackosOriginAV v1.1"
                )
                print(
                    "  Durum: AKTIF"
                )
                print(
                    "  Motor: AST + Davranis Korelasyonu"
                )
                print(
                    "  Tarama limiti: "
                    f"{MAX_SOURCE_SIZE // 1024} KB"
                )
                print(
                    "  Son tarama: "
                    + (
                        self.last_scan
                        or "Yok"
                    )
                )
                print(
                    "  Bu oturum taranan: "
                    f"{self.scanned} dosya"
                )
                print(
                    "  Bu oturum tehdit: "
                    f"{self.threats}"
                )
                print()

            elif choice == "0":

                print(
                    "\n  HackosOriginAV kapatildi."
                )
                break

            else:

                print(
                    "\n  [!] Gecersiz secim."
                )


# =========================================================
# HACKOS MOD GIRISI
# =========================================================

def setup(api):

    av = HackosOriginAV(api)

    @api.add_command(
        name="hackosav",
        description="HackosOriginAV antivirus menusu"
    )
    def hackosav(*args):

        av.menu()
