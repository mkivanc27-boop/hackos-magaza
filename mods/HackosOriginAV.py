# -*- coding: utf-8 -*-

"""
HackosOriginAV v1.0
HackOS icin normal antivirus modu.

Komut:
    hackosav

Menuden:
    1 - Hizli Tarama
    2 - Derin Tarama
    3 - Dosya Tara
    4 - Karantina
    5 - Tehdit Gecmisi
    6 - Antivirus Durumu
    0 - Cikis

Not:
Bu AV, HackOS sandboxu icinde calisir.
"""

import ast
import json
import time
from pathlib import Path


META = {
    "name": "HackosOriginAV",
    "version": "1.0",
    "author": "HackOS Security",
    "description": "HackOS icin davranis tabanli antivirus.",
    "permissions": [
        "dosya_okuma",
        "dosya_yazma",
        "yeniden_adlandirma"
    ]
}


# =========================================================
# AYARLAR
# =========================================================

QUARANTINE = ".HackosOriginAV/quarantine"
HISTORY = ".HackosOriginAV/history.json"

# Tek basina gorulduklerinde her zaman virus anlamina gelmezler.
# Birden fazla supheli davranis varsa risk puani artar.

SUSPICIOUS_IMPORTS = {
    "subprocess": 30,
    "ctypes": 35,
    "socket": 20,
    "requests": 15,
    "urllib": 15,
    "ftplib": 20,
    "telnetlib": 30,
}

DANGEROUS_CALLS = {
    "eval": 30,
    "exec": 35,
    "__import__": 20,
    "os.system": 35,
    "os.popen": 35,
    "subprocess.run": 35,
    "subprocess.Popen": 40,
    "subprocess.call": 35,
}

HACKOS_APIS = {
    "delete_file": 30,
    "rename_file": 15,
    "run": 20,
}


# =========================================================
# AST ANALIZI
# =========================================================

class CodeScanner(ast.NodeVisitor):

    def __init__(self):
        self.findings = []
        self.score = 0

    def add(self, level, score, message, line):

        self.score += score

        self.findings.append({
            "level": level,
            "score": score,
            "message": message,
            "line": line
        })

    def visit_Import(self, node):

        for item in node.names:

            name = item.name
            root = name.split(".")[0]

            if root in SUSPICIOUS_IMPORTS:

                value = SUSPICIOUS_IMPORTS[root]

                self.add(
                    "ORTA",
                    value,
                    f"Supheli kutuphane: {name}",
                    node.lineno
                )

        self.generic_visit(node)

    def visit_ImportFrom(self, node):

        name = node.module or ""
        root = name.split(".")[0]

        if root in SUSPICIOUS_IMPORTS:

            value = SUSPICIOUS_IMPORTS[root]

            self.add(
                "ORTA",
                value,
                f"Supheli kutuphane: {name}",
                node.lineno
            )

        self.generic_visit(node)

    def visit_Call(self, node):

        name = self.get_name(node.func)

        if name in DANGEROUS_CALLS:

            value = DANGEROUS_CALLS[name]

            self.add(
                "YUKSEK",
                value,
                f"Supheli kod calistirma: {name}",
                node.lineno
            )

        if name in HACKOS_APIS:

            value = HACKOS_APIS[name]

            self.add(
                "ORTA",
                value,
                f"HackOS dosya/shell API kullanimi: {name}",
                node.lineno
            )

        self.generic_visit(node)

    def visit_Constant(self, node):

        if isinstance(node.value, str):

            text = node.value.lower()

            suspicious = [
                "rm -rf",
                "powershell",
                "cmd.exe",
                "wget ",
                "curl ",
                "chmod +x"
            ]

            for item in suspicious:

                if item in text:

                    self.add(
                        "YUKSEK",
                        25,
                        f"Supheli komut/metin: {item}",
                        getattr(node, "lineno", 0)
                    )

        self.generic_visit(node)

    @staticmethod
    def get_name(node):

        if isinstance(node, ast.Name):
            return node.id

        if isinstance(node, ast.Attribute):

            parts = []

            while isinstance(node, ast.Attribute):

                parts.append(node.attr)
                node = node.value

            if isinstance(node, ast.Name):

                parts.append(node.id)

                return ".".join(
                    reversed(parts)
                )

        return ""


# =========================================================
# ANTIVIRUS
# =========================================================

class HackosOriginAV:

    def __init__(self, api):

        self.api = api

        self.scanned = 0
        self.threats = 0
        self.last_scan = None

    # -----------------------------------------------------
    # DOSYA OKU
    # -----------------------------------------------------

    def read(self, path):

        try:
            return self.api.read_file(path)

        except Exception:

            return None

    # -----------------------------------------------------
    # TEK DOSYA TARAMA
    # -----------------------------------------------------

    def scan_file(self, path):

        source = self.read(path)

        if source is None:

            return {
                "path": path,
                "score": 100,
                "status": "OKUNAMADI",
                "findings": [
                    "Dosya okunamadi."
                ]
            }

        self.scanned += 1

        try:

            tree = ast.parse(
                source,
                filename=path
            )

        except SyntaxError as e:

            return {
                "path": path,
                "score": 40,
                "status": "SUPHELI",
                "findings": [
                    f"Python syntax hatasi: {e}"
                ]
            }

        scanner = CodeScanner()

        scanner.visit(tree)

        score = min(
            scanner.score,
            100
        )

        if score >= 70:

            status = "TEHDIT"

        elif score >= 35:

            status = "SUPHELI"

        else:

            status = "TEMIZ"

        return {
            "path": path,
            "score": score,
            "status": status,
            "findings": scanner.findings
        }

    # -----------------------------------------------------
    # KLASOR TARA
    # -----------------------------------------------------

    def scan_directory(self, directory):

        results = []

        try:

            files = self.api.list_dir(
                directory
            )

        except Exception:

            return results

        for name in files:

            if not name.endswith(".py"):
                continue

            path = (
                f"{directory}/{name}"
            )

            result = self.scan_file(path)

            results.append(result)

        return results

    # -----------------------------------------------------
    # FULL SCAN
    # -----------------------------------------------------

    def full_scan(self):

        self.scanned = 0
        self.threats = 0

        print()
        print(
            "=========================================="
        )
        print(
            "       🛡️ HACKOSORIGINAV TARAMA"
        )
        print(
            "=========================================="
        )
        print()

        results = []

        print("  [1/2] Modlar taraniyor...")

        results += self.scan_directory(
            "mods"
        )

        print("  [2/2] Eklentiler taraniyor...")

        results += self.scan_directory(
            "eklentiler"
        )

        print()

        for result in results:

            status = result["status"]

            if status == "TEMIZ":

                symbol = "✓"

            elif status == "SUPHELI":

                symbol = "?"

            else:

                symbol = "!"

            print(
                f"  [{symbol}] "
                f"{result['path']}"
                f"  Risk: {result['score']}/100"
            )

            if result["score"] >= 70:

                self.threats += 1

                for finding in result[
                    "findings"
                ]:

                    if isinstance(
                        finding,
                        dict
                    ):

                        print(
                            f"       └─ "
                            f"[{finding['level']}] "
                            f"{finding['message']}"
                        )

        self.last_scan = time.strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        self.save_history(
            results
        )

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

    # -----------------------------------------------------
    # HISTORY
    # -----------------------------------------------------

    def save_history(self, results):

        try:

            old = self.api.get(
                "scan_history",
                []
            )

            old.append({
                "time": self.last_scan,
                "files": len(results),
                "threats": self.threats
            })

            old = old[-20:]

            self.api.set(
                "scan_history",
                old
            )

        except Exception:

            pass

    # -----------------------------------------------------
    # TEK DOSYA
    # -----------------------------------------------------

    def single_scan(self):

        path = input(
            "\n  Tarama yolu: "
        ).strip()

        if not path:

            print(
                "  [!] Dosya belirtilmedi."
            )

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

        print()

        for finding in result[
            "findings"
        ]:

            if isinstance(
                finding,
                dict
            ):

                print(
                    f"  [{finding['level']}] "
                    f"{finding['message']} "
                    f"(satir {finding['line']})"
                )

            else:

                print(
                    f"  [!] {finding}"
                )

        print()

    # -----------------------------------------------------
    # KARANTINA
    # -----------------------------------------------------

    def quarantine(self):

        path = input(
            "\n  Karantinaya alinacak dosya: "
        ).strip()

        if not path:

            return

        result = self.scan_file(path)

        if result["status"] == "TEMIZ":

            print(
                "\n  [✓] Dosya temiz gorunuyor."
            )

            return

        print()
        print(
            f"  Risk: {result['score']}/100"
        )

        answer = input(
            "  Karantinaya alinsin mi? [e/h]: "
        ).strip().lower()

        if answer != "e":

            print(
                "  [i] Islem iptal edildi."
            )

            return

        try:

            # Karantina klasorunun kendisi
            # HackOS sandboxunun icindedir.
            self.api.write_file(
                f"{QUARANTINE}/.keep",
                ""
            )

            filename = Path(path).name

            target = (
                f"{QUARANTINE}/"
                f"{filename}.quarantined"
            )

            self.api.rename_file(
                path,
                target
            )

            print()
            print(
                "  🛡️ DOSYA KARANTINAYA ALINDI"
            )

            print(
                f"  Eski: {path}"
            )

            print(
                f"  Yeni: {target}"
            )

            print()

        except Exception as e:

            print(
                f"\n  [!] Karantina hatasi: {e}\n"
            )

    # -----------------------------------------------------
    # HISTORY GOSTER
    # -----------------------------------------------------

    def history(self):

        history = self.api.get(
            "scan_history",
            []
        )

        print()
        print(
            "========== TARAMA GECMISI =========="
        )

        if not history:

            print(
                "  Henuz tarama yapilmamis."
            )

        else:

            for item in history:

                print(
                    f"  {item['time']} | "
                    f"Dosya: {item['files']} | "
                    f"Tehdit: {item['threats']}"
                )

        print(
            "====================================="
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
                "║       🛡️ HACKOSORIGINAV            ║"
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

                # Hizli tarama sadece modlari kontrol eder.
                self.scan_directory(
                    "mods"
                )

                print(
                    "\n  [✓] Hizli tarama tamamlandi.\n"
                )

            elif choice == "2":

                self.full_scan()

            elif choice == "3":

                self.single_scan()

            elif choice == "4":

                self.quarantine()

            elif choice == "5":

                self.history()

            elif choice == "6":

                print()
                print(
                    "  🛡️ HackosOriginAV 1.0"
                )
                print(
                    "  Durum: AKTIF"
                )
                print(
                    f"  Son tarama: "
                    f"{self.last_scan or 'Yok'}"
                )
                print(
                    f"  Bu oturum taranan: "
                    f"{self.scanned}"
                )
                print()

            elif choice == "0":

                print(
                    "\n  HackosOriginAV kapatildi.\n"
                )

                break

            else:

                print(
                    "\n  [!] Gecersiz secim.\n"
                )


# =========================================================
# HACKOS MOD GIRISI
# =========================================================

def setup(api):

    av = HackosOriginAV(api)

    # HackOS v4 + addcommands yapisinda
    # modun shell'e tek launcher komutu eklemesi.
    @api.add_command(
        name="hackosav",
        description="HackosOriginAV antivirus menusu"
    )
    def hackosav(*args):

        av.menu()
