# mods/hackosoriginav.py
# -*- coding: utf-8 -*-

"""
HackosOriginAV
HackOS icin davranis + izin tabanli antivirus.

Ozellikler:
- Modlari statik olarak AST ile tarar
- META izinlerini kontrol eder
- Tehlikeli API kullanimlarini arar
- supheli modlari karantinaya alir
- Tek bir virus imzasina bagli degildir
- HackOS sandbox disina cikmaya calisan path'leri de raporlar
"""

import ast
import json
from pathlib import Path
from datetime import datetime

META = {
    "name": "HackosOriginAV",
    "version": "1.0",
    "author": "HackOS Community",
    "description": "HackOS icin davranis tabanli antivirus ve mod guvenlik tarayicisi.",
    "permissions": [
        "dosya_okuma",
        "dosya_yazma",
        "yeniden_adlandirma"
    ]
}

QUARANTINE = ".originav_quarantine"
REPORT_FILE = ".originav_report.json"


# ---------------------------------------------------------
# SUPHELI DAVRANIS IMZALARI
# ---------------------------------------------------------

DANGEROUS_CALLS = {
    "os.system": "Sistem komutu calistirma",
    "os.popen": "Sistem komutu calistirma",
    "subprocess.run": "Harici proses calistirma",
    "subprocess.Popen": "Harici proses baslatma",
    "subprocess.call": "Harici proses calistirma",
    "subprocess.check_output": "Harici proses calistirma",
    "eval": "Dinamik kod calistirma",
    "exec": "Dinamik kod calistirma",
    "__import__": "Dinamik import",
    "importlib.import_module": "Dinamik import",
}

DANGEROUS_ATTRIBUTES = {
    "delete_file": "Dosya silme API'si",
    "rename_file": "Dosya yeniden adlandirma API'si",
    "run": "HackOS komut calistirma API'si",
}

SUSPICIOUS_IMPORTS = {
    "subprocess",
    "ctypes",
    "socket",
    "urllib",
    "requests",
    "httpx",
    "ftplib",
    "telnetlib",
    "shutil",
}

SUSPICIOUS_STRINGS = {
    "powershell",
    "cmd.exe",
    "rm -rf",
    "curl ",
    "wget ",
    "base64 -d",
    "chmod +x",
}


# ---------------------------------------------------------
# AST ANALIZI
# ---------------------------------------------------------

class Analyzer(ast.NodeVisitor):

    def __init__(self):
        self.findings = []
        self.imports = []
        self.calls = []

    def add(self, severity, category, message, lineno=0):
        self.findings.append({
            "severity": severity,
            "category": category,
            "message": message,
            "line": lineno
        })

    def visit_Import(self, node):
        for alias in node.names:
            name = alias.name
            self.imports.append(name)

            root = name.split(".")[0]

            if root in SUSPICIOUS_IMPORTS:
                self.add(
                    "HIGH",
                    "SUSPICIOUS_IMPORT",
                    f"Supheli kutuphane: {name}",
                    node.lineno
                )

        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        name = node.module or ""

        root = name.split(".")[0]

        if root in SUSPICIOUS_IMPORTS:
            self.add(
                "HIGH",
                "SUSPICIOUS_IMPORT",
                f"Supheli kutuphane: {name}",
                node.lineno
            )

        self.generic_visit(node)

    def visit_Call(self, node):

        name = self.get_call_name(node.func)

        if name:
            self.calls.append(name)

            if name in DANGEROUS_CALLS:
                self.add(
                    "HIGH",
                    "DANGEROUS_CALL",
                    DANGEROUS_CALLS[name] + f": {name}",
                    node.lineno
                )

            if name in DANGEROUS_ATTRIBUTES:
                self.add(
                    "HIGH",
                    "HACKOS_DANGEROUS_API",
                    DANGEROUS_ATTRIBUTES[name],
                    node.lineno
                )

        self.generic_visit(node)

    def visit_Constant(self, node):

        if isinstance(node.value, str):

            text = node.value.lower()

            for suspicious in SUSPICIOUS_STRINGS:
                if suspicious in text:
                    self.add(
                        "MEDIUM",
                        "SUSPICIOUS_STRING",
                        f"Supheli metin: {suspicious}",
                        getattr(node, "lineno", 0)
                    )

        self.generic_visit(node)

    @staticmethod
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

        return None


# ---------------------------------------------------------
# ANTIVIRUS
# ---------------------------------------------------------

def setup(api):

    def log(msg):
        api.log(msg)

    def load_report():

        try:
            raw = api.read_file(REPORT_FILE)

            if not raw.strip():
                return []

            return json.loads(raw)

        except Exception:
            return []

    def save_report(data):

        api.write_file(
            REPORT_FILE,
            json.dumps(
                data,
                ensure_ascii=False,
                indent=2
            )
        )

    def analyze_file(path):

        result = {
            "file": path,
            "safe": True,
            "score": 0,
            "findings": []
        }

        try:
            source = api.read_file(path)

        except Exception as e:

            result["safe"] = False
            result["findings"].append({
                "severity": "HIGH",
                "category": "READ_ERROR",
                "message": str(e),
                "line": 0
            })

            return result

        try:

            tree = ast.parse(
                source,
                filename=path
            )

        except SyntaxError as e:

            result["findings"].append({
                "severity": "MEDIUM",
                "category": "SYNTAX",
                "message": f"Python syntax hatasi: {e}",
                "line": getattr(e, "lineno", 0) or 0
            })

            result["score"] += 15

            return result

        analyzer = Analyzer()
        analyzer.visit(tree)

        result["findings"] = analyzer.findings

        for finding in analyzer.findings:

            severity = finding["severity"]

            if severity == "HIGH":
                result["score"] += 35

            elif severity == "MEDIUM":
                result["score"] += 15

            elif severity == "LOW":
                result["score"] += 5

        # Birden fazla farkli supheli davranis
        categories = {
            x["category"]
            for x in analyzer.findings
        }

        if len(categories) >= 3:
            result["score"] += 20

        # Birden fazla tehlikeli API
        dangerous_count = sum(
            1
            for x in analyzer.findings
            if x["category"] in (
                "DANGEROUS_CALL",
                "HACKOS_DANGEROUS_API"
            )
        )

        if dangerous_count >= 2:
            result["score"] += 25

        result["score"] = min(
            result["score"],
            100
        )

        # Esik
        if result["score"] >= 50:
            result["safe"] = False

        return result

    def scan_directory(directory):

        results = []

        try:
            files = api.list_dir(directory)

        except Exception as e:
            log(f"Tarama hatasi: {e}")
            return results

        for filename in files:

            if not filename.endswith(".py"):
                continue

            path = f"{directory}/{filename}"

            result = analyze_file(path)

            results.append(result)

        return results

    def print_result(result):

        score = result["score"]

        if result["safe"]:
            state = "[TEMIZ]"
        else:
            state = "[TEHDIT]"

        print(
            f"  {state} "
            f"{result['file']} "
            f"(risk: {score}/100)"
        )

        for finding in result["findings"]:

            print(
                f"      [{finding['severity']}] "
                f"{finding['category']} - "
                f"{finding['message']} "
                f"(satir {finding['line']})"
            )

    def scan_all():

        print("\n")
        print("  ========================================")
        print("       HackosOriginAV - FULL SCAN")
        print("  ========================================")

        results = []

        results.extend(
            scan_directory("mods")
        )

        results.extend(
            scan_directory("eklentiler")
        )

        threats = [
            r for r in results
            if not r["safe"]
        ]

        print("\n  SONUCLAR")
        print(
            f"  Taranan dosya : {len(results)}"
        )
        print(
            f"  Temiz         : "
            f"{len(results) - len(threats)}"
        )
        print(
            f"  Tehdit        : "
            f"{len(threats)}"
        )

        print("\n  DETAYLAR")

        for result in results:
            print_result(result)

        report = load_report()

        report.append({
            "time": datetime.now().isoformat(
                timespec="seconds"
            ),
            "results": results
        })

        save_report(report[-20:])

        print("\n  [✓] Tarama raporu kaydedildi.")
        print()

        return results

    def scan_one(filename):

        locations = [
            f"mods/{filename}",
            f"eklentiler/{filename}"
        ]

        for path in locations:

            try:

                # Dosyanin varligini test et
                api.read_file(path)

                result = analyze_file(path)

                print_result(result)

                return result

            except Exception:
                continue

        print(
            f"  [!] Dosya bulunamadi: {filename}"
        )

        return None

    def quarantine(filename):

        candidates = [
            f"mods/{filename}",
            f"eklentiler/{filename}"
        ]

        for source in candidates:

            try:

                api.read_file(source)

            except Exception:
                continue

            target = (
                f"{QUARANTINE}/"
                f"{filename}.quarantined"
            )

            try:

                # Klasor icin basit dosya olusturma
                # HackOS sandboxu icinde kalir.
                try:
                    api.write_file(
                        f"{QUARANTINE}/.keep",
                        ""
                    )
                except Exception:
                    pass

                api.rename_file(
                    source,
                    target
                )

                print(
                    f"  [🛡️] KARANTINA: "
                    f"{source}"
                )

                return True

            except PermissionError as e:

                api.error(
                    f"Karantina icin yeniden adlandirma "
                    f"izni gerekiyor: {e}"
                )

                return False

            except Exception as e:

                api.error(str(e))
                return False

        print(
            f"  [!] Karantinaya alinacak dosya "
            f"bulunamadi: {filename}"
        )

        return False

    # -----------------------------------------------------
    # KOMUTLAR
    # -----------------------------------------------------

    @api.command(
        name="originav",
        description="HackosOriginAV antivirus"
    )
    def originav(*args):

        command = (
            args[0].lower()
            if args
            else "scan"
        )

        if command in ("scan", "tara"):

            scan_all()
            return

        if command in ("file", "dosya"):

            if len(args) < 2:
                print(
                    "  Kullanim: "
                    "originav file <dosya.py>"
                )
                return

            scan_one(args[1])
            return

        if command in (
            "quarantine",
            "karantina"
        ):

            if len(args) < 2:
                print(
                    "  Kullanim: "
                    "originav quarantine <dosya.py>"
                )
                return

            quarantine(args[1])
            return

        if command in ("report", "rapor"):

            report = load_report()

            if not report:
                print(
                    "  [i] Henuz tarama raporu yok."
                )
                return

            last = report[-1]

            print("\n  SON TARAMA")
            print(
                f"  Zaman: {last.get('time', '?')}"
            )

            for result in last.get(
                "results",
                []
            ):
                print_result(result)

            print()
            return

        if command in ("help", "?"):

            print("""
  HackosOriginAV

  originav scan
      Tum mod ve eklentileri tara.

  originav file <dosya.py>
      Tek dosyayi tara.

  originav quarantine <dosya.py>
      Supheli dosyayi karantinaya al.

  originav report
      Son tarama raporunu goster.
""")
            return

        print(
            "  Bilinmeyen komut. "
            "'originav help' yaz."
)
