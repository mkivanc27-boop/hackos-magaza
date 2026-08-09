# -*- coding: utf-8 -*-
"""
HackosOriginAV
HackOS icin davranis tabanli guvenlik katmani.

- Modlari/eklentileri tarar
- Supheli davranislari puanlar
- Runtime dosya islemlerini izler
- Kisa surede cok fazla silme/rename yapan modulu engeller
- File Manager gibi guvenilir araclari bozmaz
"""

import ast
import time
from collections import defaultdict, deque

META = {
    "name": "HackosOriginAV",
    "version": "2.0",
    "author": "HackOS Security",
    "description": "HackOS davranis tabanli antivirus ve runtime koruma.",
}

# Kullanici araclari: normal dosya islemlerini engelleme.
TRUSTED = {
    "file_manager",
    "task_manager",
    "backup_manager",
    "HackosOriginAV",
    "OriginAV_TestMalware",
}

SUSPICIOUS_IMPORTS = {
    "subprocess",
    "ctypes",
    "socket",
    "requests",
    "urllib",
    "urllib3",
    "ftplib",
    "telnetlib",
}

DANGEROUS_CALLS = {
    "eval",
    "exec",
    "__import__",
    "os.system",
    "os.popen",
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.call",
}

DANGEROUS_APIS = {
    "delete_file",
    "rename_file",
    "run",
}


class Analyzer(ast.NodeVisitor):

    def __init__(self):
        self.findings = []

    def add(self, severity, message, line):
        self.findings.append({
            "severity": severity,
            "message": message,
            "line": line,
        })

    def visit_Import(self, node):
        for item in node.names:
            root = item.name.split(".")[0]

            if root in SUSPICIOUS_IMPORTS:
                self.add(
                    "HIGH",
                    f"Supheli import: {item.name}",
                    node.lineno,
                )

        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        root = (node.module or "").split(".")[0]

        if root in SUSPICIOUS_IMPORTS:
            self.add(
                "HIGH",
                f"Supheli import: {node.module}",
                node.lineno,
            )

        self.generic_visit(node)

    def visit_Call(self, node):

        name = self.call_name(node.func)

        if name in DANGEROUS_CALLS:
            self.add(
                "HIGH",
                f"Tehlikeli cagri: {name}",
                node.lineno,
            )

        if name in DANGEROUS_APIS:
            self.add(
                "MEDIUM",
                f"Dosya/shell API kullanimi: {name}",
                node.lineno,
            )

        self.generic_visit(node)

    def call_name(self, node):

        if isinstance(node, ast.Name):
            return node.id

        if isinstance(node, ast.Attribute):

            parts = []

            while isinstance(node, ast.Attribute):
                parts.append(node.attr)
                node = node.value

            if isinstance(node, ast.Name):
                parts.append(node.id)
                return ".".join(reversed(parts))

        return None


class OriginAV:

    def __init__(self, api):
        self.api = api

        self.events = defaultdict(
            lambda: deque(maxlen=50)
        )

        self.blocked = set()

        self.window = 3.0
        self.delete_limit = 5
        self.rename_limit = 10

    def record(self, owner, operation, path):

        now = time.monotonic()

        events = self.events[owner]

        events.append({
            "time": now,
            "operation": operation,
            "path": str(path),
        })

        while events:
            if now - events[0]["time"] <= self.window:
                break

            events.popleft()

    def allow_file_operation(
        self,
        owner,
        operation,
        path,
    ):

        if owner in TRUSTED:
            return True

        if owner in self.blocked:
            return False

        self.record(
            owner,
            operation,
            path,
        )

        events = list(
            self.events[owner]
        )

        deletes = sum(
            e["operation"] == "delete"
            for e in events
        )

        renames = sum(
            e["operation"] == "rename"
            for e in events
        )

        if deletes > self.delete_limit:

            self.blocked.add(owner)

            print(
                "\033[91m"
                "\n[🛡️ HackosOriginAV]"
                "\nTEHDIT ENGELLENDI"
                f"\nModul: {owner}"
                "\nSebep: Cok hizli dosya silme davranisi"
                f"\nSon hedef: {path}\n"
                "\033[0m"
            )

            return False

        if renames > self.rename_limit:

            self.blocked.add(owner)

            print(
                "\033[91m"
                "\n[🛡️ HackosOriginAV]"
                "\nTEHDIT ENGELLENDI"
                f"\nModul: {owner}"
                "\nSebep: Anormal rename davranisi\n"
                "\033[0m"
            )

            return False

        return True

    def scan_source(self, source):

        try:
            tree = ast.parse(source)
        except SyntaxError as e:
            return 50, [
                f"Python syntax hatasi: {e}"
            ]

        analyzer = Analyzer()
        analyzer.visit(tree)

        score = 0

        for finding in analyzer.findings:

            if finding["severity"] == "HIGH":
                score += 35
            else:
                score += 15

        return min(score, 100), analyzer.findings

    def scan_file(self, path):

        try:
            source = self.api.read_file(path)
        except Exception as e:
            return None, [str(e)]

        return self.scan_source(source)


def baglan(api):

    av = OriginAV(api)

    # Shell'e global olarak bagla.
    api.shell.originav = av

    @api.command(
        name="originav",
        description="HackosOriginAV antivirus",
    )
    def originav(*args):

        sub = args[0].lower() if args else "help"

        if sub in ("help", "?"):

            print("""
  HackosOriginAV

  originav tara <dosya>
      Tek bir Python dosyasini tara.

  originav engellenen
      Engellenen modulleri goster.

  originav temizle
      Engellenen modulleri sifirla.

  originav durum
      Antivirus durumunu goster.
""")
            return

        if sub == "durum":

            print()
            print("  🛡️ HackosOriginAV v2.0")
            print("  Durum : AKTIF")
            print(
                f"  Silme limiti : "
                f"{av.delete_limit}/{av.window}s"
            )
            print(
                f"  Rename limiti : "
                f"{av.rename_limit}/{av.window}s"
            )
            print()

            return

        if sub == "engellenen":

            if not av.blocked:
                print(
                    "  [✓] Engellenen modul yok."
                )
                return

            print("\n  ENGELLENEN MODULLER")

            for name in av.blocked:
                print(
                    f"   🛡️ {name}"
                )

            print()
            return

        if sub == "temizle":

            av.blocked.clear()

            print(
                "  [✓] Engellenen modul listesi temizlendi."
            )

            return

        if sub == "tara":

            if len(args) < 2:

                print(
                    "  Kullanim:"
                    " originav tara <dosya>"
                )

                return

            path = args[1]

            score, findings = av.scan_file(path)

            if score is None:
                print(
                    "  [!] Dosya okunamadi."
                )
                return

            print()
            print(
                f"  🛡️ HackosOriginAV: {path}"
            )
            print(
                f"  Risk skoru: {score}/100"
            )

            if not findings:

                print(
                    "  [✓] Supheli davranis bulunamadi."
                )

            else:

                for item in findings:

                    if isinstance(item, dict):
                        print(
                            f"  [{item['severity']}] "
                            f"{item['message']} "
                            f"(satir {item['line']})"
                        )
                    else:
                        print(
                            f"  [!] {item}"
                        )

            print()

            return

        print(
            "  Bilinmeyen komut."
            " 'originav help' yaz."
        )

    print(
        "\033[92m"
        "[✓] HackosOriginAV v2.0 aktif."
        "\033[0m"
            )
