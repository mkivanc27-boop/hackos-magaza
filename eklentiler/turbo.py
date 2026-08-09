# eklentiler/turbo.py
# -*- coding: utf-8 -*-
"""
TURBO v1.0 - Gerçek Gecikme Azaltıcı (Sodium mantığı)

Rapor vermez, "optimize edildi" demez -- iki gerçek darboğazı çözer:

  1. storage.set() her çağrıldığında JSON'u SENKRON diske yazıyordu.
     Komut satırı bu yazma bitene kadar bloklanıyordu. Turbo bunu
     0.8sn'lik pencerede GRUPLAYIP arka planda (ayrı thread) yazar.
     Kapanışta (normal çıkış veya Ctrl+C) atexit ile garanti flush yapar
     -- veri kaybı riski yok.

  2. Tab-completion her tuşta os.listdir/glob ile dizini yeniden
     tarıyordu. Turbo bunu cwd değişene kadar önbellekte tutar, 'cd'
     komutuna kancalanıp önbelleği geçersiz kılar.

KULLANIM:
  turbo         -> aktif optimizasyonların durumu
  turbo test    -> önce/sonra gerçek ms farkını ölçüp gösterir
"""
import time
import atexit
import threading
from pathlib import Path

import hackos

EKLENTI_META = {
    "name": "turbo",
    "version": "1.0",
    "author": "kanka",
    "description": "Depolama yazmalarını gruplar, tab-completion'ı önbelleğe alır"
}

_DEBOUNCE_SANIYE = 0.8


def baglan(api):
    C = hackos
    shell = api.shell

    # ================= 1. DEPOLAMA YAZMALARINI GRUPLA =================
    _orig_save_storage = shell.save_storage
    _kilit = threading.Lock()
    _durum = {"zamanlayici": None, "bekleyen": False}

    def _gercek_yaz():
        with _kilit:
            _durum["bekleyen"] = False
        _orig_save_storage()

    def gruplu_save_storage():
        with _kilit:
            _durum["bekleyen"] = True
            if _durum["zamanlayici"] is not None:
                _durum["zamanlayici"].cancel()
            t = threading.Timer(_DEBOUNCE_SANIYE, _gercek_yaz)
            t.daemon = True
            t.start()
            _durum["zamanlayici"] = t
            shell.timers.append(t)

    shell.save_storage = gruplu_save_storage

    def _kapanista_zorla_yaz():
        with _kilit:
            bekleyen = _durum["bekleyen"]
        if bekleyen:
            _orig_save_storage()

    atexit.register(_kapanista_zorla_yaz)

    # ================= 2. TAB-COMPLETION ÖNBELLEĞİ =================
    if hackos.READLINE_AVAILABLE:
        import readline
        _onbellek = {"cwd": None, "dosyalar": []}

        def _dosyalari_al():
            cwd = str(Path.cwd())
            if _onbellek["cwd"] != cwd:
                _onbellek["cwd"] = cwd
                _onbellek["dosyalar"] = [f.name for f in Path(cwd).glob("*")]
            return _onbellek["dosyalar"]

        def hizli_completer(text, state):
            builtins = ["help", "reload", "modules", "eklentiler", "clear", "exit", "cd", "pwd",
                        "ls", "mkdir", "rm", "cat", "echo", "export", "alias", "grep", "execute",
                        "run", "history", "izinler", "izinver", "izinal", "izinsifirla"]
            all_cmds = list(set(builtins + list(shell.commands.keys()) + list(shell.aliases.keys())))
            options = [c for c in all_cmds + _dosyalari_al() if c.startswith(text)]
            return options[state] if state < len(options) else None

        readline.set_completer(hizli_completer)
        readline.parse_and_bind("tab: complete")

        _orig_cmd_cd = shell.cmd_cd

        def onbellek_temizleyen_cd(path="~"):
            _orig_cmd_cd(path)
            _onbellek["cwd"] = None  # dizin değişti, bir sonraki Tab'da yeniden taransın

        shell.cmd_cd = onbellek_temizleyen_cd

    # ================= 3. KANIT: turbo test =================
    def _test():
        print(f"\n  {C.C_YELLOW}Test: 50x storage.set() -- eski (senkron) yöntem{C.C_RESET}")
        t0 = time.perf_counter()
        for i in range(50):
            shell.storage.setdefault("_turbo_test", {})[f"k{i}"] = i
            _orig_save_storage()
        eski_ms = round((time.perf_counter() - t0) * 1000, 1)
        print(f"    -> komut satırı {eski_ms} ms boyunca bloklandı")

        print(f"\n  {C.C_YELLOW}Test: 50x storage.set() -- turbo (gruplu){C.C_RESET}")
        t0 = time.perf_counter()
        for i in range(50):
            shell.storage.setdefault("_turbo_test", {})[f"k{i}"] = i
            shell.save_storage()
        yeni_ms = round((time.perf_counter() - t0) * 1000, 1)
        print(f"    -> komut satırı sadece {yeni_ms} ms bloklandı "
              f"(gerçek disk yazımı ~{int(_DEBOUNCE_SANIYE*1000)}ms sonra arka planda oldu)")

        time.sleep(_DEBOUNCE_SANIYE + 0.2)  # arka plan flush bitsin, sonra temizle
        shell.storage.pop("_turbo_test", None)
        _orig_save_storage()

        if yeni_ms > 0:
            print(f"\n  {C.C_GREEN}[✓] Ön plan gecikmesi ~{round(eski_ms/max(yeni_ms,0.1),1)}x azaldı.{C.C_RESET}\n")
        else:
            print(f"\n  {C.C_GREEN}[✓] Ön plan gecikmesi ölçülemeyecek kadar düştü (~0ms).{C.C_RESET}\n")

    @api.command(name="turbo", description="Gerçek gecikme azaltma durumu ve kanıt testi")
    def turbo(*args):
        if args and args[0] == "test":
            _test()
        else:
            print(f"\n  {C.C_BOLD}{C.C_CYAN}⚡ TURBO aktif{C.C_RESET}")
            print(f"    • storage yazmaları {_DEBOUNCE_SANIYE}s'lik pencerede gruplanıyor "
                  f"(kapanışta garanti flush)")
            if hackos.READLINE_AVAILABLE:
                print(f"    • tab-completion dizin listesi cwd değişene kadar önbellekte")
            print(f"    Kanıt için: {C.C_GREEN}turbo test{C.C_RESET}\n")

    api.log("turbo aktif -- I/O gruplandı, tab-completion önbellekte. 'turbo test' ile kanıtla.")
