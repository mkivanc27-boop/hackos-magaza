# eklentiler/addcommands.py
# -*- coding: utf-8 -*-
"""
ADDCOMMANDS v2.0 - Çekirdek Eklenti

ModuleAPI'ye add_command() ekler — AMA her mod yalnızca BİR komut
kaydedebilir. Bu komut genellikle bir menü açan launcher'dır.
İkinci kez add_command() çağırılırsa hata fırlatılır.

Neden böyle?
  Modlar, shell komutlarını doğrudan kirletmez. Kullanıcı "nexus"
  yazar, menü açılır, menüden 1/2/3 ile her şeye ulaşır.
  Birden fazla komut eklemek isteyen → eklenti yazar, EklentiAPI alır.
"""

EKLENTI_META = {
    "name": "addcommands",
    "version": "2.0",
    "author": "kanka",
    "description": "Modlara TEK bir launcher komutu ekleme yetkisi verir"
}


def baglan(api):
    ModuleAPI = api.ModuleAPI

    def add_command(self, name=None, description=None, alias=None):
        # ── TEK KOMUT KISITLAMASI ──────────────────────────
        zaten = [
            cmd for cmd, fn in self._shell.commands.items()
            if getattr(fn, "_owner_mod", None) == self._mod_name
        ]
        if zaten:
            raise RuntimeError(
                f"[addcommands] '{self._mod_name}' modu zaten "
                f"'{zaten[0]}' komutunu kaydetti.\n"
                f"  Modlar yalnızca TEK bir launcher komutu ekleyebilir.\n"
                f"  Birden fazla komut için eklenti (eklentiler/) yaz."
            )
        # ── NORMAL KAYIT ──────────────────────────────────
        def decorator(func):
            cmd_name = name or func.__name__
            func._cmd_desc = description or func.__doc__ or "Açıklama belirtilmedi."
            func._owner_mod = self._mod_name
            self._shell.commands[cmd_name] = func
            if alias:
                self._shell.aliases[alias] = cmd_name
            return func
        return decorator

    ModuleAPI.add_command = add_command
    api.log("Modlara TEK launcher komutu ekleme yetkisi verildi.")
              
