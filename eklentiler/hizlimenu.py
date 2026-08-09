# eklentiler/hizli_menu.py
# -*- coding: utf-8 -*-
"""HIZLI MENÜ v1.0 - 'menu' komutuyla açılan hızlı erişim menüsü"""

EKLENTI_META = {
    "name": "hizli_menu",
    "version": "1.0",
    "author": "kanka",
    "description": "'menu' komutuyla sık kullanılan işlemler için hızlı menü açar"
}


def baglan(api):
    @api.command(name="menu", description="Sık kullanılan komutlar için hızlı menü açar")
    def menu(*args):
        secenekler = [
            ("📦 Yüklü modülleri göster", "modules"),
            ("🧩 Bağlı eklentileri göster", "eklentiler"),
            ("🔐 İzinleri göster", "izinler"),
            ("📁 Dosyaları listele", "ls -l"),
            ("🕘 Komut geçmişi", "history"),
            ("🔄 Modülleri yeniden yükle", "reload"),
        ]
        secim = api.menu("⚡ HIZLI MENÜ", secenekler, prompt="menu")
        if secim is None:
            return
        api.shell.parse_and_run(secim)

    api.log("hizli_menu hazır -- 'menu' yaz.")
  
