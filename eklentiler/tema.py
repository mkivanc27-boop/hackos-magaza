# eklentiler/tema.py
# -*- coding: utf-8 -*-
"""
TEMA v1.0 - Gerçek Zamanlı Renk Teması Değiştirici

hackos.py'deki C_BLUE, C_GREEN, C_YELLOW, C_RED, C_CYAN, C_MAGENTA gibi
renkler modül seviyesinde GLOBAL değişkenler. hackos.py içindeki tüm
fonksiyonlar bu isimleri her çalıştıklarında yeniden okur (Python global
lookup dinamiktir) -- yani bu eklenti hackos.C_GREEN = "..." dediğinde,
prompt'tan menülere, hata mesajlarından mod çıktılarına kadar HER ŞEY
anında yeni renge boyanır. Ayrı bir tema motoru yazmaya gerek yok, zaten
var olan mekanizmayı kullanıyoruz.

BİLİNEN SINIRLAMA: Açılıştaki HACKOS ASCII banner'ı run() içinde,
eklentiler yüklenmeden HEMEN ÖNCE basılıyor -- o yüzden banner her zaman
orijinal yeşille bir an görünür, sonra kayıtlı tema hemen devreye girer.
Bunu değiştirmek hackos.py'de küçük bir sıra değişikliği gerektirir.

KULLANIM:
  tema              -> mevcut tema + liste
  tema onizle        -> tüm temaların renk örneklerini gösterir (değiştirmez)
  tema <isim>        -> temayı uygular ve kalıcı kaydeder (her açılışta geri gelir)
"""
import hackos

EKLENTI_META = {
    "name": "tema",
    "version": "1.0",
    "author": "kanka",
    "description": "Tüm terminalin rengini anında ve kalıcı olarak değiştirir"
}

TEMALAR = {
    "klasik": {  # hackos.py'nin orijinal renkleri
        "C_BLUE": "\033[94m", "C_GREEN": "\033[92m", "C_YELLOW": "\033[93m",
        "C_RED": "\033[91m", "C_CYAN": "\033[96m", "C_MAGENTA": "\033[95m",
    },
    "neon": {
        "C_BLUE": "\033[38;5;93m", "C_GREEN": "\033[38;5;118m", "C_YELLOW": "\033[38;5;226m",
        "C_RED": "\033[38;5;198m", "C_CYAN": "\033[38;5;51m", "C_MAGENTA": "\033[38;5;201m",
    },
    "gece": {
        "C_BLUE": "\033[38;5;69m", "C_GREEN": "\033[38;5;81m", "C_YELLOW": "\033[38;5;153m",
        "C_RED": "\033[38;5;204m", "C_CYAN": "\033[38;5;75m", "C_MAGENTA": "\033[38;5;63m",
    },
    "alarm": {
        "C_BLUE": "\033[38;5;166m", "C_GREEN": "\033[38;5;220m", "C_YELLOW": "\033[38;5;208m",
        "C_RED": "\033[38;5;196m", "C_CYAN": "\033[38;5;209m", "C_MAGENTA": "\033[38;5;160m",
    },
    "mono": {
        "C_BLUE": "\033[38;5;245m", "C_GREEN": "\033[38;5;250m", "C_YELLOW": "\033[38;5;253m",
        "C_RED": "\033[38;5;240m", "C_CYAN": "\033[38;5;248m", "C_MAGENTA": "\033[38;5;243m",
    },
    "gunbatimi": {
        "C_BLUE": "\033[38;5;204m", "C_GREEN": "\033[38;5;215m", "C_YELLOW": "\033[38;5;220m",
        "C_RED": "\033[38;5;209m", "C_CYAN": "\033[38;5;217m", "C_MAGENTA": "\033[38;5;213m",
    },
}


def _uygula(isim):
    for degisken, deger in TEMALAR[isim].items():
        setattr(hackos, degisken, deger)


def baglan(api):
    # Kayıtlı tema varsa açılışta otomatik uygula (kalıcılık)
    kayit = api.shell.storage.setdefault("tema", {"secili": "klasik"})
    secili = kayit.get("secili", "klasik")
    if secili in TEMALAR:
        _uygula(secili)

    def _listele():
        print(f"\n  {hackos.C_BOLD}🎨 Mevcut tema:{hackos.C_RESET} {kayit['secili']}\n")
        print(f"  {hackos.C_YELLOW}Kullanılabilir temalar:{hackos.C_RESET} "
              f"{', '.join(TEMALAR.keys())}")
        print(f"  Uygula: {hackos.C_GREEN}tema <isim>{hackos.C_RESET}   "
              f"Örnekleri gör: {hackos.C_GREEN}tema onizle{hackos.C_RESET}\n")

    def _onizle():
        print(f"\n  {hackos.C_BOLD}🎨 Tema Önizleme{hackos.C_RESET}\n")
        R = "\033[0m"
        for isim, pal in TEMALAR.items():
            swatch = "".join(f"{pal[k]}■{R}" for k in
                              ["C_GREEN", "C_CYAN", "C_MAGENTA", "C_YELLOW", "C_RED", "C_BLUE"])
            aktif = f"  {hackos.C_GREEN}← aktif{hackos.C_RESET}" if isim == kayit["secili"] else ""
            print(f"  {swatch}  {isim}{aktif}")
        print()

    @api.command(name="tema", description="Terminal renk temasını değiştirir")
    def tema(*args):
        if not args:
            _listele()
        elif args[0] == "onizle":
            _onizle()
        elif args[0] in TEMALAR:
            _uygula(args[0])
            kayit["secili"] = args[0]
            api.shell.save_storage()
            print(f"  {hackos.C_GREEN}[✓] Tema '{args[0]}' uygulandı ve kaydedildi "
                  f"-- her açılışta otomatik gelecek.{hackos.C_RESET}")
        else:
            print(f"  {hackos.C_RED}Bilinmeyen tema: {args[0]}{hackos.C_RESET}")
            _listele()

    api.log(f"tema hazır -- şu an '{secili}'. 'tema onizle' ile diğerlerine bak.")
