# eklentiler/magazacache.py
# -*- coding: utf-8 -*-
"""
MAGAZACACHE v1.0 - Mağaza İstek Önbellekleyici

Sorun: magaza.py her "magaza modlar", "magaza ara" gibi her komutta
GitHub'a gidip HEM klasör listesini HEM içindeki her .py dosyasının
tam içeriğini (META okumak için) yeniden indiriyor. 10 mod + 10
eklenti varsa bu tek bir "magaza modlar" için 20+ HTTP isteği demek --
hem yavaş hem GitHub'ın rate limit'ine gereksiz yük.

Çözüm: urllib.request.urlopen'ı GitHub'ın kendi domainleri için (api.
github.com, raw.githubusercontent.com vb.) 5 dakikalık TTL ile
önbellekleyen ince bir sarmalayıcıya çeviriyoruz. magaza.py'nin TEK
SATIRI değişmiyor -- kendi bilmeden hızlanıyor.

DÜRÜST OLALIM: Bu patch sadece GitHub domainlerini hedefliyor (bilerek
domain filtresi koydum), yoksa 'istek' gibi genel amaçlı HTTP
mod'larının GET isteklerini de sessizce önbellekler ve bu yanıltıcı
olurdu. Eğer 'istek' ile GitHub'a istek atarsan, o da bu önbellekten
etkilenir -- bunu bilerek kullan.

KULLANIM:
  magazacache durum     -> önbellekte ne var, ne kadar süresi kaldı
  magazacache temizle   -> önbelleği boşalt, sıradaki istek taze gitsin
"""
import time
import threading
import urllib.request
import urllib.parse

EKLENTI_META = {
    "name": "magazacache",
    "version": "1.0",
    "author": "berkealgan",  # farklı katkıcı -- magaza.py'yi ben yazmadım, sadece optimize ettim
    "description": "magaza.py'nin GitHub isteklerini önbellekler, her komutta yeniden indirmesini engeller"
}

TTL_SANIYE = 300  # 5 dakika
HEDEF_DOMAINLER = {"api.github.com", "raw.githubusercontent.com",
                    "objects.githubusercontent.com", "codeload.github.com"}

_ORIJINAL_URLOPEN = urllib.request.urlopen
_ONBELLEK = {}
_KILIT = threading.Lock()


class _OnbellekliYanit:
    """Gerçek urlopen'ın döndürdüğü nesneyi taklit eder (read(), status,
    headers, with-bloğu desteği) -- çağıran taraf aradaki farkı anlamaz."""
    def __init__(self, veri, status, headers):
        self._veri = veri
        self.status = status
        self.headers = headers

    def read(self):
        return self._veri

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _onbellekli_urlopen(req_veya_url, *args, **kwargs):
    url = req_veya_url.full_url if hasattr(req_veya_url, "full_url") else str(req_veya_url)
    host = urllib.parse.urlparse(url).netloc

    # POST/gövdeli istekler ve hedef dışı domainler ASLA önbelleklenmez
    govdeli_mi = getattr(req_veya_url, "data", None) is not None
    if govdeli_mi or host not in HEDEF_DOMAINLER:
        return _ORIJINAL_URLOPEN(req_veya_url, *args, **kwargs)

    with _KILIT:
        girdi = _ONBELLEK.get(url)
        if girdi and (time.time() - girdi["zaman"]) < TTL_SANIYE:
            return _OnbellekliYanit(girdi["veri"], girdi["status"], girdi["headers"])

    yanit = _ORIJINAL_URLOPEN(req_veya_url, *args, **kwargs)
    veri = yanit.read()
    status = getattr(yanit, "status", 200)
    headers = getattr(yanit, "headers", {})
    with _KILIT:
        _ONBELLEK[url] = {"veri": veri, "status": status, "headers": headers, "zaman": time.time()}
    return _OnbellekliYanit(veri, status, headers)


def baglan(api):
    C = __import__("hackos")
    urllib.request.urlopen = _onbellekli_urlopen  # global patch, sadece HEDEF_DOMAINLER etkileniyor

    @api.command(name="magazacache", description="Mağaza GitHub isteklerini önbellekler")
    def magazacache(*args):
        if args and args[0] == "temizle":
            with _KILIT:
                n = len(_ONBELLEK)
                _ONBELLEK.clear()
            print(f"  {C.C_GREEN}[✓] {n} önbellek kaydı temizlendi -- sıradaki 'magaza' taze veri çekecek.{C.C_RESET}")
        elif args and args[0] == "durum":
            with _KILIT:
                if not _ONBELLEK:
                    print(f"  {C.C_YELLOW}Önbellek boş.{C.C_RESET}")
                    return
                print(f"\n  {C.C_YELLOW}📦 Önbellekte {len(_ONBELLEK)} istek (TTL: {TTL_SANIYE}s){C.C_RESET}")
                for url, girdi in _ONBELLEK.items():
                    kalan = max(0, int(TTL_SANIYE - (time.time() - girdi["zaman"])))
                    kisa = url if len(url) < 60 else url[:57] + "..."
                    print(f"   • {kisa}  ({kalan}s kaldı)")
                print()
        else:
            print(f"  Kullanım: magazacache [durum|temizle]")
            print(f"  Otomatik: GitHub istekleri {TTL_SANIYE}s boyunca önbellekte tutuluyor "
                  f"(magaza.py'nin kendisi hiç değişmedi).")

    api.log(f"magazacache aktif -- GitHub istekleri {TTL_SANIYE}s önbellekleniyor.")
