# eklentiler/magazacache.py
# -*- coding: utf-8 -*-
"""
MAGAZACACHE v2.0 - Mağaza İstek Önbellekleyici (geliştirilmiş)

v1.0'a göre 4 gerçek değişiklik:

  1. FIX: reload'da iç içe sarmalayıcı birikme bug'ı giderildi. Artık
     urllib.request.urlopen'a "zaten patch'lendi mi" diye bakılıyor;
     ikinci baglan() çağrısı eskiyi tekrar sarmalamıyor.

  2. DİSK KALICILIĞI: önbellek artık sadece bellekte değil,
     .magazacache.json dosyasında -- HackOS'u kapatıp açsan bile
     mağaza listesi TTL süresi dolmadıysa hiç ağa gitmeden yüklenir.

  3. ETag / KOŞULLU İSTEK: TTL dolduğunda direkt yeniden indirmek
     yerine, sunucuya "If-None-Match: <eski-etag>" ile soruyoruz.
     Cevap 304 (değişmemiş) ise GitHub bunu rate limit'ten SAYMIYOR
     (GitHub'ın kendi dokümantasyonu) -- yani mağaza değişmediği sürece
     kota harcamadan "taze" kalabiliyoruz.

  4. RATE-LIMIT GÖRÜNÜRLÜĞÜ: GitHub'ın X-RateLimit-* başlıklarını
     okuyup 'magazacache durum'da gösteriyoruz -- kotanın ne zaman
     dolacağını görebilirsin.

KULLANIM:
  magazacache            -> özet + rate limit durumu
  magazacache durum      -> önbellekteki her kayıt, kalan TTL, etag var mı
  magazacache temizle    -> bellek + disk önbelleğini boşalt
  magazacache ttl <sn>   -> TTL süresini değiştirir (varsayılan 300)
"""
import base64
import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

import hackos

EKLENTI_META = {
    "name": "magazacache",
    "version": "2.0",
    "author": "kanka",
    "description": "magaza.py'nin GitHub isteklerini disk+ETag ile önbellekler, rate-limit takip eder"
}

TTL_VARSAYILAN = 300
HEDEF_DOMAINLER = {"api.github.com", "raw.githubusercontent.com",
                    "objects.githubusercontent.com", "codeload.github.com"}
DISK_DOSYA = hackos.BASE_DIR / ".magazacache.json"

_KILIT = threading.Lock()
_DURUM = {
    "onbellek": {},          # url -> {"veri_b64":, "etag":, "zaman":, "status":}
    "ttl": TTL_VARSAYILAN,
    "rate_kalan": None,
    "rate_limit": None,
    "rate_sifirlanma": None,
}


def _diske_yaz():
    try:
        DISK_DOSYA.write_text(json.dumps(_DURUM, ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass  # disk yazımı başarısız olsa bile bellek önbelleği çalışmaya devam eder


def _diskten_oku():
    if DISK_DOSYA.exists():
        try:
            kayitli = json.loads(DISK_DOSYA.read_text(encoding="utf-8"))
            _DURUM["onbellek"] = kayitli.get("onbellek", {})
            _DURUM["ttl"] = kayitli.get("ttl", TTL_VARSAYILAN)
        except Exception:
            pass


class _OnbellekliYanit:
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


def _rate_limit_guncelle(headers):
    try:
        kalan = headers.get("X-RateLimit-Remaining")
        limit = headers.get("X-RateLimit-Limit")
        sifirlanma = headers.get("X-RateLimit-Reset")
        if kalan is not None:
            _DURUM["rate_kalan"] = int(kalan)
        if limit is not None:
            _DURUM["rate_limit"] = int(limit)
        if sifirlanma is not None:
            _DURUM["rate_sifirlanma"] = int(sifirlanma)
    except (TypeError, ValueError):
        pass


def _yeni_onbellekli_urlopen(orijinal_urlopen):
    """orijinal_urlopen'ı kapanışta (closure) tutan asıl sarmalayıcıyı üretir."""

    def onbellekli_urlopen(req_veya_url, *args, **kwargs):
        url = req_veya_url.full_url if hasattr(req_veya_url, "full_url") else str(req_veya_url)
        host = urllib.parse.urlparse(url).netloc
        govdeli_mi = getattr(req_veya_url, "data", None) is not None

        if govdeli_mi or host not in HEDEF_DOMAINLER:
            return orijinal_urlopen(req_veya_url, *args, **kwargs)

        with _KILIT:
            girdi = _DURUM["onbellek"].get(url)
            ttl = _DURUM["ttl"]

        # 1) TTL içindeyse: ağa hiç gitme
        if girdi and (time.time() - girdi["zaman"]) < ttl:
            veri = base64.b64decode(girdi["veri_b64"])
            return _OnbellekliYanit(veri, girdi.get("status", 200), {})

        # 2) TTL dolmuş ama eski bir ETag'imiz var: koşullu iste (304 = bedava)
        if girdi and girdi.get("etag") and isinstance(req_veya_url, urllib.request.Request):
            req_veya_url.add_header("If-None-Match", girdi["etag"])
            try:
                yanit = orijinal_urlopen(req_veya_url, *args, **kwargs)
            except urllib.error.HTTPError as e:
                if e.code == 304:
                    _rate_limit_guncelle(dict(e.headers or {}))
                    with _KILIT:
                        girdi["zaman"] = time.time()  # tazelik süresini uzat
                        _diske_yaz()
                    veri = base64.b64decode(girdi["veri_b64"])
                    return _OnbellekliYanit(veri, girdi.get("status", 200), {})
                raise
        else:
            yanit = orijinal_urlopen(req_veya_url, *args, **kwargs)

        # 3) Gerçek (yeni) yanıt geldi -- önbelleğe al
        veri = yanit.read()
        status = getattr(yanit, "status", 200)
        headers = dict(getattr(yanit, "headers", {}) or {})
        _rate_limit_guncelle(headers)
        with _KILIT:
            _DURUM["onbellek"][url] = {
                "veri_b64": base64.b64encode(veri).decode("ascii"),
                "etag": headers.get("ETag"),
                "status": status,
                "zaman": time.time(),
            }
            _diske_yaz()
        return _OnbellekliYanit(veri, status, headers)

    return onbellekli_urlopen


def baglan(api):
    _diskten_oku()

    # FIX v1.0: reload'da eskiyi tekrar sarmalama. Zaten patch'liyse dokunma.
    if not getattr(urllib.request.urlopen, "_magazacache_patched", False):
        orijinal = urllib.request.urlopen
        sarmalayici = _yeni_onbellekli_urlopen(orijinal)
        sarmalayici._magazacache_patched = True
        sarmalayici._magazacache_orijinal = orijinal
        urllib.request.urlopen = sarmalayici

    @api.command(name="magazacache", description="Mağaza GitHub isteklerini önbellekler (disk+ETag)")
    def magazacache(*args):
        alt = args[0] if args else None

        if alt == "temizle":
            with _KILIT:
                n = len(_DURUM["onbellek"])
                _DURUM["onbellek"].clear()
                _diske_yaz()
            print(f"  ✓ {n} önbellek kaydı (bellek+disk) temizlendi.")

        elif alt == "ttl":
            if len(args) < 2 or not args[1].isdigit():
                print(f"  Kullanım: magazacache ttl <saniye>  (şu an: {_DURUM['ttl']}s)")
                return
            _DURUM["ttl"] = int(args[1])
            _diske_yaz()
            print(f"  ✓ TTL {_DURUM['ttl']} saniyeye ayarlandı.")

        elif alt == "durum":
            with _KILIT:
                if not _DURUM["onbellek"]:
                    print("  Önbellek boş.")
                else:
                    print(f"\n  📦 Önbellekte {len(_DURUM['onbellek'])} istek (TTL: {_DURUM['ttl']}s)")
                    for url, girdi in _DURUM["onbellek"].items():
                        kalan = max(0, int(_DURUM["ttl"] - (time.time() - girdi["zaman"])))
                        etag_var = "ETag ✓" if girdi.get("etag") else "ETag yok"
                        kisa = url if len(url) < 55 else url[:52] + "..."
                        print(f"   • {kisa}  ({kalan}s taze, {etag_var})")
                    print()
            _rate_ozet_yazdir()

        else:
            print(f"  Kullanım: magazacache [durum|temizle|ttl <sn>]")
            print(f"  TTL: {_DURUM['ttl']}s, {len(_DURUM['onbellek'])} kayıt (disk: {DISK_DOSYA.name})")
            _rate_ozet_yazdir()

    def _rate_ozet_yazdir():
        if _DURUM["rate_kalan"] is not None:
            kalan_sn = None
            if _DURUM["rate_sifirlanma"]:
                kalan_sn = max(0, int(_DURUM["rate_sifirlanma"] - time.time()))
            print(f"  🔑 GitHub rate limit: {_DURUM['rate_kalan']}/{_DURUM['rate_limit']} kaldı"
                  + (f", {kalan_sn//60} dk sonra sıfırlanır" if kalan_sn else ""))

    api.log(f"magazacache v2 aktif -- disk kalıcı + ETag koşullu istek + rate-limit takibi.")
                                    
