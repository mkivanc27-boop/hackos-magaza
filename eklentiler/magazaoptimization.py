# eklentiler/magazaoptimization.py
# -*- coding: utf-8 -*-

"""
HackOS Mağaza Optimization v1.0

Mevcut magaza.py dosyasına dokunmadan:
- Mağaza listesini RAM'de cache'ler
- Gereksiz GitHub API isteklerini azaltır
- magaza help gibi komutlarda API isteği oluşmasını engellemek
  için mağaza komutunun önüne cache katmanı koyar
- Cache süresi dolunca otomatik yeniler
- İnternet geçici olarak yoksa eski cache'i kullanabilir
- Manuel cache yenileme / temizleme komutları sağlar

Komutlar:
    magazaopt
    magazaopt durum
    magazaopt yenile
    magazaopt temizle
"""

import time
import threading
import urllib.error

import hackos


# =========================================================
# META
# =========================================================

EKLENTI_META = {
    "name": "magazaoptimization",
    "version": "1.0",
    "author": "HackOS",
    "description": "Mağaza GitHub isteklerini cache ile optimize eder"
}


# =========================================================
# AYARLAR
# =========================================================

CACHE_TTL = 300  # 5 dakika

_cache = None
_cache_time = 0.0

_cache_lock = threading.RLock()

_original_listeyi_topla = None

_installed = False


# =========================================================
# CACHE
# =========================================================

def _cache_gecerli_mi():

    global _cache

    if _cache is None:
        return False

    return (
        time.time() - _cache_time
        < CACHE_TTL
    )


def _cache_yasi():

    if _cache is None:
        return None

    return int(
        time.time() - _cache_time
    )


def _cache_temizle():

    global _cache
    global _cache_time

    with _cache_lock:

        _cache = None
        _cache_time = 0.0


def _listeyi_cachele():

    global _cache
    global _cache_time

    with _cache_lock:

        # Başka bir çağrı az önce cache oluşturduysa
        # tekrar GitHub'a gitme.
        if _cache_gecerli_mi():

            return _cache

        if _original_listeyi_topla is None:

            return None

        try:

            yeni_liste = (
                _original_listeyi_topla()
            )

        except Exception:

            # Eski cache varsa offline fallback.
            if _cache is not None:

                return _cache

            raise

        _cache = yeni_liste
        _cache_time = time.time()

        return _cache


# =========================================================
# MAGAZA PATCH
# =========================================================

def _magazayi_optimize_et():

    global _original_listeyi_topla
    global _installed

    if _installed:
        return True

    try:

        import magaza

    except ImportError:

        return False

    # Fonksiyon yoksa bu sürüm uyumlu değil.
    if not hasattr(
        magaza,
        "_listeyi_topla"
    ):

        return False

    # Daha önce patchlenmişse tekrar sarma.
    if getattr(
        magaza,
        "_magazaoptimization_patched",
        False
    ):

        _installed = True
        return True

    _original_listeyi_topla = (
        magaza._listeyi_topla
    )

    def optimize_listeyi_topla():

        return _listeyi_cachele()

    magaza._listeyi_topla = (
        optimize_listeyi_topla
    )

    magaza._magazaoptimization_patched = True

    _installed = True

    return True


# =========================================================
# KOMUTLAR
# =========================================================

def baglan(api):

    # -----------------------------------------------------
    # Önce mevcut mağazayı patchle
    # -----------------------------------------------------

    if not _magazayi_optimize_et():

        api.log(
            "[magazaoptimization] "
            "magaza.py bulunamadı veya uyumsuz."
        )

    else:

        api.log(
            "[magazaoptimization] "
            "GitHub cache aktif -- TTL: 5 dakika"
        )

    # -----------------------------------------------------
    # magazaopt
    # -----------------------------------------------------

    @api.command(
        name="magazaopt",
        description=(
            "Mağaza cache/optimizasyon yönetimi"
        )
    )
    def magazaopt(*args):

        alt = (
            args[0].lower()
            if args
            else None
        )

        # ---------------------------------------------
        # ANA EKRAN
        # ---------------------------------------------

        if alt is None:

            print()
            print(
                "╔════════════════════════════════════╗"
            )
            print(
                "║     ⚡ MAGAZA OPTIMIZATION v1.0   ║"
            )
            print(
                "╠════════════════════════════════════╣"
            )
            print(
                "║  durum   → Cache durumunu göster   ║"
            )
            print(
                "║  yenile  → Cache'i zorla yenile   ║"
            )
            print(
                "║  temizle → Cache'i temizle         ║"
            )
            print(
                "╚════════════════════════════════════╝"
            )
            print()

            return

        # ---------------------------------------------
        # DURUM
        # ---------------------------------------------

        if alt == "durum":

            print()
            print(
                "========== MAĞAZA OPT =========="
            )

            if _cache is None:

                print(
                    "  Cache : BOŞ"
                )

            else:

                age = _cache_yasi()

                if _cache_gecerli_mi():

                    print(
                        "  Cache : AKTİF"
                    )

                else:

                    print(
                        "  Cache : SÜRESİ DOLMUŞ"
                    )

                print(
                    f"  Yaş   : {age} saniye"
                )

                print(
                    f"  TTL   : {CACHE_TTL} saniye"
                )

                print(
                    f"  Öğe   : {len(_cache)}"
                )

            print(
                f"  Patch : "
                f"{'AKTİF' if _installed else 'PASİF'}"
            )

            print(
                "================================"
            )
            print()

            return

        # ---------------------------------------------
        # YENİLE
        # ---------------------------------------------

        if alt == "yenile":

            print(
                "\n  🔄 Mağaza cache yenileniyor..."
            )

            _cache_temizle()

            try:

                liste = _listeyi_cachele()

                if liste is None:

                    print(
                        "  [!] Mağaza yüklenemedi."
                    )

                    return

                print(
                    f"  ✓ Cache yenilendi."
                )

                print(
                    f"  ✓ {len(liste)} öğe alındı."
                )

            except Exception as error:

                print(
                    f"  [!] Yenileme hatası: {error}"
                )

            print()

            return

        # ---------------------------------------------
        # TEMİZLE
        # ---------------------------------------------

        if alt == "temizle":

            _cache_temizle()

            print(
                "\n  ✓ Mağaza cache temizlendi.\n"
            )

            return

        # ---------------------------------------------
        # BİLİNMEYEN
        # ---------------------------------------------

        print(
            "\n  Kullanım:"
        )

        print(
            "    magazaopt"
        )

        print(
            "    magazaopt durum"
        )

        print(
            "    magazaopt yenile"
        )

        print(
            "    magazaopt temizle"
        )

        print()


# =========================================================
# SON
# =========================================================
# =========================================================
# OTOMATİK BAĞLANTI
# =========================================================

# HackOS eklenti sistemi baglan(api) fonksiyonunu
# otomatik olarak çağırıyorsa burası yeterlidir.
#
# Dosyanın sonunda ekstra işlem çalıştırmıyoruz.
# Cache ilk magaza komutunda gerektiğinde oluşturulur.

__all__ = [
    "EKLENTI_META",
    "baglan"
]
