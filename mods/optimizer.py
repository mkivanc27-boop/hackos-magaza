# mods/optimizer.py
# -*- coding: utf-8 -*-
"""
OPTİMİZER v1.0 - Optimizasyon Modu

HackOS klasörünü tarar, gereksiz/geçici dosyaları bulur, "temizlik" yapar
ve sahte ama eğlenceli bir disk/performans raporu üretir.
"""

META = {
    "name": "optimizer",
    "version": "1.0",
    "author": "kanka",
    "description": "Disk analizi + geçici dosya temizliği + performans raporu",
    "permissions": ["dosya_okuma", "dosya_silme"],
    "requires": []
}

GECICI_UZANTILAR = (".tmp", ".temp", ".bak", ".log", ".cache")


def setup(api):
    import time
    import random

    @api.add_command(name="analiz", description="HackOS klasörünün disk kullanım raporunu çıkarır")
    def analiz(*args):
        from pathlib import Path
        kok = Path(api.cwd())
        toplam, dosya_sayisi, gecici = 0, 0, 0
        for f in kok.rglob("*"):
            if f.is_file():
                toplam += f.stat().st_size
                dosya_sayisi += 1
                if f.suffix in GECICI_UZANTILAR:
                    gecici += 1
        print(f"\n  📊 {kok.name}/ Analiz Raporu")
        print(f"  {'─'*36}")
        print(f"  Dosya sayısı     : {dosya_sayisi}")
        print(f"  Toplam boyut     : {toplam/1024:.1f} KB")
        print(f"  Geçici dosya     : {gecici}")
        print(f"  Durum            : {'🟢 Temiz' if gecici == 0 else '🟡 Temizlik önerilir'}\n")

    @api.add_command(name="temizle", description="Geçici uzantılı (.tmp/.bak/.log...) dosyaları siler")
    def temizle(*args):
        from pathlib import Path
        kok = Path(api.cwd())
        hedefler = [f for f in kok.rglob("*") if f.is_file() and f.suffix in GECICI_UZANTILAR]
        if not hedefler:
            print("  ✨ Temizlenecek geçici dosya yok, sistem zaten temiz.")
            return
        print(f"  🧹 {len(hedefler)} geçici dosya bulundu, siliniyor...")
        for f in hedefler:
            try:
                api.delete_file(str(f.relative_to(kok)))
                print(f"    - {f.name}")
            except Exception as e:
                print(f"    ! {f.name} silinemedi: {e}")
        print(f"  ✓ Temizlik tamamlandı.")

    @api.add_command(name="defrag", description="Sahte disk optimizasyon animasyonu (eğlence amaçlı)")
    def defrag(*args):
        print("\n  💿 Optimizasyon başlatılıyor...\n")
        genislik = 30
        for i in range(genislik + 1):
            dolu = "█" * i
            bos = "░" * (genislik - i)
            yuzde = int(i / genislik * 100)
            print(f"\r  [{dolu}{bos}] %{yuzde:>3}", end="", flush=True)
            time.sleep(0.03)
        kazanc = random.randint(2, 18)
        print(f"\n\n  ✓ Optimizasyon tamam. Simüle performans kazancı: %{kazanc}\n")

    api.log("optimizer hazır -- 'analiz', 'temizle', 'defrag' komutlarını kullan.")
      
