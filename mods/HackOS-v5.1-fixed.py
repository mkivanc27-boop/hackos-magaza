#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HackOS v4.0 - Professional Terminal Emulator & Modular Shell
Pydroid 3 / Android Optimized

DEĞİŞİKLİK (v3 -> v4):
Modlar artık import edilir edilmez komut kaydetmiyor. Her modülün
bir `setup(api)` fonksiyonu OLMAK ZORUNDA ve bu fonksiyon SADECE
HackOS shell'i tarafından, canlı shell'e bağlı bir ModuleAPI nesnesi
verilerek çağrılıyor. Yani bir modu düz Pydroid'de "Çalıştır" dersen
hiçbir şey olmaz -- setup() tetiklenmediği için komutlar kaydolmaz,
api.log/api.storage gibi şeylere erişim de olmaz. Modlamanın anlamı
bu sayede geri geliyor: mod, HackOS'un dışında işlevsiz.
"""

import os
import sys
import json
import shlex
import shutil
import socket
import threading
import importlib.util
import traceback
from pathlib import Path
from types import MappingProxyType

try:
    import readline
    READLINE_AVAILABLE = True
except ImportError:
    READLINE_AVAILABLE = False

# --- DİZİN VE HASSAS AYARLAR ---
BASE_DIR = Path("/storage/emulated/0/HackOSV2")
MODS_DIR = BASE_DIR / "mods"
EXT_DIR = BASE_DIR / "eklentiler"          # eklentiler mods/'tan ayrı, güvenilir katman
STORAGE_FILE = BASE_DIR / ".mod_storage.json"
HISTORY_FILE = BASE_DIR / ".hackos_history"
AUTOEXEC_FILE = BASE_DIR / "autoexec.hos"
PERMISSIONS_FILE = BASE_DIR / ".mod_permissions.json"

# --- MOD ⇄ EKLENTİ FARKI (basit hali) ---
# MOD    : mods/*.py   → setup(api) ile yüklenir. Sandbox'lı, izin sistemine
#          tabi, başka mod'lara bağımlı (requires) olabilir.
#          Çıplak haliyle shell'e komut EKLEYEMEZ.
# EKLENTİ: eklentiler/*.py → baglan(api) ile yüklenir, MOD'LARDAN ÖNCE.
#          Sandbox/izin yok. eklentiler/addcommands.py adlı TEK bir eklenti,
#          ModuleAPI sınıfına add_command() metodunu ekler -- bundan sonra
#          HER mod kendi setup()'ında @api.add_command(...) ile istediği
#          kadar komut tanımlayabilir. Yani mod'lar komut ekleyemez ama
#          "addcommands" eklentisi sayesinde ekleyebilir hâle gelirler.

# --- MODÜL İZİN SİSTEMİ ---
# Bir modül bu izinlerden hangilerini istediğini META["permissions"] içinde
# bildirir. İzinler SADECE HackOS'un kendi klasörü (BASE_DIR) içinde
# geçerlidir -- cihazın geri kalanına bu API üzerinden asla erişilemez.
ALL_PERMISSIONS = {
    "dosya_okuma":         "HackOS klasöründeki dosyaları okuyabilir",
    "dosya_yazma":         "HackOS klasöründeki dosyaları oluşturabilir/değiştirebilir",
    "dosya_silme":         "HackOS klasöründeki dosyaları silebilir",
    "yeniden_adlandirma":  "HackOS klasöründeki dosya/klasör isimlerini değiştirebilir",
    "komut_calistirma":    "Diğer HackOS shell komutlarını kendi adına çalıştırabilir",
    "zamanlayici":         "Arka planda zamanlanmış/periyodik görev kurabilir",
}

sys.modules["hackos"] = sys.modules[__name__]

# ANSI RENKLERİ
C_BLUE = "\033[94m"
C_GREEN = "\033[92m"
C_YELLOW = "\033[93m"
C_RED = "\033[91m"
C_CYAN = "\033[96m"
C_MAGENTA = "\033[95m"
C_BOLD = "\033[1m"
C_RESET = "\033[0m"


# --- MODÜLLERE VERİLEN TEK KAPI: ModuleAPI ---
class ModuleAPI:
    """
    Bir modülün shell ile konuşabildiği TEK yol budur.
    Bu nesne yalnızca HackOSShell.load_modules() içinde, gerçek bir
    shell instance'ına bağlı olarak oluşturulur. Modül dosyasını tek
    başına çalıştırırsan bu nesneye asla erişemezsin -- dolayısıyla
    komut kaydı, storage, renkli çıktı gibi hiçbir şey çalışmaz.
    """

    def __init__(self, shell: "HackOSShell", mod_name: str, meta: dict):
        self._shell = shell
        self._mod_name = mod_name
        self.meta = meta
        # env'i salt-okunur ver, mod shell'in ortamını kazara bozamasın
        self.env = MappingProxyType(shell.env)

    # --- İZİN KONTROLÜ ---
    def _has(self, permission):
        return permission in self._shell.permissions.get(self._mod_name, set())

    def _check_perm(self, permission):
        if not self._has(permission):
            raise PermissionError(
                f"'{self._mod_name}' modülünün '{permission}' izni yok "
                f"('izinver {self._mod_name} {permission}' ile verebilirsin)."
            )

    def require(self, permission):
        """Mod, hazır dosya metotlarının dışında bir işlem yapacaksa
        önce bu izne sahip olduğunu burada teyit ettirir."""
        self._check_perm(permission)

    def _sandbox_path(self, path):
        """Verilen yolu HackOS'un kendi klasörünün (BASE_DIR) dışına
        çıkamayacak şekilde çözer. Cihazın geri kalanına asla izin verilmez,
        modüle hangi izin verilmiş olursa olsun."""
        p = Path(path)
        p = p if p.is_absolute() else (Path(self.cwd()) / p)
        p = p.resolve()
        try:
            p.relative_to(BASE_DIR.resolve())
        except ValueError:
            raise PermissionError(f"'{path}' HackOS klasörü dışında -- erişim engellendi.")
        return p

    # --- SANDBOX'LI DOSYA İŞLEMLERİ (sadece BASE_DIR içinde, izinli ise) ---
    def read_file(self, path):
        self._check_perm("dosya_okuma")
        p = self._sandbox_path(path)
        return p.read_text(encoding="utf-8", errors="ignore")

    def write_file(self, path, content):
        self._check_perm("dosya_yazma")
        p = self._sandbox_path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")

    def delete_file(self, path):
        self._check_perm("dosya_silme")
        p = self._sandbox_path(path)
        if p.is_dir():
            shutil.rmtree(p)
        elif p.exists():
            p.unlink()

    def rename_file(self, old_path, new_path):
        self._check_perm("yeniden_adlandirma")
        p_old = self._sandbox_path(old_path)
        p_new = self._sandbox_path(new_path)
        p_old.rename(p_new)

    def list_dir(self, path="."):
        """Listeleme salt-okunur bir bilgi olduğu için izin gerektirmez,
        ama yine de BASE_DIR dışına çıkamaz."""
        p = self._sandbox_path(path)
        return sorted(x.name for x in p.iterdir())

    # --- KOMUT KAYDI (addcommands eklentisi olmadan YASAK) ---
    def add_command(self, name=None, description=None, alias=None):
        """Varsayılan olarak komut eklemeye izin verilmez.

        addcommands eklentisi yüklenince bu metot gerçek implementasyonla
        ezilir ve her mod için TEK komut hakkı tanır.

        Neden böyle?
          Modlar shell komut alanını kirletmemeli. Tek bir launcher açar,
          kullanıcı menüden ilerler. Çok komut lazımsa eklenti yazılır.
        """
        raise RuntimeError(
            f"\n  [{self._mod_name}] KOMUT EKLENEMEDİ\n"
            f"  ─────────────────────────────────────────────\n"
            f"  'addcommands' eklentisi yüklü değil.\n"
            f"  Modların komut ekleyebilmesi için bu eklentiye ihtiyaç var.\n\n"
            f"  Çözüm → eklentiler/addcommands.py dosyasını ekle ve 'reload' yap.\n"
            f"  Not   → Birden fazla komut lazımsa mod değil eklenti yaz (EklentiAPI)."
        )

    # --- GERİYE DÖNÜK KOMUT API UYUMLULUĞU ---
    def command(self, name=None, description=None, alias=None):
        """@api.command(...) kullanan eski modları da destekler.

        Komut yetkisi hâlâ addcommands eklentisinin kontrolündedir;
        bu metot yalnızca add_command() için uyumluluk katmanıdır.
        """
        return self.add_command(name=name, description=description, alias=alias)

    # --- Renkli çıktı ---
    def log(self, msg, color=None):
        c = color or C_RESET
        print(f"{c}[{self._mod_name}]{C_RESET} {msg}")

    def error(self, msg):
        print(f"{C_RED}[{self._mod_name}] HATA: {msg}{C_RESET}")

    # --- Mod başına kalıcı depolama (JSON tabanlı mini db) ---
    def get(self, key, default=None):
        return self._shell.storage.get(self._mod_name, {}).get(key, default)

    def set(self, key, value):
        self._shell.storage.setdefault(self._mod_name, {})[key] = value
        self._shell.save_storage()

    def delete(self, key):
        self._shell.storage.get(self._mod_name, {}).pop(key, None)
        self._shell.save_storage()

    # --- Modun shell komutu çalıştırabilmesi (örn. başka bir modun komutunu tetiklemek) ---
    def run(self, command_line: str):
        self._check_perm("komut_calistirma")
        self._shell.parse_and_run(command_line)

    # --- Ortak dizin bilgisi ---
    def cwd(self):
        return os.getcwd()

    # --- Zamanlayıcı: modüller X saniye sonra / periyodik iş çalıştırabilir ---
    def schedule(self, seconds: float, func, repeat=False, name=None):
        """
        Arka planda (ayrı thread) bir fonksiyonu belirtilen süre sonra
        çalıştırır. repeat=True ise aynı aralıkla tekrar eder.
        Döner: iptal için kullanılabilecek bir threading.Timer nesnesi.
        """
        self._check_perm("zamanlayici")
        label = name or func.__name__

        def wrapper():
            try:
                func()
            except Exception as e:
                print(f"\n{C_RED}[zamanlayıcı:{self._mod_name}/{label}] Hata: {e}{C_RESET}")
            if repeat and not getattr(wrapper, "_cancelled", False):
                t = threading.Timer(seconds, wrapper)
                t.daemon = True
                t.start()
                self._shell.timers.append(t)

        t = threading.Timer(seconds, wrapper)
        t.daemon = True
        t.start()
        self._shell.timers.append(t)
        return t

    # --- Yüklü modül / komut bilgisine salt-okunur erişim ---
    def list_commands(self):
        return sorted(self._shell.commands.keys())

    def list_modules(self):
        return {name: info["meta"] for name, info in self._shell.modules.items()}

    # --- EKLENTİ API'SİNE ERİŞİM (mod -> eklenti köprüsü) ---
    def use_extension(self, ext_name, key=None):
        """META['requires_ext'] içinde bildirilen bir eklentinin
        export_api() ile yayınladığı fonksiyon/değere eriş.
        Böylece nexus modu, rpg eklentisinden give_xp() alabilir."""
        req = self.meta.get("requires_ext", [])
        if ext_name not in req:
            raise PermissionError(
                f"'{self._mod_name}', META['requires_ext'] içinde '{ext_name}' "
                f"belirtmeden o eklentiye bağımlı olamaz."
            )
        pool = self._shell.ext_exports.get(ext_name, {})
        if key is None:
            return pool
        if key not in pool:
            raise KeyError(f"'{ext_name}' eklentisi '{key}' export etmemiş.")
        return pool[key]

    # --- KÜTÜPHANE MOD DESTEĞİ (ukuslib tarzı) ---
    # Bir mod kendi fonksiyon/veri/sınıflarını "export" edip başka bir mod
    # bunu "requires" ile bildirip use_dependency() ile çekebilir. Böylece
    # "ukus armor hud" mod'u "ukuslib"in kod tabanını gerçekten kullanabilir,
    # sadece varlığını şart koşmaz.
    def export(self, key, value):
        """Bu modülün bir parçasını başka modüllerin kullanımına açar."""
        self._shell.exports.setdefault(self._mod_name, {})[key] = value

    def use_dependency(self, mod_name, key=None):
        """requires listesindeki bir mod'un export ettiği şeyi al.
        key verilmezse o mod'un tüm export sözlüğünü döner."""
        if mod_name not in self.meta.get("requires", []):
            raise PermissionError(
                f"'{self._mod_name}', META['requires'] içinde '{mod_name}' "
                f"belirtmeden ona bağımlı olamaz."
            )
        pool = self._shell.exports.get(mod_name, {})
        if key is None:
            return pool
        if key not in pool:
            raise KeyError(f"'{mod_name}' modülü '{key}' adında bir şey export etmemiş.")
        return pool[key]


# --- EKLENTİLERE VERİLEN KAPI: EklentiAPI ---
# ModuleAPI'nin sandbox'lı/izinli hâlinin aksine, EklentiAPI shell'e DOĞRUDAN
# bağlanır. İzin sorulmaz, dosya erişimi BASE_DIR ile sınırlı değildir --
# eklenti kendi Python koduyla ne isterse yapabilir. Bu yüzden eklentiler
# "kur ve unut" bir mod değil, shell'in kendisine yazdığın bir uzantıdır.
class EklentiAPI:
    """
    eklentiler/*.py dosyalarındaki baglan(shell) fonksiyonuna bu nesne DEĞİL,
    shell'in kendisi (ya da bu ince sarmalayıcı) verilir -- amaç, eklentinin
    shell.commands, shell.env, shell.parse_and_run gibi çekirdek parçalara
    doğrudan uzanabilmesi. Örn: winstart gibi bir komutla tam ekran bir menü
    açıp kullanıcı seçimine göre shell.parse_and_run() tetiklemek gibi.
    """

    def __init__(self, shell: "HackOSShell", ext_name: str, meta: dict):
        self.shell = shell            # doğrudan, sarmalanmamış erişim
        self._ext_name = ext_name
        self.meta = meta
        self.ModuleAPI = ModuleAPI    # sınıfın kendisi -- addcommands.py bunu
                                       # patch'leyerek mod'lara komut ekleme
                                       # yeteneği kazandırır.

    # Eklentinin shell'e komut ekleyebildiği yol budur (mod'larda .command()
    # yoktur -- onlara bu yetkiyi vermek istersen addcommands.py'ye bak).
    def command(self, name=None, description=None, alias=None):
        def decorator(func):
            cmd_name = name or func.__name__
            func._cmd_desc = description or func.__doc__ or "Açıklama belirtilmedi."
            func._owner_ext = self._ext_name
            self.shell.commands[cmd_name] = func
            if alias:
                self.shell.aliases[alias] = cmd_name
            return func
        return decorator

    def log(self, msg, color=None):
        c = color or C_RESET
        print(f"{c}[{self._ext_name}]{C_RESET} {msg}")

    def error(self, msg):
        print(f"{C_RED}[{self._ext_name}] HATA: {msg}{C_RESET}")

    def hook_cmd(self, func):
        """Her komut çalıştırıldıktan sonra func(cmd, args) çağrılır.
        rpg.py gibi eklentiler XP/achievement takibi için bunu kullanır --
        parse_and_run'ı monkey-patch'lemek yerine temiz kayıt."""
        self.shell.hooks.append((self._ext_name, func))

    def export_api(self, **kwargs):
        """Bu eklentinin fonksiyon/değerlerini diğer mod ve eklentilere açar.
        Örn: rpg eklentisi give_xp, get_profile gibi fonksiyonları export eder,
        nexus modu api.use_extension('rpg')['give_xp'](10) ile çağırır."""
        self.shell.ext_exports.setdefault(self._ext_name, {}).update(kwargs)

    def use_extension(self, ext_name, key=None):
        """Başka bir eklentinin export_api() ile yayınladığı API'ye eriş.
        key verilmezse tüm export dict'ini döner."""
        pool = self.shell.ext_exports.get(ext_name, {})
        if key is None:
            return pool
        if key not in pool:
            raise KeyError(f"'{ext_name}' eklentisi '{key}' export etmemiş.")
        return pool[key]

    def menu(self, title, options, prompt="Seçim"):
        """Basit, yeniden kullanılabilir tam ekran seçim menüsü. Eklentiler
        (örn. winstart) bunu doğrudan çağırıp kendi arayüzlerini kurabilir.
        options: [(etiket, deger), ...]  -> seçilen deger'i döner, iptalde None."""
        while True:
            os.system('cls' if os.name == 'nt' else 'clear')
            print(f"{C_BOLD}{C_CYAN}{'═'*52}{C_RESET}")
            print(f"{C_BOLD}{C_CYAN}  {title}{C_RESET}")
            print(f"{C_CYAN}{'═'*52}{C_RESET}\n")
            for i, (etiket, _) in enumerate(options, 1):
                print(f"  {C_CYAN}{i:>2}.{C_RESET} {etiket}")
            print(f"\n  {C_YELLOW}[q]{C_RESET} vazgeç")
            secim = input(f"\n{C_BOLD}{prompt}> {C_RESET}").strip().lower()
            if secim == "q":
                return None
            if secim.isdigit() and 1 <= int(secim) <= len(options):
                return options[int(secim) - 1][1]


def module_meta(name=None, version="1.0", author="anonim", description=""):
    """
    Modül dosyasının en üstünde çağrılması ÖNERİLEN yardımcı.
    Sadece bir dict döner, hiçbir shell bağlantısı gerektirmez --
    bu yüzden tek başına çalıştırıldığında hata vermez, ama tek
    başına hiçbir işe de yaramaz (kayıt yapmaz).
    """
    return {"name": name, "version": version, "author": author, "description": description}


class HackOSShell:
    def __init__(self):
        self.commands = {}
        self.modules = {}       # mod_name -> {"module": mod, "meta": {...}}
        self.extensions = {}    # ext_name -> {"module": mod, "meta": {...}}
        self.exports = {}       # mod_name -> {key: value}  (mod kütüphane paylaşımları)
        self.ext_exports = {}   # ext_name -> {key: value}  (eklenti API paylaşımları)
        self.hooks = []         # [(ext_name, func(cmd,args))]  komut hook'ları
        self.aliases = {}
        self.storage = {}
        self.permissions = {}   # mod_name -> set(izinler)
        self.timers = []
        self.env = {
            "USER": "root",
            "HOSTNAME": socket.gethostname(),
            "SHELL": "HackOS-v5.1",
            "HOME": str(BASE_DIR)
        }
        self.running = True

        self.setup_fs()
        self.load_storage()
        self.load_permissions()
        self.setup_completion()
        self.load_history()

    def setup_fs(self):
        try:
            BASE_DIR.mkdir(parents=True, exist_ok=True)
            MODS_DIR.mkdir(parents=True, exist_ok=True)
            EXT_DIR.mkdir(parents=True, exist_ok=True)
            os.chdir(BASE_DIR)
        except PermissionError:
            print(f"{C_RED}[!] İzin Hatası: Pydroid 3 depolama iznini kontrol edin!{C_RESET}")
            sys.exit(1)

    # --- KALICI MOD DEPOLAMA ---
    def load_storage(self):
        if STORAGE_FILE.exists():
            try:
                self.storage = json.loads(STORAGE_FILE.read_text(encoding="utf-8"))
            except Exception:
                self.storage = {}

    def save_storage(self):
        try:
            STORAGE_FILE.write_text(json.dumps(self.storage, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception as e:
            print(f"{C_RED}[!] Storage yazılamadı: {e}{C_RESET}")

    # --- KALICI MOD İZİNLERİ ---
    def load_permissions(self):
        if PERMISSIONS_FILE.exists():
            try:
                raw = json.loads(PERMISSIONS_FILE.read_text(encoding="utf-8"))
                self.permissions = {k: set(v) for k, v in raw.items()}
            except Exception:
                self.permissions = {}

    def save_permissions(self):
        try:
            data = {k: sorted(v) for k, v in self.permissions.items()}
            PERMISSIONS_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception as e:
            print(f"{C_RED}[!] İzinler yazılamadı: {e}{C_RESET}")

    def request_permissions(self, mod_name, meta, requested, is_extra=False):
        """Kullanıcıdan bir modül için izin ister. Boş küme dönerse hiçbir
        izin verilmemiştir; mod yine de yüklenir ama izinli fonksiyonları
        çağırınca PermissionError alır."""
        if not requested:
            return set()

        title = "EK İZİN TALEBİ" if is_extra else "YENİ MODÜL KURULUMU"
        print(f"\n{C_BOLD}{C_YELLOW}=== 🔐 {title}: {mod_name} ==={C_RESET}")
        if meta.get("description"):
            print(f"  Açıklama: {meta['description']}")
        print(f"  Bu modül şu izinleri istiyor:\n")
        for p in sorted(requested):
            print(f"   • {C_CYAN}{p}{C_RESET} - {ALL_PERMISSIONS.get(p, '?')}")
        print(f"\n  {C_MAGENTA}[T]{C_RESET}ümünü onayla   "
              f"{C_MAGENTA}[S]{C_RESET}eç (tek tek sor)   "
              f"{C_MAGENTA}[R]{C_RESET}eddet (hiçbirini verme)")

        secim = input("  Seçiminiz [T/S/R]: ").strip().lower()
        if secim == "r":
            print(f"  {C_RED}[-] Hiçbir izin verilmedi.{C_RESET}")
            return set()
        elif secim == "s":
            onaylanan = set()
            for p in sorted(requested):
                cevap = input(f"   '{p}' izni verilsin mi? [e/h]: ").strip().lower()
                if cevap == "e":
                    onaylanan.add(p)
            return onaylanan
        else:
            print(f"  {C_GREEN}[✓] Tüm izinler onaylandı.{C_RESET}")
            return set(requested)

    def setup_completion(self):
        if not READLINE_AVAILABLE:
            return

        def completer(text, state):
            builtins = ["help", "reload", "modules", "eklentiler", "clear", "exit", "cd", "pwd", "ls",
                        "mkdir", "rm", "cat", "echo", "export", "alias", "grep", "execute",
                        "run", "history", "izinler", "izinver", "izinal", "izinsifirla"]
            all_cmds = list(set(builtins + list(self.commands.keys()) + list(self.aliases.keys())))
            files = [f.name for f in Path(os.getcwd()).glob("*")]
            options = [c for c in all_cmds + files if c.startswith(text)]
            return options[state] if state < len(options) else None

        readline.set_completer(completer)
        readline.parse_and_bind("tab: complete")

    # --- KALICI KOMUT GEÇMİŞİ ---
    def load_history(self):
        if READLINE_AVAILABLE and HISTORY_FILE.exists():
            try:
                readline.read_history_file(str(HISTORY_FILE))
            except Exception:
                pass

    def save_history(self):
        if READLINE_AVAILABLE:
            try:
                readline.write_history_file(str(HISTORY_FILE))
            except Exception:
                pass

    def cmd_history(self, *args):
        if not READLINE_AVAILABLE:
            print(f"{C_YELLOW}[!] readline mevcut değil, geçmiş gösterilemiyor.{C_RESET}")
            return
        n = readline.get_current_history_length()
        start = max(1, n - 30 + 1)
        for i in range(start, n + 1):
            print(f"  {C_CYAN}{i}{C_RESET}  {readline.get_history_item(i)}")

    # --- BATCH SCRIPT ÇALIŞTIRMA (.hos dosyaları) ---
    def cmd_run(self, filename=None, *args):
        if not filename:
            print(f"{C_RED}Kullanım: run <script.hos>{C_RESET}")
            return
        p = Path(filename)
        if not p.exists():
            print(f"{C_RED}run: {filename}: dosya bulunamadı{C_RESET}")
            return
        for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            print(f"{C_CYAN}$ {line}{C_RESET}")
            self.parse_and_run(line)

    # --- MODÜL YÜKLEYİCİ (v6: setup(api) + META['requires'] bağımlılıkları) ---
    def reload_all(self, quiet=False):
        """Eklentiler ÖNCE, mod'lar SONRA yüklenir -- addcommands.py gibi bir
        eklenti, mod'ların setup()'ı çalışmadan önce ModuleAPI'ye yeni
        yetenekler ekleyebilsin diye."""
        # Sıfırlama reload_all seviyesinde bir kez yapılır.
        # load_modules commands.clear() YAPMASIN -- eklentilerin kaydettiği
        # komutları silmemek için (örn. rpg'nin 'rpg','gorevler' komutları).
        self.commands.clear()
        self.aliases.clear()
        self.hooks.clear()
        self.ext_exports.clear()
        self.load_extensions(quiet=quiet)
        self.load_modules(quiet=quiet)

    def load_modules(self, quiet=False):
        # commands burada temizlenmez -- reload_all zaten temizledi.
        # Sadece mod kayıtlarını ve export'ları sıfırla.
        self.modules.clear()
        self.exports.clear()

        py_files = [f for f in MODS_DIR.glob("*.py") if not f.name.startswith("__")]
        loaded, skipped = 0, 0

        # --- 1. AŞAMA: hiçbir setup() çağırmadan tüm dosyaları içe aktar,
        # META'larını oku. Böylece kim kime bağımlı, setup() çalışmadan önce
        # bilinir (ukuslib örneğindeki gibi -- kütüphane, ona muhtaç olan
        # mod'dan ÖNCE hazır olmalı).
        raw = {}   # mod_name -> {"file":, "mod":, "meta":}
        for file in py_files:
            mod_name = file.stem
            try:
                spec = importlib.util.spec_from_file_location(mod_name, file)
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
            except Exception as e:
                print(f"{C_RED}[-] Modül İçe Aktarma Hatası ({file.name}): {e}{C_RESET}")
                skipped += 1
                continue

            setup_fn = getattr(mod, "setup", None)
            if not callable(setup_fn):
                if not quiet:
                    print(f"{C_YELLOW}[!] {file.name}: 'setup(api)' fonksiyonu yok, atlandı.{C_RESET}")
                skipped += 1
                continue

            meta = getattr(mod, "META", None) or {}
            raw[mod_name] = {"file": file, "mod": mod, "meta": meta, "setup": setup_fn}

        # --- 2. AŞAMA: bağımlılık grafiğini topolojik sırala ---
        order, dep_errors = self._resolve_dependency_order(raw)
        for mod_name, reason in dep_errors.items():
            print(f"{C_RED}[-] '{mod_name}' atlandı: {reason}{C_RESET}")
            skipped += 1

        # --- 3. AŞAMA: sıraya göre gerçekten kur (setup çağır) ---
        for mod_name in order:
            info = raw[mod_name]
            meta, setup_fn, mod = info["meta"], info["setup"], info["mod"]
            try:
                requested = {p for p in meta.get("permissions", []) if p in ALL_PERMISSIONS}
                unknown = set(meta.get("permissions", [])) - ALL_PERMISSIONS.keys()
                if unknown:
                    print(f"{C_YELLOW}[!] {mod_name}: bilinmeyen izin(ler) yok sayıldı: {unknown}{C_RESET}")

                known = self.permissions.get(mod_name)
                if known is None:
                    granted = self.request_permissions(mod_name, meta, requested)
                    self.permissions[mod_name] = granted
                    self.save_permissions()
                else:
                    yeni = requested - known
                    if yeni:
                        print(f"{C_YELLOW}[!] '{mod_name}' modülü önceden istemediği yeni izinler istiyor.{C_RESET}")
                        ek = self.request_permissions(mod_name, meta, yeni, is_extra=True)
                        self.permissions[mod_name] = known | ek
                        self.save_permissions()

                api = ModuleAPI(self, mod_name, meta)
                setup_fn(api)  # <-- mod SADECE burada gerçek hayata geçiyor

                self.modules[mod_name] = {"module": mod, "meta": meta}
                loaded += 1
            except Exception as e:
                print(f"{C_RED}[-] Modül Yükleme Hatası ({mod_name}): {e}{C_RESET}")
                skipped += 1

        if not quiet:
            print(f"{C_GREEN}[✓] {loaded} modül yüklendi, {skipped} atlandı. "
                  f"{len(self.commands)} komut hazır.{C_RESET}")

    def _resolve_dependency_order(self, raw):
        """raw: mod_name -> {'meta': {...}, ...}. META['requires'] bir mod adı
        listesidir. Kayan/eksik/döngüsel bağımlılıkları eler ve geri kalanı
        Kahn algoritmasıyla (kütüphaneler önce) sıralar.
        Döner: (sıralı_liste, {mod_name: hata_mesajı})"""
        errors = {}
        requires = {name: list(info["meta"].get("requires", [])) for name, info in raw.items()}

        # eksik bağımlılığı olanları baştan ele (ve onlara bağımlı olanları da
        # zincirleme eleriz -- aşağıdaki döngüde otomatik yakalanır)
        changed = True
        while changed:
            changed = False
            for name, deps in list(requires.items()):
                if name in errors:
                    continue
                for dep in deps:
                    if dep not in raw:
                        errors[name] = f"eksik bağımlılık: '{dep}' bulunamadı (kütüphane mod yüklü değil)."
                        changed = True
                        break
                    if dep in errors:
                        errors[name] = f"bağımlılığı '{dep}' yüklenemediği için o da yüklenemiyor."
                        changed = True
                        break

        remaining = {n: d for n, d in requires.items() if n not in errors}

        # Kahn topolojik sıralama -> döngü tespiti
        order = []
        indegree = {n: 0 for n in remaining}
        for n, deps in remaining.items():
            for d in deps:
                if d in remaining:
                    indegree[n] += 1
        queue = [n for n, deg in indegree.items() if deg == 0]
        while queue:
            queue.sort()  # kararlı/öngörülebilir sıra
            n = queue.pop(0)
            order.append(n)
            for other, deps in remaining.items():
                if n in deps and other in indegree:
                    indegree[other] -= 1
                    if indegree[other] == 0 and other not in order and other not in queue:
                        queue.append(other)

        for n in remaining:
            if n not in order:
                errors[n] = "döngüsel bağımlılık tespit edildi (A, B'ye; B, A'ya muhtaç gibi)."

        return order, errors

    # --- EKLENTİ YÜKLEYİCİ (v1: baglan(shell) zorunlu, izin/sandbox yok) ---
    def load_extensions(self, quiet=False):
        self.extensions.clear()
        ext_files = [f for f in EXT_DIR.glob("*.py") if not f.name.startswith("__")]
        loaded, skipped = 0, 0

        for file in ext_files:
            ext_name = file.stem
            try:
                spec = importlib.util.spec_from_file_location(ext_name, file)
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)

                baglan_fn = getattr(mod, "baglan", None)
                if not callable(baglan_fn):
                    if not quiet:
                        print(f"{C_YELLOW}[!] {file.name}: 'baglan(shell)' fonksiyonu yok, atlandı.{C_RESET}")
                    skipped += 1
                    continue

                meta = getattr(mod, "EKLENTI_META", None) or {}
                api = EklentiAPI(self, ext_name, meta)
                baglan_fn(api)  # <-- eklenti burada shell'e doğrudan bağlanır

                self.extensions[ext_name] = {"module": mod, "meta": meta}
                loaded += 1
            except Exception as e:
                print(f"{C_RED}[-] Eklenti Yükleme Hatası ({file.name}): {e}{C_RESET}")
                skipped += 1

        if not quiet:
            print(f"{C_GREEN}[✓] {loaded} eklenti bağlandı, {skipped} atlandı.{C_RESET}")

    # --- YERLEŞİK TERMINAL KOMUTLARI ---
    def cmd_cd(self, path="~"):
        target = BASE_DIR if path in ["~", ""] else Path(path).expanduser().resolve()
        if target.exists() and target.is_dir():
            os.chdir(target)
        else:
            print(f"{C_RED}cd: no such file or directory: {path}{C_RESET}")

    def cmd_ls(self, *args):
        show_all = "-a" in args or "-la" in args or "-al" in args
        long_fmt = "-l" in args or "-la" in args or "-al" in args
        curr = Path(os.getcwd())
        items = sorted(curr.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower()))
        for item in items:
            if not show_all and item.name.startswith("."):
                continue
            prefix = "d" if item.is_dir() else "-"
            size = item.stat().st_size if not item.is_dir() else 4096
            color = C_CYAN if item.is_dir() else C_RESET
            if long_fmt:
                print(f"{prefix}rwxr-xr-x 1 {self.env['USER']} {size:>8} B  {color}{item.name}{C_RESET}")
            else:
                print(f"{color}{item.name}{C_RESET}  ", end="")
        if not long_fmt:
            print()

    def cmd_cat(self, filename=None, *args):
        if not filename:
            print(f"{C_RED}cat: eksik dosya argümanı{C_RESET}")
            return
        p = Path(filename)
        if p.exists() and p.is_file():
            print(p.read_text(encoding="utf-8", errors="ignore"))
        else:
            print(f"{C_RED}cat: {filename}: Dosya bulunamadı{C_RESET}")

    def cmd_grep(self, pattern=None, filename=None):
        if not pattern or not filename:
            print(f"{C_RED}Kullanım: grep <aranan_metin> <dosya>{C_RESET}")
            return
        p = Path(filename)
        if p.exists() and p.is_file():
            lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
            for i, line in enumerate(lines, 1):
                if pattern in line:
                    highlighted = line.replace(pattern, f"{C_RED}{C_BOLD}{pattern}{C_RESET}")
                    print(f"{C_YELLOW}{i}:{C_RESET} {highlighted}")
        else:
            print(f"{C_RED}grep: {filename}: Dosya bulunamadı{C_RESET}")

    def cmd_execute(self, *args):
        if not args:
            print(f"{C_RED}Kullanım: execute <script.py>{C_RESET}")
            return
        target = " ".join(args)
        if Path(target).exists():
            print(f"{C_YELLOW}[>] Script çalıştırılıyor: {target}{C_RESET}\n" + "-" * 40)
            try:
                exec(open(target).read(), {"__name__": "__main__", "sys": sys, "os": os})
            except Exception as e:
                print(f"{C_RED}[-] Çalıştırma hatası: {e}{C_RESET}")
            print("-" * 40)
        else:
            print(f"{C_RED}execute: {target}: Dosya bulunamadı{C_RESET}")

    # --- YARDIM MENÜSÜ ---
    def cmd_help(self):
        print(f"\n{C_BOLD}{C_GREEN}=== HACKOS OPERATING SHELL v5.1 ==={C_RESET}")
        print(f"{C_YELLOW}📌 DAHİLİ SHELL KOMUTLARI:{C_RESET}")
        print("  cd [dizin]         - Dizin değiştirir")
        print("  pwd                - Çalışma dizinini basar")
        print("  ls [-l -a]         - Dosya ve klasörleri listeler")
        print("  cat <dosya>        - Dosya içeriğini okur")
        print("  grep <text> <dos>  - Dosya içinde arama yapar")
        print("  mkdir / rm / touch - Dosya/klasör işlemleri")
        print("  export VAR=VAL     - Çevre değişkeni atar")
        print("  alias k='komut'    - Komut kısayolu oluşturur")
        print("  execute <file>     - Python script dosyası çalıştırır")
        print("  run <script.hos>   - HackOS komut dosyası (batch) çalıştırır")
        print("  history            - Son komut geçmişini gösterir")
        print("  reload / modules   - Modül yönetimi (mods/, sandbox'lı+izinli)")
        print("  eklentiler         - Bağlı eklentileri listeler (eklentiler/, izinsiz+doğrudan)")
        print("  izinler [mod]      - Modül izinlerini listeler")
        print("  izinver <mod> <izin>   - Modüle izin verir")
        print("  izinal  <mod> <izin>   - Modülden izin kaldırır")
        print("  izinsifirla <mod>  - Mod izinlerini sıfırlar (yeniden sorulur)")
        print("  clear / exit       - Ekranı temizler / Çıkış")

        if self.commands:
            print(f"\n{C_YELLOW}🚀 YÜKLENEN KOMUTLAR:{C_RESET}")
            for name, func in sorted(self.commands.items()):
                desc = getattr(func, "_cmd_desc", "Açıklama yok.")
                if hasattr(func, "_owner_ext"):
                    tag = f"{C_BLUE}[⚡eklenti: {func._owner_ext}]{C_RESET}"
                else:
                    owner = getattr(func, "_owner_mod", "?")
                    tag = f"{C_MAGENTA}[📦mod: {owner}]{C_RESET}"
                print(f"  {C_CYAN}{name:<18}{C_RESET} - {desc}  {tag}")
        print(f"{C_BOLD}{C_GREEN}===================================={C_RESET}\n")

    def cmd_modules(self):
        if not self.modules:
            print(f"{C_YELLOW}Yüklü modül yok.{C_RESET}")
            return
        print(f"\n{C_YELLOW}📦 Yüklü Modüller:{C_RESET}")
        for name, info in self.modules.items():
            meta = info["meta"] or {}
            ver = meta.get("version", "?")
            author = meta.get("author", "bilinmiyor")
            desc = meta.get("description", "")
            requires = meta.get("requires", [])
            req_str = f"  {C_MAGENTA}(bağımlı: {', '.join(requires)}){C_RESET}" if requires else ""
            print(f"  {C_CYAN}{name}{C_RESET} v{ver} - {author}  {desc}{req_str}")
        print()

    def cmd_eklentiler(self):
        if not self.extensions:
            print(f"{C_YELLOW}Bağlı eklenti yok.{C_RESET}")
            return
        print(f"\n{C_YELLOW}🧩 Bağlı Eklentiler (izinsiz, doğrudan erişim):{C_RESET}")
        for name, info in self.extensions.items():
            meta = info["meta"] or {}
            ver = meta.get("version", "?")
            author = meta.get("author", "bilinmiyor")
            desc = meta.get("description", "")
            print(f"  {C_MAGENTA}{name}{C_RESET} v{ver} - {author}  {desc}")
        print()

    # --- İZİN YÖNETİM KOMUTLARI ---
    def cmd_izinler(self, mod_name=None, *args):
        if mod_name:
            perms = self.permissions.get(mod_name)
            if perms is None:
                print(f"{C_RED}'{mod_name}' için izin kaydı yok.{C_RESET}")
                return
            print(f"\n{C_YELLOW}🔐 {mod_name} izinleri:{C_RESET}")
            if not perms:
                print("  (hiçbir izin verilmemiş)")
            for p in sorted(perms):
                print(f"  • {C_CYAN}{p}{C_RESET} - {ALL_PERMISSIONS.get(p, '?')}")
        else:
            if not self.permissions:
                print(f"{C_YELLOW}Henüz izin kaydı yok.{C_RESET}")
                return
            print(f"\n{C_YELLOW}🔐 Tüm modül izinleri:{C_RESET}")
            for mod, perms in self.permissions.items():
                gosterim = ", ".join(sorted(perms)) if perms else "(yok)"
                print(f"  {C_CYAN}{mod}{C_RESET}: {gosterim}")
        print()

    def cmd_izinver(self, mod_name=None, perm=None, *args):
        if not mod_name or not perm:
            print(f"{C_RED}Kullanım: izinver <mod> <izin>{C_RESET}")
            return
        if perm not in ALL_PERMISSIONS:
            print(f"{C_RED}Bilinmeyen izin: {perm}. Geçerli izinler: {', '.join(ALL_PERMISSIONS)}{C_RESET}")
            return
        self.permissions.setdefault(mod_name, set()).add(perm)
        self.save_permissions()
        print(f"{C_GREEN}[✓] '{mod_name}' için '{perm}' izni verildi.{C_RESET}")

    def cmd_izinal(self, mod_name=None, perm=None, *args):
        if not mod_name or not perm:
            print(f"{C_RED}Kullanım: izinal <mod> <izin>{C_RESET}")
            return
        self.permissions.get(mod_name, set()).discard(perm)
        self.save_permissions()
        print(f"{C_YELLOW}[✓] '{mod_name}' için '{perm}' izni kaldırıldı.{C_RESET}")

    def cmd_izinsifirla(self, mod_name=None, *args):
        if not mod_name:
            print(f"{C_RED}Kullanım: izinsifirla <mod>{C_RESET}")
            return
        if mod_name in self.permissions:
            del self.permissions[mod_name]
            self.save_permissions()
            print(f"{C_YELLOW}[✓] '{mod_name}' izinleri sıfırlandı. Sonraki 'reload'da tekrar sorulacak.{C_RESET}")
        else:
            print(f"{C_RED}'{mod_name}' için izin kaydı yok.{C_RESET}")

    @staticmethod
    def _split_top_level(line, sep=";"):
        """';' ile böler ama tırnak içindeki ';' karakterlerine dokunmaz."""
        parts = []
        buf = []
        in_squote = in_dquote = False
        for ch in line:
            if ch == "'" and not in_dquote:
                in_squote = not in_squote
                buf.append(ch)
            elif ch == '"' and not in_squote:
                in_dquote = not in_dquote
                buf.append(ch)
            elif ch == sep and not in_squote and not in_dquote:
                parts.append("".join(buf))
                buf = []
            else:
                buf.append(ch)
        parts.append("".join(buf))
        return parts

    # --- PARSER & EXECUTION ENGINE ---
    def parse_and_run(self, raw_line):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            return

        for single_cmd in self._split_top_level(line, ";"):
            single_cmd = single_cmd.strip()
            if not single_cmd:
                continue

            parts = single_cmd.split()
            if parts[0] in self.aliases:
                single_cmd = self.aliases[parts[0]] + " " + " ".join(parts[1:])

            try:
                tokens = shlex.split(single_cmd)
            except ValueError as e:
                print(f"{C_RED}Syntax Hatası: {e}{C_RESET}")
                return

            cmd = tokens[0]
            args = tokens[1:]
            args = [self.env.get(a[1:], a) if a.startswith("$") else a for a in args]

            if cmd == "cd": self.cmd_cd(*args)
            elif cmd == "pwd": print(os.getcwd())
            elif cmd == "ls": self.cmd_ls(*args)
            elif cmd == "cat": self.cmd_cat(*args)
            elif cmd == "grep": self.cmd_grep(*args)
            elif cmd == "mkdir": os.makedirs(args[0], exist_ok=True) if args else None
            elif cmd == "touch": open(args[0], 'a').close() if args else None
            elif cmd == "rm": os.remove(args[0]) if args and os.path.isfile(args[0]) else None
            elif cmd == "echo": print(" ".join(args))
            elif cmd == "export" and args and "=" in args[0]:
                k, v = args[0].split("=", 1)
                self.env[k] = v
            elif cmd == "alias" and args and "=" in args[0]:
                k, v = args[0].split("=", 1)
                self.aliases[k] = v.strip("'\"")
            elif cmd == "execute": self.cmd_execute(*args)
            elif cmd == "run": self.cmd_run(*args)
            elif cmd == "history": self.cmd_history(*args)
            elif cmd == "help": self.cmd_help()
            elif cmd == "reload": self.reload_all(quiet=False)
            elif cmd == "modules": self.cmd_modules()
            elif cmd == "eklentiler": self.cmd_eklentiler()
            elif cmd == "izinler": self.cmd_izinler(*args)
            elif cmd == "izinver": self.cmd_izinver(*args)
            elif cmd == "izinal": self.cmd_izinal(*args)
            elif cmd == "izinsifirla": self.cmd_izinsifirla(*args)
            elif cmd in ["clear", "cls"]: os.system('cls' if os.name == 'nt' else 'clear')
            elif cmd in ["exit", "quit"]: self.running = False
            elif cmd in self.commands:
                try:
                    self.commands[cmd](*args)
                except PermissionError as e:
                    print(f"{C_RED}[🔒] İzin reddedildi: {e}{C_RESET}")
                except Exception as e:
                    print(f"{C_RED}[-] Komut İcrasına Hata [{cmd}]: {e}{C_RESET}")
                    traceback.print_exc()
            else:
                print(f"{C_RED}hackos: command not found: {cmd}{C_RESET}")
                continue

            # --- HOOK'LARI ÇAĞIR (eklentiler komuttan sonra tetiklenir) ---
            for ext_name, hook_fn in self.hooks:
                try:
                    hook_fn(cmd, args)
                except Exception as e:
                    print(f"{C_RED}[hook:{ext_name}] {e}{C_RESET}")

    def run(self):
        os.system('cls' if os.name == 'nt' else 'clear')
        print(f"{C_BOLD}{C_GREEN}")
        print("  ██╗  ██╗ █████╗  ██████╗██╗  ██╗ ██████╗ ███████╗  ██╗██╗")
        print("  ██║  ██║██╔══██╗██╔════╝██║ ██╔╝██╔═══██╗██╔════╝  ██║██║")
        print("  ███████║███████║██║     █████╔╝ ██║   ██║███████╗  ██║██║")
        print("  ██╔══██║██╔══██║██║     ██╔═██╗ ██║   ██║╚════██║  ╚═╝╚═╝")
        print("  ██║  ██║██║  ██║╚██████╗██║  ██╗╚██████╔╝███████║  ██╗██╗")
        print("  ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝  ╚═╝╚═╝")
        print(f"  System Ready (v5.1 - Eklenti + Mod + Bağımlılık Sistemi) | 'help' yaz.{C_RESET}\n")

        self.reload_all(quiet=True)

        if AUTOEXEC_FILE.exists():
            print(f"{C_YELLOW}[*] autoexec.hos bulundu, çalıştırılıyor...{C_RESET}")
            self.cmd_run(str(AUTOEXEC_FILE))

        while self.running:
            try:
                cwd = os.getcwd().replace(str(BASE_DIR), "~")
                prompt = f"{C_BOLD}{C_GREEN}{self.env['USER']}@{self.env['HOSTNAME']}{C_RESET}:{C_BLUE}{cwd}{C_RESET}$ "
                user_input = input(prompt)
                self.parse_and_run(user_input)
            except KeyboardInterrupt:
                print(f"\n{C_YELLOW}[!] Sistem kapatılıyor...{C_RESET}")
                break
            except Exception as e:
                print(f"{C_RED}[-] Shell İçi Hata: {e}{C_RESET}")

        for t in self.timers:
            t.cancel()
        self.save_history()


if __name__ == "__main__":
    shell = HackOSShell()
    shell.run()
