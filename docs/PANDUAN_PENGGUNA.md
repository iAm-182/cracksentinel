# Panduan Lengkap CrackSentinel v2.2.0 — Update, Audit PC, & Proteksi Download Otomatis

Panduan ini dibuat khusus untuk pengguna yang sebelumnya sudah pernah `git clone` **CrackSentinel** (versi `1.x`) atau pengguna baru yang ingin mengaktifkan **proteksi otomatis saat download game/file** agar tidak terkena jebakan link iklan/malware.

---

## 1. Cara Update dari Versi Lama (`1.x`) ke `v2.2.0`

Jika kamu sebelumnya sudah pernah `git clone` repo ini:

1. Pastikan aplikasi `CrackSentinel.exe` / `scanner.exe` yang lama sedang **ditutup**.
2. Buka **File Explorer**, lalu masuk ke dalam folder `cracksentinel` kamu.
3. Klik kanan di ruang kosong dalam folder tersebut -> pilih **Open in Terminal** *(atau klik kotak alamat/address bar di atas Explorer, ketik `powershell`, lalu tekan **Enter**)*.
4. Jalankan perintah berikut secara berurutan:

```powershell
git pull origin main --tags
.\setup.bat
```

> **Catatan jika muncul pesan error `conflict` / perubahan lokal saat `git pull`:**  
> Jalankan perintah ini terlebih dahulu, baru lanjutkan `.\setup.bat`:
> ```powershell
> git fetch --all --tags
> git reset --hard origin/main
> .\setup.bat
> ```

### Alternatif: Install Baru 1-Klik (Tanpa Git / Tanpa Go)
Jika ingin langsung install bersih di PC mana pun tanpa mengurus `git`, cukup buka **PowerShell** dan jalankan 1 baris ini:

```powershell
irm https://raw.githubusercontent.com/iAm-182/cracksentinel/main/install.ps1 | iex
```

**Apa yang otomatis dilakukan oleh `setup.bat` / `install.ps1`?**
- Memasang **7-Zip** dan **YARA portable (`tools\yara64.exe`)** jika belum ada di PC.
- Meng-update / mem-build **`CrackSentinel.exe`** & **`scanner.exe`** ke versi terbaru (**`v2.2.0`**) lengkap dengan verifikasi **SHA-256**.
- Membuat **Shortcut `CrackSentinel`** di Desktop dan langsung membuka aplikasinya.
- **Untuk rilis berikutnya (`v2.3+` dst):** Kamu tidak perlu `git pull` lagi — cukup klik tombol **Update & Restart** yang otomatis muncul di dalam aplikasi!

---

## 2. Cek Dulu Apakah PC Sudah Terlanjur Terkena Malware (`Audit PC`)

Jika sebelumnya kamu sempat mendownload dan menjalankan file dari link mencurigakan:

1. Buka aplikasi **CrackSentinel** (dari shortcut Desktop).
2. Klik menu **Audit PC** di sidebar sebelah kiri.
3. Klik tombol **Mulai Audit PC Sekarang** *(100% aman & read-only, selesai dalam ~3 detik)*.
4. Perhatikan hasilnya:
   - **`SAFE` (Hijau):** Sistem aman, tidak ditemukan penyusupan persistensi maupun pembajakan Defender.
   - **`WARNING` / `CRITICAL` (Kuning / Merah):** Segera periksa tabel temuan! Malware download-an paling sering melakukan:
     - Menambahkan folder `C:\`, `%APPDATA%`, atau `%TEMP%` ke **`ExclusionPath` Windows Defender** agar virusnya kebal dari scan antivirus.
     - Mematikan **Real-Time Protection** Windows Defender.
     - Menanam script `powershell` / `mshta` / `.vbs` di **Registry `Run`/`RunOnce`**, **Folder Startup**, atau **Scheduled Tasks**.
     - Memblokir domain antivirus / VirusTotal di dalam file `C:\Windows\System32\drivers\etc\hosts`.

---

## 3. Cara Mengaktifkan Cegatan Otomatis Saat Download

Agar setiap kali mendownload game/archive yang ditempeli malware langsung tertangkap **sebelum sempat dibuka**, aktifkan 2 lapis proteksi berikut:

### Lapis A — Real-Time Download Guard (Wajib Aktif!)
Berfungsi untuk **semua** metode download: Chrome, Edge, Brave, Firefox, **IDM (Internet Download Manager)**, **FDM**, maupun **qBittorrent**.

1. Buka menu **Download Guard** di sidebar kiri:
   - Pastikan lokasi folder mengarah ke folder `Downloads` kamu *(bisa klik **Pilih Folder** jika memakai folder download lain)*.
   - Centang **Notifikasi Windows Desktop Toast**.
   - Centang **Auto-Karantina file MALICIOUS (skor >= 70)**.
   - Klik **Aktifkan Download Guard**.
2. Buka menu **Pengaturan** di sidebar kiri:
   - Centang **Auto-Aktifkan Download Guard Saat Aplikasi Dibuka**.
   - Di bagian bawah (**Pemeliharaan & Integrasi Windows Explorer**), aktifkan 2 saklar ini:
     - **Menu Klik-Kanan Windows Explorer ("Scan with CrackSentinel")** — supaya kamu bisa klik kanan folder game/file apa saja di Explorer untuk langsung scan.
     - **Background Download Guard Otomatis Saat Login Windows** — supaya `CrackSentinel.exe --background` otomatis berjaga di latar belakang setiap PC dinyalakan tanpa memunculkan jendela.
   - Klik **Simpan Pengaturan** di kanan atas.

**Cara Kerja Saat Ada Download Masuk:**
- CrackSentinel otomatis mengabaikan file yang masih setengah jalan (`.crdownload`, `.part`, `.!qB`, `.tmp`).
- Detik download selesai 100%, CrackSentinel langsung membaca asal website pengirimnya (**Mark-of-the-Web**), **membongkar isi `.zip/.rar/.7z/.iso/.asar` & `setup.exe`**, dan jika terdeteksi **`MALICIOUS`**, file tersebut **langsung dipindahkan otomatis ke Quarantine Vault** + memunculkan peringatan Windows sebelum kamu sempat mengkliknya!

---

### Lapis B — Ekstensi Browser CrackSentinel (Cegat Link Sejak Detik Pertama Klik)
Berfungsi di **Google Chrome, Microsoft Edge, Brave, Opera, Vivaldi** untuk mencegat link download palsu/berbahaya **bahkan sebelum download selesai**:

1. Buka browser kamu, ketik di address bar:
   - Chrome: `chrome://extensions`
   - Edge: `edge://extensions`
   - Brave: `brave://extensions`
2. Aktifkan saklar **Developer mode** (Mode Pengembang) di pojok kanan atas.
3. Klik tombol **Load unpacked** (Muat yang belum dikemas) di pojok kiri atas.
4. Arahkan dan pilih folder **`extension`** yang berada di dalam folder instalasi `cracksentinel` kamu -> klik **Select Folder**.

**Cara Kerja Ekstensi:**
- Saat kamu mengklik link download di situs game, ekstensi langsung memeriksa reputasi URL, rantai redirect (`redirect chain`), ukuran file palsu (misal klaim game besar tapi ternyata `.zip` 15 MB berisi stealer), dan ekstensi ganda (`.pdf.exe`).
- Jika link terdeteksi **`MALICIOUS`**, ekstensi **otomatis menghentikan sementara (`Auto-Pause`) download tersebut** dan memunculkan notifikasi bahaya!
- Begitu file yang aman selesai terunduh, ekstensi otomatis memerintahkan CrackSentinel lokal untuk memindai isi filenya.

---

## 4. Cara Membaca Hasil Scan: Mana Crack Aman vs Virus Asli?

Crack game bajakan (`steam_api64.dll`, `emp.dll`, trainer) sering membuat antivirus biasa salah deteksi (*false positive*). Di CrackSentinel, hasil scan sudah dilengkapi **Kesimpulan Bahasa Indonesia**:

### Tanda Game / Crack AMAN (`CLEAN` atau `Cenderung Aman — Teknis Crack`)
- Hanya muncul label biru **`Teknis Crack` / `Teknis Installer`**, misalnya:
  - `emu_steamapi` / `crack_whitelist` (Emulator Goldberg, TENOKE, RUNE, FLT, SmartSteamEmu).
  - `imp_injection` / `imp_keylogger` / `packed` **tanpa** disertai koneksi pencuri data.
  - `known_runtime_dll` (File resmi seperti `QuickSFV.exe`, `unins000.exe`, `UnityPlayer.dll`, `vcruntime140.dll`).

### Tanda BAHAYA / VIRUS ASLI (`MALICIOUS` — JANGAN DIJALANKAN!)
Segera klik **Karantina** atau hapus jika muncul label merah **`BAHAYA`**:
- **Pencuri Password, Cookie, & Wallet:** `stealer_app_bound_enc`, `stealer_wallet_session`, `malware_family_ioc` (LummaC2, StealC, Rhadamanthys, Vidar, RedLine, AsyncRAT, XWorm), `lsass_cred_dump`, `crypto_clipper_ioc`.
- **Koneksi C2 Pelaku:** `discord_webhook`, `telegram_token`, `live_gofile_pixeldrain_c2_exfil`.
- **Teknik Sembunyi & Pembajak Sistem:** `dll_sideload_proxy` (*White+Black* DLL palsu), `direct_syscall_stubs` / `ntdll_unhook_evasion`, `peb_ldr_shellcode`, `defense_uac_evasion` (mematikan Windows Defender).
- **Installer / Mod / Game Palsu:** `decoy_renpy_dropper` (folder game jebakan), `installer_malicious_script` (setup NSIS/Inno beracun), `gamemod_trojan_plugin` (mod `BepInEx`/`MelonLoader`/`.asi` bervirus), `masquerading_pe` (file `.png`/`.dat` yang aslinya `.exe`).

> **Tips Ragu-Ragu (`SUSPICIOUS`):**  
> Jika ada file kuning (`SUSPICIOUS`) dan kamu masih ragu, klik tombol **Sandbox** di sebelah kanan baris file tersebut! CrackSentinel akan membukanya di dalam **Windows Sandbox terisolasi** (tanpa internet & folder host dikunci *Read-Only*) sehingga PC aslimu 100% aman.

---

## 5. Pemeliharaan Rutin (1 Klik)
- **Update Database Virus:** Buka **Pengaturan -> Update Database Virus** untuk menarik daftar ribuan hash malware terbaru (sinkron otomatis tiap 6 jam di GitHub, selesai `<0.5 detik` tanpa restart).
- **Cek Link Sebelum Download Manual:** Bisa juga tempel link download ke menu **Cek Link URL** di aplikasi atau akses versi web 24/7 di **`https://sentinel.breakthematrix.id`**.
