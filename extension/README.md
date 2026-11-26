# CrackSentinel Download Guard — Browser Extension (Chrome / Edge / Brave)

Ekstensi ini menghubungkan browser ke server lokal **CrackSentinel** (`http://127.0.0.1:8787`) untuk melindungi saat kamu download game dari website:

1. **Pre-check URL real-time** saat download baru dimulai (deteksi domain decoy numerik/random, double-extension `.pdf.exe`, host dropper Discord/Pastebin, ukuran repack palsu) + opsi **auto-pause** otomatis jika terdeteksi `MALICIOUS`.
2. **Auto-scan file & isi archive (`.zip/.rar/.7z/.iso/.msi`)** begitu download selesai, lalu tampilkan notifikasi desktop dengan skor & temuan teratas.

## Cara Pasang (3 Langkah)

1. Jalankan `CrackSentinel-UI.bat` di folder `E:\ilham_yarsi\tools-virus`.
2. Buka `chrome://extensions` (atau `edge://extensions`), aktifkan **Developer mode** di pojok kanan atas.
3. Klik **Load unpacked** → pilih folder `E:\ilham_yarsi\tools-virus\extension`.
