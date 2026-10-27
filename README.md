\# 🍯 SSH Honeypot — Analisis Serangan Dunia Nyata dengan Cowrie



Men-deploy honeypot SSH (Cowrie) di VPS publik, membiarkannya menangkap serangan nyata dari internet, lalu menganalisis telemetri yang terkumpul: statistik serangan, enrichment IP (GeoIP + reputasi AbuseIPDB), dan pemetaan perilaku penyerang ke framework \*\*MITRE ATT\&CK\*\*.



Proyek ini mensimulasikan alur kerja seorang \*\*SOC Analyst\*\*: dari mengumpulkan log, memperkaya data, mengidentifikasi ancaman, sampai menuliskannya menjadi temuan yang bisa ditindaklanjuti.



\---



\## 📌 Ringkasan



| | |

|---|---|

| \*\*Sensor\*\* | Cowrie SSH Honeypot (low-interaction) |

| \*\*Platform\*\* | VPS publik (Ubuntu 22.04), region Singapura |

| \*\*Durasi pengamatan\*\* | \~11 jam (sampel awal) |

| \*\*Total event terekam\*\* | \*\*3.355\*\* |

| \*\*IP penyerang unik\*\* | \*\*27\*\* (dari \~13 negara) |

| \*\*Botnet teridentifikasi\*\* | Outlaw/Dota, XSec scanner |



\---



\## 🏗️ Arsitektur



```

Internet (penyerang/bot)

&#x20;       │  ketuk port 22

&#x20;       ▼

┌─────────────────────────────────────┐

│  VPS Publik (Ubuntu 22.04)          │

│                                     │

│   iptables: 22 ──redirect──► 2222   │

│                                │    │

│                          ┌─────▼─────┐

│                          │  Cowrie   │ ← merekam semua aktivitas

│                          └───────────┘

│                                     │

│   port 2200 ──► SSH admin (aman)    │

└─────────────────────────────────────┘

```



\*\*Prinsip desain utama — pemisahan jalur:\*\*

\- \*\*Port 22\*\* → umpan, dibelokkan ke Cowrie. Semua serangan masuk ke sini.

\- \*\*Port 2200\*\* → SSH admin asli, autentikasi berbasis SSH key. Penyerang tidak pernah menyentuh sistem sebenarnya.

\- Cowrie berjalan sebagai user non-root (\*least privilege\*).



\---



\## 🛠️ Teknologi



\- \*\*Cowrie\*\* — SSH/Telnet honeypot

\- \*\*Linux\*\* (Ubuntu), `iptables` (NAT redirect), `ufw`, `systemd` (auto-start, tahan reboot)

\- \*\*Python\*\* (`pandas`, `matplotlib`, `requests`) — pipeline analisis \& visualisasi

\- \*\*GeoIP\*\* (ip-api.com) \& \*\*AbuseIPDB\*\* — threat intelligence / enrichment

\- \*\*MITRE ATT\&CK\*\* — framework klasifikasi perilaku penyerang



\---



\## 🔧 Ringkasan Setup



1\. \*\*Hardening\*\* — SSH admin dipindah ke port non-standar (2200), autentikasi SSH key, firewall `ufw`.

2\. \*\*Deploy Cowrie\*\* — virtualenv Python, user non-root khusus, listen di port 2222.

3\. \*\*Redirect\*\* — `iptables` membelokkan port 22 → 2222 agar honeypot tampak seperti SSH sungguhan.

4\. \*\*Persistence\*\* — Cowrie dijadikan `systemd service`; rule `iptables` disimpan via `iptables-persistent` agar tahan reboot.

5\. \*\*Validasi\*\* — uji serangan terkontrol, konfirmasi event terekam di log JSON.



> Catatan keamanan: IP server disamarkan di dokumentasi ini. Honeypot diisolasi dari jaringan pribadi (VPS terpisah).



\---



\## 📊 Temuan



\### 1. Volume \& konsentrasi serangan

Dua IP mendominasi \~88% dari seluruh trafik — pola khas bot brute-force yang gigih, bukan serangan tersebar merata.



!\[Top IP Penyerang](01\_top\_ip.png)



\### 2. Kredensial yang dicoba

Bot menyasar username/password default dan lemah (mayoritas `root` + password umum) — bukti pentingnya kebijakan kredensial kuat.



!\[Top Password](02\_top\_password.png)

!\[Top Username](03\_top\_username.png)



\### 3. Asal geografis \& infrastruktur

Serangan datang dari \~13 negara. \*\*Temuan kunci:\*\* hampir semua IP milik penyedia \*\*hosting/cloud\*\* (bukan ISP residensial) — penyerang menggunakan server sewaan/terkompromi, bukan komputer pribadi.



!\[Serangan per Negara](06\_attacks\_by\_country.png)



\### 4. Reputasi IP (AbuseIPDB)

\*\*25 dari 27 IP\*\* memiliki abuse confidence score \*\*100/100\*\* — dikonfirmasi jahat oleh komunitas keamanan global. Beberapa sudah dilaporkan \*\*puluhan ribu kali\*\* (satu IP: 42.000+ laporan). Honeypot menangkap \*known bad actors\*, bukan trafik acak.



!\[Skor Reputasi AbuseIPDB](07\_abuse\_scores.png)



\### 5. Perilaku penyerang (MITRE ATT\&CK)

Perintah yang dijalankan penyerang dipetakan ke teknik MITRE ATT\&CK:



!\[MITRE ATT\&CK](08\_mitre\_attack.png)



| Taktik | Teknik (ID) | Bukti di honeypot |

|---|---|---|

| Credential Access | \*\*T1110\*\* Brute Force | Ribuan percobaan login dari 27 IP |

| Initial Access | \*\*T1078\*\* Valid Accounts | Login sebagai `root` dengan kredensial tebakan |

| Persistence | \*\*T1098.004\*\* SSH Authorized Keys | Menanam kunci SSH penyerang ke `authorized\_keys` |

| Defense Evasion | \*\*T1222.002\*\* Linux File Permissions | `chattr -ia` / `chmod -R go=` mengunci key |

| Defense Evasion | \*\*T1070.004\*\* File Deletion | `rm -rf .ssh`, hapus skrip jejak |

| Discovery | \*\*T1082\*\* System Info Discovery | `uname -a`, verifikasi shell (`$$`, aritmetika) |

| Execution | \*\*T1059.004\*\* Unix Shell | `sh -c '...'` |

| Ingress Tool Transfer | \*\*T1105\*\* | Upaya unduh \& jalankan `setup.sh` / `clean.sh` |



\### 6. Identifikasi botnet

\- \*\*Outlaw / Dota botnet\*\* — signature `mdrfckr` pada payload penanaman SSH key. Kampanye cryptomining SSH yang terdokumentasi. Pola: hapus `authorized\_keys` korban → tanam kunci penyerang → kunci file dengan `chattr`.

\- \*\*XSec scanner\*\* — ratusan `echo xsec` berulang, penanda alat pemindai otomatis.



\### 7. Observasi menarik

Beberapa bot menjalankan tes verifikasi shell (evaluasi aritmetika `$((a\*b+c))`, PID `$$`) sebelum mengirim payload — teknik untuk mendeteksi sandbox/honeypot. Karena Cowrie tidak mengevaluasi aritmetika tersebut, sebagian bot kemungkinan mengenali lingkungan sebagai honeypot dan berhenti. Ini menegaskan pentingnya realisme honeypot.



\---



\## 💡 Lessons Learned



\- Server dengan IP publik mulai diserang dalam \*\*hitungan menit\*\* setelah online — ancaman latar belakang internet bersifat konstan dan otomatis.

\- Mayoritas serangan berasal dari \*\*infrastruktur cloud/hosting\*\*, bukan perangkat residensial.

\- \*\*Enrichment\*\* (GeoIP + reputasi) mengubah IP anonim menjadi intelijen yang dapat ditindaklanjuti — inti pekerjaan SOC.

\- Pemisahan jalur admin/umpan dan prinsip \*least privilege\* krusial untuk men-deploy honeypot dengan aman.



\---



\## 📁 Struktur Repo



```

.

├── README.md

├── analyze.py          # statistik serangan → grafik 1-5

├── geoip.py            # enrichment GeoIP → grafik 6 + CSV

├── abuseipdb.py        # enrichment reputasi → grafik 7 + CSV

├── mitre.py            # pemetaan MITRE ATT\&CK → grafik 8

├── 01\_top\_ip.png ... 08\_mitre\_attack.png

└── .gitignore          # menutup apikey.txt \& log mentah

```



> `cowrie.json` (log mentah) dan `apikey.txt` sengaja \*\*tidak\*\* di-commit (lihat `.gitignore`) — praktik keamanan dasar untuk tidak mengekspos data sensitif/kredensial.



\---



\## 🚀 Pengembangan Lanjutan



\- Perpanjang pengumpulan data (mingguan) untuk tren yang lebih kaya.

\- Forward log Cowrie ke \*\*Wazuh SIEM\*\* untuk korelasi \& dashboard real-time.

\- Analisis sampel malware yang diunduh penyerang di lingkungan terisolasi.

