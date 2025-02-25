# 🛡️ Email Security Analyzer

## 📝 Gambaran Umum

Email Security Analyzer adalah alat komprehensif yang dirancang untuk menganalisis header email dan lampiran untuk ancaman keamanan. Alat ini melakukan beberapa pemeriksaan termasuk validasi SPF, DKIM, DMARC, pemeriksaan RBL (Realtime Blackhole List), pencarian WHOIS, deteksi kata kunci scam menggunakan NLP, dan analisis URL serta lampiran menggunakan VirusTotal. Hasil analisis dirangkum dalam laporan PDF yang rinci.

## ✨ Fitur

- **🔐 Validasi SPF, DKIM, dan DMARC**: Memverifikasi metode otentikasi pengirim email untuk mencegah pemalsuan email.
- **🛑 Pemeriksaan RBL**: Memeriksa apakah IP domain masuk dalam daftar hitam RBL umum.
- **🌐 Pencarian WHOIS**: Mendapatkan tanggal pembuatan domain untuk membantu mengidentifikasi domain baru yang sering digunakan dalam scam.
- **🕵️‍♂️ Deteksi Kata Kunci Scam**: Menggunakan pencocokan kata kunci sederhana dan model NLP untuk mendeteksi upaya phishing potensial.
- **🔍 Analisis URL dengan VirusTotal**: Mengirimkan URL ke VirusTotal untuk pemindaian dan mengambil hasilnya.
- **📎 Analisis Lampiran**: Memeriksa lampiran email untuk malware menggunakan VirusTotal.
- **📄 Pembuatan Laporan PDF**: Menghasilkan laporan rinci dengan semua temuan.

## ⚙️ Instalasi

### Prasyarat

- Python 3.7 atau lebih tinggi
- Pip (pengelola paket Python)

### Instal Paket yang Diperlukan

```sh
pip install requests dnspython aiohttp whois fpdf transformers
```

### Clone Repository

```sh
git clone https://github.com/yourusername/email-security-analyzer.git
cd email-security-analyzer
```

## 🚀 Penggunaan

### Command Line Interface (CLI)

Untuk menganalisis header email atau file `.eml`, jalankan skrip dengan argumen berikut:

```sh
python email_security_analyzer.py --email "your_email_header_or_path_to_eml" --verbose
```

- `--email`: Header email sebagai string atau path ke file `.eml`.
- `--verbose`: Mengaktifkan mode verbose untuk output yang lebih rinci.

### Contoh

```sh
python email_security_analyzer.py --email "your_email_header_or_path_to_eml" --verbose
```

## 🖨️ Output

Skrip ini menghasilkan laporan PDF rinci bernama `email_security_report.pdf` di direktori saat ini. Jika mode verbose diaktifkan, hasil analisis rinci akan dicetak ke konsol.

## 📋 Penjelasan Rinci Fitur

### Validasi SPF, DKIM, dan DMARC

- **SPF (Sender Policy Framework)**: Memeriksa apakah email dikirim dari server yang diotorisasi.
- **DKIM (DomainKeys Identified Mail)**: Memverifikasi integritas email dan memastikan tidak ada perubahan.
- **DMARC (Domain-based Message Authentication, Reporting & Conformance)**: Memastikan bahwa pemeriksaan SPF dan DKIM telah dilakukan.

### Pemeriksaan RBL

- Memeriksa apakah alamat IP domain terdaftar dalam RBL umum seperti Spamhaus dan SpamCop.

### Pencarian WHOIS

- Mendapatkan detail pendaftaran domain, termasuk tanggal pembuatan, untuk membantu mengidentifikasi domain yang mencurigakan.

### Deteksi Kata Kunci Scam

- **Pencocokan Sederhana**: Mencari kata kunci scam umum dalam header email.
- **Model NLP**: Menggunakan model klasifikasi zero-shot untuk mendeteksi upaya phishing.

### Analisis URL dengan VirusTotal

- Mengirimkan URL ke VirusTotal untuk pemindaian dan mengambil hasilnya, menunjukkan apakah URL aman atau mencurigakan.

### Analisis Lampiran

- Mengirimkan lampiran email ke VirusTotal untuk pemindaian malware dan mengambil hasilnya.

## 👥 Kontribusi

Kami menyambut kontribusi untuk Email Security Analyzer! Jika Anda memiliki saran, laporan bug, atau permintaan fitur, silakan buka issue atau kirim pull request.

## 📧 Kontak

Untuk pertanyaan atau pertanyaan, silakan hubungi [dekurity@gmail.com].

---

## ❤️ Kontributor

Terima kasih kepada semua kontributor yang telah membantu dalam pengembangan proyek ini! ❤️

| Nama Kontributor | Peran             |
|------------------|-------------------|
| Dekurity          | Pengembang Utama  |
