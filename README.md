# Phantom-Net

Phantom-Net, saldirgani gercek sistemden uzak tutup sahte bir ortama ceken savunma odakli bir honeypot ve analiz platformudur. Bu ilk surum yerel gelistirme icin guvenli bir MVP'dir: gelen istekleri kaydeder, risk skoru uretir, supheli davranisi sahte servislere yonlendirilmis kabul eder ve dashboard'da gosterir.

## Amac

Phantom-Net'in amaci, supheli kullanici veya otomasyonlarin gercek sisteme ulasmadan once davranislarini anlamak, kaydetmek ve kontrollu bir sahte ortamda oyalamaktir. Sistem bir savunma katmani gibi dusunulur:

- Gelen trafik izlenir.
- Riskli davranislar kural motoruyla skorlanir.
- Temiz trafik gateway tarafinda normal akista kalir.
- Supheli trafik decoy/honeypot ortamina yonlendirilir.
- Saldirganin denedigi path, login, servis yoklama, fake dosya ve fake veri erisimleri kaydedilir.
- Admin panelde olaylar, raporlar, AI ozetleri ve audit log takip edilir.

Bu proje saldiri yapmak icin degil; savunma, farkindalik, laboratuvar calismasi ve guvenlik analizi icin tasarlanmistir.

## Nerelerde Kullanilir

- Siber guvenlik laboratuvarlari ve egitim ortamlarinda saldirgan davranisi gozlemlemek.
- Web uygulamasi onunde supheli istekleri decoy ortama tasiyan deneysel gateway olarak.
- Blue team / SOC pratiklerinde olay toplama, raporlama ve analiz akisini gostermek.
- Honeypot, deception technology ve dinamik savunma mimarilerini prototiplemek.
- Admin panel, raporlama, alarm ve AI ozetleme gibi guvenlik urunu bilesenlerini gosteren bitirme/proje calismalarinda.
- Gercek sistemlere zarar vermeden fake admin panel, fake backup, fake terminal, fake FTP ve fake veritabani tepkileriyle saldirganin niyetini analiz etmek.

## Ne Degildir

- Tek basina uretim ortami WAF, IDS veya EDR degildir.
- Izinsiz aglarda kullanilacak bir saldiri araci degildir.
- Gercek firewall/NAT kurallarini otomatik degistirmez.
- Gercek kimlik bilgisi, gercek musteri verisi veya canli secret icermemelidir.

## Genel Mimari

```text
Client / Attacker
        |
        v
   Gateway :8082
   | temiz trafik
   v
Real backend opsiyonel

   | supheli trafik
   v
Honeypot / Decoy :8081
        |
        v
SQLite event store + migrations
        |
        v
Dashboard :8080
```

Ana bilesenler:

- **Gateway:** Gelen istegi kural motoruna sokar. Risk dusukse placeholder veya opsiyonel backend'e yollar; risk yuksekse decoy ortama yonlendirir.
- **Rule Engine:** `config.yaml` icindeki kurallarla risk skoru ve etiket uretir.
- **Honeypot:** Fake admin panel, fake dosyalar, fake DB, fake backup, fake FTP ve fake terminal cevaplari verir.
- **Event Store:** Olaylari SQLite'a kaydeder, migration sistemiyle semayi yonetir.
- **Dashboard:** Olaylari, IP detayini, raporlari, AI ozetlerini ve admin audit loglarini gosterir.
- **AI Analyst:** Son olaylari dogal dille ozetler ve davranisa gore sahte veri onerileri uretir.
- **Alerts:** Yuksek riskli olaylari JSONL dosyasina yazar, istenirse webhook'a gonderir.
- **SIEM Export:** Olaylari JSONL, CEF ve syslog benzeri log formatlarina aktarir.
- **MITRE ATT&CK:** Detection taglerini ATT&CK teknikleriyle esler.
- **Incident Management:** Supheli IP uzerinden incident olusturur, durumunu takip eder ve analyst notu saklar.

API referansi icin: [docs/API.md](docs/API.md)
Dagitim rehberi icin: [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)

## Ozellikler

- Web honeypot: sahte admin paneli, login formu, robots.txt, fake API ve fake secret endpointleri.
- Zengin decoy ortam: sahte dosya listeleri, veritabani tablolari, admin kullanicilari, backup manifestleri ve oyalayici export/restore cevaplari.
- Gateway: dusuk riskli istekleri korunan uygulamada tutar, supheli istekleri decoy ortama yonlendirir.
- Reverse proxy: temiz trafigi gercek backend'e aktarirken `X-Forwarded-*` headerlari, backend redirectleri, HEAD/PUT/PATCH/DELETE/OPTIONS metotlari ve hop-by-hop header temizligiyle daha gercekci proxy davranisi sunar.
- TCP decoy servisleri: SSH, MySQL ve PostgreSQL benzeri banner veren izole dinleyiciler.
- Davranis tespiti: port tarama, hizli istek, hassas path arama ve brute-force denemesi icin risk skoru.
- IP oturum hafizasi: ayni IP'nin kisa sureli istek ritmi, gezdigi pathler, yokladigi servisler ve onceki risk seviyesi karar motorunda kullanilir.
- Olay kaydi: SQLite veritabani ile kalici event log.
- Dashboard: toplam olay, supheli IP, yuksek riskli olaylar, yonlendirme kararlari ve son olaylar.
- Raporlama: gunluk/haftalik saldiri ozeti, en riskli IP'ler, saldiri turleri, JSON/CSV export.
- AI Analyst: son olaylari dogal dille ozetler, aksiyon onerir ve davranisa gore sahte veri paketi uretir.
- Admin login: dashboard varsayilan olarak kullanici/sifre ile korunur.
- Reverse proxy modu: temiz gateway trafigi opsiyonel gercek backend'e aktarilir.
- Alarm sistemi: riskli olaylari JSONL dosyasina yazar, opsiyonel webhook gonderebilir.
- SIEM/log entegrasyonu: JSONL, CEF ve syslog dosyalarina SOC/SIEM uyumlu olay ciktisi.
- Docker: `docker compose up --build` ile tek komut kurulum.
- MITRE ATT&CK etiketleme: brute-force, service discovery, path discovery gibi sinyalleri ATT&CK teknikleriyle esler.
- Incident yonetimi: IP bazli incident olusturma, open/resolved durumu, severity ve analyst note.

## Calistirma

```sh
cd phantom-net
python3 main.py
```

Varsayilan ayarlar `config.yaml` dosyasindan okunur. Farkli bir dosya kullanmak icin:

```sh
python3 main.py --config config.lab.yaml
```

Ayar onceligi:

```text
kod varsayilanlari < config.yaml < ortam degiskenleri < CLI argumanlari
```

Admin girisi:

```text
http://127.0.0.1:8080/login
Kullanici: admin
Sifre: phantom-admin
```

Guvenli admin panel ozellikleri:

- PBKDF2-SHA256 password hash destegi
- CSRF token kontrolu
- IP bazli login brute-force limiti
- Session expiry
- Logout
- Admin audit log

Password hash uretme:

```sh
python3 hash_password.py
```

Urettiginiz hash'i `config.yaml` icinde kullanabilirsiniz:

```yaml
auth:
  username: admin
  password: ""
  password_hash: "pbkdf2_sha256$..."
```

Ortam degiskenleriyle degistirme:

```sh
export PHANTOM_ADMIN_USER="admin"
export PHANTOM_ADMIN_PASSWORD="guclu-bir-sifre"
export PHANTOM_ADMIN_PASSWORD_HASH="pbkdf2_sha256$..."
export PHANTOM_AUTH_SECRET="uzun-rastgele-bir-secret"
```

Config dogrulama:

```sh
python3 main.py --check-config
python3 main.py --check-config --strict-config
```

Health endpointleri:

```sh
curl http://127.0.0.1:8080/healthz
curl http://127.0.0.1:8080/readyz
```

Port ve profil degiskenleri:

```sh
export PHANTOM_PROFILE="lab"
export PHANTOM_HOST="127.0.0.1"
export PHANTOM_DASHBOARD_PORT="8090"
export PHANTOM_GATEWAY_PORT="8092"
export PHANTOM_HONEYPOT_PORT="8091"
export PHANTOM_NO_TCP_DECOYS="true"
```

Kural motoru `config.yaml` icindeki `rules` listesinden calisir. Ornek:

```yaml
rules:
  - name: sensitive_path
    condition: haystack_contains:suspicious_path_hints
    tag: sensitive_path
    score: 30
    enabled: true
```

Desteklenen kosullar:

```text
service_not_trusted
unique_probe_services_gte:<sayi veya threshold_adi>
recent_burst_gte:<sayi veya threshold_adi>
recent_hits_gte:<sayi>
unique_paths_gte:<sayi veya threshold_adi>
session_max_risk_gte:<sayi veya threshold_adi>
event_type_equals:<event_type>
haystack_contains:<fact_listesi>
payload_contains:<fact_listesi>
decoy_locked
```

Dashboard:

```text
http://127.0.0.1:8080
```

Web honeypot:

```text
http://127.0.0.1:8081
```

Gateway:

```text
http://127.0.0.1:8082
```

TCP decoy portlari:

```text
2222 ssh
3306 mysql
5432 postgres
```

Port cakismasi varsa:

```sh
python3 main.py --dashboard-port 8090 --honeypot-port 8091 --no-tcp-decoys
```

Gercek backend proxy modu:

```sh
python3 main.py --backend-url http://127.0.0.1:9000 --no-tcp-decoys
```

Alarm webhook:

```sh
export PHANTOM_ALERT_WEBHOOK_URL="https://example.com/webhook"
```

Yuksek riskli olaylar ayrica `data/alerts.jsonl` dosyasina yazilir.

SIEM / log export:

```yaml
siem:
  enabled: true
  formats: jsonl,cef,syslog
  jsonl_path: data/siem_events.jsonl
  cef_path: data/siem_cef.log
  syslog_path: data/siem_syslog.log
```

Bu dosyalar her olay icin otomatik guncellenir:

```text
data/siem_events.jsonl   JSON Lines formatinda zengin olay kaydi
data/siem_cef.log        CEF benzeri SIEM uyumlu satirlar
data/siem_syslog.log     Syslog benzeri tek satir JSON mesajlari
```

Ortam degiskenleri:

```sh
export PHANTOM_SIEM_ENABLED=true
export PHANTOM_SIEM_FORMATS="jsonl,cef,syslog"
export PHANTOM_SIEM_JSONL_PATH="data/siem_events.jsonl"
export PHANTOM_SIEM_CEF_PATH="data/siem_cef.log"
export PHANTOM_SIEM_SYSLOG_PATH="data/siem_syslog.log"
```

Dashboard ana sayfasindaki SIEM Export paneli aktif formatlari ve hedef dosyalari gosterir.

## Test Etme

```sh
curl http://127.0.0.1:8081/admin
curl http://127.0.0.1:8081/.env
curl http://127.0.0.1:8081/files
curl http://127.0.0.1:8081/api/db/tables
curl 'http://127.0.0.1:8081/api/db/query?q=select%20*%20from%20api_keys%20limit%205'
curl http://127.0.0.1:8081/backup
curl http://127.0.0.1:8081/backup/daily-prod-2026-05-23.tar.gz
curl http://127.0.0.1:8081/ftp
curl 'http://127.0.0.1:8081/api/terminal/run?cmd=cat%20.env'
curl -X POST http://127.0.0.1:8081/login -d 'username=admin&password=123456'
curl -i http://127.0.0.1:8082/admin
```

Sonra dashboard'u yenileyin.

Gateway karar motorunu denemek icin:

```sh
for path in / /status /assets /health /old /pricing; do curl -i "http://127.0.0.1:8082$path"; done
```

Ilk istekler normal uygulamada kalir; kisa surede cok farkli path gezilince gateway decoy ortama yonlendirir.

Gercek backend'e reverse proxy yapmak icin:

```sh
python3 main.py --backend-url http://127.0.0.1:9000
```

Gateway temiz trafigi backend'e aktarir, supheli trafigi honeypot'a yonlendirir. Detayli endpoint ve proxy davranisi icin `docs/API.md` dosyasina bakin.

Demo trafigi uretmek icin:

```sh
python3 simulate_attack.py
```

Kod testleri:

```sh
python3 -m unittest discover -s tests
```

Rapor API'leri:

```sh
curl 'http://127.0.0.1:8080/api/reports/summary?period=daily'
curl 'http://127.0.0.1:8080/api/reports/summary?period=weekly'
curl 'http://127.0.0.1:8080/api/reports/export?format=json&limit=100'
curl 'http://127.0.0.1:8080/api/reports/export?format=csv&limit=100'
```

AI API'leri:

```sh
curl 'http://127.0.0.1:8080/api/ai/summary'
curl 'http://127.0.0.1:8080/api/ai/decoy-data'
curl 'http://127.0.0.1:8080/api/ai/report'
curl 'http://127.0.0.1:8080/api/ai/reports'
```

Gercek OpenAI modeli kullanmak icin:

```yaml
ai:
  provider: openai
  model: gpt-5.2
  api_key: ""
  timeout_seconds: 20
```

API anahtarini ortam degiskeniyle verin:

```sh
export OPENAI_API_KEY="sk-..."
export PHANTOM_AI_PROVIDER="openai"
export PHANTOM_OPENAI_MODEL="gpt-5.2"
python3 main.py
```

`OPENAI_API_KEY` yoksa AI Analyst otomatik olarak yerel rule-based ozete geri doner. Model cevaplari yalnizca JSON bekler; hatali/eksik API cevaplarinda panel calismaya devam eder.

Incident API'leri:

```sh
curl 'http://127.0.0.1:8080/api/incidents'
curl -X POST 'http://127.0.0.1:8080/api/incidents/create' -d 'source_ip=127.0.0.1&severity=high'
curl -X POST 'http://127.0.0.1:8080/api/incidents/update' -d 'id=1&status=resolved&analyst_note=contained'
```

Not: Dashboard API'leri login session gerektirir.

## Docker

```sh
cp .env.example .env
docker compose up --build
```

Container non-root kullanici ile calisir, `/healthz` healthcheck endpointini kullanir ve `./data` dizinini kalici volume olarak baglar. Production icin `config.production.example.yaml` dosyasini temel alip gercek secret ve password hash degerleriyle ayrica yayinlayin.

## Veritabani Migrasyonlari

Phantom-Net SQLite semasini versiyonlu migration dosyalariyla yonetir.

```text
phantom_net/migrations/
  001_initial_schema.sql
```

Uygulama acilirken uygulanmamis migration dosyalari otomatik calistirilir ve `schema_migrations` tablosuna kaydedilir. Yeni tablo veya kolon eklemek icin siradaki numarayla yeni SQL dosyasi olusturun:

```text
phantom_net/migrations/002_ornek_degisiklik.sql
```

Migration kurallari:

- Dosya adlari sirali ve kalici olmali.
- Uygulanmis migration dosyalari geriye donuk degistirilmemeli.
- Geriye uyumsuz degisiklikler yeni migration ile yapilmali.
- Testlerde `EventStore(...).migration_versions()` ile uygulanan versiyonlar kontrol edilebilir.

## Sonraki Asamalar

1. Gercek reverse-proxy entegrasyonu ve sadece supheli oturumlari decoy ortama tasima.
2. Daha zengin sahte servisler ve senaryo bazli honeytoken uretimi.
3. Alarm kanallari: e-posta, webhook, SIEM entegrasyonu.
4. Yapay zeka katmani: sahte veri uretimi, saldirgan davranisina gore dinamik cevaplar, otomatik olay ozetleri.

## Guvenlik Notu

Bu proje savunma, analiz ve egitim amaclidir. Ilk surum sistem firewall kurallarini degistirmez, gercek ag trafigini zorla yonlendirmez ve sadece sizin baslattiginiz yerel servislerde calisir.
