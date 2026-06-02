# Phantom-Net API Dokumantasyonu

Bu dokuman Phantom-Net admin dashboard API'lerini, raporlama endpointlerini, AI endpointlerini, incident akisini ve SIEM durum endpointini aciklar.

## Genel Bilgiler

Base URL:

```text
http://127.0.0.1:8080
```

Dashboard API'leri login session gerektirir. Tarayicidan giris yaptiktan sonra ayni session cookie ile API'ler calisir.

Varsayilan admin bilgileri:

```text
Kullanici: admin
Sifre: phantom-admin
```

Giris:

```http
GET /login
POST /login
Content-Type: application/x-www-form-urlencoded

username=admin&password=phantom-admin&csrf_token=<login-sayfasindan-gelen-token>
```

Cikis:

```http
GET /logout
```

## Dashboard Olay API'leri

### Sistem istatistikleri

```http
GET /api/stats
```

Ornek cevap:

```json
{
  "total_events": 120,
  "unique_sources": 8,
  "high_risk_events": 21,
  "redirected_sessions": 44,
  "top_ips": [
    {"source_ip": "10.0.0.9", "count": 18, "max_risk": 90}
  ],
  "top_tags": [
    {"tags": "sensitive_path", "count": 16}
  ]
}
```

### Olay listesi

```http
GET /api/events?limit=150&source_ip=10.0.0.9&decision=redirect_to_decoy&min_risk=70
```

Query parametreleri:

| Parametre | Aciklama |
| --- | --- |
| `limit` | 1-500 arasi kayit sayisi |
| `source_ip` | Belirli IP icin filtre |
| `decision` | `observe` veya `redirect_to_decoy` |
| `min_risk` | Minimum risk skoru |

### IP detay

```http
GET /api/sources/{source_ip}
```

Cevap IP ozeti, servis dagilimi, detection tagleri, MITRE teknikleri ve olay timeline'i icerir.

## Raporlama API'leri

### Gunluk/haftalik ozet

```http
GET /api/reports/summary?period=daily&limit=14
GET /api/reports/summary?period=weekly&limit=14
```

Cevap alanlari:

| Alan | Aciklama |
| --- | --- |
| `buckets` | Gunluk/haftalik toplamlar |
| `risky_ips` | En riskli IP'ler |
| `attack_types` | Detection tag bazli saldiri turleri |
| `mitre_techniques` | ATT&CK eslesmeleri |
| `event_types` | Event type dagilimi |

### Export

```http
GET /api/reports/export?format=json&limit=100
GET /api/reports/export?format=csv&limit=100
```

Desteklenen formatlar:

```text
json
csv
```

Filtreler `/api/events` ile aynidir: `source_ip`, `decision`, `min_risk`, `limit`.

## AI Analyst API'leri

### Dogal dil ozet

```http
GET /api/ai/summary?limit=150
```

### Sahte veri uretimi

```http
GET /api/ai/decoy-data?limit=150
```

### AI raporu kaydetme

```http
GET /api/ai/report?limit=150
```

### Kayitli AI raporlari

```http
GET /api/ai/reports?limit=20
```

AI local modda kural tabanli calisir. `PHANTOM_AI_PROVIDER=openai` ve `OPENAI_API_KEY` verildiginde gercek modele baglanir.

## Incident API'leri

### Incident listesi

```http
GET /api/incidents?limit=50&status=open
```

### Incident olusturma

```http
POST /api/incidents/create
Content-Type: application/x-www-form-urlencoded

source_ip=10.0.0.9&severity=high&title=Suspicious%20activity&analyst_note=Initial%20triage
```

### Incident guncelleme

```http
POST /api/incidents/update
Content-Type: application/x-www-form-urlencoded

id=1&status=resolved&severity=medium&analyst_note=Contained
```

Durumlar:

```text
open
resolved
```

## SIEM / Log API

### SIEM durum

```http
GET /api/siem/status
```

Ornek cevap:

```json
{
  "enabled": true,
  "formats": ["jsonl", "cef", "syslog"],
  "targets": {
    "jsonl": "/path/to/data/siem_events.jsonl",
    "cef": "/path/to/data/siem_cef.log",
    "syslog": "/path/to/data/siem_syslog.log"
  }
}
```

## Admin Audit API

```http
GET /api/admin/audit?limit=100
```

Login, logout, AI report kaydi ve incident islemleri burada gorulur.

## Gateway ve Reverse Proxy

Gateway base URL:

```text
http://127.0.0.1:8082
```

Temiz trafik icin backend baglamak:

```sh
python3 main.py --backend-url http://127.0.0.1:9000
```

Veya config:

```yaml
gateway:
  backend_url: "http://127.0.0.1:9000"
```

Gateway su metotlari destekler:

```text
GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS
```

Dusuk riskli istekler backend'e aktarilir. Supheli istekler decoy ortama yonlendirilir:

```http
HTTP/1.1 302 Found
Location: http://127.0.0.1:8081/admin
X-Phantom-Net-Decision: redirect_to_decoy
```

POST/PUT/PATCH gibi body tasiyan metotlarda decoy yonlendirmesi `307 Temporary Redirect` ile yapilir.

Proxy davranisi:

- `X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host` headerlari eklenir.
- Hop-by-hop headerlar backend'e aktarilmaz.
- Backend 3xx cevaplari gateway icinde takip edilmez; istemciye aynen dondurulur.
- Backend cevaplarina `X-Phantom-Net-Decision: observe` eklenir.
- Buyuk request body'leri 1 MB ile sinirlanir.
