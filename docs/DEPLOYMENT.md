# Phantom-Net Dagitim Rehberi

Bu rehber Phantom-Net'i daha duzenli bir sekilde Docker Compose veya systemd ile calistirmak icin hazirlandi.

## Dagitim Oncesi Kontrol

Config dosyasini dogrulayin:

```sh
python3 main.py --check-config
python3 main.py --check-config --strict-config
```

Production icin varsayilan sifre ve varsayilan secret kullanmayin.

Password hash uretin:

```sh
python3 hash_password.py
```

Sonra `config.production.example.yaml` dosyasini kopyalayip gercek degerlerle duzenleyin:

```sh
cp config.production.example.yaml config.production.yaml
```

## Healthcheck Endpointleri

Orchestrator ve load balancer kontrolleri icin:

```http
GET /healthz
GET /readyz
```

`/healthz` uygulama prosesinin ayakta oldugunu gosterir. `/readyz` SQLite baglantisini ve migration durumunu da kontrol eder.

## Docker Compose

Ortam dosyasini hazirlayin:

```sh
cp .env.example .env
```

`.env` icinde en az su degerleri degistirin:

```text
PHANTOM_ADMIN_PASSWORD_HASH
PHANTOM_AUTH_SECRET
PHANTOM_BACKEND_URL
```

Calistirma:

```sh
docker compose up --build -d
docker compose ps
docker compose logs -f phantom-net
```

Health durumu:

```sh
docker inspect --format='{{json .State.Health}}' phantom-net-phantom-net-1
```

Kalici veriler:

```text
./data -> /app/data
```

Bu dizinde SQLite veritabani, SIEM loglari ve alert loglari tutulur.

## Systemd

Onerilen dizinler:

```text
/opt/phantom-net
/etc/phantom-net/config.yaml
/etc/phantom-net/phantom-net.env
```

Servis kullanicisi:

```sh
sudo useradd --system --home /opt/phantom-net --shell /usr/sbin/nologin phantom
sudo mkdir -p /opt/phantom-net /etc/phantom-net /opt/phantom-net/data
sudo chown -R phantom:phantom /opt/phantom-net
```

Servis dosyasini kurma:

```sh
sudo cp deploy/phantom-net.service /etc/systemd/system/phantom-net.service
sudo systemctl daemon-reload
sudo systemctl enable --now phantom-net
sudo systemctl status phantom-net
```

Loglar:

```sh
journalctl -u phantom-net -f
```

## Reverse Proxy Arkasi

Dashboard'u direkt internete acmak yerine Nginx/Caddy gibi bir reverse proxy arkasinda TLS ile yayinlayin. Admin panel icin IP allowlist veya VPN onerilir.

Ornek Nginx upstream:

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

Gateway servisini ayrica yayinlamak isterseniz `8082` portunu disari acin. Honeypot portu `8081` genelde yalniz gateway tarafindan kullanilmalidir.

## Minimum Production Checklist

- `profile: production`
- Varsayilan admin sifresi kapali, `password_hash` aktif
- Uzun ve rastgele `auth.secret`
- Dashboard TLS arkasinda
- `data/` dizini kalici ve yedeklenebilir
- SIEM log hedefleri izleniyor
- `/healthz` ve `/readyz` monitoring'e bagli
- `--check-config --strict-config` deployment pipeline'da calisiyor
