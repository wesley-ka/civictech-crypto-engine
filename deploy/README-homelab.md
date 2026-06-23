# CivicTech Crypto Engine — homelab deployment

Spring Boot API replacing Render backend. Public URL: **https://api.awka.dev/api**

## Quick status

```bash
curl -s http://127.0.0.1:8085/api/v1/health
/usr/bin/podman ps --filter name=civictech-crypto-engine
```

## Manage container

```bash
# Rebuild and restart
bash /homelab/civictech-crypto-engine/scripts/restart.sh

# Install as systemd Quadlet (requires sudo on homeserver)
bash /homelab/civictech-crypto-engine/scripts/install-quadlet.sh
```

## Secrets

Copy `.env.example` to `.env` and set `CRYPTO_API_KEY` (see `homelab-secrets` skill). Never commit `.env`.

## Ingress setup (manual — Cloudflare dashboard + NPM)

Complete these three steps once to expose the API publicly.

### 1. Cloudflare Tunnel — `api.awka.dev`

1. [Cloudflare Zero Trust](https://one.dash.cloudflare.com/) → **Networks** → **Tunnels**
2. Open the tunnel connected to this server
3. **Public Hostname** → Add:
   - Subdomain: `api` · Domain: `awka.dev`
   - Type: **HTTP** · URL: `localhost:80`
4. **SSL/TLS** for `awka.dev` → mode **Full**

Verify:

```bash
dig +short api.awka.dev
curl -s https://api.awka.dev/api/v1/health
```

### 2. NPM proxy host

NPM admin: **http://homeserver.local:81**

| Setting | Value |
|---------|-------|
| Domain Names | `api.awka.dev` |
| Scheme | `http` |
| Forward Hostname / IP | `10.89.0.1` |
| Forward Port | `8085` |
| Block Common Exploits | On |

Or via API (set your NPM admin credentials):

```bash
NPM_IDENTITY='your@email.com' NPM_SECRET='your-npm-password' \
  bash /homelab/civictech-crypto-engine/scripts/configure-npm-proxy.sh
```

### 3. Cloudflare Pages frontend

In your Pages project → **Settings** → **Environment variables**:

| Variable | Value |
|----------|-------|
| `VITE_API_URL` (or your app's API var) | `https://api.awka.dev/api` |

Redeploy Pages. Store `CRYPTO_API_KEY` as an encrypted Pages env var if the browser calls authenticated endpoints.

## Architecture

```
Cloudflare Pages → https://api.awka.dev/api
  → Cloudflare Tunnel → NPM :80 → 10.89.0.1:8085 → civictech-crypto-engine
```

## Env vars (names only)

| Name | Purpose |
|------|---------|
| `CRYPTO_API_KEY` | Bearer token for `/api/v1/**` |
| `SPRING_PROFILES_ACTIVE` | `production` |
| `VOTING_STORAGE_TYPE` | `local` or `b2` |
| `CRYPTO_KEYS_VAULT_KEY_HEX` | Persist vault key across restarts |
| `VOTING_TELEGRAM_BOT_TOKEN` | Optional voting notifications |
| `B2_*` | Optional Backblaze storage |
