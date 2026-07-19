# TLS Configuration

AgentShield itself serves plain HTTP — it has no built-in TLS listener, by design (matches the
project's "keep the app simple, push TLS termination to standard infrastructure" approach used
throughout `docs/deployment.md`). The `prod` Spring profile's session cookie is marked `Secure`,
which means **login will not work at all without TLS in front of the app** — this isn't optional
hardening, it's a hard requirement once `prod` is active.

## Kubernetes / Helm (recommended path)

`helm/agentshield/values.yaml` already has an `ingress.tls` toggle; when enabled, the Ingress
template (`helm/agentshield/templates/ingress.yaml`) references a Secret named
`<release>-agentshield-tls` holding the certificate. The two common ways to provision that secret:

### Option A: cert-manager + Let's Encrypt (recommended for a real domain)

```bash
# One-time cluster setup, if cert-manager isn't already installed:
helm repo add jetstack https://charts.jetstack.io
helm install cert-manager jetstack/cert-manager --namespace cert-manager --create-namespace --set installCRDs=true
```

```yaml
# cluster-issuer.yaml — one per cluster, not per app
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: you@example.com
    privateKeySecretRef:
      name: letsencrypt-prod-account-key
    solvers:
      - http01:
          ingress:
            class: nginx   # match your ingress controller
```

```bash
kubectl apply -f cluster-issuer.yaml
```

Then annotate the Ingress to request a certificate automatically — add to
`helm/agentshield/templates/ingress.yaml`'s `metadata.annotations` (or pass via
`--set ingress.annotations."cert-manager\.io/cluster-issuer"=letsencrypt-prod` if you extend
`values.yaml` with an `annotations` map):

```yaml
metadata:
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
```

cert-manager then creates and continuously renews the `<release>-agentshield-tls` Secret
automatically — no manual certificate handling.

### Option B: manually provisioned certificate

```bash
kubectl create secret tls agentshield-agentshield-tls --cert=fullchain.pem --key=privkey.pem
```

Then `helm install`/`upgrade` with `--set ingress.tls=true`. You're responsible for renewal before
expiry with this option.

## Plain `k8s/agentshield.yaml` manifests (no Ingress included)

The plain manifests only define a `Deployment` and a `ClusterIP` `Service` — no `Ingress`, so
there's no TLS termination point out of the box. Either add an `Ingress` resource following the
Helm chart's `ingress.yaml` as a template (same cert-manager annotation approach applies), or put a
standalone reverse proxy/load balancer (cloud provider's managed load balancer with TLS, or an
`nginx`/Caddy pod) in front of the `Service` and terminate TLS there.

## Docker Compose / bare-metal (no Kubernetes)

`docker-compose.yml` has no TLS layer — add a reverse proxy service in front of `app`. The
simplest option for a real domain is Caddy, which handles Let's Encrypt automatically with no
separate cert-manager-equivalent setup:

```yaml
# Add to docker-compose.yml
  proxy:
    image: caddy:2-alpine
    ports:
      - "443:443"
      - "80:80"   # required for the ACME HTTP-01 challenge
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile
      - caddy-data:/data
    depends_on:
      - app

volumes:
  caddy-data:
```

```caddyfile
# Caddyfile
agentshield.example.com {
    reverse_proxy app:8080
}
```

Point `agentshield.example.com`'s DNS A/AAAA record at this host, open ports 80/443, and Caddy
handles certificate issuance and renewal automatically on first request.

For an internal-only deployment with no public DNS, use nginx with a manually-provisioned or
internal-CA certificate instead:

```nginx
server {
    listen 443 ssl;
    server_name agentshield.internal;

    ssl_certificate     /etc/nginx/certs/fullchain.pem;
    ssl_certificate_key /etc/nginx/certs/privkey.pem;

    location / {
        proxy_pass http://app:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## Verifying it worked

- `curl -I https://<your-host>/actuator/health` should return `200` over HTTPS.
- Logging into the admin UI should set a session cookie with the `Secure` attribute (visible in
  browser dev tools) — if login silently fails to persist a session with the `prod` profile
  active, TLS isn't actually reaching the app, or the proxy isn't forwarding
  `X-Forwarded-Proto: https` (Spring needs that header to know the original request was HTTPS when
  it's sitting behind a proxy terminating TLS).
