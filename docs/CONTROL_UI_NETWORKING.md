# Personal Control UI: lab DNS, proxy and WebUI recreation

This runbook separates the browser-side DNS/TLS path from the Supervisor's Docker checks. It does not install DNS software, change a DNS client, edit Nginx, or deploy to a VM.

## DNS for per-agent hostnames

`AGENT_CONTROL_UI_DOMAIN` is the configured suffix; each agent uses `<instance_id>.<suffix>`. DNS must resolve that hostname to the HTTPS reverse proxy, not directly to the Gateway or Sidecar.

Prefer an existing external DNS zone when one is available. Configure a wildcard A record for `*.<AGENT_CONTROL_UI_DOMAIN>` to the Nginx IPv4 address. In that case, do not install or start dnsmasq for this feature.

If the lab has no wildcard DNS service, `ops/lab_dnsmasq.py` renders an optional dnsmasq snippet from deployment values. It prints configuration only; it does not install packages, write system files, enable/restart a service, or change client DNS settings:

```bash
python3 ops/lab_dnsmasq.py \
  --domain "$AGENT_CONTROL_UI_DOMAIN" \
  --proxy-ip "$NGINX_IPV4" \
  --listen-address "$DNS_LISTEN_IPV4" \
  --interface "$DNS_LAB_INTERFACE" \
  --upstream "$UPSTREAM_RESOLVER_IPV4" \
  > ./agents.dnsmasq.conf
```

Supply the actual values for that lab; none are embedded in the application. The renderer checks that `DNS_LISTEN_IPV4` is assigned to `DNS_LAB_INTERFACE` using the read-only Linux `ip` command, then prints a snippet; it does not install packages, write system files, enable/restart a service, or change client DNS settings. Review the rendered file before an administrator installs it. The snippet binds to the selected interface/address, excludes loopback, disables DHCP on that interface, avoids `/etc/resolv.conf` loops, forwards other queries only to the supplied upstream resolver(s), and adds `address=/<domain>/<proxy-ip>`. Configure the host firewall to allow DNS only from the trusted lab network. Do not expose a DNS-forwarder to an untrusted network.

Configure the browser machine to use the lab DNS server only in the intended lab network/profile. From that same machine, verify a real instance hostname:

```text
nslookup <instance_id>.<AGENT_CONTROL_UI_DOMAIN> <DNS_SERVER_IP>
```

The A answer must be the Nginx address. Remove stale AAAA records if the proxy has no IPv6 listener.

### Manual hosts-file fallback

For a machine without local DNS, add one entry per agent using the Nginx address:

```text
<NGINX_IPV4> <instance_id>.<AGENT_CONTROL_UI_DOMAIN>
```

This is a manual, per-instance fallback and must be repeated for each new agent. On Linux/macOS the file is `/etc/hosts`; on Windows it is `%SystemRoot%\System32\drivers\etc\hosts`. It does not provide wildcard resolution.

## HTTPS and Nginx forwarding

The TLS certificate must be trusted by the browser and cover both the BEZR application hostname and `*.<AGENT_CONTROL_UI_DOMAIN>`. The host-local Nginx edge can proxy to the Compose-published WebUI port, which remains bound to loopback.

Define the WebSocket `map` once in the Nginx `http` context if it is not already present:

```nginx
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}
```

In the existing TLS server's WebUI location, preserve the request host and browser Origin, and overwrite client-supplied forwarded headers:

```nginx
proxy_pass http://127.0.0.1:<WEB_PORT>;
proxy_http_version 1.1;
proxy_set_header Host $host;
proxy_set_header Origin $http_origin;
proxy_set_header X-Forwarded-For $remote_addr;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_set_header Upgrade $http_upgrade;
proxy_set_header Connection $connection_upgrade;
```

Do not use `$proxy_add_x_forwarded_for` for this single trusted edge, and do not replace `Origin` with a fixed application origin. The handoff endpoint intentionally requires exactly the browser's expected Origin; missing, `null`, duplicate, and foreign Origin values remain rejected. If Nginx itself is behind another proxy, configure and restrict that upstream's real-IP handling separately; do not trust client-supplied forwarding headers.

## Uvicorn's trusted proxy address

`compose.yaml` now takes `FORWARDED_ALLOW_IPS` from `.env`; the generated web-only default remains `127.0.0.1`. For host Nginx reaching the published container port, add the exact peer address observed for the Compose `web` bridge gateway. Obtain it read-only from the active Compose network:

```bash
docker network ls \
  --filter label=com.docker.compose.project=personal-agent-platform \
  --filter label=com.docker.compose.network=web

docker network inspect <NETWORK_ID> \
  --format '{{range .IPAM.Config}}{{.Gateway}}{{end}}'
```

Set `FORWARDED_ALLOW_IPS` in the local `.env` to that exact gateway IP. Add another literal IP only if it is a separately trusted proxy. Do not use `*`, CIDR ranges, or an entire Docker subnet. The Supervisor verifies the live Compose project/network identity, its actual IPAM gateway and endpoint, and that the configured literal-IP list contains that gateway. This is an IP trust boundary, not Nginx process authentication: any host process able to reach the loopback-published WebUI port shares that trust, so keep the port loopback-only and do not let untrusted workloads reach it. A gateway change after network recreation makes Control UI unavailable until `.env` is updated and WebUI is recreated; trust is not broadened automatically. A forwarded-proxy mismatch does not by itself stop or remove the Gateway.

## Read-only browser-side preflight

Run `ops/control_ui_preflight.py` from the browser machine after DNS and TLS have been configured. It uses that machine's resolver and trust store, verifies the A answer against the expected Nginx IP, then sends a diagnostic POST to `/_bezr/enter` with an intentionally invalid `text/plain` content type, the exact application Origin, and deliberately forged `X-Forwarded-For`/`X-Forwarded-Proto` request headers. Nginx must overwrite the forged forwarding values; HTTP 415 is expected only after the request reaches the intended handler. The body is a fixed probe string; it sends no ticket, cookie, credentials, or session and does not read the response body.

```bash
python3 ops/control_ui_preflight.py \
  --instance-id <32-character-instance-id> \
  --domain "$AGENT_CONTROL_UI_DOMAIN" \
  --proxy-ip "$NGINX_IPV4" \
  --app-origin "$AGENT_PLATFORM_PUBLIC_ORIGIN"
```

A 415 confirms that DNS, certificate validation, Host routing, HTTPS forwarding, Origin validation and content-type ordering reached the intended handler. The probe supplies forged X-Forwarded-For and X-Forwarded-Proto headers; the handoff route checks the effective HTTPS scheme, but does not validate client IP, so a 415 alone does **not** prove Nginx overwrote X-Forwarded-For. Verify that directive in the Nginx configuration and exercise the owner-scoped Access Proxy in the VM/browser acceptance. A 404 or 403 is a failure; do not weaken the server's Origin gate. The Supervisor separately gates readiness on Docker network identity and `FORWARDED_ALLOW_IPS`. This client-side preflight is not a substitute for a real Firefox/Chromium launch and WebSocket acceptance.

## Recreating WebUI without changing its image

For the reported `--no-build --force-recreate --no-deps web` case, keep the immutable image ID unchanged. The Supervisor discovers the new WebUI container ID, validates it, and idempotently reconnects it to each active agent's already-verified frontend network at the Supervisor-assigned IP. On Supervisor startup, `reconcile()` inspects all active instances; Control UI status/launch and start checks also run the same verified repair. No agent/Gateway container, data directory, Docker volume, network, XFS quota, or workspace is removed by this repair.

Use the existing maintenance process for the host Supervisor so it runs the updated local code, then recreate only the WebUI container:

```bash
docker compose up -d --no-build --no-deps --force-recreate web
```

Do not use `docker compose down -v`, remove agent networks, or run a manual `docker network connect`; the Supervisor owns those attachments. Re-run the browser-side preflight and open each affected agent through `/agent`.

If a WebUI build changes the immutable image ID, the existing Sidecar image identity check remains strict. The current same-image recreation path does not rotate Sidecars to a new image ID; Control UI remains unavailable for that mismatch rather than accepting a stale Sidecar. The Supervisor can keep the Gateway running only while the old Sidecar image and its exact configuration, networks, and firewall state still verify; otherwise existing fail-closed handling may stop the proxy workloads. Do not count an image-changing update as accepted until a separately reviewed Sidecar migration is available and verified.

## Acceptance boundary

Unit tests exercise synthetic Docker responses and the preflight's mocked network/HTTP boundaries only. They do not prove dnsmasq behavior, DNS-client configuration, Nginx behavior, Docker Engine networking, TLS deployment, Firefox/Chromium behavior, Linux/XFS isolation, or clean-VM acceptance. Those checks must be performed on the intended Linux VM and browser machine by the operator.
