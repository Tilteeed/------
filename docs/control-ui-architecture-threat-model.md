# Control UI: architecture and threat model

Status: **local implementation, not production-accepted**. This document records the intended `agent_proxy_v1` topology and the security boundary. The firewall semantics gate remains disabled; Docker/Linux/nftables and browser acceptance have not been demonstrated by local synthetic tests.

## Architecture contract

For each runtime instance, Supervisor creates:

- one OpenClaw Gateway and one Sidecar HTTP/WebSocket proxy;
- `pa-agent-{instance_id}` — that instance's dedicated internal Docker bridge between its Gateway and Sidecar;
- `pa-front-{instance_id}` — that instance's dedicated internal Docker bridge between its Sidecar and the central BEZR WebUI.

The two networks are distinct per instance. A shared frontend network is not an allowed substitute.

```text
Browser
  | HTTPS / WSS; BEZR user session checked before forwarding
BEZR WebUI / Backend / Access Proxy (one shared trust boundary)
  | joins pa-front-A, pa-front-B, ...; never joins pa-agent networks
  +---- pa-front-A ---- Sidecar-A ---- pa-agent-A ---- Gateway-A
  +---- pa-front-B ---- Sidecar-B ---- pa-agent-B ---- Gateway-B
```

Network membership requirements:

| Component | Permitted runtime networks |
|---|---|
| Central BEZR WebUI | Each instance's `pa-front-{id}` only; no `pa-agent-*` |
| Sidecar for instance A | `pa-front-A` and `pa-agent-A` only |
| Gateway for instance A | `pa-agent-A` only |

Each bridge uses an explicitly configured site CIDR pool, a dedicated `/29`, Docker `Internal=true`, and IPv6 disabled. The bounded host inventory preserves route device/type/protocol/scope and interface addresses. A retained subnet is exempted from route-conflict rejection only after the matching Docker network ID has been re-inspected and its instance labels, IPAM gateway/subnet, bridge option, and route/interface evidence agree. A bridge name alone never establishes ownership. The check is point-in-time, not a live route-change monitor.

Gateway trusted-proxy configuration contains only the exact fixed IPv4 address assigned to its own Sidecar. Agent Gateway ports are not published. Sidecar pairing is manual; automatic approval is disabled. Sidecar resource caps are 128 MiB RAM, 100 millicores CPU, and 32 PIDs. The Sidecar secret is supplied through a private file and must not appear in API responses, logs, labels, or routine inspection output.

All public browser-to-service access must use HTTPS/WSS. The BEZR backend/access proxy validates the authenticated BEZR user session and derives the owner on the server; it must not trust a browser-supplied owner or arbitrary Gateway URL. HTTP/WSS relay paths preserve the query string and reject non-canonical forwarded identity/protocol metadata. TLS termination and the ASGI trusted-proxy configuration still require deployment-level verification.

## Trust boundaries

| Classification | Components and implications |
|---|---|
| Trusted | Supervisor, BEZR Backend/Access Proxy, BEZR session authorization, host administrator, Docker daemon, Linux kernel/nftables. These components can affect isolation or identity and require privileged operational control. |
| Shared trusted boundary | Central BEZR WebUI. It participates in every per-instance frontend network. A WebUI compromise can potentially reach every personal Sidecar; per-instance frontend bridges do **not** contain this shared-component compromise. |
| Limited trust | Sidecar A is trusted only to relay for owner A and to the explicitly configured Gateway A endpoint. A Sidecar compromise should not provide a network path to another owner's Gateway. The Sidecar is still a security-sensitive parser and relay. |
| Untrusted | User-controlled OpenClaw behavior, its tools/extensions, prompts, workspace files, imported content, and data received from external services. Treat their content as potentially malicious, including prompt injection and hostile protocol payloads. |
| External | Browser, networks beyond the BEZR edge, model/tool providers, Telegram or other integrations. Their data is untrusted; public ingress must pass TLS and BEZR session authorization. |

## Isolation goals and limits

1. A Sidecar for owner A has no Docker-network membership in B's networks and is configured to reach only Gateway A. This is the intended network isolation boundary between user workloads.
2. Gateway A trusts only Sidecar A's exact address, not a subnet or a shared proxy range.
3. The WebUI is deliberately multi-homed across frontend networks. It remains a cross-tenant control point; an attacker controlling it may invoke any Sidecar it can reach. Stronger protection against WebUI compromise would require changing the trust architecture, not merely adding more frontend bridges.
4. The design relies on Supervisor-owned, dedicated nftables tables (`inet` and `bridge`, `agent_proxy_v1`) to deny host input/output and routed cross-network traffic while allowing only the intended same-instance endpoint pairs. The adapter requests handles with `nft -a -j`, uses bounded JSON inventory, ownership checks, one table-scoped nft batch, and exact readback. It must not flush the global ruleset or modify Docker-owned tables.
5. nftables/kernel behavior, bridge hook semantics, forwarding behavior, and Docker interaction have not been validated on the target Linux host. `NFTABLES_SEMANTICS_VALIDATED` is therefore false; `agent_proxy_v1` is fail-closed and must not be enabled based on synthetic tests alone.
6. Container/network isolation does not defend against a compromised host administrator, Docker daemon, kernel, Supervisor, BEZR authorization service, or the shared WebUI. Resource limits reduce resource abuse but are not a substitute for host isolation.

## Implementation state and acceptance boundary

Implemented locally: per-instance network planning and Docker API lifecycle helpers; route/interface inventory parser and conflict-aware `/29` allocation; Sidecar/Gateway membership checks; exact trusted-proxy configuration; owner-scoped, session-gated HTTP/WS relay logic; manual-pairing configuration; nftables adapter and synthetic readback/drift tests; fail-closed firewall readiness gate.

Not accepted or proven by local checks: actual Docker IPAM and network membership on Linux; real kernel enforcement and nftables rule semantics; host/neighbor/routed isolation; live TLS edge and ASGI forwarded-header behavior; browser authentication, WebSocket and pairing E2E; route-change handling after allocation; upgrade/restart/partial-failure behavior on a real daemon. An isolated Linux-namespace pre-acceptance harness is prepared in [`ISOLATED_LINUX_PROXY_CHECK.md`](ISOLATED_LINUX_PROXY_CHECK.md), but it has not been run and deliberately uses a synthetic Docker API fixture. No production CIDR pools are selected here. `legacy_none` remains the default, and `agent_proxy_v1` must remain unavailable until separate target-host acceptance explicitly enables the semantics gate.

Local tests use synthetic Docker/nftables adapters and fixtures. They establish code behavior for those fixtures only; they are not evidence of real Docker, Linux, nftables, VM, or browser acceptance.
