# Ollama route packet acceptance

**Status: implemented locally; real Linux/Docker acceptance NOT RUN. No receipt
has been produced.** Portable tests validate contracts, rejection and argv only.

## Authorized operator run

Use an explicitly authorized, disposable Linux VM as the outer boundary. Root,
network/mount/PID namespaces, existing `unshare`, `ip`, `nft`, `nsenter`, `mount`,
`sleep`, `docker`, `dockerd` and their already-installed runtime dependencies are
required. Supply an absolute regular Docker image archive and its exact
`sha256:<64 lowercase hex>` image ID. The image must contain `python3` with the
standard library. Nothing is downloaded, installed, pulled or published.

From the repository root, with **site-specific** disjoint RFC1918 pools,
endpoint and interface (example values below are not site discovery):

```sh
python3 scripts/activate_ollama_route.py \
  --execute --confirm-disposable-host \
  --agent-pool 10.240.0.0/13 --frontend-pool 10.248.0.0/13 \
  --ollama-pool 172.20.0.0/16 --endpoint 192.168.40.10 --interface ens18 \
  --image-archive /absolute/operator-provided/probe.tar \
  --probe-image sha256:REPLACE_WITH_ACTUAL_64_LOWERCASE_HEX_IMAGE_ID \
  --state-dir /var/lib/personal-agent-supervisor
```

The two underlying commands can also be run independently, with the same
explicit binding arguments and opt-in flags:

- `scripts/linux_ollama_route_check.py` (no image arguments).
- `scripts/linux_docker_ollama_route_acceptance.py` (archive and image required).

Independent checks emit bounded JSON on success but never write a receipt.
The orchestrator accepts neither report files nor skip flags, and does not reuse
the proxy/host firewall acceptance receipt. It executes both fixed commands,
requires zero exits and exact structured reports, rechecks host/config binding,
then invokes the existing atomic Ollama receipt writer and production loader.
It does not change production rules, profiles, services or the default profile.

## What actually executes

Each check creates an outer private mount/network/PID namespace, preserving an
open descriptor to the original caller network namespace. Every command that
can mutate network/firewall state checks that the current router inode is the
expected child inode and differs from that descriptor. Target/client namespaces
are independently checked before namespace mutations. `/run` is mounted private
inside the lab. A veth target uses the **exact configured endpoint IPv4 and
exact interface name**, without contacting the real endpoint. Its additional
foreign address and HTTP listeners are controlled by the harness.

Two instances use canonical production /29 allocation, bridge names, fixed
addresses and complete Docker network options/labels. Each Gateway is attached
to its Ollama and agent network; each actual Sidecar is attached to its agent
and frontend networks, not an invented sidecar on the Ollama bridge. Web
listeners occupy the frontend addresses. Both canonical proxy and canonical
Ollama policies are rendered and read back with unmodified `NftablesAdapter`.
No policy normalization, extra accepts, trace/counter amendments or relaxed
readback are used by the harness.

The Docker check starts an actual nested `dockerd` inside that isolated router
namespace. Its socket, daemon config, CLI config, PID file, exec-root and vfs
data-root are unique and disposable. It does not contact the caller daemon.
Daemon iptables/ip-forward/default bridge/userland-proxy integration is disabled;
all test routing occurs inside the lab. Only the explicit archive is loaded;
container creation uses `--pull=never`, exact immutable image identity, dropped
capabilities, no-new-privileges and bounded memory/PIDs. Live network and
container endpoint identity is inspected, not replaced by fixtures. Lab-only
routes are added in independently proven container namespaces so even internal
Sidecar networks have reachable negative controls; absence of a route cannot
masquerade as a firewall pass.

Each check executes 22 HTTP-over-TCP probes, including successful exact Ollama
requests with complete nonce-bound multi-packet response bodies, wrong port,
foreign destination, host access, other Gateway/Sidecar, Sidecar-to-Ollama,
unsolicited reverse connections, both allowed local agent/frontend pairs, and
cross-instance isolation. For **every** probe a real listening transaction must
succeed both before and after enforcement with only the owned BEZR tables
narrowly removed. Between those controls, the exact production policies must
read back and the probe must match its allow/deny expectation. A timeout,
refusal, missing image/Python, malformed HTTP, command failure, no route or dead
listener alone cannot satisfy acceptance. Changing the canonical policy to make
the test pass is not an acceptance result.

Each subprocess has bounded output and timeout. Child cleanup removes only
tracked containers/networks, checks private-daemon inventories, stops tracked
processes and verifies table/link absence. The outer PID namespace is a kill
boundary; the outer process owns/removes the temporary directory even when a
child times out. JSON success is forwarded only after normal lab cleanup,
namespace-process exit and outer directory removal succeed. No system prune,
caller ruleset flush or caller Docker/network mutation is used.

## Local blocker found without privileged execution

The current `expected_ollama_ruleset()` returns mixed-chain rule order, whereas
`NftablesAdapter._normalise_table()` sorts rules by chain. A portable comparison
of the canonical manifests showed `inet=False, bridge=False` for equality to
that sorted form. Therefore strict readback will fail until the production
policy owner resolves that consistency bug (stable sorting preserves each
chain's rule order). The acceptance scripts intentionally do not sort/relax
observations or modify the production renderer to conceal it.

Real namespace/nftables/Docker behavior, including namespace permissions,
installed nft syntax and nested runtime/cgroup support, still requires an
operator-authorized Linux VM run. A failed prerequisite or packet test is a
failure, not synthetic evidence and not authorization for a receipt.
