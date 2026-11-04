# Isolated Linux check for proxy IPAM and nftables read-back

## Purpose and limits

This is a **pre-acceptance** check for the route-ownership fix and nft handle/JSON behavior. It is intentionally not a Docker deployment and does not touch user data, start an agent, expose ports, or connect to a VM. It does not enable `agent_proxy_v1`.

The script starts an anonymous Linux network namespace with `unshare --net`, creates two temporary bridges and gateway addresses inside that namespace, reads actual kernel route/interface JSON with `ip -j`, and supplies a synthetic Docker API inspection fixture containing network IDs, exact IPAM, bridge options, and BEZR labels. It exercises repeated network preparation, the Supervisor restore-preparation path, rejection of a foreign route, and a real `nft -a -j` create/read-back/remove cycle inside that namespace.

**What this does not prove:** Docker daemon-created bridge/IPAM behavior; actual Docker labels and membership; packet-level allow/deny between containers; host/neighbor isolation; TLS/ASGI/browser behavior; pairing or model connectivity. It cannot justify setting `NFTABLES_SEMANTICS_VALIDATED=True` or enabling the profile. A separate disposable-VM Docker/data-plane acceptance is still required.

## Prerequisites

Use a disposable Linux VM or a fresh VM snapshot. The script needs existing `python3`, `unshare` (util-linux), `ip` (iproute2), and `nft` binaries, plus privileges sufficient to create a network namespace, bridges, routes, and nftables tables. It installs nothing. Do not use a production host. Kernel modules may be loaded by the kernel when nftables is first used, so a disposable VM is part of the isolation boundary.

From the project root, run:

```sh
sudo python3 scripts/linux_proxy_isolated_check.py
```

The command creates no persistent named namespace or files. The script verifies that its child is in a different network-namespace inode before any network operation. All temporary links, routes, and nftables tables are inside that namespace; they disappear when the child exits. If `unshare` is unavailable or denied, the check fails rather than falling back to the caller's network namespace.

## Expected result and interpretation

A successful run prints `PASS` and explicitly reports that the Docker API was synthetic and `agent_proxy_v1` remains disabled. A failure is evidence that this isolated pre-acceptance check did not pass; do not infer a fix by weakening the gate. The script suppresses raw command diagnostics and emits a bounded error message.

After this check, the remaining acceptance must still use an explicitly isolated Linux/Docker environment to verify real Docker inspect output, container membership, route inventory from Docker-created networks, and packet-level policy behavior. No such live Docker check has been run as part of preparing this script.
