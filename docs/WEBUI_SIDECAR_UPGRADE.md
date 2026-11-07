# WebUI image update and Sidecar migration

This procedure is for an **existing Linux host** already configured for `agent_proxy_v1`. First installation remains in [`SUPERVISOR_RUN.md`](SUPERVISOR_RUN.md). It is not a VM acceptance record and does not automate installation, backup creation, Compose deployment, or WebUI rollback.

## Safety boundary

- The Supervisor discovers the target immutable image ID from the single running, labelled WebUI container. The CLI accepts only an action and, for `apply`, the hash of the displayed plan; it accepts no image ID, instance ID, Docker socket path, or Docker command.
- `plan` is read-only. `apply` re-plans and refuses if the plan hash changed or any preflight blocker remains.
- The migration replaces only Sidecar containers, one at a time. It never calls agent `remove`, `restore`, `purge`, or Gateway create/start/restart; Gateway IDs, user workspaces, XFS quotas, RuntimeStore reservations, named volume `webui_data`, and existing network IDs/IP plans are checked and retained.
- The image-ID equality check, owner/spec/label checks, exact network membership/IP checks, firewall receipt/readiness, Sidecar security settings, and fail-closed ticket gate remain enabled.
- While the durable journal is active, public Control UI target resolution returns unavailable, lifecycle mutations are blocked, and normal `reconcile()` skips journaled instances. Use the maintenance CLI to continue or inspect the operation.
- The journal is stored under the root-only Supervisor state directory, written atomically with `fsync`, mode `0600`; it contains Docker identities and saved Sidecar specs, not Sidecar proxy tokens or WebUI secrets. The status response omits saved specs and paths.

## Before updating

1. Use the host's already-tested backup/recovery procedure for the WebUI database/volume and Supervisor state. This feature does **not** make a backup and does not validate a backup restore.
2. Keep the old immutable WebUI Docker image available until the update is accepted. The plan rejects a missing old Sidecar image because rollback would otherwise be unsafe.
3. Confirm that the host Supervisor is running the updated project code, its Linux/Docker/firewall acceptance is still valid, and `runtime.json` names the expected Control UI domain and network pools. Do not change firewall trust or network pools as part of this update.
4. Run commands below from the project root. Do not run `docker compose down -v`, delete `webui_data`, remove `pa-agent-*`/`pa-front-*` networks, or use agent remove/restore to rotate Sidecars.

## Build and update the WebUI

Build the new local WebUI image first. The Compose build runs the Dockerfile's backend/frontend test stages; do not continue if build or tests fail.

```bash
sudo docker compose build web
```

Then update only the WebUI container. Compose retains the declared `webui_data` volume; do not add `-v`.

```bash
sudo docker compose up -d --no-deps web
```

The Supervisor discovers the new running WebUI container and immutable image ID. During the mismatch window, old Sidecars are not accepted and new Control UI tickets remain unavailable.

## Plan, apply, and inspect

Create a read-only plan:

```bash
sudo python3 scripts/manage_control_ui_sidecars.py plan \
  --config /var/lib/personal-agent-supervisor/runtime.json \
  --enable-host-maintenance
```

Review the returned WebUI container/image ID, every affected instance/owner, old and target image IDs, Gateway/Sidecar IDs, network IDs/IPs, actions, blockers, and `plan_sha256`. **Do not apply** if `blockers` is non-empty, if any identity is unexpected, or if the old image is not available. Resolve the issue and create a new plan; never reuse a stale hash.

Apply exactly the reviewed plan by copying its `plan_sha256` value:

```bash
sudo python3 scripts/manage_control_ui_sidecars.py apply \
  --config /var/lib/personal-agent-supervisor/runtime.json \
  --plan-sha256 <PLAN_SHA256_FROM_PLAN> \
  --enable-host-maintenance
```

Check progress or the final result:

```bash
sudo python3 scripts/manage_control_ui_sidecars.py status \
  --config /var/lib/personal-agent-supervisor/runtime.json \
  --enable-host-maintenance
```

`completed` means the Supervisor verified every target Sidecar, healthcheck, Gateway identity, network/IP membership, firewall policy, and owner-bound Control UI target. It is not HTTP/WebSocket/browser acceptance; complete the existing Linux VM and browser acceptance separately.

## Resume after interruption

The journal records each Sidecar stage before/after Docker mutations. After restarting the host Supervisor, inspect status and explicitly resume:

```bash
sudo python3 scripts/manage_control_ui_sidecars.py status \
  --config /var/lib/personal-agent-supervisor/runtime.json \
  --enable-host-maintenance

sudo python3 scripts/manage_control_ui_sidecars.py resume \
  --config /var/lib/personal-agent-supervisor/runtime.json \
  --enable-host-maintenance
```

`resume` reads Docker state again and adopts only an exact journalled old/target Sidecar. An unknown container, changed WebUI/Gateway/network identity, damaged journal, or invalid firewall state stops the operation without deleting an unverified resource. Do not delete the journal or edit Docker labels to force progress.

## Failure and rollback

If new Sidecar verification/health fails, the Supervisor attempts a batch rollback: it removes only exact, journal-created target Sidecars and recreates the saved Sidecars from the cached old immutable image. Gateway containers and user data are not rolled back or recreated. A successful Sidecar rollback is reported as `rolled_back` with `old_sidecar_restored_control_ui_closed`: because WebUI still uses the new image, image IDs do not match and Control UI stays closed.

If rollback is interrupted, `status` reports `in_progress` or `needs_attention` with `mode: rollback`; `resume` continues the rollback. If it reports `needs_attention`, leave Control UI closed and require host-admin investigation. Do not use `remove`, `restore`, `purge`, `docker system prune`, or manual network changes as a recovery shortcut.

This Supervisor does not own Compose state and **does not automatically roll WebUI back**. If the new WebUI itself must be reverted, use the host's reviewed Compose/image rollback procedure to restore the retained old immutable WebUI image while preserving the same `webui_data` volume and Compose project identity. Then run a fresh `plan` and verify the current state. The root-only CLI is not a substitute for a tested Compose rollback.

## Acceptance boundary

Synthetic unit tests cover planning, journal checkpoints, fail-closed maintenance gating, and mocked Docker lifecycle transitions. They do not prove a real Docker Engine update, Supervisor process restart, Linux firewall/nftables state, two-agent migration, XFS/workspace preservation, HTTP 303/cookie behavior, WebSocket continuity, or browser acceptance. Those remain required on the intended disposable Linux VM before treating the update workflow as accepted.
