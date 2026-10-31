# Seccomp policy provenance

Base: Moby v26.1.5, immutable commit `411e817ddf710ff8e08fa193da80cb78af708191`, `profiles/seccomp/default.json`. Source repository: `https://github.com/moby/moby`. Apache-2.0 license and upstream notice retained in `MOBY_LICENSE` and `MOBY_NOTICE`.

Local changes: unrestricted ioctl removed from all rules; only TCGETS, TIOCSPGRP, TIOCGWINSZ, FIONREAD, FIONBIO, FIOCLEX and FIONCLEX allowed, each by an exact request-code match on ioctl argument 1. TIOCSPGRP (`0x5410`, 21520) is required by tini to set the controlling terminal process group. Filesystem flag/project setters are not allowed. fileattr_set/file_setattr and io_uring entrypoints are not allowed; unknown syscalls remain denied by default. Existing capability/architecture conditions and the default-deny model are preserved.

The user report for commit `4494d7575b0c7534076684e6d8547477b527a42f` confirms tini startup and healthy OpenClaw on the laboratory VM after this rule was added. That validates the reported instance/run only; it is not a general compatibility proof or security audit.

## Existing containers

Docker applies seccomp at container creation; replacing this JSON does not update an existing container. The Docker adapter verifies the complete expected security configuration, including seccomp, and startup reconciliation occurs before the private socket opens. The user-reported VM update succeeded in this order: the old supervisor removed the failed container with retain; Docker absence and SQLite `(active=0, state='removed')` were verified; the old supervisor stopped; the new supervisor started with the existing DB; only then was a new container created. Retained data/quota stayed reserved, and the new instance used a separate Project ID. This is not active-container adoption or retained-volume reattachment.

Do not start the updated supervisor over an active container created with the old profile as if it will migrate it; exact inspection may block startup. Do not clear the runtime SQLite or manually alter/remove retained data/quota to force adoption. For an active old-profile instance, plan an explicitly approved data-preserving migration first. The confirmed sequence and evidence scope are recorded in `docs/verification.md`.
