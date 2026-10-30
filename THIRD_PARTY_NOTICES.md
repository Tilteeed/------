# Third-party components

This project extends Open WebUI without replacing its authentication or branding.

## Open WebUI

- Upstream: `https://github.com/open-webui/open-webui`
- Reviewed release: `v0.12.5`
- Reviewed commit: `f7ac7ee10962ddec0017f5c29b6740d9b9c5faca`
- Runtime image and digest: see `upstream.lock.json` and `Dockerfile`.
- License: the upstream **Open WebUI License** and `LICENSE_HISTORY`, not a blanket assumption of MIT for current versions.
- Original notices and branding in the base image are retained. Review upstream license terms before distribution or public hosting; this file is attribution, not legal advice.

The project does not embed an OpenClaw image yet. Referenced OpenClaw functionality is not redistributed as part of the current source tree.

## Moby seccomp configuration

`supervisor/seccomp.json` derives from Moby v26.1.5 commit `411e817ddf710ff8e08fa193da80cb78af708191`, `profiles/seccomp/default.json`. The Apache-2.0 license and upstream notice are retained in `supervisor/MOBY_LICENSE` and `supervisor/MOBY_NOTICE`; source provenance and local changes are listed in `supervisor/SECCOMP_SOURCE.md`. The local policy retains default-deny and replaces unrestricted ioctl with a small terminal/pipe whitelist to protect project-quota inheritance. This does not assert completed Linux/Docker verification.

Node is used only in a container test stage for dependency-free frontend unit tests. Python/FastAPI and other runtime dependencies are supplied by the pinned upstream image; the host environment is not modified by writing this repository.
