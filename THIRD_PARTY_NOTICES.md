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

Node is used only in a container test stage for dependency-free frontend unit tests. Python/FastAPI and other runtime dependencies are supplied by the pinned upstream image; the host environment is not modified by writing this repository.
