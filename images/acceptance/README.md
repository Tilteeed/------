# BEZR acceptance probe image

`bezr-acceptance-probe-linux-amd64.tar` is the exact offline Docker image archive
used for the four successful GPU-host acceptance checks on 14 November 2026.
It is a **test probe**, not the OpenClaw agent image and not the WebUI image.
It contains Python 3.10 and runtime libraries copied from Ubuntu 22.04 on the
test server. The archive has no build recipe and should not be considered a
reproducible image build or a general-purpose, maintained base image.

- Platform: Linux `amd64`.
- Archive size: 71,680,000 bytes.
- Archive SHA-256: `25961d215337caf6d223dd437479bc0f9b513a5b3da26fb536991a2e9879b778`.
- Docker image ID: `sha256:801f33cfdb491fe6d751bbb99d9925edb7175e49fab758ad44c56e288e5abb9a`.
- Archive tag: `bezr-acceptance-probe:local`.

Verify the archive hash after transfer. Configure the acceptance profile with
the archive's **absolute, root-controlled server path** and the image ID above.
The busy-host acceptance runner loads it into its own bounded temporary Docker
daemon; do not load it into the production daemon merely to perform acceptance.
The archive must be on the I/O device approved by the acceptance budget.

`licenses/` contains copyright notices and package versions observed on the
source Ubuntu installation on 14 November 2026 for identified principal
components. The archived image does not contain a package database, so those
versions are not independently proven for every file inside the archive. The
image also contains the Python standard library license. Review the included
notices and redistribution/source obligations before publishing this binary.

This file is approximately 68.4 MiB and is intentionally below GitHub's 100 MiB
single-file limit, but it will increase every ordinary Git clone. It is excluded
from the WebUI Docker build context.
