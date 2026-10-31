# Seccomp policy provenance

Base: Moby v26.1.5, immutable commit `411e817ddf710ff8e08fa193da80cb78af708191`, `profiles/seccomp/default.json`. Source repository: `https://github.com/moby/moby`. Apache-2.0 license and upstream notice retained in `MOBY_LICENSE` and `MOBY_NOTICE`.

Local changes: unrestricted ioctl removed from all rules; only TCGETS, TIOCSPGRP, TIOCGWINSZ, FIONREAD, FIONBIO, FIOCLEX and FIONCLEX allowed, each by an exact request-code match on ioctl argument 1. TIOCSPGRP (`0x5410`, 21520) is required by tini to set the controlling terminal process group. Filesystem flag/project setters are not allowed. fileattr_set/file_setattr and io_uring entrypoints are not allowed; unknown syscalls remain denied by default. Existing capability/architecture conditions and the default-deny model are preserved.

This is a project configuration asset, not an installed package. Linux/Docker validation remains required on the VM; no compatibility or security audit is implied.

## Existing containers

Docker applies seccomp at container creation; replacing this JSON does not update an existing container. The Docker adapter also verifies the complete expected security configuration, so a container created with the previous profile will not match the new expected configuration. The current runtime has no controlled in-place policy migration or retained-volume reattachment workflow. Do not manually remove the container, alter its XFS project/quota, clear the runtime SQLite, or restart a newly deployed supervisor against that existing binding as a way to force adoption. Plan a separately approved, data-preserving migration before deploying this policy to a VM with an existing managed instance. The new rule itself has only been structurally tested locally; full tini/OpenClaw startup and healthcheck still require the Linux/Docker acceptance run.
