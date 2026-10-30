# Seccomp policy provenance

Base: Moby v26.1.5, immutable commit `411e817ddf710ff8e08fa193da80cb78af708191`, `profiles/seccomp/default.json`. Source repository: `https://github.com/moby/moby`. Apache-2.0 license and upstream notice retained in `MOBY_LICENSE` and `MOBY_NOTICE`.

Local changes: unrestricted ioctl removed from all rules; only TCGETS, TIOCGWINSZ, FIONREAD, FIONBIO, FIONCLEX and FIOCLEX allowed. Filesystem flag/project setters are not allowed. fileattr_set/file_setattr and io_uring entrypoints are not allowed; unknown syscalls remain denied by default. Existing capability/architecture conditions and the default-deny model are preserved.

This is a project configuration asset, not an installed package. Linux/Docker validation remains required on the VM; no compatibility or security audit is implied.
