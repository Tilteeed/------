# Ollama route acceptance: blocked

No Ollama route acceptance command or receipt is supplied by this change. The
existing proxy acceptance scripts test a different policy and are not evidence
that the Ollama route policy works. Synthetic fixtures are not packet-level
acceptance.

## Receipt serialization

The previously identified literal-backslash newline defect has been corrected
in the local writer, with a synthetic writer-to-loader round-trip regression.
This does not establish packet acceptance or authorize production of a receipt.
Do not bypass the loader or manufacture a receipt.

## Acceptance still required

A future implementation must, on an explicitly authorized disposable Linux
VM, independently exercise the actual Ollama rules with real packets in both a
separate network namespace and a real Docker topology. It must verify allowed
and denied traffic, including established return paths, wrong source,
destination and port, and isolation from other bridges and the host. Failed
connections alone are insufficient evidence of firewall enforcement: verify
that each denied target is reachable when its restriction is absent and that
the intended rules are installed and read back. The test must not contact the
real Ollama endpoint or alter the production host's network state.

The orchestrator must refuse execution without explicit disposable-host
confirmation, validate all route inputs, ensure both real checks succeed,
recheck host identity and binding inputs before writing, and fail closed on
errors or drift. Cleanup and timeouts must not endanger unrelated resources.
No claim of real Linux, Docker, or packet acceptance follows from mocked tests.
The current environment and task constraints prohibit running or verifying the
required privileged, network and Docker checks; a future implementation must be
validated in the target environment before any receipt is produced.
