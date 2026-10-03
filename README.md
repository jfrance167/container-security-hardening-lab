# Container Security Hardening Lab

This defensive DevSecOps lab compares intentionally insecure Docker and Kubernetes configuration with a hardened equivalent. A dependency-free Python policy engine produces reproducible before/after evidence without building images, starting containers, or contacting a cluster.

## What the lab checks

- Immutable SHA-256 image references
- Non-root execution
- Embedded secret patterns in Docker build declarations
- Container health checks
- Seccomp profiles
- Disabled privilege escalation and privileged mode
- Read-only root filesystems
- Dropped Linux capabilities
- CPU and memory limits
- Disabled service-account token automount
- Host-network avoidance
- Namespace-scoped ingress-and-egress default-deny NetworkPolicy coverage

## Run it

Python 3.10 or later is required. There are no runtime dependencies.

```bash
python container_policy.py fixtures/vulnerable --output reports/vulnerable-report.md
python container_policy.py fixtures/hardened --output reports/hardened-report.md --fail-on-findings
python -m unittest discover -s tests -v
```

Use `--format json` for machine-readable findings. `--fail-on-findings` returns exit status 1 when a policy violation is detected, making the tool suitable for a CI quality gate.

## Evidence

- [`LAB_REPORT.md`](LAB_REPORT.md) documents the method, results, limitations, and conclusion.
- [`reports/vulnerable-report.md`](reports/vulnerable-report.md) records the baseline failures.
- [`reports/hardened-report.md`](reports/hardened-report.md) proves the hardened fixture passes.
- [`fixtures/`](fixtures/) contains the intentionally insecure and hardened configurations.

## Safety

The vulnerable fixture is deliberately insecure and exists only for static analysis. Do not build, deploy, or copy it into a real environment. Image names and digests are illustrative placeholders; they are not deployable artifacts. The analyzer evaluates regular files only and refuses symbolic links so a scanned tree cannot redirect it outside the selected target.

## Repository map

```text
container-security-hardening-lab/
|-- .github/
|-- .gitignore
|-- LAB_REPORT.md
|-- README.md
|-- SECURITY.md
|-- container_policy.py
|-- fixtures/
|-- reports/
`-- tests/
```

Follow the setup and safety boundaries above before running or deploying any code.
