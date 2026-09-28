# Lab Report: Container Security Hardening

## Question

Can a small policy-as-code gate detect high-impact Docker and Kubernetes configuration weaknesses and verify that a hardened configuration removes them?

## Hypothesis

The intentionally insecure baseline will fail controls related to image integrity, identity, privileges, isolation, resource governance, secrets, and networking. A hardened configuration addressing those controls will produce zero findings.

## Materials

- Python 3.10 or later
- One intentionally insecure Dockerfile and Kubernetes Deployment
- One hardened Dockerfile, Deployment, and NetworkPolicy
- Python `unittest`

## Procedure

1. Created a non-deployable vulnerable fixture with a mutable image tag, root execution, an embedded placeholder token, privileged container settings, host networking, and missing isolation controls.
2. Implemented a static policy engine with stable rule identifiers and severity levels.
3. Scanned the vulnerable fixture and generated a Markdown baseline report.
4. Created a hardened fixture using illustrative immutable digests, non-root identity, runtime-default seccomp, least privilege, a read-only filesystem, resource limits, disabled token automount, and default-deny NetworkPolicy.
5. Scanned the hardened fixture with the same rules and generated a second report.
6. Ran unit and repository-policy tests plus Bandit and CodeQL.

## Results

The vulnerable fixture produced 15 findings: 8 high, 6 medium, and 1 low. The hardened fixture produced zero findings and passed the policy gate.

| Measurement | Vulnerable | Hardened |
| --- | ---: | ---: |
| High findings | 8 | 0 |
| Medium findings | 6 | 0 |
| Low findings | 1 | 0 |
| Total | 15 | 0 |
| Policy result | Fail | Pass |

## Interpretation

The experiment supports the hypothesis for the controlled fixtures. The same deterministic checks that rejected the vulnerable configuration accepted the hardened version, providing auditable before/after evidence.

## Limitations

- This is static configuration analysis, not runtime isolation testing.
- The engine supports Dockerfiles and Kubernetes JSON, not arbitrary YAML syntax or Helm templates.
- NetworkPolicy presence does not prove that a policy permits only necessary traffic.
- Illustrative image digests are intentionally non-deployable and are checked only for immutable-reference structure.
- Production programs should add admission control, image signing, provenance verification, vulnerability scanning, runtime monitoring, and platform-specific policy.

## Conclusion

A focused policy gate can catch common container configuration weaknesses early and verify a hardened baseline. It complements, but does not replace, image scanning, admission enforcement, or runtime security controls.
