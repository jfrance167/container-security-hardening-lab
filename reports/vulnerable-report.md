# Container Security Policy Report

> Educational static analysis only. No image was built, deployed, or executed.

Target: `vulnerable`

Result: **FAIL**

Findings: **15** (high 8, medium 6, low 1)

| Rule | Severity | Artifact | Finding | Remediation |
| --- | --- | --- | --- | --- |
| DKR001 | High | Dockerfile | Base image is not pinned by SHA-256 digest. | Pin every FROM image to a reviewed immutable digest. |
| DKR002 | High | Dockerfile | Container runtime user is root. | Set a dedicated non-root runtime user. |
| DKR004 | High | Dockerfile | Possible embedded secret in API_TOKEN. | Inject secrets at runtime from an approved secret store. |
| K8S001 | High | deployment.json | Pod does not require non-root execution. | Set pod securityContext.runAsNonRoot to true. |
| K8S004 | High | deployment.json | Workload uses the host network namespace. | Remove hostNetwork unless an approved exception requires it. |
| K8S005 | High | deployment.json#app | Image is not pinned by SHA-256 digest. | Deploy a reviewed image by immutable digest. |
| K8S006 | High | deployment.json#app | Privilege escalation is not explicitly disabled. | Set allowPrivilegeEscalation to false. |
| K8S008 | High | deployment.json#app | Container requests privileged mode. | Remove privileged mode and grant only narrowly required capabilities. |
| K8S002 | Medium | deployment.json | Pod lacks an approved seccomp profile. | Set seccompProfile.type to RuntimeDefault or an approved Localhost profile. |
| K8S003 | Medium | deployment.json | Service-account token automount is not disabled. | Disable token automount unless the workload uses the Kubernetes API. |
| K8S007 | Medium | deployment.json#app | Root filesystem is writable. | Set readOnlyRootFilesystem to true and mount only required writable paths. |
| K8S009 | Medium | deployment.json#app | Linux capabilities are not dropped by default. | Set capabilities.drop to ["ALL"] and add back only reviewed capabilities. |
| K8S010 | Medium | deployment.json#app | CPU and memory limits are incomplete. | Define both CPU and memory limits after workload testing. |
| K8S011 | Medium | . | No NetworkPolicy manifest accompanies the workload. | Add default-deny policy and narrowly scoped required flows. |
| DKR003 | Low | Dockerfile | No HEALTHCHECK is declared. | Add a bounded health check appropriate for the service. |
