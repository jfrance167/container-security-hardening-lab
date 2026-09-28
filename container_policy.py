#!/usr/bin/env python3
"""Audit educational Dockerfiles and Kubernetes JSON manifests."""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence


DIGEST_PATTERN = re.compile(r"@sha256:[0-9a-f]{64}$", re.IGNORECASE)
SENSITIVE_NAME_PATTERN = re.compile(
    r"(?:password|passwd|secret|token|api[_-]?key|private[_-]?key)", re.IGNORECASE
)
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


class PolicyInputError(ValueError):
    """Raised when a manifest cannot be safely interpreted."""


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    artifact: str
    message: str
    remediation: str


def image_is_pinned(image: object) -> bool:
    return isinstance(image, str) and DIGEST_PATTERN.search(image) is not None


def scan_dockerfile(path: Path, root: Path) -> list[Finding]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyInputError(f"could not read {path}: {exc}") from exc
    artifact = path.relative_to(root).as_posix()
    lines = [line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    findings: list[Finding] = []

    from_lines = [line for line in lines if line.upper().startswith("FROM ")]
    for line in from_lines:
        image = line.split()[1] if len(line.split()) > 1 else ""
        if not image_is_pinned(image):
            findings.append(
                Finding("DKR001", "high", artifact, "Base image is not pinned by SHA-256 digest.", "Pin every FROM image to a reviewed immutable digest.")
            )

    user_lines = [line for line in lines if line.upper().startswith("USER ")]
    if not user_lines:
        findings.append(Finding("DKR002", "high", artifact, "No runtime USER is declared.", "Set a dedicated non-root runtime user."))
    else:
        user = user_lines[-1].split(maxsplit=1)[1].strip().lower()
        if user in {"0", "root", "0:0", "root:root"}:
            findings.append(Finding("DKR002", "high", artifact, "Container runtime user is root.", "Set a dedicated non-root runtime user."))

    if not any(line.upper().startswith("HEALTHCHECK ") for line in lines):
        findings.append(Finding("DKR003", "low", artifact, "No HEALTHCHECK is declared.", "Add a bounded health check appropriate for the service."))

    for line in lines:
        if not (line.upper().startswith("ENV ") or line.upper().startswith("ARG ")):
            continue
        declaration = line.split(maxsplit=1)[1] if len(line.split(maxsplit=1)) == 2 else ""
        key = re.split(r"[=\s]", declaration, maxsplit=1)[0]
        if SENSITIVE_NAME_PATTERN.search(key) and "=" in declaration:
            value = declaration.split("=", maxsplit=1)[1].strip()
            if value and not value.startswith("$"):
                findings.append(Finding("DKR004", "high", artifact, f"Possible embedded secret in {key}.", "Inject secrets at runtime from an approved secret store."))
    return findings


def _mapping(value: object, context: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise PolicyInputError(f"{context} must be a JSON object")
    return value


def _containers(spec: dict[str, object], artifact: str) -> list[dict[str, object]]:
    value = spec.get("containers")
    if not isinstance(value, list) or not value:
        raise PolicyInputError(f"{artifact}: pod spec must contain a non-empty containers list")
    return [_mapping(item, f"{artifact}: container") for item in value]


def scan_workload(document: dict[str, object], artifact: str) -> list[Finding]:
    kind = document.get("kind")
    if kind not in {"Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "Pod"}:
        return []

    if kind == "Pod":
        pod_spec = _mapping(document.get("spec"), f"{artifact}: spec")
    else:
        spec = _mapping(document.get("spec"), f"{artifact}: spec")
        if kind == "CronJob":
            job_template = _mapping(spec.get("jobTemplate"), f"{artifact}: jobTemplate")
            job_spec = _mapping(job_template.get("spec"), f"{artifact}: jobTemplate.spec")
            template = _mapping(job_spec.get("template"), f"{artifact}: template")
        else:
            template = _mapping(spec.get("template"), f"{artifact}: template")
        pod_spec = _mapping(template.get("spec"), f"{artifact}: pod spec")

    findings: list[Finding] = []
    pod_security = pod_spec.get("securityContext")
    pod_security = pod_security if isinstance(pod_security, dict) else {}
    if pod_security.get("runAsNonRoot") is not True:
        findings.append(Finding("K8S001", "high", artifact, "Pod does not require non-root execution.", "Set pod securityContext.runAsNonRoot to true."))
    seccomp = pod_security.get("seccompProfile")
    seccomp = seccomp if isinstance(seccomp, dict) else {}
    if seccomp.get("type") not in {"RuntimeDefault", "Localhost"}:
        findings.append(Finding("K8S002", "medium", artifact, "Pod lacks an approved seccomp profile.", "Set seccompProfile.type to RuntimeDefault or an approved Localhost profile."))
    if pod_spec.get("automountServiceAccountToken") is not False:
        findings.append(Finding("K8S003", "medium", artifact, "Service-account token automount is not disabled.", "Disable token automount unless the workload uses the Kubernetes API."))
    if pod_spec.get("hostNetwork") is True:
        findings.append(Finding("K8S004", "high", artifact, "Workload uses the host network namespace.", "Remove hostNetwork unless an approved exception requires it."))

    for index, container in enumerate(_containers(pod_spec, artifact), start=1):
        name = str(container.get("name") or f"container-{index}")
        location = f"{artifact}#{name}"
        if not image_is_pinned(container.get("image")):
            findings.append(Finding("K8S005", "high", location, "Image is not pinned by SHA-256 digest.", "Deploy a reviewed image by immutable digest."))
        security = container.get("securityContext")
        security = security if isinstance(security, dict) else {}
        if security.get("allowPrivilegeEscalation") is not False:
            findings.append(Finding("K8S006", "high", location, "Privilege escalation is not explicitly disabled.", "Set allowPrivilegeEscalation to false."))
        if security.get("readOnlyRootFilesystem") is not True:
            findings.append(Finding("K8S007", "medium", location, "Root filesystem is writable.", "Set readOnlyRootFilesystem to true and mount only required writable paths."))
        if security.get("privileged") is True:
            findings.append(Finding("K8S008", "high", location, "Container requests privileged mode.", "Remove privileged mode and grant only narrowly required capabilities."))
        capabilities = security.get("capabilities")
        capabilities = capabilities if isinstance(capabilities, dict) else {}
        dropped = capabilities.get("drop")
        if not isinstance(dropped, list) or "ALL" not in dropped:
            findings.append(Finding("K8S009", "medium", location, "Linux capabilities are not dropped by default.", "Set capabilities.drop to [\"ALL\"] and add back only reviewed capabilities."))
        resources = container.get("resources")
        resources = resources if isinstance(resources, dict) else {}
        limits = resources.get("limits")
        limits = limits if isinstance(limits, dict) else {}
        if not limits.get("cpu") or not limits.get("memory"):
            findings.append(Finding("K8S010", "medium", location, "CPU and memory limits are incomplete.", "Define both CPU and memory limits after workload testing."))
    return findings


def load_json(path: Path) -> dict[str, object]:
    try:
        return _mapping(json.loads(path.read_text(encoding="utf-8")), str(path))
    except (OSError, json.JSONDecodeError) as exc:
        raise PolicyInputError(f"could not read valid JSON from {path}: {exc}") from exc


def scan_directory(root: Path) -> tuple[Finding, ...]:
    root = root.resolve()
    if not root.is_dir():
        raise PolicyInputError(f"scan target is not a directory: {root}")
    findings: list[Finding] = []
    workloads = 0
    network_policies = 0
    for path in sorted(root.rglob("Dockerfile*")):
        if path.is_file():
            findings.extend(scan_dockerfile(path, root))
    for path in sorted(root.rglob("*.json")):
        document = load_json(path)
        artifact = path.relative_to(root).as_posix()
        kind = document.get("kind")
        if kind in {"Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "Pod"}:
            workloads += 1
            findings.extend(scan_workload(document, artifact))
        elif kind == "NetworkPolicy":
            network_policies += 1
    if workloads and not network_policies:
        findings.append(Finding("K8S011", "medium", ".", "No NetworkPolicy manifest accompanies the workload.", "Add default-deny policy and narrowly scoped required flows."))
    return tuple(sorted(findings, key=lambda item: (SEVERITY_ORDER[item.severity], item.rule_id, item.artifact)))


def render_report(findings: Sequence[Finding], target_name: str) -> str:
    counts = Counter(item.severity for item in findings)
    lines = [
        "# Container Security Policy Report",
        "",
        "> Educational static analysis only. No image was built, deployed, or executed.",
        "",
        f"Target: `{target_name}`",
        "",
        f"Result: **{'PASS' if not findings else 'FAIL'}**",
        "",
        f"Findings: **{len(findings)}** (high {counts['high']}, medium {counts['medium']}, low {counts['low']})",
        "",
        "| Rule | Severity | Artifact | Finding | Remediation |",
        "| --- | --- | --- | --- | --- |",
    ]
    if not findings:
        lines.append("| — | — | — | No policy violations detected. | — |")
    for finding in findings:
        lines.append(f"| {finding.rule_id} | {finding.severity.title()} | {finding.artifact} | {finding.message} | {finding.remediation} |")
    lines.append("")
    return "\n".join(lines)


def render_json(findings: Iterable[Finding]) -> str:
    return json.dumps([finding.__dict__ for finding in findings], indent=2, sort_keys=True) + "\n"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", type=Path, help="directory containing Dockerfiles and Kubernetes JSON")
    parser.add_argument("--output", type=Path, help="write the report instead of printing it")
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    parser.add_argument("--fail-on-findings", action="store_true", help="return exit status 1 when findings exist")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        findings = scan_directory(args.target)
    except PolicyInputError as exc:
        print(f"Error: {exc}")
        return 2
    content = render_json(findings) if args.format == "json" else render_report(findings, args.target.name)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(content, encoding="utf-8")
    else:
        print(content)
    return 1 if args.fail_on_findings and findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
