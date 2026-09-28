#!/usr/bin/env python3
"""Audit educational Dockerfiles and Kubernetes JSON manifests."""

from __future__ import annotations

import argparse
import json
import re
import shlex
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


def _docker_logical_lines(text: str) -> list[str]:
    escape = "\\"
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if stripped.lower().startswith("# escape="):
            candidate = stripped.split("=", maxsplit=1)[1].strip()
            if candidate in {"\\", "`"}:
                escape = candidate
            break
        if stripped and not stripped.startswith("#"):
            break

    lines: list[str] = []
    pending = ""
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped or (stripped.startswith("#") and not pending):
            continue
        if stripped.endswith(escape):
            pending += stripped[: -len(escape)].rstrip() + " "
            continue
        lines.append((pending + stripped).strip())
        pending = ""
    if pending:
        raise PolicyInputError("Dockerfile ends with an unfinished line continuation")
    return lines


def _docker_assignments(instruction: str, declaration: str) -> list[tuple[str, str]]:
    try:
        tokens = shlex.split(declaration, posix=True)
    except ValueError as exc:
        raise PolicyInputError(f"could not parse {instruction} declaration: {exc}") from exc
    if not tokens:
        return []
    if instruction == "ARG":
        return [tuple(tokens[0].split("=", maxsplit=1))] if "=" in tokens[0] else []
    if all("=" in token for token in tokens):
        return [tuple(token.split("=", maxsplit=1)) for token in tokens]
    return [(tokens[0], " ".join(tokens[1:]))] if len(tokens) > 1 else []


def scan_dockerfile(path: Path, root: Path) -> list[Finding]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyInputError(f"could not read {path}: {exc}") from exc
    artifact = path.relative_to(root).as_posix()
    lines = _docker_logical_lines(text)
    findings: list[Finding] = []

    from_indexes = [index for index, line in enumerate(lines) if line.upper().startswith("FROM ")]
    from_lines = [lines[index] for index in from_indexes]
    if not from_lines:
        findings.append(Finding("DKR001", "high", artifact, "No base image is declared.", "Declare and digest-pin a reviewed FROM image."))
    for line in from_lines:
        image = line.split()[1] if len(line.split()) > 1 else ""
        if not image_is_pinned(image):
            findings.append(
                Finding("DKR001", "high", artifact, "Base image is not pinned by SHA-256 digest.", "Pin every FROM image to a reviewed immutable digest.")
            )

    final_stage = lines[from_indexes[-1] + 1 :] if from_indexes else lines
    user_lines = [line for line in final_stage if line.upper().startswith("USER ")]
    if not user_lines:
        findings.append(Finding("DKR002", "high", artifact, "No runtime USER is declared.", "Set a dedicated non-root runtime user."))
    else:
        user = user_lines[-1].split(maxsplit=1)[1].strip().lower()
        identity = user.split(":", maxsplit=1)[0]
        numeric_identity = re.fullmatch(r"[+-]?\d+", identity)
        if identity == "root" or "$" in identity or (numeric_identity and int(identity) == 0):
            findings.append(Finding("DKR002", "high", artifact, "Container runtime user is root or is not statically non-root.", "Set a dedicated, statically known non-root runtime user."))

    health_lines = [line for line in final_stage if line.upper().startswith("HEALTHCHECK ")]
    last_healthcheck = health_lines[-1].split(maxsplit=1)[1].strip().upper() if health_lines else "NONE"
    if last_healthcheck == "NONE":
        findings.append(Finding("DKR003", "low", artifact, "No HEALTHCHECK is declared.", "Add a bounded health check appropriate for the service."))

    for line in lines:
        instruction = line.split(maxsplit=1)[0].upper()
        if instruction not in {"ENV", "ARG"}:
            continue
        declaration = line.split(maxsplit=1)[1] if len(line.split(maxsplit=1)) == 2 else ""
        for key, value in _docker_assignments(instruction, declaration):
            if not SENSITIVE_NAME_PATTERN.search(key):
                continue
            value = value.strip()
            if value and not value.startswith("$"):
                findings.append(Finding("DKR004", "high", artifact, f"Possible embedded secret in {key}.", "Inject secrets at runtime from an approved secret store."))
    return findings


def _mapping(value: object, context: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise PolicyInputError(f"{context} must be a JSON object")
    return value


def _container_entries(spec: dict[str, object], artifact: str) -> list[tuple[str, dict[str, object]]]:
    containers = spec.get("containers")
    if not isinstance(containers, list) or not containers:
        raise PolicyInputError(f"{artifact}: pod spec must contain a non-empty containers list")
    entries = [("containers", _mapping(item, f"{artifact}: container")) for item in containers]
    for group in ("initContainers", "ephemeralContainers"):
        additional = spec.get(group, [])
        if not isinstance(additional, list):
            raise PolicyInputError(f"{artifact}: {group} must be a list")
        entries.extend((group, _mapping(item, f"{artifact}: {group}")) for item in additional)
    return entries


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
    if pod_spec.get("automountServiceAccountToken") is not False:
        findings.append(Finding("K8S003", "medium", artifact, "Service-account token automount is not disabled.", "Disable token automount unless the workload uses the Kubernetes API."))
    if pod_spec.get("hostNetwork") is True:
        findings.append(Finding("K8S004", "high", artifact, "Workload uses the host network namespace.", "Remove hostNetwork unless an approved exception requires it."))

    for index, (group, container) in enumerate(_container_entries(pod_spec, artifact), start=1):
        name = str(container.get("name") or f"container-{index}")
        location = f"{artifact}#{group}/{name}"
        security = container.get("securityContext")
        security = security if isinstance(security, dict) else {}
        run_as_non_root = security.get("runAsNonRoot", pod_security.get("runAsNonRoot"))
        run_as_user = security.get("runAsUser", pod_security.get("runAsUser"))
        if run_as_non_root is not True or run_as_user == 0:
            findings.append(Finding("K8S001", "high", location, "Container does not enforce non-root execution.", "Require runAsNonRoot and prevent runAsUser 0 at the effective container security context."))
        seccomp = security.get("seccompProfile", pod_security.get("seccompProfile"))
        seccomp = seccomp if isinstance(seccomp, dict) else {}
        if seccomp.get("type") not in {"RuntimeDefault", "Localhost"}:
            findings.append(Finding("K8S002", "medium", location, "Container lacks an approved effective seccomp profile.", "Use RuntimeDefault or an approved Localhost profile without a container override."))
        if not image_is_pinned(container.get("image")):
            findings.append(Finding("K8S005", "high", location, "Image is not pinned by SHA-256 digest.", "Deploy a reviewed image by immutable digest."))
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


def _namespace(document: dict[str, object]) -> str:
    metadata = document.get("metadata")
    metadata = metadata if isinstance(metadata, dict) else {}
    value = metadata.get("namespace")
    return value if isinstance(value, str) and value else "default"


def _is_default_deny(document: dict[str, object]) -> bool:
    spec = document.get("spec")
    if not isinstance(spec, dict) or spec.get("podSelector") != {}:
        return False
    policy_types = spec.get("policyTypes")
    if not isinstance(policy_types, list):
        return False
    ingress_denied = "ingress" not in spec or spec.get("ingress") == []
    egress_denied = "egress" not in spec or spec.get("egress") == []
    return {"Ingress", "Egress"}.issubset(policy_types) and ingress_denied and egress_denied


def _validate_scan_path(path: Path, root: Path) -> None:
    if path.is_symlink():
        raise PolicyInputError(f"symbolic links are not scanned: {path}")
    try:
        path.resolve().relative_to(root)
    except ValueError as exc:
        raise PolicyInputError(f"scan path escapes target directory: {path}") from exc


def scan_directory(root: Path) -> tuple[Finding, ...]:
    requested_root = root.absolute()
    if root.is_symlink() or requested_root != root.resolve():
        raise PolicyInputError(f"scan target must not be a symbolic link or junction: {root}")
    root = root.resolve()
    if not root.is_dir():
        raise PolicyInputError(f"scan target is not a directory: {root}")
    findings: list[Finding] = []
    workload_namespaces: set[str] = set()
    default_deny_namespaces: set[str] = set()
    for path in sorted(root.rglob("Dockerfile*")):
        if path.is_file():
            _validate_scan_path(path, root)
            findings.extend(scan_dockerfile(path, root))
    for path in sorted(root.rglob("*.json")):
        _validate_scan_path(path, root)
        document = load_json(path)
        artifact = path.relative_to(root).as_posix()
        kind = document.get("kind")
        if kind in {"Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "Pod"}:
            workload_namespaces.add(_namespace(document))
            findings.extend(scan_workload(document, artifact))
        elif kind == "NetworkPolicy" and _is_default_deny(document):
            default_deny_namespaces.add(_namespace(document))
    for namespace in sorted(workload_namespaces - default_deny_namespaces):
        findings.append(Finding("K8S011", "medium", namespace, "Namespace lacks an ingress-and-egress default-deny NetworkPolicy.", "Add a default-deny policy in the workload namespace, then allow only required flows."))
    return tuple(sorted(findings, key=lambda item: (SEVERITY_ORDER[item.severity], item.rule_id, item.artifact)))


def _markdown_cell(value: object) -> str:
    return str(value).replace("\\", "\\\\").replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _inline_code(value: object) -> str:
    content = str(value).replace("\r", " ").replace("\n", " ")
    longest_run = max((len(match.group()) for match in re.finditer(r"`+", content)), default=0)
    fence = "`" * max(1, longest_run + 1)
    return f"{fence} {content} {fence}"


def render_report(findings: Sequence[Finding], target_name: str) -> str:
    counts = Counter(item.severity for item in findings)
    lines = [
        "# Container Security Policy Report",
        "",
        "> Educational static analysis only. No image was built, deployed, or executed.",
        "",
        f"Target: {_inline_code(target_name)}",
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
        cells = (finding.rule_id, finding.severity.title(), finding.artifact, finding.message, finding.remediation)
        lines.append("| " + " | ".join(_markdown_cell(cell) for cell in cells) + " |")
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
