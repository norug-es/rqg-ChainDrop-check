#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import URLError, HTTPError
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen


ALLOWED_SCHEMA = "rqg-ioc-feed/v1"
ALLOWED_KINDS = {
    "sha256",
    "domain",
    "url",
    "ipv4",
    "ethereum_address",
    "ethereum_selector",
    "filename",
    "path",
    "marker",
    "npm_package_version",
    "rsa_fingerprint",
    "contextual_domain",
    "commit_pattern",
    "behavior",
}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SCORE_BY_SEVERITY = {"critical": 100, "high": 75, "medium": 40, "low": 15}
LIFECYCLE_KEYS = ("preinstall", "install", "postinstall", "prepare", "prepublish", "prepublishOnly")
DEFAULT_MAX_TEXT_BYTES = 500_000
DEFAULT_MAX_HASH_BYTES = 25 * 1024 * 1024
DEFAULT_MAX_TARBALL_BYTES = 25 * 1024 * 1024
DEFAULT_MAX_SCAN_FILES = 2000
DEFAULT_TIMEOUT = 20

EXCLUDED_DIRS = {
    ".git",
    "node_modules",
    ".rqg",
    ".venv",
    "venv",
    "__pycache__",
    "dist",
    "build",
    "coverage",
    ".next",
    "out",
}

EXCLUDED_FILES = {
    "app/data/ioc-feed-v1.json",
    "app/data/chaindrop.json",
    "tools/rqg-local-audit.py",
}

EXCLUDED_PATH_PREFIXES = (
    "threat-intel/feeds/",
)

TEXT_EXTS = {
    ".js",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".json",
    ".yaml",
    ".yml",
    ".sh",
    ".ps1",
    ".py",
    ".md",
    ".txt",
    ".toml",
    ".ini",
    ".cfg",
    ".env",
    ".xml",
    ".html",
    ".css",
    ".lock",
}

HIGH_VALUE_PATH_PATTERNS = [
    re.compile(r"(^|/)(package\.json|package-lock\.json|npm-shrinkwrap\.json|pnpm-lock\.yaml|yarn\.lock|bun\.lock)$", re.I),
    re.compile(r"(^|/)(AGENTS|CLAUDE|README)\.md$", re.I),
    re.compile(r"(^|/)(Dockerfile|docker-compose\.ya?ml)$", re.I),
    re.compile(r"(^|/)\.(github/workflows|vscode|claude)/", re.I),
    re.compile(r"\.(m?js|cjs|ts|tsx|py|sh|ps1|ya?ml|json|toml|ini|cfg|env)$", re.I),
]

SUSPICIOUS_FILENAMES = {
    "setup.mjs",
    "math_init.js",
    "Math_Symbol.js",
    "router_runtime.js",
}

SUSPICIOUS_PATH_MARKERS = {
    ".claude/",
    ".vscode/",
    ".github/workflows/",
    ".local/bin/gh-token-monitor.sh",
    ".config/gh-token-monitor/",
    "library/launchagents/com.user.gh-token-monitor.plist",
    ".config/systemd/user/gh-token-monitor.service",
}

KNOWN_CONTENT_MARKERS = {
    "awqhnjewqjkl.icu",
    "npm-cache.com",
    "pypi-get.com",
    "js-mirror.com",
    "thebeautifulmarchoftime",
    "thebeautifulsnadsoftime",
    "IfYouBlockThisAPIKeyItWillCrashTheLiveProductionServersOfAllThirdPartyClients",
    "0xE1f2395ee43e45A1556EC6438a88c31B83493103",
    "0x53ed5143",
    "SessionStart",
    "_NODE_RUNTIME_INIT=1",
    "tmp.dpkg_14527.lock",
    "gh-token-monitor",
}

GENERIC_PATTERNS = [
    (
        "RQG-GEN-001",
        r"\b(eval\s*\(|new\s+Function\s*\(|Function\s*\()",
        "critical",
        "Dynamic code execution primitive",
        "eval / Function detected",
    ),
    (
        "RQG-GEN-002",
        r"(curl[^\n]{0,140}\|\s*(bash|sh)|Invoke-WebRequest[^\n]{0,140}\|\s*powershell|powershell[^\n]{0,140}-enc|FromBase64String\s*\()",
        "critical",
        "Bootstrap or encoded shell execution",
        "shell bootstrap or encoded PowerShell detected",
    ),
    (
        "RQG-GEN-003",
        r"(Buffer\.from\([^\n]{0,220}base64|atob\s*\(|b64decode\s*\()",
        "high",
        "Base64 decoding near execution path",
        "base64 decoding primitive detected",
    ),
    (
        "RQG-GEN-004",
        r"(child_process|execSync\s*\(|spawnSync\s*\(|execFile\s*\()",
        "high",
        "Process spawning primitive",
        "child process execution detected",
    ),
    (
        "RQG-GEN-005",
        r"(fetch\s*\(|axios\.[a-z]+\(|https?://)",
        "low",
        "Network access present",
        "network call detected",
    ),
]


@dataclass
class Finding:
    rule_id: str
    severity: str
    title: str
    path: str
    evidence: str
    confidence: str = "high"
    remediation: str = ""
    line: int | None = None

    def as_dict(self) -> dict[str, Any]:
        data = {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "title": self.title,
            "path": self.path,
            "evidence": self.evidence,
            "confidence": self.confidence,
            "remediation": self.remediation,
        }
        if self.line is not None:
            data["line"] = self.line
        return data


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="RQG portable local audit. Scans a repository, downloads IoC feeds, and reports vulnerability signals.",
    )
    parser.add_argument("repo_path", nargs="?", default=".", help="Repository path to scan")
    parser.add_argument(
        "--feed-url",
        action="append",
        default=[],
        help="HTTPS URL of an RQG IoC feed. Can be passed multiple times.",
    )
    parser.add_argument(
        "--feed-file",
        action="append",
        default=[],
        help="Local feed file path. Can be passed multiple times.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON instead of a human-readable report.",
    )
    parser.add_argument(
        "--skip-registry",
        action="store_true",
        help="Disable npm registry integrity checks.",
    )
    parser.add_argument(
        "--registry",
        default=os.getenv("RQG_NPM_REGISTRY", "https://registry.npmjs.org"),
        help="npm registry base URL for registry integrity checks.",
    )
    parser.add_argument(
        "--tarball-host",
        action="append",
        default=[],
        help="Allowed tarball host. Can be passed multiple times. Defaults to the registry host.",
    )
    parser.add_argument(
        "--max-files",
        type=int,
        default=DEFAULT_MAX_SCAN_FILES,
        help="Maximum number of files to inspect deeply.",
    )
    parser.add_argument(
        "--max-text-bytes",
        type=int,
        default=DEFAULT_MAX_TEXT_BYTES,
        help="Maximum bytes to read per file for text scanning.",
    )
    parser.add_argument(
        "--max-hash-bytes",
        type=int,
        default=DEFAULT_MAX_HASH_BYTES,
        help="Maximum bytes to hash per file for exact hash IoCs.",
    )
    parser.add_argument(
        "--max-tarball-bytes",
        type=int,
        default=DEFAULT_MAX_TARBALL_BYTES,
        help="Maximum npm tarball size to inspect in memory.",
    )
    return parser.parse_args()


def normalize_relpath(path: Path) -> str:
    return path.as_posix().lstrip("./")


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8", errors="replace"))


def validate_feed(feed: dict[str, Any]) -> dict[str, Any]:
    if feed.get("schema") != ALLOWED_SCHEMA:
        raise ValueError("unsupported schema")
    if not feed.get("feed_id") or not feed.get("version") or not feed.get("generated_at"):
        raise ValueError("metadata")
    indicators = feed.get("indicators")
    if not isinstance(indicators, list):
        raise ValueError("indicators required")
    seen: set[tuple[str, str]] = set()
    for item in indicators:
        if not isinstance(item, dict):
            raise ValueError("invalid indicator")
        kind = str(item.get("kind") or "").strip()
        value = str(item.get("value") or "").strip()
        severity = str(item.get("severity") or "high").strip().lower()
        if kind not in ALLOWED_KINDS:
            raise ValueError(f"unsupported kind: {kind}")
        if severity not in SEVERITY_ORDER:
            raise ValueError("severity")
        if not value or len(value) >= 2048:
            raise ValueError("value")
        key = (kind.lower(), value.lower())
        if key in seen:
            raise ValueError(f"duplicate {key}")
        seen.add(key)
        if kind == "sha256" and not re.fullmatch(r"[0-9a-fA-F]{64}", value):
            raise ValueError("sha256")
        if not item.get("source"):
            raise ValueError("source required")
    return feed


def load_feed_from_file(path: Path, source: str) -> dict[str, Any]:
    return {"source": source, "feed": validate_feed(read_json(path))}


def fetch_json(url: str, timeout: int = DEFAULT_TIMEOUT) -> Any:
    req = Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "RQG-Local-Audit/1.0.0",
        },
    )
    with urlopen(req, timeout=timeout) as response:
        raw = response.read()
        if not raw:
            return None
        return json.loads(raw.decode("utf-8", errors="replace"))


def load_feed_from_url(url: str) -> dict[str, Any]:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ValueError("HTTPS required")
    return {"source": url, "feed": validate_feed(fetch_json(url))}


def resolve_feed_sources(args: argparse.Namespace) -> list[str]:
    urls = list(args.feed_url or [])
    env_urls = [x.strip() for x in os.getenv("RQG_IOC_FEEDS", "").split(",") if x.strip()]
    for url in env_urls:
        if url not in urls:
            urls.append(url)
    return urls


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, str, str]] = set()
    out: list[Finding] = []
    for finding in findings:
        key = (finding.rule_id, finding.path, finding.evidence, finding.severity)
        if key in seen:
            continue
        seen.add(key)
        out.append(finding)
    out.sort(key=lambda item: (SEVERITY_ORDER.get(item.severity, 9), item.path, item.rule_id, item.line or 0))
    return out


def score_from_findings(findings: list[Finding]) -> int:
    if not findings:
        return 0
    severities = {f.severity for f in findings}
    if "critical" in severities:
        return 100
    if "high" in severities:
        return 75
    if "medium" in severities:
        return 40
    return 15


def verdict_from_score(score: int) -> str:
    if score >= 90:
        return "QUARANTINE"
    if score >= 60:
        return "REVIEW"
    if score > 0:
        return "LOW"
    return "CLEAN"


def find_line(text: str, needle: str) -> int | None:
    lower = needle.lower()
    for idx, line in enumerate(text.splitlines(), start=1):
        if lower in line.lower():
            return idx
    return None


def regex_line(text: str, pattern: str) -> int | None:
    m = re.search(pattern, text, re.I | re.M)
    if not m:
        return None
    return text.count("\n", 0, m.start()) + 1


def should_scan_text(path: Path, size: int, max_text_bytes: int) -> bool:
    if size <= max_text_bytes:
        return True
    ext = path.suffix.lower()
    if ext in TEXT_EXTS:
        return True
    if path.name in {"Dockerfile", "Makefile", "LICENSE", "README", "README.md"}:
        return True
    return False


def safe_read_bytes(path: Path, limit: int | None = None) -> bytes:
    with path.open("rb") as handle:
        if limit is None:
            return handle.read()
        return handle.read(limit)


def sha256_file(path: Path, max_bytes: int) -> tuple[str | None, int]:
    size = 0
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > max_bytes:
                return None, size
            digest.update(chunk)
    return digest.hexdigest(), size


def add_finding(
    findings: list[Finding],
    seen: set[tuple[str, str, str, str]],
    rule_id: str,
    severity: str,
    title: str,
    path: str,
    evidence: str,
    remediation: str,
    confidence: str = "high",
    line: int | None = None,
) -> None:
    key = (rule_id, path, evidence, severity)
    if key in seen:
        return
    seen.add(key)
    findings.append(
        Finding(
            rule_id=rule_id,
            severity=severity,
            title=title,
            path=path,
            evidence=evidence,
            remediation=remediation,
            confidence=confidence,
            line=line,
        )
    )


def is_excluded(rel: str, extra_excludes: set[str] | None = None) -> bool:
    rel_l = rel.lower()
    if rel_l in EXCLUDED_FILES:
        return True
    if extra_excludes and rel_l in extra_excludes:
        return True
    if any(rel_l.startswith(prefix) for prefix in EXCLUDED_PATH_PREFIXES):
        return True
    if rel_l.startswith(".git/") or rel_l == ".git":
        return True
    for part in rel_l.split("/"):
        if part in EXCLUDED_DIRS:
            return True
    return False


def is_high_value_candidate(rel: str) -> bool:
    rel_norm = rel.replace("\\", "/")
    return any(pattern.search(rel_norm) for pattern in HIGH_VALUE_PATH_PATTERNS)


def iter_repo_files(root: Path, extra_excludes: set[str] | None = None) -> list[Path]:
    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        current = Path(dirpath)
        rel_dir = normalize_relpath(current.relative_to(root)) if current != root else ""
        dirnames[:] = [d for d in dirnames if not is_excluded(f"{rel_dir}/{d}" if rel_dir else d, extra_excludes)]
        for filename in filenames:
            full = current / filename
            rel = normalize_relpath(full.relative_to(root))
            if is_excluded(rel, extra_excludes):
                continue
            files.append(full)
    files.sort(key=lambda p: normalize_relpath(p.relative_to(root)))
    return files


def looks_like_lifecycle_script(value: str) -> bool:
    text = value.lower()
    return any(token in text for token in ("setup.mjs", "math_init.js", "router_runtime.js", "eval(", "curl ", "wget ", "invoke-webrequest", "powershell", "frombase64string", "buffer.from", "atob("))


def package_spec_name(spec: str) -> tuple[str, str] | None:
    spec = spec.strip()
    if "@" not in spec:
        return None
    if spec.startswith("@"):
        idx = spec.rfind("@")
    else:
        idx = spec.find("@")
    if idx <= 0:
        return None
    return spec[:idx], spec[idx + 1 :]


def versionish_match(declared: str, target_version: str) -> bool:
    decl = declared.strip().lower()
    target = target_version.strip().lower()
    if not decl or not target:
        return False
    decl = re.sub(r"^[\^~<>=\s]+", "", decl)
    return target == decl or target in decl or decl in target


def match_feed_indicator(
    rel: str,
    text: str,
    digest: str | None,
    indicators: list[dict[str, Any]],
    findings: list[Finding],
    seen: set[tuple[str, str, str, str]],
) -> None:
    lower_text = text.lower()
    rel_norm = rel.lower()
    basename = Path(rel).name.lower()
    for ind in indicators:
        kind = str(ind.get("kind") or "").strip()
        value = str(ind.get("value") or "").strip()
        severity = str(ind.get("severity") or "high").strip().lower()
        source = str(ind.get("source") or "").strip()
        evidence = value
        remediation = "Indicador activo del feed. Revisa contención y procedencia antes de confiar en el repo."
        matched = False
        if kind == "sha256" and digest and digest.lower() == value.lower():
            matched = True
        elif kind in {"filename"} and basename == value.lower():
            matched = True
        elif kind in {"path"} and value.lower().replace("\\", "/") in rel_norm:
            matched = True
        elif kind in {"domain", "contextual_domain", "url", "marker", "ethereum_address", "ethereum_selector", "rsa_fingerprint", "commit_pattern"} and value.lower() in lower_text:
            matched = True
        elif kind == "behavior":
            pieces = [p for p in re.split(r"[^a-zA-Z0-9_\.]+", value.lower()) if p]
            if pieces and all(piece in lower_text for piece in pieces):
                matched = True
        elif kind == "ipv4" and value in lower_text:
            matched = True
        elif kind == "npm_package_version":
            if value.lower() in lower_text:
                matched = True
            else:
                spec = package_spec_name(value)
                if spec:
                    pkg, ver = spec
                    if pkg.lower() in lower_text and ver.lower() in lower_text:
                        matched = True
        if matched:
            line = None
            if kind in {"filename", "path"}:
                line = 1
            else:
                line = find_line(text, value) or regex_line(text, re.escape(value))
            add_finding(
                findings,
                seen,
                "RQG-FEED-001" if kind != "npm_package_version" else "RQG-FEED-PKG",
                severity,
                f"IoC activo: {kind}",
                rel,
                evidence,
                remediation,
                confidence="very-high",
                line=line,
            )


def scan_text_for_patterns(rel: str, text: str, findings: list[Finding], seen: set[tuple[str, str, str, str]]) -> None:
    lower = text.lower()
    rel_l = rel.lower()

    for marker in sorted(KNOWN_CONTENT_MARKERS):
        if marker.lower() in lower or marker.lower() in rel_l:
            add_finding(
                findings,
                seen,
                "RQG-MARK-001",
                "critical",
                "Known ChainDrop marker",
                rel,
                marker,
                "Aísla el repositorio y verifica si la cadena llegó a ejecutarse.",
                confidence="very-high",
                line=find_line(text, marker),
            )

    for rule_id, pattern, severity, title, evidence_hint in GENERIC_PATTERNS:
        line = regex_line(text, pattern)
        if line is not None:
            evidence = re.search(pattern, text, re.I | re.M).group(0)  # type: ignore[union-attr]
            add_finding(
                findings,
                seen,
                rule_id,
                severity,
                title,
                rel,
                evidence,
                evidence_hint,
                line=line,
            )

    if "fetch(" in lower and "eval(" in lower:
        add_finding(
            findings,
            seen,
            "RQG-BEH-001",
            "critical",
            "Fetch-to-eval flow",
            rel,
            "fetch + eval in same file",
            "Revisa el flujo de respuesta remota a ejecución dinámica.",
            confidence="high",
            line=find_line(text, "eval(") or find_line(text, "fetch("),
        )

    if "sessionstart" in lower or "folderopen" in lower:
        add_finding(
            findings,
            seen,
            "RQG-IDE-001",
            "critical",
            "IDE or agent startup hook",
            rel,
            "SessionStart / folderOpen",
            "No confíes en hooks de IDE/agent sin revisión manual.",
            confidence="high",
            line=find_line(text, "SessionStart") or find_line(text, "folderOpen"),
        )


def scan_package_manifests(
    manifests: dict[str, dict[str, Any]],
    files: dict[str, str],
    findings: list[Finding],
    seen: set[tuple[str, str, str, str]],
) -> None:
    for rel, manifest in manifests.items():
        scripts = manifest.get("scripts") or {}
        if not isinstance(scripts, dict):
            continue
        for key in LIFECYCLE_KEYS:
            value = scripts.get(key)
            if not value:
                continue
            severity = "critical" if looks_like_lifecycle_script(str(value)) else "warning"
            # Keep bare lifecycle presence visible even if it is not malicious by itself.
            add_finding(
                findings,
                seen,
                "RQG-PKG-LIFECYCLE",
                "high" if severity == "critical" else "low",
                f"Lifecycle script present: {key}",
                rel,
                str(value),
                "Verifica que el script no se use para bootstrap, persistencia o ejecución remota.",
                confidence="high",
                line=find_line(files.get(rel, ""), key),
            )
            if severity == "critical":
                add_finding(
                    findings,
                    seen,
                    "RQG-PKG-LIFECYCLE-RISK",
                    "critical",
                    f"Suspicious lifecycle script: {key}",
                    rel,
                    str(value),
                    "No instales dependencias hasta revisar el script y el origen del cambio.",
                    confidence="high",
                    line=find_line(files.get(rel, ""), str(value)),
                )


def scan_package_versions(
    manifests: dict[str, dict[str, Any]],
    files: dict[str, str],
    indicators: list[dict[str, Any]],
    findings: list[Finding],
    seen: set[tuple[str, str, str, str]],
) -> None:
    package_specs = [ind["value"] for ind in indicators if ind.get("kind") == "npm_package_version"]
    for rel, manifest in manifests.items():
        manifest_text = files.get(rel, "")
        all_deps: dict[str, Any] = {}
        for group in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            values = manifest.get(group) or {}
            if isinstance(values, dict):
                for name, version in values.items():
                    all_deps[f"{name}@{version}"] = (name, str(version), group)
        for spec in package_specs:
            pkg = package_spec_name(spec)
            if not pkg:
                continue
            pkg_name, pkg_version = pkg
            if spec.lower() in manifest_text.lower():
                add_finding(
                    findings,
                    seen,
                    "RQG-FEED-PKG",
                    "critical",
                    f"Feed package/version present: {spec}",
                    rel,
                    spec,
                    "No instales esta versión hasta validar el feed y el origen del paquete.",
                    confidence="very-high",
                    line=find_line(manifest_text, spec),
                )
                continue
            for declared_name, declared_version, group in all_deps.values():
                if declared_name.lower() == pkg_name.lower() and versionish_match(declared_version, pkg_version):
                    add_finding(
                        findings,
                        seen,
                        "RQG-FEED-PKG",
                        "critical",
                        f"Feed package/version present: {spec}",
                        rel,
                        f"{declared_name}@{declared_version} ({group})",
                        "No instales esta versión hasta validar el feed y el origen del paquete.",
                        confidence="very-high",
                        line=find_line(manifest_text, declared_name) or find_line(manifest_text, declared_version),
                    )


def find_package_manifests(files: list[Path], root: Path) -> dict[str, dict[str, Any]]:
    manifests: dict[str, dict[str, Any]] = {}
    for file in files:
        if file.name != "package.json":
            continue
        rel = normalize_relpath(file.relative_to(root))
        try:
            manifests[rel] = read_json(file)
        except Exception:
            continue
    return manifests


def scan_git_commits(root: Path, indicators: list[dict[str, Any]], findings: list[Finding], seen: set[tuple[str, str, str, str]]) -> None:
    commit_patterns = [ind["value"] for ind in indicators if ind.get("kind") == "commit_pattern"]
    if not commit_patterns:
        return
    git_dir = root / ".git"
    if not git_dir.exists():
        return
    try:
        proc = subprocess.run(
            [
                "git",
                "-C",
                str(root),
                "log",
                "--all",
                "--pretty=format:%H%x09%s%x09%b",
                "--max-count=500",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=20,
        )
    except Exception:
        return
    if proc.returncode != 0 or not proc.stdout.strip():
        return
    log_text = proc.stdout
    for pat in commit_patterns:
        try:
            if re.search(pat, log_text, re.I | re.M):
                add_finding(
                    findings,
                    seen,
                    "RQG-COMMIT-001",
                    "high",
                    "Commit pattern matched",
                    "git log",
                    pat,
                    "Revisa el historial que introdujo el patrón y confirma si fue un cambio legítimo.",
                    confidence="high",
                    line=regex_line(log_text, pat),
                )
        except re.error:
            if pat.lower() in log_text.lower():
                add_finding(
                    findings,
                    seen,
                    "RQG-COMMIT-001",
                    "high",
                    "Commit pattern matched",
                    "git log",
                    pat,
                    "Revisa el historial que introdujo el patrón y confirma si fue un cambio legítimo.",
                    confidence="high",
                    line=find_line(log_text, pat),
                )


def fetch_packument(registry: str, package_name: str) -> dict[str, Any] | None:
    url = f"{registry.rstrip('/')}/{quote(package_name, safe='')}"
    try:
        data = fetch_json(url)
        if isinstance(data, dict):
            return data
    except HTTPError as exc:
        if exc.code == 404:
            return None
        raise
    return None


def sha_ok(integrity: str | None, blob: bytes) -> bool | None:
    if not integrity:
        return None
    for token in str(integrity).split():
        if "-" not in token:
            continue
        algo, expected = token.split("-", 1)
        algo = algo.lower()
        if algo not in {"sha256", "sha384", "sha512"}:
            continue
        try:
            if base64.b64encode(hashlib.new(algo, blob).digest()).decode() == expected:
                return True
        except Exception:
            continue
    return False


def safe_tar_inspect(blob: bytes, max_text_bytes: int) -> tuple[dict[str, Any], dict[str, Any] | None, list[Finding]]:
    stats = {"members": 0, "unpacked_bytes": 0, "unsafe_paths": 0, "text_files_scanned": 0}
    package_manifest: dict[str, Any] | None = None
    findings: list[Finding] = []
    try:
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tf:
            for member in tf:
                stats["members"] += 1
                name = member.name.replace("\\", "/")
                if name.startswith("/") or ".." in name.split("/"):
                    stats["unsafe_paths"] += 1
                    continue
                if not member.isfile():
                    continue
                stats["unpacked_bytes"] += max(0, member.size)
                if stats["unpacked_bytes"] > DEFAULT_MAX_TARBALL_BYTES * 4:
                    raise ValueError("tar unpacked size limit exceeded")
                if name in {"package/package.json", "package.json"} and member.size <= 2_000_000:
                    handle = tf.extractfile(member)
                    if handle:
                        package_manifest = json.loads(handle.read().decode("utf-8", errors="replace"))
                if stats["text_files_scanned"] < 250 and member.size <= max_text_bytes and re.search(r"\.(m?js|cjs|ts|json|ya?ml|sh|ps1)$", name, re.I):
                    handle = tf.extractfile(member)
                    if not handle:
                        continue
                    raw = handle.read()
                    text = raw.decode("utf-8", errors="ignore")
                    stats["text_files_scanned"] += 1
                    if re.search(r"(gh-token-monitor|Runner\.Worker|/proc/.{0,80}/mem)", name + "\n" + text, re.I | re.M):
                        findings.append(
                            Finding(
                                rule_id="RQG-REG-ART-001",
                                severity="critical",
                                title="Suspicious npm artifact behavior",
                                path=f"npm-tar:{name}",
                                evidence=re.search(r"(gh-token-monitor|Runner\.Worker|/proc/.{0,80}/mem)", name + "\n" + text, re.I | re.M).group(0),  # type: ignore[union-attr]
                                confidence="very-high",
                                remediation="No instales el artefacto. Revisa si el paquete intenta persistencia o scraping de credenciales.",
                            )
                        )
    except Exception as exc:
        stats["error"] = str(exc)[:180]
    return stats, package_manifest, findings


def security_diff(source: dict[str, Any] | None, artifact: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not source or not artifact:
        return []
    out: list[dict[str, Any]] = []
    source_scripts = source.get("scripts") or {}
    artifact_scripts = artifact.get("scripts") or {}
    for key in LIFECYCLE_KEYS:
        sv = source_scripts.get(key) if isinstance(source_scripts, dict) else None
        av = artifact_scripts.get(key) if isinstance(artifact_scripts, dict) else None
        if sv != av and av is not None:
            out.append(
                {
                    "type": "lifecycle_script_mismatch",
                    "field": f"scripts.{key}",
                    "source": sv,
                    "artifact": av,
                    "severity": "critical" if key in {"preinstall", "install", "postinstall"} else "high",
                }
            )
    for group in ("dependencies", "optionalDependencies"):
        source_deps = source.get(group) or {}
        artifact_deps = artifact.get(group) or {}
        if not isinstance(source_deps, dict) or not isinstance(artifact_deps, dict):
            continue
        for name, value in artifact_deps.items():
            if name not in source_deps:
                out.append(
                    {
                        "type": "dependency_added_in_artifact",
                        "field": f"{group}.{name}",
                        "source": None,
                        "artifact": value,
                        "severity": "critical"
                        if group == "optionalDependencies" and isinstance(value, str) and ("github:" in value or "github.com" in value)
                        else "high",
                    }
                )
            elif source_deps.get(name) != value:
                out.append(
                    {
                        "type": "dependency_range_mismatch",
                        "field": f"{group}.{name}",
                        "source": source_deps.get(name),
                        "artifact": value,
                        "severity": "high",
                    }
                )
    return out


def inspect_npm_package(
    registry: str,
    package_manifest: dict[str, Any],
    manifest_path: str,
    source_manifest: dict[str, Any],
    tarball_hosts: set[str],
    max_text_bytes: int,
    max_tarball_bytes: int,
    findings: list[Finding],
    seen: set[tuple[str, str, str, str]],
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "enabled": True,
        "status": "not_applicable",
        "packages_checked": 0,
        "versions_checked": 0,
        "mismatches": 0,
        "findings": [],
        "packages": [],
        "manifest_path": manifest_path,
    }
    package_name = str(package_manifest.get("name") or "").strip()
    if not package_name or package_manifest.get("private") is True:
        result["reason"] = "manifest is private or has no npm package name"
        return result

    source_version = str(package_manifest.get("version") or "").strip()
    packument = fetch_packument(registry, package_name)
    if not packument:
        result.update(status="not_published", package_name=package_name)
        return result

    versions = packument.get("versions") or {}
    latest = (packument.get("dist-tags") or {}).get("latest")
    targets: list[str] = []
    for version in (source_version, latest):
        if version and version in versions and version not in targets:
            targets.append(version)
    if not targets:
        result.update(status="published_but_version_unresolved", package_name=package_name)
        return result

    result.update(status="checked", packages_checked=1, package_name=package_name)
    for version in targets[:2]:
        meta = versions.get(version) or {}
        dist = meta.get("dist") or {}
        tar_url = dist.get("tarball")
        item: dict[str, Any] = {
            "name": package_name,
            "version": version,
            "manifest_path": manifest_path,
            "gitHead": meta.get("gitHead"),
            "integrity_present": bool(dist.get("integrity")),
            "registry_signatures_present": bool(dist.get("signatures")),
            "provenance_metadata_present": bool(dist.get("attestations")),
        }
        result["packages"].append(item)
        if not tar_url:
            item["status"] = "missing_tarball"
            continue
        host = (urlparse(tar_url).hostname or "").lower()
        if host not in tarball_hosts:
            findings.append(
                Finding(
                    rule_id="RQG-REG-SSRF",
                    severity="critical",
                    title="Registry tarball host not allowed",
                    path=f"npm:{package_name}@{version}",
                    evidence=host,
                    confidence="very-high",
                    remediation="No descargues el artefacto desde un host no aprobado.",
                )
            )
            continue
        try:
            req = Request(
                tar_url,
                headers={"User-Agent": "RQG-Local-Audit/1.0.0", "Accept": "application/octet-stream"},
            )
            with urlopen(req, timeout=DEFAULT_TIMEOUT) as response:
                blob = response.read(max_tarball_bytes + 1)
        except Exception as exc:
            item["status"] = f"tarball_error: {str(exc)[:120]}"
            continue
        if len(blob) > max_tarball_bytes:
            item["status"] = "tarball_too_large"
            continue
        item["tarball_bytes"] = len(blob)
        item["sri_valid"] = sha_ok(dist.get("integrity"), blob)
        item["sha1_valid"] = hashlib.sha1(blob).hexdigest() == dist.get("shasum") if dist.get("shasum") else None
        tarstats, artifact, tar_findings = safe_tar_inspect(blob, max_text_bytes)
        item["tar"] = tarstats
        item["security_diffs"] = security_diff(source_manifest, artifact)
        result["versions_checked"] += 1
        result["findings"].extend([f.as_dict() for f in tar_findings])
        if item["sri_valid"] is False or item["sha1_valid"] is False:
            findings.append(
                Finding(
                    rule_id="RQG-REG-001",
                    severity="critical",
                    title=f"npm tarball integrity mismatch: {package_name}@{version}",
                    path=f"npm:{package_name}@{version}",
                    evidence="dist.integrity/shasum mismatch",
                    confidence="very-high",
                    remediation="No instales. Verifica la metadata desde un registry y red limpios.",
                )
            )
        if tarstats.get("unsafe_paths"):
            findings.append(
                Finding(
                    rule_id="RQG-REG-002",
                    severity="critical",
                    title="Unsafe paths inside npm tarball",
                    path=f"npm:{package_name}@{version}",
                    evidence=str(tarstats["unsafe_paths"]),
                    confidence="very-high",
                    remediation="No extraigas ni instales el tarball.",
                )
            )
        if artifact and (artifact.get("name") != package_name or str(artifact.get("version")) != version):
            findings.append(
                Finding(
                    rule_id="RQG-REG-003",
                    severity="critical",
                    title="Packument ↔ tarball metadata mismatch",
                    path=f"npm:{package_name}@{version}",
                    evidence=f"artifact={artifact.get('name')}@{artifact.get('version')}",
                    confidence="very-high",
                    remediation="No instales; metadata y artefacto divergen.",
                )
            )
        for diff in item.get("security_diffs") or []:
            findings.append(
                Finding(
                    rule_id="RQG-REG-006",
                    severity=str(diff.get("severity") or "high"),
                    title=f"Registry artifact differs from source: {diff.get('field')}",
                    path=f"npm:{package_name}@{version}",
                    evidence=f"source={diff.get('source')!r}; artifact={diff.get('artifact')!r}",
                    confidence="very-high",
                    remediation="No instales. Revisa quién publicó la versión y la divergencia del tarball.",
                )
            )

        for diff in item.get("security_diffs") or []:
            if diff.get("severity") == "critical":
                result["findings"].append(diff)
        if any(f.rule_id == "RQG-REG-001" for f in findings):
            result["status"] = "checked"
    result["mismatches"] = len(result["findings"])
    return result


def inspect_registry(
    root: Path,
    manifests: dict[str, dict[str, Any]],
    files: dict[str, str],
    args: argparse.Namespace,
    findings: list[Finding],
    seen: set[tuple[str, str, str, str]],
) -> dict[str, Any]:
    if args.skip_registry:
        return {
            "enabled": False,
            "status": "disabled",
            "packages_checked": 0,
            "versions_checked": 0,
            "mismatches": 0,
            "findings": [],
            "packages": [],
        }
    if not manifests:
        return {
            "enabled": True,
            "status": "not_applicable",
            "packages_checked": 0,
            "versions_checked": 0,
            "mismatches": 0,
            "findings": [],
            "packages": [],
        }

    registry = args.registry.rstrip("/")
    tarball_hosts = {urlparse(registry).hostname or "registry.npmjs.org"}
    tarball_hosts.update({x.strip().lower() for x in args.tarball_host if x.strip()})
    package_results: list[dict[str, Any]] = []
    aggregated = {
        "enabled": True,
        "status": "checked",
        "packages_checked": 0,
        "versions_checked": 0,
        "mismatches": 0,
        "findings": [],
        "packages": [],
        "package_results": [],
    }
    for rel, manifest in list(manifests.items())[:25]:
        source_manifest = manifest
        result = inspect_npm_package(
            registry,
            manifest,
            rel,
            source_manifest,
            tarball_hosts,
            args.max_text_bytes,
            args.max_tarball_bytes,
            findings,
            seen,
        )
        package_results.append(result)
        aggregated["package_results"].append(result)
        aggregated["packages_checked"] += int(result.get("packages_checked") or 0)
        aggregated["versions_checked"] += int(result.get("versions_checked") or 0)
        aggregated["mismatches"] += int(result.get("mismatches") or 0)
        aggregated["findings"].extend(result.get("findings") or [])
        aggregated["packages"].extend(result.get("packages") or [])
    if not aggregated["packages_checked"]:
        aggregated["status"] = "not_applicable"
    return aggregated


def scan_repo(
    root: Path,
    args: argparse.Namespace,
    feeds: list[dict[str, Any]],
    extra_excludes: set[str] | None = None,
) -> dict[str, Any]:
    files = iter_repo_files(root, extra_excludes)
    manifests = find_package_manifests(files, root)
    file_texts: dict[str, str] = {}
    findings: list[Finding] = []
    seen: set[tuple[str, str, str, str]] = set()
    feed_indicators: list[dict[str, Any]] = []
    feed_sources: list[dict[str, Any]] = []

    for feed_source in feeds:
        feed_sources.append(
            {
                "source": feed_source["source"],
                "feed_id": feed_source["feed"]["feed_id"],
                "version": feed_source["feed"]["version"],
                "indicators": len(feed_source["feed"].get("indicators") or []),
            }
        )
        feed_indicators.extend(feed_source["feed"].get("indicators") or [])

    feed_indicators = sorted(feed_indicators, key=lambda item: (str(item.get("kind") or ""), str(item.get("value") or "")))

    scanned = 0
    for file in files:
        rel = normalize_relpath(file.relative_to(root))
        size = file.stat().st_size
        if scanned >= args.max_files:
            break
        scanned += 1

        digest: str | None = None
        if size <= args.max_hash_bytes:
            digest, _ = sha256_file(file, args.max_hash_bytes)
        if should_scan_text(file, size, args.max_text_bytes):
            raw = safe_read_bytes(file, args.max_text_bytes)
            text = raw.decode("utf-8", errors="ignore")
            file_texts[rel] = text

            if file.name in SUSPICIOUS_FILENAMES:
                add_finding(
                    findings,
                    seen,
                    "RQG-FILE-001",
                    "critical",
                    "Suspicious filename",
                    rel,
                    file.name,
                    "Revisa la procedencia del archivo y elimina el artefacto si no forma parte del proyecto.",
                    confidence="high",
                    line=1,
                )

            for marker in SUSPICIOUS_PATH_MARKERS:
                if marker in rel.lower():
                    add_finding(
                        findings,
                        seen,
                        "RQG-PATH-001",
                        "high",
                        "Suspicious persistence or IDE path",
                        rel,
                        marker,
                        "Revisa si es un archivo de desarrollo legítimo o una vía de persistencia.",
                        confidence="high",
                        line=1,
                    )

            if is_high_value_candidate(rel):
                scan_text_for_patterns(rel, text, findings, seen)
                match_feed_indicator(rel, text, digest, feed_indicators, findings, seen)
        elif digest:
            match_feed_indicator(rel, "", digest, feed_indicators, findings, seen)

    scan_package_manifests(manifests, file_texts, findings, seen)
    scan_package_versions(manifests, file_texts, feed_indicators, findings, seen)
    scan_git_commits(root, feed_indicators, findings, seen)
    registry = inspect_registry(root, manifests, file_texts, args, findings, seen)

    findings = dedupe_findings(findings)
    score = score_from_findings(findings)
    if registry.get("mismatches"):
        score = max(score, 100 if any(f.severity == "critical" for f in findings) else 75)

    report = {
        "engine_version": "rqg-local-audit-1.0.0",
        "repo": {
            "path": str(root),
            "name": root.name,
        },
        "feeds": {
            "sources": feed_sources,
            "indicators": len(feed_indicators),
        },
        "stats": {
            "files_scanned": scanned,
            "package_manifests": len(manifests),
            "registry_versions_checked": registry.get("versions_checked", 0),
            "registry_mismatches": registry.get("mismatches", 0),
        },
        "score": score,
        "verdict": verdict_from_score(score),
        "confidence": "Alta" if scanned > 10 else "Media",
        "findings": [f.as_dict() for f in findings],
        "registry_integrity": registry,
        "limitations": [
            "El análisis es estático: no ejecuta el repositorio.",
            "Los archivos muy grandes pueden quedar fuera de la inspección de texto.",
            "Las coincidencias de feed dependen de la calidad del feed remoto.",
        ],
    }
    return report


def print_human(report: dict[str, Any]) -> None:
    print()
    print("============================================")
    print(" RQG Local Audit v1.0")
    print("============================================")
    print(f"Repo: {report['repo']['path']}")
    print(f"Feeds: {report['feeds']['indicators']} indicators from {len(report['feeds']['sources'])} source(s)")
    print()
    print("============================================")
    print(" SUMMARY")
    print("============================================")
    print(f"RESULT: {report['verdict']}")
    print(f"Score: {report['score']} | Confidence: {report['confidence']}")
    print(f"Files scanned: {report['stats']['files_scanned']} | Package manifests: {report['stats']['package_manifests']}")
    if report["stats"].get("registry_versions_checked"):
        print(
            f"Registry versions checked: {report['stats']['registry_versions_checked']} | Registry mismatches: {report['stats']['registry_mismatches']}"
        )
    print()
    findings = report.get("findings") or []
    if not findings:
        print("No se encontraron señales conocidas.")
    else:
        print("Findings:")
        for finding in findings[:50]:
            line = f":{finding['line']}" if finding.get("line") else ""
            print(
                f"- [{finding['severity'].upper()}] {finding['rule_id']} {finding['path']}{line} - {finding['title']} | {finding['evidence']}"
            )
    print()
    if report.get("limitations"):
        print("Limitations:")
        for item in report["limitations"]:
            print(f"- {item}")


def load_feeds(args: argparse.Namespace) -> tuple[list[dict[str, Any]], list[Path]]:
    feeds: list[dict[str, Any]] = []
    errors: list[str] = []
    local_sources: list[Path] = []
    feed_urls = resolve_feed_sources(args)
    feed_files = [Path(p) for p in args.feed_file]

    for path in feed_files:
        try:
            feeds.append(load_feed_from_file(path, str(path)))
            local_sources.append(path)
        except Exception as exc:
            errors.append(f"{path}: {exc}")

    for url in feed_urls:
        try:
            feeds.append(load_feed_from_url(url))
        except Exception as exc:
            errors.append(f"{url}: {exc}")

    if not feeds:
        bundled = Path(__file__).resolve().parents[1] / "app" / "data" / "ioc-feed-v1.json"
        if bundled.is_file():
            try:
                feeds.append(load_feed_from_file(bundled, "bundled"))
                local_sources.append(bundled)
            except Exception as exc:
                errors.append(f"{bundled}: {exc}")

    if errors and not feeds:
        raise SystemExit("No se pudieron cargar feeds:\n- " + "\n- ".join(errors))
    if errors:
        print("Feed warnings:")
        for item in errors:
            print(f"- {item}", file=sys.stderr)
    return feeds, local_sources


def main() -> int:
    args = parse_args()
    root = Path(args.repo_path).expanduser().resolve()
    if not root.exists():
        print(f"Repository path not found: {root}", file=sys.stderr)
        return 3
    if not root.is_dir():
        print(f"Repository path is not a directory: {root}", file=sys.stderr)
        return 3

    feeds, local_sources = load_feeds(args)
    extra_excludes: set[str] = set()
    for source in local_sources:
        try:
            rel = normalize_relpath(source.resolve().relative_to(root))
            extra_excludes.add(rel.lower())
        except Exception:
            continue
    report = scan_repo(root, args, feeds, extra_excludes)

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print_human(report)

    if report["verdict"] == "QUARANTINE":
        return 2
    if report["verdict"] == "REVIEW":
        return 1
    if report["verdict"] == "LOW":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
