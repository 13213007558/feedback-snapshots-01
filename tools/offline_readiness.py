#!/usr/bin/env python3
"""
Offline verification readiness checker for sigstore-python deployments.

This tool answers three operational questions without requiring network access:

1. Which verification steps can this host complete using only local material
   (embedded roots, TUF cache, bundle contents)?
2. Which steps depend on network access, and therefore must be pre-staged?
3. When a bundle cannot be verified, is the cause a missing local root/proof
   (fixable by shipping trust material) or a defect in the artifact itself?

It is deliberately dependency-light: it uses only sigstore-python and python-tuf,
which the deployment already has.

Exit codes:
  0  every requested bundle verified offline (or the selftest passed)
  1  at least one bundle failed (ablation: at least one variant was rejected)
  2  usage or environment error
"""

from __future__ import annotations

import argparse
import contextlib
import json
import socket
import sys
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

EXIT_OK = 0
EXIT_FAIL = 1
EXIT_USAGE = 2

# Default bundle search order used by the CLI (modern name first).
BUNDLE_SUFFIXES = (".sigstore.json", ".sigstore")


class NetworkAttempted(RuntimeError):
    """Raised when code under test tries to open a network connection."""


@contextlib.contextmanager
def no_network() -> Iterator[None]:
    """
    Hard-block outbound sockets for the duration of the block.

    This is stronger than simply passing `offline=True`: it catches code paths
    that accept the offline flag but still perform an I/O operation.
    """

    original_connect = socket.socket.connect
    original_connect_ex = socket.socket.connect_ex
    original_create = socket.create_connection
    original_getaddrinfo = socket.getaddrinfo

    def _deny(*args: Any, **kwargs: Any) -> Any:
        raise NetworkAttempted("network access attempted while offline")

    socket.socket.connect = _deny  # type: ignore[method-assign]
    socket.socket.connect_ex = _deny  # type: ignore[method-assign]
    socket.create_connection = _deny  # type: ignore[assignment]
    socket.getaddrinfo = _deny  # type: ignore[assignment]
    try:
        yield
    finally:
        socket.socket.connect = original_connect  # type: ignore[method-assign]
        socket.socket.connect_ex = original_connect_ex  # type: ignore[method-assign]
        socket.create_connection = original_create  # type: ignore[assignment]
        socket.getaddrinfo = original_getaddrinfo  # type: ignore[assignment]


@dataclass
class BundleFacts:
    """Proof material actually present in a bundle."""

    path: Path
    media_type: str | None = None
    load_error: str | None = None
    certificate: bool = False
    tlog_entries: int = 0
    inclusion_promise: bool = False
    inclusion_proof: bool = False
    checkpoint: bool = False
    signed_timestamps: int = 0
    integrated_time: int | None = None
    entry_kind: str | None = None
    entry_version: str | None = None
    has_dsse: bool = False

    @property
    def time_sources(self) -> list[str]:
        sources = []
        if self.integrated_time is not None and self.inclusion_promise:
            sources.append("rekor integratedTime + SET")
        if self.signed_timestamps:
            sources.append(f"{self.signed_timestamps}x RFC3161 timestamp")
        return sources

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": str(self.path),
            "media_type": self.media_type,
            "load_error": self.load_error,
            "certificate": self.certificate,
            "tlog_entries": self.tlog_entries,
            "inclusion_promise": self.inclusion_promise,
            "inclusion_proof": self.inclusion_proof,
            "checkpoint": self.checkpoint,
            "signed_timestamps": self.signed_timestamps,
            "time_sources": self.time_sources,
            "entry_kind": self.entry_kind,
            "entry_version": self.entry_version,
            "has_dsse": self.has_dsse,
        }


@dataclass
class RootFacts:
    """Facts about a trust root, independent of where it came from."""

    source: str
    certificate_authorities: int = 0
    tlogs: int = 0
    ctlogs: int = 0
    timestamp_authorities: int = 0
    tlog_base_urls: list[str] = field(default_factory=list)
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "certificate_authorities": self.certificate_authorities,
            "tlogs": self.tlogs,
            "ctlogs": self.ctlogs,
            "timestamp_authorities": self.timestamp_authorities,
            "tlog_base_urls": self.tlog_base_urls,
            "error": self.error,
        }


@dataclass
class CheckResult:
    """Outcome of one offline verification attempt."""

    bundle: Path
    artifact: Path | None
    status: str
    detail: str
    root_source: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "bundle": str(self.bundle),
            "artifact": str(self.artifact) if self.artifact else None,
            "status": self.status,
            "detail": self.detail,
            "root_source": self.root_source,
        }


@dataclass
class BundleVerdict:
    """Aggregate verdict for one bundle across all roots that were tried."""

    bundle: Path
    outcome: str
    root_source: str | None
    attempts: list[dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "bundle": str(self.bundle),
            "outcome": self.outcome,
            "root_source": self.root_source,
            "attempts": self.attempts,
        }


def classify_failure(detail: str) -> str:
    """
    Map a failure string to a coarse repair category.

    The categories correspond to the deployment runbook: which side has to act
    to make the bundle verifiable offline.
    """

    lowered = detail.lower()
    if "bundle rejected" in lowered:
        if "inclusion proof" in lowered or "checkpoint" in lowered:
            return "bundle-missing-proof"
        if "inclusion promise" in lowered or "signed timestamp" in lowered:
            return "bundle-missing-time-source"
        if "certificate" in lowered:
            return "bundle-missing-certificate"
        if "log entry" in lowered:
            return "bundle-missing-log-entry"
        if "media type" in lowered or "failed to load bundle" in lowered:
            return "bundle-malformed"
        return "bundle-invalid"
    if "no transparency log" in lowered:
        return "root-missing-tlog"
    if "ctfe keys not found" in lowered:
        return "root-missing-ctlog"
    if "fulcio certificates not found" in lowered:
        return "root-missing-ca"
    if "no timestamp authorities" in lowered:
        return "root-missing-tsa"
    if "not enough sources of verified time" in lowered:
        return "proof-time-unverifiable"
    if (
        "certvalidationerror" in lowered
        or "failed to build timestamp certificate chain" in lowered
    ):
        return "root-or-bundle-instance-mismatch"
    if "invalid log entry" in lowered and "checkpoint" in lowered:
        return "root-mismatch-log-key"
    if "trusted root" in lowered:
        return "root-missing-tlog"
    return "verification-failed"


def _bundle_json(path: Path) -> dict[str, Any]:
    try:
        raw = json.loads(path.read_bytes())
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"not a JSON bundle: {exc}") from exc
    if not isinstance(raw, dict):
        raise ValueError("bundle root is not a JSON object")
    return raw


def inspect_bundle(path: Path) -> BundleFacts:
    """
    Read a bundle's proof material directly from JSON.

    We intentionally do not use `Bundle.from_json` here: this inspection must
    work even for bundles that sigstore-python would reject, so that operators
    can see *what is missing* rather than only that loading failed.
    """

    facts = BundleFacts(path=path)
    try:
        raw = _bundle_json(path)
    except ValueError as exc:
        facts.load_error = str(exc)
        return facts

    facts.media_type = raw.get("mediaType")
    facts.has_dsse = "dsseEnvelope" in raw
    vm = raw.get("verificationMaterial") or {}
    facts.certificate = bool(vm.get("certificate") or vm.get("x509CertificateChain"))

    entries = vm.get("tlogEntries") or []
    facts.tlog_entries = len(entries)
    if entries:
        entry = entries[0]
        facts.inclusion_promise = bool(entry.get("inclusionPromise"))
        proof = entry.get("inclusionProof") or {}
        facts.inclusion_proof = bool(proof)
        facts.checkpoint = bool(proof.get("checkpoint"))
        facts.integrated_time = entry.get("integratedTime")
        kind = entry.get("kindVersion") or {}
        facts.entry_kind = kind.get("kind")
        facts.entry_version = kind.get("version")

    tsa = vm.get("timestampVerificationData") or {}
    facts.signed_timestamps = len(tsa.get("rfc3161Timestamps") or [])

    return facts


def _discover_artifact(bundle: Path) -> Path | None:
    name = bundle.name
    for suffix in BUNDLE_SUFFIXES:
        if name.endswith(suffix):
            candidate = bundle.with_name(name[: -len(suffix)])
            if candidate.is_file():
                return candidate
    return None


def inspect_root(source: str, trusted_root: Any) -> RootFacts:
    """Summarize a `TrustedRoot` without touching the network."""

    facts = RootFacts(source=source)
    try:
        inner = trusted_root._inner
        facts.certificate_authorities = len(inner.certificate_authorities)
        facts.tlogs = len(inner.tlogs)
        facts.ctlogs = len(inner.ctlogs)
        facts.timestamp_authorities = len(inner.timestamp_authorities)
        facts.tlog_base_urls = [t.base_url for t in inner.tlogs]
    except Exception as exc:  # noqa: BLE001 - report, never crash a preflight
        facts.error = f"{type(exc).__name__}: {exc}"
    return facts


def _now() -> datetime:
    return datetime.now(UTC)


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def assess_freshness(trusted_root: Any, at: datetime | None = None) -> list[str]:
    """
    Return human-readable warnings about stale trust material.

    Note: this is advisory. sigstore-python does not enforce Fulcio
    `validFor` windows when building chains offline (it trusts the bundle's
    signed time), so a stale window does not by itself cause a failure. TLOG and
    CT `validFor` are not present in the v0.1 trusted root at all.

    A CA whose window has ended is only noteworthy when it is the *newest* CA
    for that URI; otherwise it is simply a superseded generation.
    """

    at = at or _now()
    warnings: list[str] = []

    c_as_by_uri: dict[str, list[Any]] = {}
    for ca in trusted_root._inner.certificate_authorities:
        c_as_by_uri.setdefault(ca.uri, []).append(ca)
    for uri, authorities in c_as_by_uri.items():
        latest = max(
            authorities,
            key=lambda ca: getattr(ca.valid_for, "start", at),
        )
        end = getattr(latest.valid_for, "end", None)
        if end and end < at:
            warnings.append(
                f"Fulcio CA {uri}: newest generation ended {end.isoformat()}; "
                "signatures made after that instant cannot be attributed to it"
            )

    for tsa in trusted_root._inner.timestamp_authorities:
        start = getattr(tsa.valid_for, "start", None)
        end = getattr(tsa.valid_for, "end", None)
        if start and start > at:
            warnings.append(
                f"TSA {tsa.uri} validity window starts {start.isoformat()} "
                "(future-dated material)"
            )
        if end and end < at:
            warnings.append(f"TSA {tsa.uri} validity window ended {end.isoformat()}")
    return warnings


def tuf_cache_paths(url: str) -> tuple[Path, Path]:
    """Return the (metadata, targets) directories for a TUF repository URL."""

    from sigstore._internal.tuf import _get_dirs

    return _get_dirs(url)


def inspect_cache(url: str) -> dict[str, Any]:
    """Report what is actually present in the local TUF cache for `url`."""

    metadata_dir, targets_dir = tuf_cache_paths(url)

    def _listing(path: Path) -> list[str] | None:
        if not path.is_dir():
            return None
        return sorted(p.name for p in path.iterdir())

    root_json = metadata_dir / "root.json"
    root_version = root_expires = None
    root_error = None
    if root_json.is_file():
        try:
            signed = json.loads(root_json.read_bytes())["signed"]
            root_version = signed.get("version")
            root_expires = signed.get("expires")
        except Exception as exc:  # noqa: BLE001 - diagnostics only
            root_error = f"{type(exc).__name__}: {exc}"

    expires_dt = _parse_time(root_expires)
    expired = bool(expires_dt and expires_dt < _now())

    return {
        "url": url,
        "metadata_dir": str(metadata_dir),
        "targets_dir": str(targets_dir),
        "metadata_files": _listing(metadata_dir),
        "target_files": _listing(targets_dir),
        "root_version": root_version,
        "root_expires": root_expires,
        "root_expired": expired,
        "root_error": root_error,
        "trusted_root_present": (targets_dir / "trusted_root.json").is_file(),
        "signing_config_present": (targets_dir / "signing_config.v0.2.json").is_file(),
    }


def load_roots(args: argparse.Namespace) -> list[tuple[str, Any]]:
    """
    Build the list of trust roots to try, in operator-defined priority order.

    Each entry is (label, TrustedRoot). Failures are recorded as a synthetic
    entry with a `None` root so the report explains why a source was unusable.
    """

    from sigstore.models import ClientTrustConfig

    roots: list[tuple[str, Any]] = []

    if args.trust_config:
        path: Path = args.trust_config
        try:
            config = ClientTrustConfig.from_json(path.read_text())
            roots.append((f"trust-config:{path}", config.trusted_root))
        except Exception as exc:  # noqa: BLE001
            roots.append((f"trust-config:{path}", exc))

    if args.store:
        path = args.store / "trusted_root.json"
        try:
            from sigstore.models import TrustedRoot

            roots.append((f"store:{path}", TrustedRoot.from_file(path)))
        except Exception as exc:  # noqa: BLE001
            roots.append((f"store:{path}", exc))

    if args.embedded:
        from sigstore_models.trustroot import v1 as trustroot_v1

        from sigstore._utils import read_embedded
        from sigstore.models import TrustedRoot

        for label, url in (
            ("embedded:production", "https://tuf-repo-cdn.sigstore.dev"),
            ("embedded:staging", "https://tuf-repo-cdn.sigstage.dev"),
        ):
            try:
                raw = read_embedded("trusted_root.json", url)
                roots.append(
                    (label, TrustedRoot(trustroot_v1.TrustedRoot.from_json(raw)))
                )
            except Exception as exc:  # noqa: BLE001
                roots.append((label, exc))

    if args.tuf_url:
        for url in args.tuf_url:
            label = f"tuf-cache:{url}"
            try:
                with no_network():
                    config = ClientTrustConfig.from_tuf(url, offline=True)
                roots.append((label, config.trusted_root))
            except Exception as exc:  # noqa: BLE001
                roots.append((label, exc))

    return roots


def _verify_one(bundle: BundleFacts, root: Any) -> tuple[bool, str]:
    """Attempt an offline verification of one bundle against one root."""

    from sigstore.models import Bundle, InvalidBundle
    from sigstore.verify.verifier import Verifier

    class _AcceptAll:
        def verify(self, cert: Any) -> None:
            return None

    try:
        parsed = Bundle.from_json(bundle.path.read_bytes())
    except InvalidBundle as exc:
        return False, f"bundle rejected: {exc}"

    artifact = _discover_artifact(bundle.path)
    try:
        verifier = Verifier(trusted_root=root)
        if parsed._dsse_envelope is not None:
            verifier.verify_dsse(parsed, _AcceptAll())
        elif artifact is None:
            return False, "artifact not found next to bundle"
        else:
            verifier.verify_artifact(artifact.read_bytes(), parsed, _AcceptAll())
    except NetworkAttempted:
        return False, "internal error: verification attempted network access"
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}"
    return True, "ok"


def run_ablation(args: argparse.Namespace) -> dict[str, Any]:
    """
    Build synthetic variants of one known-good bundle, each missing one proof
    class, and report which classes sigstore-python refuses to verify without.

    This is the empirical answer to "which proofs are load-bearing?" It uses the
    same `no_network()` guard, so every row is proven to be offline-only.
    """

    from sigstore.models import Bundle
    from sigstore.verify.verifier import Verifier

    source = Path(args.ablate)
    raw = _bundle_json(source)

    class _AcceptAll:
        def verify(self, cert: Any) -> None:
            return None

    def _entry(d: dict[str, Any]) -> dict[str, Any]:
        return (d["verificationMaterial"].get("tlogEntries") or [{}])[0]

    def _cert_key(d: dict[str, Any]) -> str:
        vm = d["verificationMaterial"]
        return "certificate" if "certificate" in vm else "x509CertificateChain"

    mutations = {
        "baseline": lambda d: None,
        "drop certificate": lambda d: d["verificationMaterial"].pop(_cert_key(d), None),
        "drop log entry": lambda d: d["verificationMaterial"].__setitem__(
            "tlogEntries", []
        ),
        "drop inclusion promise": lambda d: _entry(d).pop("inclusionPromise", None),
        "drop inclusion proof": lambda d: _entry(d).__setitem__("inclusionProof", {}),
        "drop checkpoint": lambda d: _entry(d)
        .get("inclusionProof", {})
        .pop("checkpoint", None),
        "drop signed timestamps": lambda d: d["verificationMaterial"].pop(
            "timestampVerificationData", None
        ),
    }

    roots = [
        (label, root)
        for label, root in load_roots(args)
        if not isinstance(root, Exception)
    ]
    if not roots:
        raise SystemExit("no usable trust root for ablation")

    rows = []
    for name, mutate in mutations.items():
        document = json.loads(json.dumps(raw))
        mutate(document)
        encoded = json.dumps(document).encode()

        try:
            parsed = Bundle.from_json(encoded)
            load_error = None
        except Exception as exc:  # noqa: BLE001
            parsed = None
            load_error = f"{type(exc).__name__}: {exc}"

        outcome = "load-rejected"
        detail = load_error or ""
        if parsed is not None:
            artifact = _discover_artifact(source)
            for label, root in roots:
                try:
                    with no_network():
                        verifier = Verifier(trusted_root=root)
                        if parsed._dsse_envelope is not None:
                            verifier.verify_dsse(parsed, _AcceptAll())
                        elif artifact is not None:
                            verifier.verify_artifact(
                                artifact.read_bytes(), parsed, _AcceptAll()
                            )
                        else:
                            detail = "artifact not found"
                            outcome = "unverified"
                            break
                    outcome, detail = "verified", f"ok via {label}"
                    break
                except Exception as exc:  # noqa: BLE001
                    outcome = classify_failure(f"{type(exc).__name__}: {exc}")
                    detail = f"{type(exc).__name__}: {exc}"

        rows.append({"variant": name, "outcome": outcome, "detail": detail})

    return {"source": str(source), "rows": rows}


def build_local_tuf_repo(
    repo: Path, targets: dict[str, bytes], *, days_valid: int = 30
) -> Path:
    """
    Build a minimal, self-signed TUF repository on disk.

    This is used only by `--selftest`: it lets us exercise sigstore-python's
    real TUF refresh path with a *fake downloader*, proving which inputs can be
    satisfied without network access.
    """

    import datetime
    import hashlib

    from securesystemslib.signer import CryptoSigner
    from tuf.api.metadata import (
        Key,
        Metadata,
        MetaFile,
        Role,
        Root,
        Snapshot,
        TargetFile,
        Targets,
        Timestamp,
    )
    from tuf.api.serialization.json import JSONSerializer

    (repo / "targets").mkdir(parents=True, exist_ok=True)
    (repo / "metadata").mkdir(parents=True, exist_ok=True)

    signer = CryptoSigner.generate_ed25519()
    key = Key.from_dict(signer.public_key.keyid, signer.public_key.to_dict())
    expires = (
        datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=days_valid)
    ).replace(microsecond=0)

    def signed(payload: Any) -> Metadata:
        metadata = Metadata(payload)
        metadata.sign(signer)
        return metadata

    def raw(metadata: Metadata) -> bytes:
        return metadata.to_bytes(JSONSerializer())

    def meta_file(metadata: Metadata) -> MetaFile:
        encoded = raw(metadata)
        return MetaFile(
            metadata.signed.version,
            len(encoded),
            {"sha256": hashlib.sha256(encoded).hexdigest()},
        )

    roles = {
        name: Role([key.keyid], 1)
        for name in ("root", "targets", "snapshot", "timestamp")
    }
    root = signed(Root(1, "1.0.31", expires, {key.keyid: key}, roles))

    target_files = {}
    for name, data in targets.items():
        (repo / "targets" / name).write_bytes(data)
        target_files[name] = TargetFile.from_file(name, str(repo / "targets" / name))

    targets_md = signed(Targets(1, "1.0.31", expires, target_files))
    snapshot = signed(
        Snapshot(1, "1.0.31", expires, {"targets.json": meta_file(targets_md)})
    )
    timestamp = signed(Timestamp(1, "1.0.31", expires, meta_file(snapshot)))

    for name, metadata in (
        ("root.json", root),
        ("targets.json", targets_md),
        ("snapshot.json", snapshot),
        ("timestamp.json", timestamp),
    ):
        (repo / "metadata" / name).write_bytes(raw(metadata))

    return repo


def run_selftest(args: argparse.Namespace) -> dict[str, Any]:
    """
    Prove the offline-downloader contract without any network access at all.

    The check installs a fake TUF downloader that serves a locally-built
    repository, blocks all sockets, and asks sigstore-python to perform a
    *non-offline* trust refresh. If it succeeds, the deployment can stage trust
    material as plain files and the client's "online" code path will accept it.
    """

    import tempfile
    from urllib.parse import urlparse

    from tuf.api.exceptions import DownloadHTTPError
    from tuf.ngclient import FetcherInterface, updater

    from sigstore._internal import tuf
    from sigstore.models import ClientTrustConfig

    if not args.selftest_targets:
        raise SystemExit("--selftest needs --selftest-targets DIR")

    source = Path(args.selftest_targets)
    targets = {
        "trusted_root.json": (source / "trusted_root.json").read_bytes(),
        "signing_config.v0.2.json": (source / "signing_config.v0.2.json").read_bytes(),
    }

    workdir = Path(tempfile.mkdtemp(prefix="sigstore-offline-selftest-"))
    repo = build_local_tuf_repo(workdir / "repo", targets)
    metadata_dir = workdir / "data"
    targets_dir = workdir / "cache"
    metadata_dir.mkdir(parents=True)
    targets_dir.mkdir(parents=True)
    (metadata_dir / "root.json").write_bytes(
        (repo / "metadata" / "root.json").read_bytes()
    )

    import re

    base = "http://selftest.invalid/tuf/"
    requested: list[str] = []

    class LocalFetcher(FetcherInterface):
        def _fetch(self, url: str) -> Any:
            requested.append(url)
            rel = (
                url[len(base) :]
                if url.startswith(base)
                else urlparse(url).path.rsplit("/", 1)[-1]
            )
            if re.match(r"^\d+\.root\.json$", rel) and not rel.startswith("1."):
                raise DownloadHTTPError("no newer root", 404)
            rel = rel[len("targets/") :] if rel.startswith("targets/") else rel
            name = re.sub(r"^(\d+\.|[0-9a-f]{64}\.)", "", rel)
            for candidate in (repo / "metadata" / name, repo / "targets" / name):
                if candidate.is_file():
                    import io

                    return io.BytesIO(candidate.read_bytes())
            raise DownloadHTTPError("not found", 404)

    original_fetcher = updater.Urllib3Fetcher
    original_dirs = tuf._get_dirs
    updater.Urllib3Fetcher = lambda **kwargs: LocalFetcher()
    tuf._get_dirs = lambda url: (metadata_dir, targets_dir)
    try:
        with no_network():
            config = ClientTrustConfig.from_tuf(base.rstrip("/"))
    finally:
        updater.Urllib3Fetcher = original_fetcher
        tuf._get_dirs = original_dirs

    return {
        "status": "ok",
        "network_requests": 0,
        "fake_downloader_requests": len(requested),
        "refreshed_tlogs": len(config.trusted_root._inner.tlogs),
        "refreshed_timestamp_authorities": len(
            config.trusted_root._inner.timestamp_authorities
        ),
        "workdir": str(workdir),
        "cached_targets": sorted(p.name for p in targets_dir.iterdir()),
    }


def run_checks(args: argparse.Namespace) -> dict[str, Any]:
    """Execute the full readiness report and return it as a dict."""

    bundles = [Path(p) for p in args.bundle] if args.bundle else []
    if not bundles:
        raise SystemExit("no --bundle given")

    report: dict[str, Any] = {
        "generated_at": _now().isoformat(),
        "roots": [],
        "cache": [],
        "bundles": [],
        "verdicts": [],
        "results": [],
        "freshness_warnings": [],
    }

    roots = load_roots(args)
    for label, root in roots:
        if isinstance(root, Exception):
            report["roots"].append(RootFacts(source=label, error=str(root)).as_dict())
        else:
            report["roots"].append(inspect_root(label, root).as_dict())

    if args.tuf_url:
        report["cache"] = [inspect_cache(url) for url in args.tuf_url]

    bundle_facts = [inspect_bundle(p) for p in bundles]
    report["bundles"] = [b.as_dict() for b in bundle_facts]

    usable = [(label, root) for label, root in roots if not isinstance(root, Exception)]
    for label, root in usable:
        report["freshness_warnings"].extend(assess_freshness(root))

    for facts in bundle_facts:
        attempts: list[dict[str, Any]] = []
        verified_via: str | None = None
        for label, root in usable:
            with no_network():
                ok, detail = _verify_one(facts, root)
            attempts.append(
                CheckResult(
                    facts.path,
                    _discover_artifact(facts.path),
                    "verified" if ok else "failed",
                    detail,
                    label,
                ).as_dict()
            )
            if ok:
                verified_via = label
                break

        if verified_via:
            outcome = "verified"
        elif not usable:
            outcome = "no-root"
        else:
            outcome = classify_failure(attempts[-1]["detail"])

        report["verdicts"].append(
            BundleVerdict(facts.path, outcome, verified_via, attempts).as_dict()
        )
        report["results"].extend(attempts)

    return report


def _print_ablation(report: dict[str, Any]) -> None:
    print(f"Proof-class ablation of {report['source']}")
    print("  Each variant is verified offline with sockets blocked.")
    for row in report["rows"]:
        print(f"  [{row['outcome']}] {row['variant']}")
        if row["detail"]:
            print(f"      {row['detail']}")


def _print_human(report: dict[str, Any]) -> None:
    print("Trust roots")
    for root in report["roots"]:
        if root["error"]:
            print(f"  [unusable] {root['source']}: {root['error']}")
        else:
            print(
                f"  [ok] {root['source']}: CAs={root['certificate_authorities']} "
                f"tlogs={root['tlogs']} ctlogs={root['ctlogs']} "
                f"TSAs={root['timestamp_authorities']}"
            )
            if root["tlog_base_urls"]:
                print(f"       log URLs: {', '.join(root['tlog_base_urls'])}")

    if report["cache"]:
        print("\nTUF cache")
        for cache in report["cache"]:
            print(f"  {cache['url']}")
            print(f"    metadata: {cache['metadata_dir']} -> {cache['metadata_files']}")
            print(f"    targets : {cache['targets_dir']} -> {cache['target_files']}")
            print(
                f"    root.json: version={cache['root_version']} "
                f"expires={cache['root_expires']} expired={cache['root_expired']}"
            )
            if cache["root_error"]:
                print(f"    root.json parse error: {cache['root_error']}")

    print("\nBundles")
    for facts in report["bundles"]:
        print(f"  {facts['path']}")
        print(
            f"    mediaType={facts['media_type']} entry={facts['entry_kind']}/"
            f"{facts['entry_version']}"
        )
        print(
            "    certificate={certificate} tlog_entries={tlog_entries} "
            "promise={inclusion_promise} proof={inclusion_proof} "
            "checkpoint={checkpoint} timestamps={signed_timestamps}".format(**facts)
        )
        print(f"    time sources: {facts['time_sources'] or 'none'}")
        if facts["load_error"]:
            print(f"    load error: {facts['load_error']}")

    print("\nVerification")
    for verdict in report["verdicts"]:
        print(f"  [{verdict['outcome']}] {verdict['bundle']}")
        if verdict["root_source"]:
            print(f"      verified with {verdict['root_source']}")
        for attempt in verdict["attempts"]:
            if attempt["status"] != "verified":
                print(f"      tried {attempt['root_source']}: {attempt['detail']}")

    if report["freshness_warnings"]:
        print("\nFreshness warnings")
        for warning in dict.fromkeys(report["freshness_warnings"]):
            print(f"  - {warning}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--bundle", action="append", metavar="FILE")
    parser.add_argument("--trust-config", type=Path, metavar="FILE")
    parser.add_argument(
        "--store",
        type=Path,
        metavar="DIR",
        help="directory containing trusted_root.json",
    )
    parser.add_argument(
        "--tuf-url",
        action="append",
        metavar="URL",
        help="read trusted_root.json from the local TUF cache for URL",
    )
    parser.add_argument(
        "--embedded",
        action="store_true",
        help="include sigstore-python's baked-in roots",
    )
    parser.add_argument(
        "--ablate", metavar="FILE", help="known-good bundle to strip proof classes from"
    )
    parser.add_argument(
        "--selftest",
        action="store_true",
        help="prove trust refresh works with a fake downloader and no sockets",
    )
    parser.add_argument(
        "--selftest-targets",
        type=Path,
        metavar="DIR",
        help="directory holding trusted_root.json and signing_config.v0.2.json",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON")
    args = parser.parse_args(argv)

    if args.selftest:
        result = run_selftest(args)
        print(
            json.dumps(result, indent=2)
            if args.json
            else "\n".join(f"{k}: {v}" for k, v in result.items())
        )
        return EXIT_OK

    if not any((args.trust_config, args.store, args.tuf_url, args.embedded)):
        parser.error("specify at least one root source")

    if args.ablate:
        report = run_ablation(args)
        if args.json:
            print(json.dumps(report, indent=2))
        else:
            _print_ablation(report)
        failures = [r for r in report["rows"] if r["outcome"] not in ("verified",)]
        return EXIT_OK if not failures else EXIT_FAIL

    try:
        report = run_checks(args)
    except SystemExit as exc:
        print(exc, file=sys.stderr)
        return EXIT_USAGE

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        _print_human(report)

    failures = [v for v in report["verdicts"] if v["outcome"] != "verified"]
    return EXIT_OK if not failures else EXIT_FAIL


if __name__ == "__main__":
    sys.exit(main())
