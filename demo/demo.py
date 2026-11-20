"""
End-to-end demonstration of the per-environment trust config service.

Generates two local trust configs (preview / release) and two valid
artifacts, then shows:

1. initial load + successful verification in both environments;
2. a successful config update (key rotation, version bump);
3. rejected updates (wrong identity, stale version, malformed config)
   that leave the active config untouched;
4. an interleaved verification: a session started before a swap keeps
   using its original root material;
5. no cross-environment borrowing when one config is unavailable.

Run from the repository root:

    .venv/bin/python -m demo.demo
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from demo.trust_config_service import (
    ArtifactVerificationError,
    ConfigUnavailableError,
    ConfigValidationError,
    TrustConfigManager,
    VerificationService,
)

PREVIEW = "preview"
RELEASE = "release"


def write_config(directory: Path, name: str, environment: str, version: int,
                 keys: dict[str, Ed25519PrivateKey]) -> Path:
    config = {
        "environment": environment,
        "version": version,
        "roots": [
            {
                "key_id": key_id,
                "public_key": key.public_key().public_bytes_raw().hex(),
            }
            for key_id, key in keys.items()
        ],
    }
    path = directory / name
    path.write_text(json.dumps(config, indent=2), encoding="utf-8")
    return path


def write_artifact(directory: Path, name: str, key_id: str,
                   key: Ed25519PrivateKey, payload: str) -> Path:
    artifact = {
        "payload": payload,
        "key_id": key_id,
        "signature": key.sign(payload.encode("utf-8")).hex(),
    }
    path = directory / name
    path.write_text(json.dumps(artifact, indent=2), encoding="utf-8")
    return path


def main() -> None:
    workdir = Path(tempfile.mkdtemp(prefix="trust-config-demo-"))
    print(f"working directory: {workdir}\n")

    preview_key_v1 = Ed25519PrivateKey.generate()
    preview_key_v2 = Ed25519PrivateKey.generate()
    release_key = Ed25519PrivateKey.generate()

    preview_v1 = write_config(workdir, "preview-v1.json", PREVIEW, 1,
                              {"preview-root-1": preview_key_v1})
    release_v1 = write_config(workdir, "release-v1.json", RELEASE, 1,
                              {"release-root-1": release_key})

    preview_artifact = write_artifact(workdir, "artifact-preview.json",
                                      "preview-root-1", preview_key_v1,
                                      "preview build 1234")
    release_artifact = write_artifact(workdir, "artifact-release.json",
                                      "release-root-1", release_key,
                                      "release build 5678")

    manager = TrustConfigManager()
    service = VerificationService(manager)

    print("== 1. initial load: one fixed-identity config per environment ==")
    manager.load(preview_v1)
    manager.load(release_v1)
    for env, artifact in ((PREVIEW, preview_artifact), (RELEASE, release_artifact)):
        result = service.verify(env, artifact)
        print(f"  {env}: verified {artifact.name} with config "
              f"v{result.config_version} (key {result.key_id})")
    print(f"  inspectable versions: preview=v{manager.current_version(PREVIEW)}, "
          f"release=v{manager.current_version(RELEASE)}\n")

    print("== 2. successful update: rotate the preview root, bump the version ==")
    preview_v2 = write_config(workdir, "preview-v2.json", PREVIEW, 2,
                              {"preview-root-2": preview_key_v2})
    manager.update(PREVIEW, preview_v2)
    print(f"  preview now at v{manager.current_version(PREVIEW)}, "
          f"release untouched at v{manager.current_version(RELEASE)}")
    preview_artifact_v2 = write_artifact(workdir, "artifact-preview-v2.json",
                                         "preview-root-2", preview_key_v2,
                                         "preview build 1235")
    result = service.verify(PREVIEW, preview_artifact_v2)
    print(f"  new artifact verified with config v{result.config_version} "
          f"(key {result.key_id})\n")

    print("== 3. rejected updates: active config stays untouched ==")
    wrong_identity = write_config(workdir, "sneaky.json", RELEASE, 99,
                                  {"release-root-1": release_key})
    stale = write_config(workdir, "preview-stale.json", PREVIEW, 1,
                         {"preview-root-1": preview_key_v1})
    malformed = workdir / "malformed.json"
    malformed.write_text('{"environment": "preview", "version": 3, "roots": []}',
                         encoding="utf-8")
    for label, path in (("identity mismatch", wrong_identity),
                        ("stale version", stale),
                        ("empty roots", malformed)):
        try:
            manager.update(PREVIEW, path)
        except ConfigValidationError as exc:
            print(f"  rejected ({label}): {exc}")
    print(f"  preview still at v{manager.current_version(PREVIEW)} and "
          "still verifies:")
    result = service.verify(PREVIEW, preview_artifact_v2)
    print(f"  verified {preview_artifact_v2.name} with config "
          f"v{result.config_version}\n")

    print("== 4. interleaved verification: a started session keeps its roots ==")
    session = service.begin(PREVIEW)
    print(f"  session started against config v{session.config_version}")
    preview_v3 = write_config(workdir, "preview-v3.json", PREVIEW, 3,
                              {"preview-root-1": preview_key_v1})
    manager.update(PREVIEW, preview_v3)
    print(f"  config swapped to v{manager.current_version(PREVIEW)} mid-session")
    result = session.verify(preview_artifact_v2)
    print(f"  in-flight verification still used config "
              f"v{result.config_version} (key {result.key_id})")
    result = service.verify(PREVIEW, preview_artifact)
    print(f"  a new verification uses the swapped-in config "
          f"v{result.config_version} (key {result.key_id})\n")

    print("== 5. no cross-environment borrowing ==")
    lonely = TrustConfigManager()
    lonely.load(release_v1)
    lonely_service = VerificationService(lonely)
    try:
        lonely_service.verify(PREVIEW, preview_artifact)
    except ConfigUnavailableError as exc:
        print(f"  preview config unavailable, refused to borrow release roots: {exc}")
    try:
        service.verify(PREVIEW, release_artifact)
    except ArtifactVerificationError as exc:
        print(f"  release artifact presented to preview env, rejected: {exc}")


if __name__ == "__main__":
    main()
