"""Create a deterministic archive and identity record for a staged release."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import plistlib
import re
import stat
import sys
import tarfile
import tempfile
from pathlib import Path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tree_sha256(root: Path) -> str:
    digest = hashlib.sha256()
    digest.update(b".\x00")
    digest.update(stat.S_IMODE(root.stat().st_mode).to_bytes(4, "big"))
    digest.update(b"D")
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        if path.is_symlink():
            raise ValueError("candidate_symlink_invalid")
        relative = path.relative_to(root).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(stat.S_IMODE(path.stat().st_mode).to_bytes(4, "big"))
        if path.is_file():
            digest.update(b"F")
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
        elif path.is_dir():
            digest.update(b"D")
        else:
            raise ValueError("candidate_file_type_invalid")
    return digest.hexdigest()


def _app_signing_verifier():
    path = Path(__file__).resolve().parents[1] / "scripts/build_macos_ai_app.py"
    spec = importlib.util.spec_from_file_location("wireclaw_app_signing_verifier", path)
    if spec is None or spec.loader is None:
        raise ValueError("candidate_signature_verifier_unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _signed_code_inventory(
    bundle: Path, app: Path, signed_app: dict, *, codesign_runner=None
) -> list[dict]:
    mode = signed_app.get("signing_mode")
    if mode not in {"adhoc", "developer-id"}:
        raise ValueError("candidate_signing_mode_invalid")
    verifier_args = {"mode": mode}
    if codesign_runner is not None:
        verifier_args["runner"] = codesign_runner
    _app_signing_verifier().verify_signed_bundle(app, **verifier_args)
    expected_parent = {
        "com.apple.security.app-sandbox": True,
        "com.apple.security.network.server": True,
    }
    expected_helper = {
        "com.apple.security.app-sandbox": True,
        "com.apple.security.inherit": True,
    }
    targets = [
        (app, expected_parent),
        (app / "Contents/MacOS/WireclawAI", expected_parent),
        (app / "Contents/MacOS/llama-server", expected_helper),
    ]
    frameworks = app / "Contents/Frameworks"
    if frameworks.exists():
        targets.extend(
            (path, None)
            for path in sorted(frameworks.rglob("*"))
            if path.is_file() and (path.suffix == ".dylib" or os.access(path, os.X_OK))
        )
    result = []
    for path, entitlements in targets:
        if path.is_symlink() or (path != app and not path.is_file()):
            raise ValueError("candidate_signed_code_invalid")
        argv = ["/usr/bin/codesign", "-dv", "--verbose=4", str(path)]
        if codesign_runner is None:
            details = _app_signing_verifier()._run_codesign(argv)
        else:
            details = codesign_runner(argv, capture_output=True, text=True, check=False)
        detail_text = details.stdout + details.stderr
        identifier = re.search(r"^Identifier=(.+)$", detail_text, flags=re.MULTILINE)
        authority = re.search(r"^Authority=(.+)$", detail_text, flags=re.MULTILINE)
        team = re.search(r"^TeamIdentifier=(.+)$", detail_text, flags=re.MULTILINE)
        signature = re.search(r"^Signature=(.+)$", detail_text, flags=re.MULTILINE)
        if details.returncode or not identifier:
            raise ValueError("candidate_signed_code_identity_invalid")
        if mode == "adhoc" and (not signature or signature.group(1) != "adhoc"):
            raise ValueError("candidate_signed_code_identity_invalid")
        if mode == "developer-id" and (
            not authority
            or not team
            or team.group(1) in {"not set", "-"}
            or authority.group(1) != signed_app.get("signing_identity")
        ):
            raise ValueError("candidate_signed_code_identity_invalid")
        result.append(
            {
                "path": path.relative_to(bundle).as_posix(),
                "sha256": tree_sha256(path) if path == app else sha256(path),
                "identifier": identifier.group(1),
                "authority": authority.group(1) if authority else None,
                "team_id": team.group(1) if team else None,
                "signature": signature.group(1) if signature else None,
                "signing_mode": mode,
                "hardened_runtime": mode == "developer-id",
                "entitlements_sha256": (
                    hashlib.sha256(
                        json.dumps(entitlements, sort_keys=True, separators=(",", ":")).encode()
                    ).hexdigest()
                    if entitlements is not None
                    else None
                ),
            }
        )
    return result


def freeze_candidate(bundle: Path, archive: Path, *, codesign_runner=None) -> dict:
    bundle = bundle.expanduser()
    if bundle.is_symlink() or not bundle.is_dir():
        raise ValueError("candidate_bundle_invalid")
    bundle = bundle.resolve(strict=True)
    archive = archive.expanduser()
    if archive.is_symlink():
        raise ValueError("candidate_archive_symlink_invalid")
    archive = archive.resolve()
    if archive == bundle or bundle in archive.parents:
        raise ValueError("candidate_archive_inside_bundle")
    if archive.exists():
        raise ValueError("candidate_archive_exists")
    bundle_tree_before = tree_sha256(bundle)
    metadata_path = bundle / "release-metadata.json"
    try:
        release_metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        raise ValueError("candidate_release_metadata_invalid") from None
    if not isinstance(release_metadata, dict):
        raise ValueError("candidate_release_metadata_invalid")
    source_sha = release_metadata.get("source_sha")
    embedded_ai = release_metadata.get("embedded_ai")
    signed_app = release_metadata.get("signed_app")
    model_sha = signed_app.get("model_sha256") if isinstance(signed_app, dict) else None
    server_sha = signed_app.get("llama_server_sha256") if isinstance(signed_app, dict) else None
    if (
        not isinstance(source_sha, str)
        or len(source_sha) != 40
        or any(char not in "0123456789abcdef" for char in source_sha)
        or not isinstance(embedded_ai, dict)
        or not isinstance(signed_app, dict)
        or signed_app.get("path") != "ai/WireclawAI.app"
        or signed_app.get("bundle_identifier") != "com.wireclaw.WireclawAI"
        or not isinstance(model_sha, str)
        or not re.fullmatch(r"[0-9a-f]{64}", model_sha)
        or not isinstance(server_sha, str)
        or not re.fullmatch(r"[0-9a-f]{64}", server_sha)
        or signed_app.get("signing_mode") not in {"adhoc", "developer-id"}
    ):
        raise ValueError("candidate_release_metadata_invalid")
    app = bundle / signed_app["path"]
    if app.is_symlink() or not app.is_dir():
        raise ValueError("candidate_signed_app_missing")
    try:
        info = plistlib.loads((app / "Contents/Info.plist").read_bytes())
    except (OSError, plistlib.InvalidFileException):
        raise ValueError("candidate_app_identity_invalid") from None
    if (
        not isinstance(info, dict)
        or info.get("CFBundleIdentifier") != signed_app["bundle_identifier"]
    ):
        raise ValueError("candidate_app_identity_invalid")
    if signed_app["signing_mode"] == "adhoc":
        if (
            signed_app.get("signing_identity") != "-"
            or signed_app.get("hardened_runtime") is not False
            or any(
                signed_app.get(key) != "NOT_RUN"
                for key in (
                    "developer_id_validation",
                    "production_qualification",
                    "notarization",
                    "stapling",
                )
            )
        ):
            raise ValueError("candidate_signing_status_invalid")
    elif (
        signed_app.get("hardened_runtime") is not True
        or signed_app.get("developer_id_validation") != "PASS"
    ):
        raise ValueError("candidate_signing_status_invalid")
    signed_code = _signed_code_inventory(bundle, app, signed_app, codesign_runner=codesign_runner)
    if tree_sha256(bundle) != bundle_tree_before:
        raise ValueError("candidate_bundle_changed_during_verification")
    archive.parent.mkdir(parents=True, exist_ok=True)
    paths = [bundle, *sorted(bundle.rglob("*"), key=lambda p: p.relative_to(bundle).as_posix())]
    for path in paths:
        if path.is_symlink():
            raise ValueError("candidate_symlink_invalid")
        if not path.is_dir() and not path.is_file():
            raise ValueError("candidate_file_type_invalid")
    fd, temporary_name = tempfile.mkstemp(prefix=".wireclaw-candidate-", dir=archive.parent)
    os.close(fd)
    temporary = Path(temporary_name)
    try:
        with tarfile.open(temporary, mode="w", format=tarfile.PAX_FORMAT) as output:
            for path in paths:
                name = "wireclaw-release" + (
                    "/" + path.relative_to(bundle).as_posix() if path != bundle else ""
                )
                info = output.gettarinfo(str(path), arcname=name)
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                info.mtime = 0
                info.pax_headers = {}
                if path.is_dir():
                    info.mode = stat.S_IMODE(path.stat().st_mode)
                    output.addfile(info)
                else:
                    info.mode = stat.S_IMODE(path.stat().st_mode)
                    with path.open("rb") as stream:
                        output.addfile(info, stream)
        os.replace(temporary, archive)
    finally:
        temporary.unlink(missing_ok=True)
    if tree_sha256(bundle) != bundle_tree_before:
        archive.unlink(missing_ok=True)
        raise ValueError("candidate_bundle_changed_during_archive")
    result = {
        "source_sha": source_sha,
        "bundle_tree_sha256": tree_sha256(bundle),
        "archive_sha256": sha256(archive),
        "archive_size_bytes": archive.stat().st_size,
        "embedded_ai": embedded_ai,
        "signed_app": {
            **signed_app,
            "bundle_tree_sha256": tree_sha256(app),
            "signed_code": signed_code,
        },
        "frozen": True,
    }
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--metadata", type=Path)
    args = parser.parse_args(argv)
    if args.metadata is not None:
        metadata_path = args.metadata.expanduser()
        bundle_path = args.bundle.expanduser().resolve(strict=True)
        archive_path = args.archive.expanduser().resolve()
        if (
            metadata_path.is_symlink()
            or metadata_path.exists()
            or metadata_path.resolve() == archive_path
            or bundle_path in metadata_path.resolve().parents
        ):
            raise SystemExit("candidate_metadata_path_invalid")
    result = freeze_candidate(args.bundle, args.archive)
    if args.metadata:
        args.metadata.parent.mkdir(parents=True, exist_ok=True)
        args.metadata.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, json.JSONDecodeError) as error:
        raise SystemExit(str(error)) from None
