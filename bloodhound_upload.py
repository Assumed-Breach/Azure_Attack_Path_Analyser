#!/usr/bin/env python3
import argparse
import base64
import datetime
import hashlib
import hmac
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parent
ENV_PATH = ROOT / ".env"


def load_env_file(path: Path) -> None:
    if not path.exists():
        return

    for raw_line in path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()

        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]

        os.environ.setdefault(key, value)


def require_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise SystemExit(f"Missing required environment variable: {name}")
    return value


def build_headers(method: str, uri: str, body: bytes | None, token_id: str, token_key: str) -> dict[str, str]:
    digester = hmac.new(token_key.encode(), None, hashlib.sha256)
    digester.update(f"{method}{uri}".encode())

    digester = hmac.new(digester.digest(), None, hashlib.sha256)
    request_date = datetime.datetime.now().astimezone().isoformat("T")
    digester.update(request_date[:13].encode())

    digester = hmac.new(digester.digest(), None, hashlib.sha256)
    if body is not None:
        digester.update(body)

    return {
        "User-Agent": "bloodhound-upload-script 0.1",
        "Authorization": f"bhesignature {token_id}",
        "RequestDate": request_date,
        "Signature": base64.b64encode(digester.digest()).decode(),
    }


def api_request(
    method: str,
    uri: str,
    *,
    body: bytes | None = None,
    extra_headers: dict[str, str] | None = None,
    expect_json: bool = True,
) -> dict | str | None:
    domain = require_env("BLOODHOUND_DOMAIN")
    port = require_env("BLOODHOUND_PORT")
    scheme = os.getenv("BLOODHOUND_SCHEME", "https")
    token_id = require_env("BLOODHOUND_TOKEN_ID")
    token_key = require_env("BLOODHOUND_TOKEN_KEY")

    normalized_uri = "/" + uri.lstrip("/")
    url = f"{scheme}://{domain}:{port}{normalized_uri}"
    headers = build_headers(method, normalized_uri, body, token_id, token_key)

    if extra_headers:
        headers.update(extra_headers)

    request = urllib.request.Request(url=url, data=body, method=method, headers=headers)

    try:
        with urllib.request.urlopen(request) as response:
            payload = response.read()
    except urllib.error.HTTPError as exc:
        payload = exc.read()
        message = payload.decode(errors="replace") if payload else str(exc)
        raise SystemExit(f"{exc.code} {exc.reason}: {message}") from exc
    except urllib.error.URLError as exc:
        raise SystemExit(f"Connection failed: {exc.reason}") from exc

    if not expect_json:
        if payload:
            return payload.decode(errors="replace")
        return None

    if not payload:
        return None

    return json.loads(payload.decode())


def content_type_for(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix == ".json":
        return "application/json"
    if suffix == ".zip":
        return "application/zip"
    raise SystemExit(f"Unsupported file type for upload: {path}")


def create_upload_job() -> int:
    response = api_request("POST", "/api/v2/file-upload/start")
    if not isinstance(response, dict) or "data" not in response or "id" not in response["data"]:
        raise SystemExit("Unexpected response when creating file upload job")
    return int(response["data"]["id"])


def upload_file(job_id: int, path: Path) -> None:
    body = path.read_bytes()
    api_request(
        "POST",
        f"/api/v2/file-upload/{job_id}",
        body=body,
        extra_headers={
            "Content-Type": content_type_for(path),
            "X-File-Upload-Name": path.name,
        },
        expect_json=False,
    )


def end_upload_job(job_id: int) -> None:
    api_request("POST", f"/api/v2/file-upload/{job_id}/end", expect_json=False)


def find_default_upload_files() -> list[Path]:
    output_dir = Path.cwd() / "output"
    zip_candidates = sorted(
        (
            path.resolve()
            for path in output_dir.glob("*.zip")
            if path.is_file()
        ),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    if zip_candidates:
        return zip_candidates

    json_candidates = sorted(
        (
            path.resolve()
            for path in output_dir.glob("*.json")
            if path.is_file()
        ),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    if json_candidates:
        return json_candidates

    raise SystemExit(f"No uploadable .zip or .json files found in {output_dir}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Upload BloodHound collection files through the CE API.")
    parser.add_argument(
        "files",
        nargs="*",
        help=(
            "File(s) to upload. Defaults to all .zip files in ./output, "
            "or .json files if no zip files are present, "
            "under the current working directory."
        ),
    )
    return parser.parse_args()


def main() -> int:
    load_env_file(ENV_PATH)
    args = parse_args()

    files = [Path(file_path).expanduser().resolve() for file_path in args.files] if args.files else find_default_upload_files()
    missing = [str(path) for path in files if not path.exists()]
    if missing:
        raise SystemExit(f"Missing upload file(s): {', '.join(missing)}")

    job_id = create_upload_job()
    print(f"Started file upload job {job_id}")

    for path in files:
        upload_file(job_id, path)
        print(f"Uploaded {path}")

    end_upload_job(job_id)
    print(f"Ended file upload job {job_id}")
    print("Check BloodHound File Ingest or API job status for processing progress.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
