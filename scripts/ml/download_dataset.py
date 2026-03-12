#!/usr/bin/env python3
"""Download the LSNM2024 dataset for NIDS model training.

The LSNM2024 dataset contains labeled network flow samples split into
Benign and Malicious (15 attack-type) categories.

Reference:
    Q. Abu Al-Haija et al., "Revolutionizing Threat Hunting in Communication
    Networks", ICICS 2024.

Source: Mendeley Data
    https://data.mendeley.com/datasets/7pzyfvv9jn/1

Usage:
    python scripts/ml/download_dataset.py [--output-dir data/]
"""

import argparse
import hashlib
import sys
import zipfile
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent

try:
    import requests
    from tqdm import tqdm
except ImportError:
    print(
        "Missing dependencies. Install with: pip install requests tqdm",
        file=sys.stderr,
    )
    sys.exit(1)


# Mendeley Data public REST API
MENDELEY_API_BASE = "https://data.mendeley.com/public-api"
DATASET_ID = "7pzyfvv9jn"
DATASET_VERSION = 1

# Expected SHA-256 of the downloaded archive (update after first successful download).
EXPECTED_SHA256 = None  # Set after verifying the first download

MANUAL_DOWNLOAD_URL = (
    f"https://data.mendeley.com/datasets/{DATASET_ID}/{DATASET_VERSION}"
)


# ---------------------------------------------------------------------------
# Mendeley API helpers
# ---------------------------------------------------------------------------


def get_dataset_files(dataset_id: str, version: int) -> list[dict]:
    """Query the Mendeley Data API and return the list of file records.

    Tries two known API path formats:
      1. https://data.mendeley.com/api/datasets/<id>/versions/<v>/files
      2. https://data.mendeley.com/public-api/datasets/<id>/versions/<v>/files
    """
    paths = [
        f"https://data.mendeley.com/api/datasets/{dataset_id}/versions/{version}/files",
        f"https://data.mendeley.com/public-api/datasets/{dataset_id}/versions/{version}/files",
    ]
    last_exc: Exception | None = None
    for url in paths:
        try:
            resp = requests.get(url, timeout=30)
            resp.raise_for_status()
            if "application/json" not in resp.headers.get("content-type", ""):
                continue  # HTML response — wrong endpoint
            data = resp.json()
            if isinstance(data, list):
                return data
            # {"data": {"results": [...]}} or {"files": [...]}
            if isinstance(data, dict):
                files = (
                    data.get("files")
                    or data.get("data", {}).get("results")
                    or data.get("data")
                    or []
                )
                if files:
                    return files
        except Exception as exc:
            last_exc = exc
    raise RuntimeError(f"All API endpoints failed. Last error: {last_exc}")


def pick_download_url(files: list[dict]) -> tuple[str, str]:
    """Return (download_url, filename) for the best file to download.

    Preference: single zip archive > any zip > first file listed.
    """
    zips = [f for f in files if f.get("filename", "").lower().endswith(".zip")]
    candidates = zips if zips else files
    best = candidates[0]
    # Mendeley v1 API uses 'content_details.download_url' or 'download_url'
    url = (
        best.get("content_details", {}).get("download_url")
        or best.get("download_url")
        or best.get("file_url")
        or ""
    )
    name = best.get("filename") or url.rsplit("/", 1)[-1] or "lsnm2024_dataset.zip"
    return url, name


# ---------------------------------------------------------------------------
# Download / verify / extract
# ---------------------------------------------------------------------------


def download_file(url: str, dest: Path, chunk_size: int = 8192) -> None:
    """Stream-download *url* to *dest* with a progress bar."""
    resp = requests.get(url, stream=True, timeout=300)
    resp.raise_for_status()

    total = int(resp.headers.get("content-length", 0))
    with (
        open(dest, "wb") as fh,
        tqdm(total=total, unit="B", unit_scale=True, desc=dest.name) as pbar,
    ):
        for chunk in resp.iter_content(chunk_size=chunk_size):
            fh.write(chunk)
            pbar.update(len(chunk))


def verify_sha256(filepath: Path, expected: str | None) -> bool:
    """Verify file integrity via SHA-256. Skips check when *expected* is None."""
    sha = hashlib.sha256()
    with open(filepath, "rb") as fh:
        for chunk in iter(lambda: fh.read(8192), b""):
            sha.update(chunk)
    computed = sha.hexdigest()

    if expected is None:
        print("SHA-256 verification skipped (no expected hash set).")
        print(f"  Computed SHA-256: {computed}")
        print("  Set EXPECTED_SHA256 in this script for future verification.")
        return True

    if computed != expected:
        print(f"SHA-256 mismatch!\n  Expected: {expected}\n  Got:      {computed}")
        return False

    print(f"SHA-256 verified: {computed[:16]}...")
    return True


def extract_archive(archive_path: Path, output_dir: Path) -> None:
    """Extract a zip archive into *output_dir*."""
    print(f"Extracting {archive_path.name} → {output_dir}/…")
    with zipfile.ZipFile(archive_path, "r") as zf:
        zf.extractall(output_dir)
    print("Extraction complete.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Download the LSNM2024 dataset for NIDS model training."
    )
    parser.add_argument(
        "--output-dir",
        "-o",
        type=Path,
        default=SCRIPT_DIR / "data",
        help="Directory to store the dataset (default: scripts/data/)",
    )
    parser.add_argument(
        "--url",
        type=str,
        default=None,
        help=(
            "Direct download URL (skip API lookup). "
            "Use this if the Mendeley API is unavailable."
        ),
    )
    parser.add_argument(
        "--skip-extract",
        action="store_true",
        help="Download only, do not extract the archive",
    )
    args = parser.parse_args()

    output_dir: Path = args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Resolve the download URL
    # ------------------------------------------------------------------
    download_url: str = args.url or ""
    archive_name = "lsnm2024_dataset.zip"

    if not download_url:
        print(
            f"Querying Mendeley Data API for dataset {DATASET_ID} "
            f"(version {DATASET_VERSION})…"
        )
        try:
            files = get_dataset_files(DATASET_ID, DATASET_VERSION)
            if not files:
                raise ValueError("API returned an empty file list.")
            download_url, archive_name = pick_download_url(files)
            if not download_url:
                raise ValueError(
                    "Could not extract a download URL from the API response."
                )
            print(f"  Resolved: {archive_name}")
        except Exception as exc:
            print(
                f"  API lookup failed: {exc}\n\n"
                "Please download the dataset manually from Mendeley Data:\n"
                f"  {MANUAL_DOWNLOAD_URL}\n\n"
                "Then re-run with:\n"
                f"  python scripts/ml/download_dataset.py --url <direct-file-url>\n"
                "or place the extracted CSV files directly in the data/ directory.",
                file=sys.stderr,
            )
            sys.exit(1)

    archive_path = output_dir / archive_name

    # ------------------------------------------------------------------
    # Download (skip if already present)
    # ------------------------------------------------------------------
    if archive_path.exists():
        print(f"Archive already exists: {archive_path}")
        print("Skipping download. Delete the file to re-download.")
    else:
        print(f"\nDownloading LSNM2024 dataset:\n  {download_url}")
        print(f"Saving to: {archive_path}\n")
        try:
            download_file(download_url, archive_path)
        except requests.HTTPError as exc:
            print(
                f"\nDownload failed: {exc}\n\n"
                "Download the dataset manually from Mendeley Data:\n"
                f"  {MANUAL_DOWNLOAD_URL}\n\n"
                "Place the CSV files in the data/ directory and re-run preprocessing.",
                file=sys.stderr,
            )
            sys.exit(1)

    # ------------------------------------------------------------------
    # Verify integrity
    # ------------------------------------------------------------------
    if not verify_sha256(archive_path, EXPECTED_SHA256):
        print("WARNING: File integrity check failed. The download may be corrupted.")
        sys.exit(1)

    # ------------------------------------------------------------------
    # Extract
    # ------------------------------------------------------------------
    if not args.skip_extract:
        if zipfile.is_zipfile(archive_path):
            extract_archive(archive_path, output_dir)
        else:
            print(
                f"{archive_path.name} is not a ZIP archive — "
                "it may already be a CSV file."
            )

    # ------------------------------------------------------------------
    # Report
    # ------------------------------------------------------------------
    csv_files = sorted(output_dir.rglob("*.csv"))
    if csv_files:
        print(f"\nFound {len(csv_files)} CSV file(s):")
        for f in csv_files:
            size_mb = f.stat().st_size / (1024 * 1024)
            rel = f.relative_to(output_dir)
            print(f"  {rel}  ({size_mb:.1f} MB)")
    else:
        print("\nNo CSV files found. Check the archive contents manually.")

    print(f"\nDataset ready in: {output_dir.resolve()}")
    print("Next step: python scripts/ml/preprocess.py --input-dir data/")


if __name__ == "__main__":
    main()
