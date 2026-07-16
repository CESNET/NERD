#!/usr/bin/env python3

import logging
import argparse
import csv
import gzip
import ipaddress
import os
import sys
import sqlite3
import requests
from pathlib import Path

# Add to path the "one directory above the current file location" to find modules from "common"
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')))

from common.config import read_config

BATCH_SIZE = 10000
HTTP_TIMEOUT = 300

# Logging config
LOGFORMAT = "%(asctime)-15s,%(name)s [%(levelname)s] %(message)s"
LOGDATEFORMAT = "%Y-%m-%dT%H:%M:%S"
logging.basicConfig(level=logging.INFO, format=LOGFORMAT, datefmt=LOGDATEFORMAT)
logger = logging.getLogger("download_layer3intel_data")

# Parse arguments
parser = argparse.ArgumentParser(prog="download_layer3intel_data.py", description="NERD standalone script to download Layer3 Intel residential proxy feed")
parser.add_argument("-v", "--verbose", dest="verbose", action="store_true", help="Verbose mode")
parser.add_argument("-c", "--config", metavar="CONFIG_FILE", default="/etc/nerd/nerd.yml", help="Path to configuration file (default: /etc/nerd/nerd.yml)")
parser.add_argument("-i", "--insecure", dest="insecure", action="store_true", help="Skip certificate verification")
parser.add_argument("-w", "--workdir", metavar="WORKDIR", default="/data/layer3intel", help="Path to a directory where the downloaded files and local DB will be stored (default: /data/layer3intel)")
args = parser.parse_args()

if args.verbose:
    logger.setLevel("DEBUG")

workdir = Path(args.workdir)
etag_dir = workdir / ".etag"
db_file = workdir / "layer3intel.db"
residential_proxies_file = workdir / "residential_proxies.csv.gz"
providers_file = workdir / "provider_map.csv"
data_files = {
    "residential_proxies.csv.gz": residential_proxies_file,
    "provider_map.csv": providers_file,
}

# Load config
logger.info("Loading config file {}".format(args.config))
config = read_config(args.config)
l3i_url = config.get('layer3intel', {}).get('base_url')
l3i_username = config.get('layer3intel', {}).get('username')
l3i_password = config.get('layer3intel', {}).get('password')

def download_file(session: requests.Session, remote_name: str, local_path: Path) -> bool:
    """
    Download file if it has changed.

    Returns:
        True  -> downloaded
        False -> server returned 304 Not Modified
    """

    headers = {}
    etag_file = etag_dir / (remote_name + ".etag")
    if etag_file.exists():
        headers["If-None-Match"] = etag_file.read_text().strip()

    with session.get(
        f"{l3i_url}/{remote_name}",
        auth=(l3i_username, l3i_password),
        headers=headers,
        stream=True,
        timeout=HTTP_TIMEOUT,
        verify=(not args.insecure)
    ) as response:
        if response.status_code == 304:
            logger.debug(f"{remote_name}: unchanged")
            return False
        response.raise_for_status()

        tmp = local_path.with_suffix(local_path.suffix + ".tmp")
        with open(tmp, "wb") as f:
            for chunk in response.iter_content(chunk_size=1024 * 1024):
                if chunk:
                    f.write(chunk)
        os.replace(tmp, local_path)

        etag = response.headers.get("ETag")
        if etag:
            etag_file.write_text(etag)

        logger.debug(f"{remote_name}: downloaded")
        return True


def create_schema(conn: sqlite3.Connection):
    conn.executescript("""
        PRAGMA journal_mode=OFF;
        PRAGMA synchronous=OFF;
        PRAGMA locking_mode=EXCLUSIVE;
        PRAGMA temp_store=MEMORY;
        PRAGMA cache_size=-200000;

        CREATE TABLE providers(
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL
        );

        CREATE TABLE residential_proxies(
            ip INTEGER PRIMARY KEY,
            last_seen INTEGER NOT NULL,
            percent_days_seen INTEGER NOT NULL,
            providers TEXT NOT NULL
        );
    """)


def import_providers(conn: sqlite3.Connection):
    with open(providers_file, newline="") as f:
        reader = csv.DictReader(f)
        conn.executemany(
            """
            INSERT INTO providers(id, name)
            VALUES (?, ?)
            """,
            (
                (
                    int(row["provider_number"]),
                    row["provider_name"],
                )
                for row in reader
            ),
        )


def import_residential_proxies(conn: sqlite3.Connection):
    cursor = conn.cursor()
    batch = []

    with gzip.open(residential_proxies_file, "rt", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            batch.append(
                (
                    int(ipaddress.IPv4Address(row["ip"])),
                    int(row["last_seen"]),
                    int(row["percent_days_seen"]),
                    row["data_sources"],
                )
            )
            if len(batch) >= BATCH_SIZE:
                cursor.executemany(
                    """
                    INSERT INTO residential_proxies
                    VALUES (?, ?, ?, ?)
                    """,
                    batch,
                )
                batch.clear()
        if batch:
            cursor.executemany(
                """
                INSERT INTO residential_proxies
                VALUES (?, ?, ?, ?)
                """,
                batch,
            )


def main():
    workdir.mkdir(parents=True, exist_ok=True)
    etag_dir.mkdir(parents=True, exist_ok=True)

    logger.info("Downloading data files")
    changed = False
    try:
        with requests.Session() as session:
            for remote_name, local_path in data_files.items():
                changed |= download_file(session, remote_name, local_path)
    except Exception:
        logger.exception("Failed to download data files")
        return

    if not changed and db_file.exists():
        logger.info("Feed unchanged, nothing to do.")
        return

    tmp_db = db_file.with_suffix(".db.tmp")
    if tmp_db.exists():
        tmp_db.unlink()
    conn = sqlite3.connect(tmp_db)

    logger.info("Rebuilding local DB")
    try:
        create_schema(conn)
        conn.execute("BEGIN")

        logger.debug("Importing provider map")
        import_providers(conn)

        logger.debug("Importing residential proxies feed")
        import_residential_proxies(conn)

        conn.commit()
        os.replace(tmp_db, db_file)
        logger.info("Done")
    except Exception:
        logger.exception("Failed to rebuild local DB")
    finally:
        if conn is not None:
            conn.close()
        if tmp_db.exists():
            tmp_db.unlink()

if __name__ == "__main__":
    main()
