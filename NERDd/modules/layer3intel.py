"""
NERD module getting IP info from Layer3 Intel (residential proxy feed).

Acknowledgment:
This product includes data from Layer3 Intel, available at https://www.layer3intel.com.
"""
import os
import logging
import sqlite3
import ipaddress

from datetime import datetime
from core.basemodule import NERDModule
import g

DB_FILE = "/data/layer3intel/layer3intel.db"

class Layer3Intel(NERDModule):
    """
    Layer3intel module.

    Queries IP addresses in Layer3 Intel residential proxy feed.
    Stores the following attributes:
      l3i.last_seen             # Last seen timestamp
      l3i.percent_days_seen     # How many days out of the last 30 we observed this IP as active
      l3i.networks              # Network/provider names
    """

    def __init__(self):
        self.log = logging.getLogger("Layer3intel")
        self.conn = None
        self.mtime = None
        self.provider_map = None

        g.um.register_handler(
            self.handler,
            'ip',
            ('!NEW', '!every1d', '!refresh_l3i'),
            ('l3i.last_seen', 'l3i.percent_days_seen', 'l3i.networks')
        )

    def __del__(self):
        if self.conn is not None:
            try:
                self.conn.close()
            except Exception:
                pass

    def handler(self, ekey, rec, updates):
        """
        Look up IP in Layer3 Intel data feed (stored locally in SQLite DB).
        If found, set/update last seen timestamp and other attributes, otherwise don't set anything.

        Arguments:
        ekey -- two-tuple of entity type and key, e.g. ('ip', '192.0.2.42')
        rec -- record currently assigned to the key
        updates -- list of all attributes whose update triggerd this call and
          their new values (or events and their parameters) as a list of
          2-tuples: [(attr, val), (!event, param), ...]

        Returns:
        List of update requests.
        """

        etype, key = ekey
        if etype != 'ip':
            return None

        if not os.path.exists(DB_FILE):
            self.log.warning(f"DB file '{DB_FILE}' not found!")
            return None
        self.reload_db_if_needed()

        try:
            ip_int = int(ipaddress.IPv4Address(key))
            cur = self.conn.cursor()
            cur.execute(
                """
                SELECT last_seen, percent_days_seen, providers
                FROM residential_proxies
                WHERE ip = ?
                """,
                (ip_int,)
            )

            row = cur.fetchone()
            if not row:
                return None
            last_seen, percent_days_seen, provider_ids = row

            # Map provider IDs to names
            provider_names = ", ".join(
                self.provider_map.get(int(pid), f"UNKNOWN({pid})")
                for pid in provider_ids.split(";")
                if pid
            )

            return [
                ('set', 'l3i.last_seen', datetime.utcfromtimestamp(last_seen)),
                ('set', 'l3i.percent_days_seen', percent_days_seen),
                ('set', 'l3i.networks', provider_names)
            ]
        except Exception as e:
            self.log.exception("Failed to query Layer3 Intel")
            return None

    def reload_db_if_needed(self):
        """Reopen DB file if download script replaced it"""

        if (mtime := os.path.getmtime(DB_FILE)) != self.mtime:
            self.mtime = mtime

            # Reopen DB file
            self.log.debug("Local DB was updated, reopening.")
            if self.conn is not None:
                self.conn.close()
            self.conn = sqlite3.connect(DB_FILE, check_same_thread=False)
            self.conn.execute("PRAGMA query_only = ON")

            # Reload provider map
            cur = self.conn.cursor()
            cur.execute("SELECT id, name FROM providers")
            self.provider_map = dict(cur.fetchall())
