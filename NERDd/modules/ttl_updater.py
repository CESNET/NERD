"""
NERD module for management of TTL of IP records.
"""

from core.basemodule import NERDModule
import g

import logging
from datetime import datetime, timedelta


class TTLUpdater(NERDModule):
    """
    Module for updating TTL in highly active or long active IP address records.
    """
    # minimum number of events, where IP address has to occur in last 7 days, to be marked as highly active
    HIGHLY_ACTIVE_THRESHOLD = 1000
    # TTL in days of highly active IP address
    HIGHLY_ACTIVE_TTL = 14
    # number of days, which IP address has to be in NERD, to be marked as long active
    LONG_ACTIVE_THRESHOLD = 30
    # TTL in days of long active IP address
    LONG_ACTIVE_TTL = 28

    def __init__(self):
        self.log = logging.getLogger('TTLUpdater')
        self.log.setLevel("DEBUG")

        g.um.register_handler(
            self.check_ttl,    # function (or bound method) to call
            'ip',              # entity type
            # tuple/list/set of attributes to watch (their update triggers call of the registered method)
            ('_ttl.warden', 'event_meta.total7'),
            ('_ttl.highly_active', '_ttl.long_active')    # tuple/list/set of attributes the method may change
        )

    def check_high_activity(self, new_updates, rec):
        try:
            if rec['events_meta']['total7'] > TTLUpdater.HIGHLY_ACTIVE_THRESHOLD:
                record_ttl = datetime.utcnow() + timedelta(days=self.HIGHLY_ACTIVE_TTL)
                new_updates.append(('set', '_ttl.highly_active', record_ttl))
        except KeyError:
            pass

    def check_long_activity(self, new_updates, rec):
        ip_lifetime = (rec['ts_last_update'] - rec['ts_added']).days
        if ip_lifetime > TTLUpdater.LONG_ACTIVE_THRESHOLD:
            record_ttl = rec['ts_last_update'] + timedelta(days=self.LONG_ACTIVE_TTL)
            new_updates.append(('set', '_ttl.long_active', record_ttl))

    def check_ttl(self, ekey, rec, updates):
        """
        Check if IP address is 'highly active' or 'long active' and if so, then set corresponding TTL
        :param ekey: two-tuple of entity type and key, e.g. ('ip', '212.227.17.11')
        :param rec: record currently assigned to the key
        :param updates: list of all attributes whose update triggered this call and their new values (or events and
                    their parameters) as a list of 2-tuples: [(attr, val), (!event, param), ...]
        :return: List of update requests (3-tuples describing requested attribute updates or events).
        """
        etype, key = ekey

        if etype != "ip":
            return None

        new_updates = []
        self.check_high_activity(new_updates, rec)
        self.check_long_activity(new_updates, rec)
        return new_updates
