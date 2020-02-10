"""
NERD module for management of TTL of IP records.
"""

from core.basemodule import NERDModule
import g

import logging
from datetime import datetime, timedelta

# minimum number of events, where IP address has to occur in last 7 days, to be marked as highly active
DEFAULT_HIGHLY_ACTIVE_THRESHOLD = 1000
# TTL in days of highly active IP address
DEFAULT_HIGHLY_ACTIVE_TTL = 30
# number of days, which IP address has to be in NERD, to be marked as long active
DEFAULT_LONG_ACTIVE_THRESHOLD = 30
# TTL in days of long active IP address
DEFAULT_LONG_ACTIVE_TTL = 30

class TTLUpdater(NERDModule):
    """
    Module for updating TTL in highly active or long active IP address records.
    """
    def __init__(self):
        self.log = logging.getLogger('TTLUpdater')
        self.log.setLevel("DEBUG")

        # minimum number of events, where IP address has to occur in last 7 days, to be marked as highly active
        self.highly_active_threshold = g.config.get('record_life_threshold.highly_active', DEFAULT_HIGHLY_ACTIVE_THRESHOLD)
        # TTL in days of highly active IP address
        self.highly_active_ttl = g.config.get('record_life_length.highly_active', DEFAULT_HIGHLY_ACTIVE_TTL)

        # number of days, which IP address has to be in NERD, to be marked as long active
        self.long_active_threshold = g.config.get('record_life_threshold.long_active', DEFAULT_LONG_ACTIVE_THRESHOLD)
        # TTL in days of long active IP address
        self.long_active_ttl = g.config.get('record_life_length.long_active', DEFAULT_LONG_ACTIVE_TTL)

        g.um.register_handler(
            self.check_ttl,    # function (or bound method) to call
            'ip',              # entity type
            # tuple/list/set of attributes to watch (their update triggers call of the registered method)
            ('_ttl.warden', 'event_meta.total7'),
            ('_ttl.highly_active', '_ttl.long_active')    # tuple/list/set of attributes the method may change
        )

    def check_high_activity(self, new_updates, rec):
        try:
            if rec['events_meta']['total7'] > self.highly_active_threshold:
                record_ttl = datetime.utcnow() + timedelta(days=self.highly_active_ttl)
                new_updates.append(('set', '_ttl.highly_active', record_ttl))
        except KeyError:
            pass

    def check_long_activity(self, new_updates, rec):
        ip_lifetime = (rec['last_activity'] - rec['ts_added']).days
        if ip_lifetime > self.long_active_threshold:
            record_ttl = rec['last_activity'] + timedelta(days=self.long_active_ttl)
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
