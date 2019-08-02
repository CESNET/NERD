"""
NERD update planner - adds NRU (next regular update) fields to the newly added entity.
Updater uses NRU fields to issue corresponding regular updates at the specified time.
Various modules may hook their functions to the regular updates.
"""

import logging
from datetime import datetime, timedelta, timezone

from core.basemodule import NERDModule
import g


class UpdatePlanner(NERDModule):
    """
    NERD update planner - adds NRU fields to the newly added entity.
    Fields added:
      '_nru4h'   Once every 4 hours
      '_nru1d'   Once every 1 day (24 hours)
      '_nru1w'   Once every 1 week (7 days)
    """
    def __init__(self):
        self.log = logging.getLogger('Updater')

        g.um.register_handler(self.add_nru_fields, 'ip', ('!NEW',),
            ('_nru4h','_nru1d','_nru1w',))
        g.um.register_handler(self.add_nru_fields, 'asn', ('!NEW',),
            ('_nru4h','_nru1d','_nru1w',))

    # Handler: !NEW -> set _nru*
    def add_nru_fields(self, ekey, rec, updates):
        """When a new entity is added, add NRU (next regular update) fields to
        its record."""
        return [
            ('set', '_nru4h', rec['ts_added'] + timedelta(seconds=4*60*60)),
            ('set', '_nru1d', rec['ts_added'] + timedelta(days=1)),
            ('set', '_nru1w', rec['ts_added'] + timedelta(days=7)),
        ]
