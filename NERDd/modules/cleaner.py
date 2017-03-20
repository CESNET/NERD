"""
NERD module clearing old entries from entity records.

This only removes old parts of records (like metadata about evetns),
whole records are removed by an external script.
"""
import logging
from datetime import datetime, timedelta

from core.basemodule import NERDModule
import g

class Cleaner(NERDModule):
    """
    Module clearing old entries from entity records.

    Event flow specification:
      !every1d -> clear_events -> []
    """

    def __init__(self):
        self.log = logging.getLogger("Cleaner")
        #self.log.setLevel("DEBUG")

        max_event_history = g.config.get("max_event_history")
        self.max_event_history = timedelta(days=max_event_history)

        g.um.register_handler(
            self.clear_events,
            'ip',
            ('!every1d',),
            tuple() # No key is changed; some are removed, but there's no way to specify list of keys to delete in advance; anyway it shouldn't be a problem in this case.
        )


    def clear_events(self, ekey, rec, updates):
        """
        Handler function to clear old events metadata.
        
        Remove all keys named "events.%Y-%m-%d" with the date older then current
        day minus 'max_event_history' days.
        """
        etype, key = ekey
        if etype != 'ip':
            return None

        today = datetime.utcnow().date()
        cut_day = (today - self.max_event_history).strftime("%Y-%m-%d")

        # Get list of days to delete
        days = [d for d in rec['events'].keys() if not d.startswith("total") and d < cut_day]
        if not days:
            return None
        # Get total number of events that will be deleted
        events = rec['events']
        num_events = sum(events[d][cat] for d in days for cat in events[d].keys() if cat != "nodes")

        # Issue request to remove info from given days and subtract corresponding number of events from "total" counter
        self.log.debug("Cleaning {}: Removing info on {} events from dates: {}".format(key, num_events, ','.join(days)))
        return [('remove', 'events.'+d, None) for d in days] + [('sub', 'events.total', num_events)]

