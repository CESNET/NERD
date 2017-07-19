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

        # Remove all event-records with day before cut_day
        actions = []
        num_events = 0
        for evtrec in rec['events']:
            if evtrec['date'] < cut_day: # Thanks to ISO format it's OK to compare dates as strings
                actions.append( ('array_remove', 'events', {'date': evtrec['date'], 'node': evtrec['node'], 'cat': evtrec['cat']}) )
            else:
                num_events += evtrec['n']
        
        # Set new total number of events
        if actions:
            actions.append(('set', 'events_meta.total', num_events))
        
        self.log.debug("Cleaning {}: Removing {} old event-records".format(key, len(actions)-1))
        return actions

