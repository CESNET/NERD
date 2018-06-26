"""
NERD module clearing old entries from entity records.
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
        ip_lifetime = g.config.get("inactive_ip_lifetime")
        self.ip_lifetime = timedelta(days=ip_lifetime)
        self.max_event_history = timedelta(days=max_event_history)

        g.um.register_handler(
            self.clear_events,
            'ip',
            ('!every1d',),
            tuple() # No key is changed; some are removed, but there's no way to specify list of keys to delete in advance; anyway it shouldn't be a problem in this case.
        )
        g.um.register_handler(
            self.clear_bl_hist,
            'ip',
            ('!every1d',),
            tuple() # No key is changed; some are removed, but there's no way to specify list of keys to delete in advance; anyway it shouldn't be a problem in this case.
        )
        g.um.register_handler(
            self.check_ip_expiration,
            'ip',
            ('!check_and_update_1d',),
            tuple()
        )


    def clear_events(self, ekey, rec, updates):
        """
        Handler function to clear old events metadata.
        
        Remove all items under events with "date" older then current
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


    def clear_bl_hist(self, ekey, rec, updates):
        """
        Handler function to clear old blacklist data.
        
        Remove all items from bl[].h arrays with date older then current
        day minus 'max_event_history' days.
        """
        etype, key = ekey
        if etype != 'ip':
            return None

        cut_time = datetime.utcnow() - self.max_event_history

        actions = []
        # IP blacklists
        for blrec in rec.get('bl', []):
            # Create a new list without the old records
            newlist = [ts for ts in blrec['h'] if ts > cut_time]
            if len(newlist) == 0:
                # Everything was removed -> remove whole blacklist-record
                actions.append( ('array_remove', 'bl', {'n': blrec['n']}) )
            elif len(newlist) != len(blrec['h']):
                # If something was removed, replace the list in the record with the new one
                actions.append( ('array_update', 'bl', {'n': blrec['n']}, [('set', 'h', newlist)]) )
        
        # Domain blacklists
        for blrec in rec.get('dbl', []):
            # Create a new list without the old records
            newlist = [ts for ts in blrec['h'] if ts > cut_time]
            if len(newlist) == 0:
                # Everything was removed -> remove whole blacklist-record
                actions.append( ('array_remove', 'dbl', {'n': blrec['n'], 'd': blrec['d']}) )
            elif len(newlist) != len(blrec['h']):
                # If something was removed, replace the list in the record with the new one
                actions.append( ('array_update', 'dbl', {'n': blrec['n'], 'd': blrec['d']}, [('set', 'h', newlist)]) )
        
        return actions

    def check_ip_expiration(self, ekey, rec, updates):
        """
        Handler function to issue !every1d and !every1w event in case the IP record is still valid.
        If the IP record is no longer valid, a !DELETE event is issued.
        """
        etype, key = ekey
        if etype != 'ip':
            return None

        diff = datetime.utcnow() - rec['ts_last_event']
        actions = []

        if diff >= self.ip_lifetime:
            actions.append(('event', '!DELETE'))
            return actions
        else:
            actions.append(('event', '!every1d'))
            return actions
