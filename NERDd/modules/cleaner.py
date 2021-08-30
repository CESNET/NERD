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
        # self.log.setLevel("DEBUG")

        max_event_history = g.config.get("max_event_history")
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
            self.clear_otx_pulses,
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
        Handler function to clear old Warden events metadata.
        
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
        for evtrec in rec.get('events', []):
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
    
    def clear_otx_pulses(self, ekey, rec, updates):
        """
        Handler function to clear old otx pulses data
        Remove all items under otx_pulses with "indicator_expiration" older then current
        day minus 'max_event_history' days.
        """
        etype, key = ekey
        if etype != 'ip':
            return None

        cut_time = datetime.utcnow()-timedelta(days=30)-self.max_event_history
        actions = []
        
        for otx_pulse in rec.get('otx_pulses', []):
            if (otx_pulse.get('indicator_expiration') and (otx_pulse.get('indicator_expiration') < cut_time)) or ((otx_pulse.get('indicator_expiration') is None) and (otx_pulse.get('indicator_created') < cut_time)):
                actions.append(('array_remove', 'otx_pulses', {'pulse_id': otx_pulse['pulse_id']}))
        return actions

    def check_ip_expiration(self, ekey, rec, updates):
        """
        Check record's TTL tokens, and either issue normal !every1d or delete the record.

        Event !check_and_update_1d is called by Updater instead of normal !every1d, in order to first check if the
        record still has some valid TTL token. If not (all token has expired), the record is no longer valid and !DELETE
        event is issued. Otherwise, any expired tokens are removed from '_ttl' dict and normal !every1d event is issued.
        """
        etype, key = ekey
        if etype != 'ip':
            return None

        now = datetime.utcnow()
        actions = []
        ttl_tokens = rec.get('_ttl', {})
        new_ttl_tokens = ttl_tokens.copy()
        for name, expiration in ttl_tokens.items():
            if expiration == '*':
                # record should be alive forever
                continue
            elif now >= expiration:
                # token expired, remove it
                new_ttl_tokens.pop(name)

        if not new_ttl_tokens:
            # all tokens are expired (_ttl empty), delete the record
            actions.append(('event', '!DELETE'))
            return actions

        if new_ttl_tokens != ttl_tokens:
            # some token was removed, update _ttl
            actions.append(('set', '_ttl', rec['_ttl']))

        # there is still at least one _ttl token - keep the record and issue normal !every1d event
        actions.append(('event', '!every1d'))
        return actions
