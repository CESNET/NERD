"""
NERD module summarizing number of events in last day, week and month (30 days).

Should be triggered at least once a day for every address.
"""

from core.basemodule import NERDModule
import g

import datetime

# TODO - (re)compute sets of nodes for 1, 7 and 30 days as well (or do it in frontend?)

class EventCounter(NERDModule):
    """
    Module counting number of recent events.

    Periodically updates number of events in the last 1, 7 and 30 days.
    
    It's always the number of events in the current day (since 00:00 UTC) plus
    number of events in 1, 7 or 30 previous days.
    Therefore, "total1" contains number of events in previous 24 to 48 hours,
    depending on the time this function was triggered.
    
    The !refresh_event_count should be triggered when no event was added to 
    the IP for more than 24 hours.

    Event flow specification:
      events.total -> count_events -> events_meta.{total1,total7,total30}
      !every1d -> count_events -> events_meta.{total1,total7,total30}

    # TODO: for now this hooks on events.total which is updated by event_receiver on every new event
      since it can't be hooked on events.<date> because date is changing.
      It would be better to even allow to hook on "events.*"
      or to issue an "!NEW_EVENT" update request when a new event is added, and hook this to it instead.
    """

    def __init__(self):
        g.um.register_handler(
            self.count_events, # function (or bound method) to call
            'ip', # entity type
            ('events_meta.total','!every1d'), # tuple/list/set of attributes to watch (their update triggers call of the registered method)
            ('events_meta.total1','events_meta.total7','events_meta.total30') # tuple/list/set of attributes the method may change
        )


    def count_events(self, ekey, rec, updates):
        """
        Count total number of events in last 1, 7 adn 30 days for given IP.

        Arguments:
        ekey -- two-tuple of entity type and key, e.g. ('ip', '192.0.2.42')
        rec -- record currently assigned to the key
        updates -- list of all attributes whose update triggered this call and  
          their new values (or events and their parameters) as a list of 
          2-tuples: [(attr, val), (!event, param), ...]

        Returns:
        List of update requests (3-tuples describing requested attribute updates
        or events).
        In particular, the following updates are requested:
          ('set', 'events_meta.total{1,7,30}', number_of_events)
        """
        etype, key = ekey
        if etype != 'ip':
            return None

        today = datetime.datetime.utcnow().date()
        
        total1 = 0
        total7 = 0
        total30 = 0
        for evtrec in rec['events']:
            n = evtrec['n']
            date = evtrec['date']
            date = datetime.date(int(date[0:4]), int(date[5:7]), int(date[8:10]))
            days_diff = (today - date).days
            if days_diff <= 1:
                total1 += n
            if days_diff <= 7:
                total7 += n
            if days_diff <= 30:
                total30 += n

        return [
            ('set', 'events_meta.total1', total1),
            ('set', 'events_meta.total7', total7),
            ('set', 'events_meta.total30', total30),
        ]

