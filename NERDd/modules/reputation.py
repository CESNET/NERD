"""
NERD module summarizing all information about an entity into its reputation
score. (first prototype version)

Should be triggered at least once a day for every address.
"""

from core.basemodule import NERDModule
import g

import datetime


def nonlin(val, coef=0.5, max=20):
    """Nonlinear transformation of [0,inf) to [0,1)"""
    if val > max:
        return 1.0
    else:
        return (1 - coef**val)


class Reputation(NERDModule):
    """
    Module estimating reputation score of IPs.
    
    TODO better description
    
    Event flow specification:
      !every1d -> estimate_reputation -> rep
    """

    def __init__(self):
        g.um.register_handler(
            self.estimate_reputation, # function (or bound method) to call
            'ip', # entity type
            ('events_meta.total','!every1d',), # tuple/list/set of attributes to watch (their update triggers call of the registered method)
            ('rep',) # tuple/list/set of attributes the method may change
        )


    def estimate_reputation(self, ekey, rec, updates):
        """
        Handler function to compute the reputation.
        
        Simple method (first prototype):
        - take list of events from last 14 days
        - compute a "daily reputation" for each day as:
          - nonlin(num_of_events) * nonlin(number_of_nodes)
          - where nonlin is a nonlinear transformation: 1 - 1/2^x
        - get total reputation as weighted average of all "daily" ones with
          linearly decreasing weight (weight = (14-n)/14 for n=0..13)
        """
        etype, key = ekey
        if etype != 'ip':
            return None

        if 'events' not in rec:
            return None # No Warden event, nothing to do

        today = datetime.datetime.utcnow().date()
        DATE_RANGE = 14
        
        # Get total number of events and list of nodes for each day
        # (index 'd' of arrays is 'number of days before today')
        num_events = [0 for _ in range(DATE_RANGE)]
        set_nodes = [set() for _ in range(DATE_RANGE)]
        for evtrec in rec['events']:
            date = evtrec['date']
            date = datetime.date(int(date[0:4]), int(date[5:7]), int(date[8:10]))
            d = (today - date).days
            if d >= DATE_RANGE:
                continue
            num_events[d] += evtrec['n']
            set_nodes[d].add(evtrec['node'])
        
        # Compute reputation score
        sum_weight = 0
        rep = 0
        for d in range(0,DATE_RANGE):
            # reputation at day 'd'
            daily_rep = nonlin(num_events[d]) * nonlin(len(set_nodes[d]))
            # total reputation as weighted average with linearly decreasing weight
            weight = float(DATE_RANGE - d) / DATE_RANGE
            sum_weight += weight
            rep += daily_rep * weight
        rep /= sum_weight
        return [('set', 'rep', rep)]

