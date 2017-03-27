"""
NERD module summarizing all information about an entity into its reputation
score. (first prototype version)

Should be triggered at least once a day for every address.
"""

from core.basemodule import NERDModule
import g

from datetime import datetime, timedelta


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
            ('events.total','!every1d',), # tuple/list/set of attributes to watch (their update triggers call of the registered method)
            ('rep',) # tuple/list/set of attributes the method may change
        )


    def estimate_reputation(self, ekey, rec, updates):
        """
        Handler function to compute the reputation.
        
        Simple method (first prototype):
        - take list of events from last 14 days
        - compute a "daily repoutation" for each day as:
          - nonlin(num_of_events) * nonlin(number_of_nodes)
          - where nonlin is a nonlinear tranformation: 1 - 1/2^x
        - get total reputation as weighted average of all "daily" ones with
          linearly decreasing weight (weight = (14-n)/14 for n=0..13)
        """
        etype, key = ekey
        if etype != 'ip':
            return None

        today = datetime.utcnow().date()
        DATE_RANGE = 14
        sum_weight = 0
        rep = 0
        for n in range(0,DATE_RANGE): # n - iterating dates from now back to history
            d = today - timedelta(days=n)
            dstr = d.strftime("%Y-%m-%d")
            # reputation at day 'd'
            if dstr in rec['events']:
                d_events = rec['events'][dstr]
                d_n_nodes = len(d_events['nodes'])
                d_n_events = sum(val for cat,val in d_events.items() if cat != 'nodes')
                daily_rep = nonlin(d_n_events) * nonlin(d_n_nodes)
                #print(ip['_id'], dstr, d_n_nodes, d_n_events, nonlin(d_n_events), nonlin(d_n_nodes), daily_rep)
            else:
                daily_rep = 0.0
            # total reputation as weighted avergae with linearly decreasing weight
            weight = float(DATE_RANGE - n) / DATE_RANGE
            sum_weight += weight
            rep += daily_rep * weight
            #print(daily_rep, weight, sum_weight, rep)
        rep /= sum_weight
        return [('set', 'rep', rep)]

