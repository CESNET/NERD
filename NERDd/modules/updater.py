"""
NERD updater - periodically issue special events (eg. '!every4h') for each
entity, various modules may hook on these events to perform periodic updates
of their data.

TODO: describe database keys and how it works
"""

import logging
from datetime import datetime, timedelta, timezone

from core.basemodule import NERDModule
import g

class Updater(NERDModule):
    """
    NERD updater - periodically issue special events for each entity.
    Events issued:
      '!every4h'   Once every 4 hours
      '!every1d'   Once every 1 day (24 hours)
      '!every1w'   Once every 1 week (7 days)
    Not all entities are updated at once, but each is updated after the
    specific time interval from its last update.
    """
    def __init__(self):
        self.log = logging.getLogger('Updater')
        #self.log.setLevel("DEBUG")
        
        self.POLL_INTERVAL = 10 # should be divisor of 60 (seconds)
        
        self.last_fetch_time = datetime(1970, 1, 1) # Time of last fetch of entites from DB
        
        g.um.register_handler(self.add_nru_fields, 'ip', ('!NEW',),
            ('_nru4h','_nru1d','_nru1w',))
        g.um.register_handler(self.add_nru_fields, 'asn', ('!NEW',),
            ('_nru4h','_nru1d','_nru1w',))
        
        g.scheduler.register(self.issue_events, second="*/"+str(self.POLL_INTERVAL))
        
    
    # Handler: !NEW -> set _nru*
    def add_nru_fields(self, ekey, rec, updates):
        """When new entity is added, add NRU (next regular update) fields to 
        its record."""
        # TODO round time to whole seconds
        return [
            ('set', '_nru4h', rec['ts_added'] + timedelta(seconds=4*60*60)),
            ('set', '_nru1d', rec['ts_added'] + timedelta(days=1)),
            ('set', '_nru1w', rec['ts_added'] + timedelta(days=7)),
        ]
    
    # Scheduled to be called every few seconds
    def issue_events(self):
        """Issue '!every*' events for all entites with NRU* > current time"""
        # Get all records whose next-regular-update time has passed
        time = datetime.utcnow()
        
        for etype in ('ip','asn'):
            # Get list of IDs for each update interval
            # (i.e. all entities with _nru* less then current time
            #  AND greater than time of the last query - this is important since
            #  _nru* of an entity is set to next interval only after the update
            #  is processed, which may take some time, and we don't want to
            #  fetch the same entity twice)
            self.log.debug("Getting list of '{}' entities to update ...".format(etype))
            ids4h = set()#set(g.db.find(etype, {'_nru4h': {'$lte': time, '$gt': self.last_fetch_time}}))
            ids1d = set(g.db.find(etype, {'_nru1d': {'$lte': time, '$gt': self.last_fetch_time}}))
            ids1w = set(g.db.find(etype, {'_nru1w': {'$lte': time, '$gt': self.last_fetch_time}}))
            self.last_fetch_time = time
            # Merge the lists, so for each entity only one update request is issued, possibly containing more than one event
            all_ids = ids4h | ids1d | ids1w # (Union not needed since list for 1d and 1w are always subsets of 4h)
            self.log.debug("Requesting updates for {} '{}' entities ({} 4h, {} 1d, {} 1w)".format(
                len(all_ids), etype, len(ids4h), len(ids1d), len(ids1w)
            ))
            for id in all_ids:
                # Each update request contains the corresponding "every*" event,
                # and a change of the '_nru*' attribute.
                requests = []
#                 if True: #id in ids4h:  (Since ids4h is superset of other, this is always true)
#                     requests.append(('event', '!every4h', None))
#                     requests.append(('next_step', '_nru4h', ('ts_added', time, timedelta(seconds=4*60*60))))
                if id in ids1d:
                    requests.append(('event', '!every1d', None))
                    requests.append(('next_step', '_nru1d', ('ts_added', time, timedelta(days=1))))
                if id in ids1w:
                    requests.append(('event', '!every1w', None))
                    requests.append(('next_step', '_nru1w', ('ts_added', time, timedelta(days=7))))
                # Issue update requests
                g.um.update((etype, id), requests)

