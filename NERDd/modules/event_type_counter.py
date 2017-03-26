"""
NERD module determines main types of attack going from IP according to given parameters. 
"""

from .base import NERDModule

import datetime
import logging
import os
import re

class EventTypeCounter(NERDModule):
    """
    EventTypeCounter module updates main event types for IP which triggered this module.  
    Behavior of this module can be parameterized by threshold, time period 
    and minimal required number of events for event type determination.

    Event flow specification:
    [ip] 'events.total' -> count_type() -> 'events.types'
    """
    
    def __init__(self, config, update_manager):
        self.log = logging.getLogger("EventTypeCounter")
        self.event_days = config.get("event_type_counter.days", None)
        self.event_threshold = config.get("event_type_counter.threshold", 5)
        self.event_min = config.get("event_type_counter.min_num_of_events", 0)
	
        update_manager.register_handler(
	    self.count_type,
	    'ip',
	    ('events.total',),
	    ('events.types',)
        )


    def count_type(self, ekey, rec, updates):
        """
        Counts number of events for each event type for given time period (or counts all 
        event if time period is not set).
        If total number of events is equal or greater than minimal required number of events and
        percentage of specific event type is equal or greater than threshold, this specific
        event type extends list of main event type for IP which triggered this module.

        Arguments:
        ekey -- two-tuple of entity type and key, e.g. ('ip', '192.0.2.42')
        rec -- record currently assigned to the key
        updates -- list of all attributes whose update triggered this call and
                   their new values (or events and their parameters) as a list of
                   2-tuples: [(attr, val), (!event, param), ...]

        Return:
        List of update requests.
        """

        etype, key = ekey
        if etype != 'ip':
            return None

        ret = []
        total_events = 0
        types = {}

        if self.event_days is not None:
            today = datetime.datetime.utcnow().date()
            for day in range(0,self.event_days+1):
                date = today - datetime.timedelta(days=day)
                if date.isoformat() in rec["events"]:
                    events_in_day = rec["events"][date.isoformat()]
                    for event_type in events_in_day:
                        if event_type != "nodes":
                            total_events += events_in_day[event_type]
                            if event_type not in types:
                                types[event_type] = events_in_day[event_type]
                            else:
                                types[event_type] += events_in_day[event_type]

        else:
            regex = re.compile("[0-9]{4}-[0-9]{2}-[0-9]{2}")
            for event_key in rec["events"]:
                if regex.match(event_key):
                    events_in_day = rec["events"][event_key]
                    for event_type in events_in_day:
                        if event_type != "nodes":
                            total_events += events_in_day[event_type]
                            if event_type not in types:
                                types[event_type] = events_in_day[event_type]
                            else:
                                types[event_type] += events_in_day[event_type]


        if total_events < self.event_min:
            if self.event_days is not None:
                self.log.debug("In last {} days only {} events happened for IP {} (minimal number of events for classification is {}).".format(self.event_days, total_events, key, self.event_min)) 
            else:
                self.log.debug("Only {} events happened for IP {} (minimal number of events for classification is {}).".format(total_events, key, self.event_min)) 
            return [('set', 'events.types', [])]

        for event_type in types:
            if (types[event_type]/total_events*100) >= self.event_threshold:
               self.log.debug("Event type {} exceed {}% threshold for IP {} ({} events from {}).".format(event_type, self.event_threshold, key, types[event_type], total_events))
               ret.append(event_type)
            else:
               self.log.debug("Event type {} doesn't exceed {}% threshold for IP {} ({} events from {}).".format(event_type, self.event_threshold, key, types[event_type], total_events))

        return [('set', 'events.types', ret)] 
