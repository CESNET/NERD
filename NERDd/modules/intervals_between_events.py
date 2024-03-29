from core.basemodule import NERDModule
import g

import logging


class IntervalsBetweenEvents(NERDModule):
    """
    This module stores timestamps of the last N warden events.
    """
    def __init__(self):
        self.log = logging.getLogger("FMPmodule")
        self.max_events = 21

        # Register all necessary handlers.
        g.um.register_handler(
            self.updateIntervalsBetweenEvents,
            'ip',
            ('last_warden_event',),
            ('_intervals_between_events',)
        )

    def updateIntervalsBetweenEvents(self, ekey, rec, updates):
        if '_intervals_between_events' in rec:
            timestamps = rec['_intervals_between_events']
            timestamps.append(rec['last_warden_event'])
        else:
            timestamps = [rec['last_warden_event']]

        return [
            ('set', '_intervals_between_events', timestamps[-self.max_events:])
        ]