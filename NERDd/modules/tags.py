"""
NERD module 
"""

from core.basemodule import NERDModule

import g

import datetime
import logging
import os
import re

class Tags(NERDModule):
    """

    Event flow specification:
    [ip] '' -> update_tags() -> ''
    """
    
    def __init__(self, config, update_manager):
        self.log = logging.getLogger("Tags")
	
        g.um.register_handler(
	    self.update_tags,
	    'ip',
	    ('events.types',),
	    ('ts_added',)
        )


    def update_tags(self, ekey, rec, updates):
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

        return [('del', 'ts_added', None)] 
