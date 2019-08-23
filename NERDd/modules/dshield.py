"""
NERD module for getting data from DShield API.

API documentation (with xml response example, but module uses json):
https://isc.sans.edu/api/#ip
XML: https://isc.sans.edu/api/ip/70.91.145.10
vs
JSON: https://isc.sans.edu/api/ip/70.91.145.10?json
"""

from core.basemodule import NERDModule
import g

import requests
import logging
import json


class DShield(NERDModule):
    """
    NERD class for getting data from DShield API.
    """

    def __init__(self):
        self.log = logging.getLogger('DShield')
        #self.log.setLevel("DEBUG")
        g.um.register_handler(
            self.set_dshield,  # function (or bound method) to call
            'ip',                # entity type
            ('!NEW', '!every1d'), # tuple/list/set of attributes to watch (their update triggers call of the registered method)
            ('dshield.reports',
             'dshield.targets',
             'dshield.mindate',
             'dshield.maxdate')    # tuple/list/set of attributes the method may change
        )

    def set_dshield(self, ekey, rec, updates):
        """
        Gets data from DShield api, parses them and returns them.
        """

        etype, key = ekey

        if etype != 'ip':
            return None

        try:
            # get response from server
            response = requests.get("https://isc.sans.edu/api/ip/" + key + "?json")
            data = json.loads(response.content.decode('utf-8'))['ip']

            dshield_record = {
                'reports': 0,
                'targets': 0,
                'mindate': "",
                'maxdate': "",
            }

            # server can return no values, if it has no record of this IP
            if data['count']:
                dshield_record['reports'] = data['count']
            if data['attacks']:
                dshield_record['targets'] = data['attacks']
            if data['mindate']:
                dshield_record['mindate'] = data['mindate']
            if data['maxdate']:
                dshield_record['maxdate'] = data['maxdate']

            # if some value is missing, DShield have no data for the IP (or the record is damaged), do not store
            if not (dshield_record['reports'] and dshield_record['targets'] and dshield_record['mindate'] and
                    dshield_record['maxdate']):
                self.log.debug("No data in DShield for IP {}".format(key))
                return None

        except Exception as e:
            self.log.error("Can't get DShield data for IP {}: {}".format(key, e))
            return None             # could be connection error etc.

        self.log.debug("DShield record for IP {}: {}".format(key, dshield_record))
        return [('set', 'dshield', dshield_record)]
