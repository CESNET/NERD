"""
NERD module for getting data from DShield API.

API documentation (with xml response example):
https://isc.sans.edu/api/#ip

"""

from core.basemodule import NERDModule
import g

from copy import copy
import xml.etree.ElementTree as ET
import requests
import logging
import json

class DShield(NERDModule):
    """
    NERD class for getting data from DShield API.

    """

    def __init__(self):
        self.log = logging.getLogger('DShield')
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
            response = requests.get("http://isc.sans.edu/api/ip/" + ekey[1])
            # parse xml response
            root = ET.fromstring(response.text)
            # make a dict from the response
            dict_response = self.dictify(root)
            reports = targets = mindate = maxdate = ""

            # server can return no values, if it has no record of this IP
            if "value" in dict_response["ip"]["count"][0].keys():
                reports = dict_response["ip"]["count"][0]["value"]
            if "value" in dict_response["ip"]["attacks"][0].keys():
                targets = dict_response["ip"]["attacks"][0]["value"]
            if "value" in dict_response["ip"]["mindate"][0].keys():
                mindate = dict_response["ip"]["mindate"][0]["value"]
            if "value" in dict_response["ip"]["maxdate"][0].keys():
                maxdate = dict_response["ip"]["maxdate"][0]["value"]

            if reports == "" or targets == "" or mindate == "" or maxdate == "":
                return None

        except Exception as e:
            self.log.exception(e.__str__())
            return None             # could be connection error etc.

        return_arr = [
            ('set', 'dshield.reports', reports),
            ('set', 'dshield.targets', targets),
            ('set', 'dshield.mindate', mindate),
            ('set', 'dshield.maxdate', maxdate)
        ]

        return return_arr

    def dictify(self, r, root=True):
        if root:
            return {r.tag: self.dictify(r, False)}
        d = copy(r.attrib)
        if r.text:
            d["value"] = r.text
        for x in r.findall("./*"):
            if x.tag not in d:
                d[x.tag] = []
            d[x.tag].append(self.dictify(x, False))
        return d

# easy test
# dshield_reporter = DShield()
# print (dshield_reporter.set_dshield(('ip', '70.91.145.10'), None, None))
