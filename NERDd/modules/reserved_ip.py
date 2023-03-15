"""
NERD module checks whether the ip address is reserved or not, based on the list:
https://en.wikipedia.org/wiki/Reserved_IP_addresses
"""

import logging
import re

from core.basemodule import NERDModule
import g


class ReservedIPTags(NERDModule):
    # these prefixes stands for 0.0.0.0 - 0.255.255.255, 10.0.0.0 - 10.255.255.255, ...
    # https://en.wikipedia.org/wiki/Reserved_IP_addresses
    reserved_ip_prefix_list = ["0.", "10.", "127.", "169.254.", "192.0.0.", "192.0.2.", "192.168.", "198.51.100.",
                               "203.0.113.", "255.255.255.255"]

    # list of regular expressions for more complicated ip ranges. The first one is:
    #                       100.64.0.0 - 100.127.255.255
    #                       100. 64-69|70-99|100-119|120-127 .0-255.0-255
    # The rest is in the same format, so only ranges are in the comment. The end of range (0-255 = \d{1,3}) is not
    # absolutely correct part of the regular expression, but should be totally fine in this use case.
    reserved_ip_re_list = [re.compile("100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\.\d{1,3}\.\d{1,3}"),
                           # 172.16.0.0 - 172.31.255.255
                           re.compile("172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}"),
                           # 198.18.0.0 - 198.19.255.255
                           re.compile("198\.1[8-9]\.\d{1,3}\.\d{1,3}]"),
                           # 224.0.0.0 - 255.255.255.255
                           re.compile("2(2[4-9]|[3-4][0-9]|5[0-5])\.\d{1,3}\.\d{1,3}\.\d{1,3}")]

    def __init__(self):
        # self.logger = logging.getLogger("ReservedIPTags")
        g.um.register_handler(
            self.is_reserved,
            'ip',
            ('!NEW', ),
            ('reserved_range', )
        )

    def is_reserved(self, ekey, rec, updates):
        """
        Checks if IP address is reserved IP address or not. If the IP address is reserved, then sets 'reserved_range'
        attribute to 1, otherwise sets 'reserved range' to 0

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

        # Go through all the prefixes and try to match the IP (key) with prefix. When match found, then tag it. If no
        # match found, try the rest of reserved ranges (regular expressions)
        for ip_prefix in ReservedIPTags.reserved_ip_prefix_list:
            if key.startswith(ip_prefix):
                # tag it, set 1 as True, because IP is in reserved range
                return [('set', 'reserved_range', 1)]
        else:
            for re_ip in ReservedIPTags.reserved_ip_re_list:
                if re_ip.search(key):
                    # tag it, set 1 as True, because IP is in reserved range
                    return [('set', 'reserved_range', 1)]

        # set 0 as False, because IP is not in reserved range
        return [('set', 'reserved_range', 0)]
