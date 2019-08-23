"""
NERD module fetching BGP ranking of ASNs from CIRCL's server.

Official API client is not used, since it's just a simple 'requests' wrapper. We rather construct requests ourselves.
"""

from core.basemodule import NERDModule
import g

import logging
import requests

BASE_URL = "https://bgpranking-ng.circl.lu/"
QUERY_URL = BASE_URL + "json/asn"

class CIRCL_BGPRank(NERDModule):
    """
    BGP Rank module.

    Module for getting BGP rank of ASN entities using BGP Ranking API (bgpranking_web).
    """

    def __init__(self):
        self.log = logging.getLogger('CIRCL_BGPRank')
        self.log.setLevel("DEBUG")
        self.requests_session = requests.session()
        g.um.register_handler(
            self.set_bgprank,  # function (or bound method) to call
            'asn',                # entity type
            ('!NEW', '!every1d'), # tuple/list/set of attributes to watch (their update triggers call of the registered method)
            ('circl_bgprank',)    # tuple/list/set of attributes the method may change
        )

    def set_bgprank(self, ekey, rec, updates):
        """
        Set a 'circl_bgprank' attribute as a result of BGP Ranking query on the ASN.

        Arguments:
        ekey -- two-tuple of entity type and key, e.g. ('asn', 1234)
        rec -- record currently assigned to the key
        updates -- list of all attributes whose update triggered this call and
          their new values (or events and their parameters) as a list of
          2-tuples: [(attr, val), (!event, param), ...]

        Returns:
        List of update requests (3-tuples describing requested attribute updates
        or events).
        None in case of error.
        In particular, the following update is requested
          ('set', 'circl_bgprank', RANK_NUM)
        """
        etype, key = ekey

        if etype != 'asn':
            return None

        #query = json.dumps({'asn': key, 'address_family': 'v4'})
        query = '{"asn": ' + str(key) + ', "address_family": "v4"}'
        try:
            # the return format is:
            # {'meta': {'asn': integer, 'address_family': 'v4'},
            #  'response': {'asn_description': 'xxx',
            #               'ranking': {'rank': double,
            #                           'position': integer,
            #                           'total_known_asns': integer
            #                          }
            #              }
            # }
            reply = self.requests_session.post(QUERY_URL, data=query, timeout=(1,3))
            reply = reply.json()

            # when ASN is not found (or request is completely wrong), server returns the same response format with
            # empty asn_description, rank equal to 0.0 and position is None
            rank = reply['response']['ranking']['rank']
            pos = reply['response']['ranking']['position']
            if not reply['response']['asn_description'] and rank == 0.0 and pos is None:
                self.log.info("ASN {} not found in BGP ranking database".format(key))
            self.log.debug("Setting BGPRank of ASN {} to {}".format(key, rank))
        except Exception as e:
            self.log.error("Can't get BGPRank of ASN {}: {}".format(key, str(e)))
            return None             # could be connection error etc.

        return [('set', 'circl_bgprank', rank)]
