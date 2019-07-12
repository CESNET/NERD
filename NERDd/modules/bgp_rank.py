"""
TODO: Test if the python library pybgpranking will ge installed properly with clean installation
TODO: Try to properly handle error while querying - returns 0, when even wrong number/string is queried
NERD module

BGP Ranking API Python installation:

    git clone https://github.com/CIRCL/bgpranking-redis-api.git
    cd bgpranking-redis-api/example/api_web/client/
    python3 setup.py build
    sudo python3 setup.py install

I had to change the __init__.py file of this module:
(This path may vary.)
~/.local/lib/python3.5/site-packages/bgpranking_web/__init__.py
from api import *   ----> from .api import *

"""

from core.basemodule import NERDModule
import g

import logging
from pybgpranking.api import BGPRanking


class CIRCL_BGPRank(NERDModule):
    """
    BGP Rank module.

    Module for getting BGP rank of ASN entities using BGP Ranking API (bgpranking_web).
    """

    def __init__(self):
        self.bgp_session = BGPRanking()
        self.log = logging.getLogger('CIRCL_BGPRank')
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
            reply = self.bgp_session.query(key)

            # not sure if this error handle is enough, but when wrong format send to server, server returns same
            # response format with description equal to {}, rank equal to 0.0 and position is None
            if not reply['response']['asn_description'] and reply['response']['ranking']['rank'] == 0.0 and \
                    reply['response']['ranking']['position'] is None:
                self.log.error("Can't get BGPRank of ASN {}!".format(key))
                return None
            rank = reply['response']['ranking']['rank']
        except Exception as e:
            self.log.exception("Can't get BGPRank of ASN {}".format(key))
            return None             # could be connection error etc.

        return [('set', 'circl_bgprank', rank)]
