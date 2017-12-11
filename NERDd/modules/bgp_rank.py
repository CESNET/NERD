"""
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

import bgpranking_web
import logging


class CIRCL_BGPRank(NERDModule):
    """
    BGP Rank module.

    Module for getting BGP rank of ASN entities using BGP Ranking API (bgpranking_web).
    """

    def __init__(self):
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
        ekey -- two-tuple of entity type and key, e.g. ('ip', '192.0.2.42')
        rec -- record currently assigned to the key
        updates -- list of all attributes whose update triggered this call and
          their new values (or events and their parameters) as a list of
          2-tuples: [(attr, val), (!event, param), ...]

        Returns:
        List of update requests (3-tuples describing requested attribute updates
        or events).
        None in case of error.
        In particular, the following update is requested:
          ('set', 'circl_bgprank', RANK_NUM)
        """
        etype, key = ekey

        if etype != 'asn':
            return None

        try:
            # the return format is: [asn, name, date, source, rank]
            reply = bgpranking_web.cached_daily_rank(ekey[1])
            if isinstance(reply, dict) and 'error' in reply:
                self.log.error("Can't get BGPRank of ASN {}, server returned error: {}".format(key, reply['error']))
                return None
            rank = reply[-1]
        except Exception as e:
            self.log.exception("Can't get BGPRank of ASN {}".format(key))
            return None             # could be connection error etc.

        return [('set', 'circl_bgprank', rank)]
