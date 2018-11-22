"""
NERD module 
"""
from core.basemodule import NERDModule
import g

import logging
import numpy as np
from datetime import datetime, timedelta, timezone

class FMP(NERDModule):
    def __init__(self):
        self.log = logging.getLogger("FMPmodule")
        #self.log.setLevel('DEBUG')

        # Register all necessary handlers.
        g.um.register_handler(
            self.updateFMP,
            'ip',
            ('!every1d',),
            ('fmp',)
        )

    def updateFMP(self, ekey, rec, updates):
        etype, ip = ekey
        if etype != 'ip':
            return None

        actions = []
        watched_bl = set(['tor', 'blocklist-de-ssh', 'uceprotect', 'sorbs-dul', 'sorbs-noserver', 'sorbs-spam', 'spamcop', 'spamhaus-pbl', 'spamhaus-pbl-isp', 'spamhaus-xbl-cbl'])

        feat_v = np.array([])
        feat_v = np.resize(feat_v, 21)

        i = 0;
        if 'events_meta' in rec:
            metadata = rec['events_meta']
            # Alerts 1d
            feat_v[i] = metadata.get('total1', 0)
            i += 1
            # Alerts 7d
            feat_v[i] = metadata.get('total7', 0)
            i += 1
            # Nodes 1d
            feat_v[i] = metadata.get('nodes_1d', 0)
            i += 1
            # Nodes 7d
            feat_v[i] = metadata.get('nodes_7d', 0)
            i += 1
            # Alerts EWMA
            feat_v[i] = metadata.get('ewma', 0)
            i += 1
            # Binary Alerts EWMA
            feat_v[i] = metadata.get('bin_ewma', 0)
            i += 1
        else:
            i += 6

        # Last alert age
        feat_v[i] = (datetime.utcnow() - rec['ts_last_event']).total_seconds() / 86400
        i += 1

        # Blacklists
        if 'bl' in rec:
            present_blacklists = rec['bl']
            for bl in watched_bl:
                for present_bl in present_blacklists:
                    if present_bl['n'] == bl:
                        feat_v[i] = 1
                        break
                i += 1
        else:
            i += len(watched_bl)

        # Hostname exists
        if 'hostname' in rec:
            feat_v[i] = 1
            i += 1

            if 'tags' in rec:
                tags = rec['tags']

                # Static / dynamic IP
                if 'staticIP' in tags:
                    feat_v[i] = 1
                elif 'dynamicIP' in tags:
                    feat_v[i] = -1

                i += 1

                # DSL
                if 'dsl' in tags:
                    feat_v[i] = 1

                i += 1

                # IP in hostname
                if 'ip_in_hostname' in tags:
                    feat_v[i] = 1

                i += 1
            else:
                i += 3
        else:
            i += 4

        

        self.log.debug('FV: {}'.format(feat_v))


        #actions.append(('set', 'fmp.general', '0.5'))
        return actions