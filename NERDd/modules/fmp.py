"""
NERD module 
"""
from core.basemodule import NERDModule
import g
import threading

import logging
import numpy as np
from datetime import datetime, timedelta, timezone
import re
import os
import fcntl

class FMP(NERDModule):
    def __init__(self):
        self.log = logging.getLogger("FMPmodule")
        #self.log.setLevel('DEBUG')
        self.paths = g.config.get("fmp.paths", {"general" : "/data/fmp/general/"})
        for key, value in self.paths.items():
            if not os.path.exists(value):
                os.makedirs(value)
                os.makedirs(value + "result/")

        np.set_printoptions(formatter={'float_kind': lambda x: "{:7.4f}".format(x)})

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
        attacked = 0

        i = 0;
        if 'events_meta' in rec:
            metadata = rec['events_meta']
            # Alerts 1d
            feat_v[i] = attacked = metadata.get('total1', 0)
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
        if feat_v[i] > 7.0:
            feat_v[i] = inf
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

        # TODO: load data model, process feature vector
        #actions.append(('set', 'fmp.general', '...'))

        self.logFMP(ip, feat_v, 0.5, attacked, self.paths['general'])

        return actions

    def logFMP(self, ip, fv, fmp, attacked, path):
        curTime = datetime.utcnow()
        logTime = curTime.strftime("%Y-%m-%dT%H:%M:%S")
        fileSuffix = curTime.strftime("%Y_%m_%d")
        attacked_bin = '1' if attacked > 0 else '0'
        prefix = logTime + ',' + ip + ','
        suffix = ",{:.4f}".format(fmp)

        f = open(path + fileSuffix, 'a')
        fcntl.flock(f, fcntl.LOCK_EX)
        f.write(prefix + re.sub(r"[ \]\[]", r"", np.array2string(fv, max_line_width=1000, separator=',')) + suffix + '\n')
        fcntl.flock(f, fcntl.LOCK_UN)
        f.close()

        f = open(path + 'result/' + fileSuffix, 'a')
        fcntl.flock(f, fcntl.LOCK_EX)
        f.write(prefix + attacked_bin + '\n')
        fcntl.flock(f, fcntl.LOCK_UN)
        f.close()