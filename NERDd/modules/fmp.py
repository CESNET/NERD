"""
NERD module 
"""
from core.basemodule import NERDModule
import g

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
                os.makedirs(os.path.join(value, "results/"))

        np.set_printoptions(formatter={'float_kind': lambda x: "{:7.4f}".format(x)})
        self.watched_bl = {
            'tor' : 0,
            'blocklist-de-ssh' : 1,
            'uceprotect' : 2,
            'sorbs-dul' : 3,
            'sorbs-noserver' : 4,
            'sorbs-spam' : 5,
            'spamcop' : 6,
            'spamhaus-pbl' : 7,
            'spamhaus-pbl-isp' : 8,
            'spamhaus-xbl-cbl': 9
        }

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

        feat_v = np.zeros(21)
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
            feat_v[i] = float("inf")
        i += 1

        # Blacklists
        if 'bl' in rec:
            present_blacklists = rec['bl']
            for bl in present_blacklists:
                if bl in self.watched_bl.keys() and bl['v'] == "1":
                    feat_v[i + self.watched_bl[bl]] = 1

        i += len(self.watched_bl)

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

        f = open(os.path.join(path, fileSuffix), 'a')
        fcntl.flock(f, fcntl.LOCK_EX)
        f.write(prefix + re.sub(r"[ \]\[]", r"", np.array2string(fv, max_line_width=1000, separator=',')) + suffix + '\n')
        fcntl.flock(f, fcntl.LOCK_UN)
        f.close()

        f = open(os.path.join(path, 'results', fileSuffix), 'a')
        fcntl.flock(f, fcntl.LOCK_EX)
        f.write(prefix + attacked_bin + '\n')
        fcntl.flock(f, fcntl.LOCK_UN)
        f.close()