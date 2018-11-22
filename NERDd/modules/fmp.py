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

import xgboost as xgb

class FMP(NERDModule):
    def __init__(self):
        self.log = logging.getLogger("FMPmodule")
        #self.log.setLevel('DEBUG')
        self.paths = g.config.get("fmp.paths", {"general" : "/data/fmp/general/"})
        for key, value in self.paths.items():
            if not os.path.exists(value):
                os.makedirs(value)
            if not os.path.exists(os.path.join(value, "results/")):
                os.makedirs(os.path.join(value, "results/"))

        self.modelsPaths = g.config.get("fmp.models", {"general" : "/data/fmp/models/general.bin"})
        self.models = {}

        # Can segfault in case of non-existing file
        for key, value in self.modelsPaths.items():
            if os.path.exists(value):
                self.models[key] = xgb.Booster({'nthread': 4})
                self.models[key].load_model(value)
            else:
                self.log.warning('Unable to find model file "{}"" for type "{}".'.format(value, key))

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
            self.updateFMPGeneral,
            'ip',
            ('!every1d',),
            ('fmp',)
        )

    def updateFMPGeneral(self, ekey, rec, updates):
        etype, ip = ekey
        if etype != 'ip' or 'general' not in self.models.keys():
            return None

        actions = []
        featV = np.zeros(21)
        attacked = 0

        i = 0;
        if 'events_meta' in rec:
            metadata = rec['events_meta']
            # Alerts 1d
            featV[i] = attacked = metadata.get('total1', 0)
            i += 1
            # Alerts 7d
            featV[i] = metadata.get('total7', 0)
            i += 1
            # Nodes 1d
            featV[i] = metadata.get('nodes_1d', 0)
            i += 1
            # Nodes 7d
            featV[i] = metadata.get('nodes_7d', 0)
            i += 1
            # Alerts EWMA
            featV[i] = metadata.get('ewma', 0)
            i += 1
            # Binary Alerts EWMA
            featV[i] = metadata.get('bin_ewma', 0)
            i += 1
        else:
            i += 6

        # Last alert age
        featV[i] = (datetime.utcnow() - rec['ts_last_event']).total_seconds() / 86400
        if featV[i] > 7.0:
            featV[i] = float("inf")
        i += 1

        # Blacklists
        if 'bl' in rec:
            present_blacklists = rec['bl']
            for bl in present_blacklists:
                if bl in self.watched_bl.keys() and bl['v'] == "1":
                    featV[i + self.watched_bl[bl]] = 1

        i += len(self.watched_bl)

        # Hostname exists
        if 'hostname' in rec:
            featV[i] = 1
            i += 1

            if 'tags' in rec:
                tags = rec['tags']

                # Static / dynamic IP
                if 'staticIP' in tags:
                    featV[i] = 1
                elif 'dynamicIP' in tags:
                    featV[i] = -1

                i += 1

                # DSL
                if 'dsl' in tags:
                    featV[i] = 1

                i += 1

                # IP in hostname
                if 'ip_in_hostname' in tags:
                    featV[i] = 1

                i += 1
            else:
                i += 3
        else:
            i += 4

        dtest = xgb.DMatrix(np.array([featV]))
        fmp = float(self.models['general'].predict(dtest))
        actions.append(('set', 'fmp.general', fmp))

        self.logFMP(ip, featV, fmp, attacked, self.paths['general'])

        return actions

    def logFMP(self, ip, fv, fmp, attacked, path):
        curTime = datetime.utcnow()
        logTime = curTime.strftime("%Y-%m-%dT%H:%M:%S")
        fileSuffix = curTime.strftime("%Y_%m_%d")
        attackedBin = '1' if attacked > 0 else '0'
        prefix = logTime + ',' + ip + ','
        suffix = ",{:.4f}".format(fmp)

        f = open(os.path.join(path, fileSuffix), 'a')
        fcntl.flock(f, fcntl.LOCK_EX)
        f.write(prefix + re.sub(r"[ \]\[]", r"", np.array2string(fv, max_line_width=1000, separator=',')) + suffix + '\n')
        fcntl.flock(f, fcntl.LOCK_UN)
        f.close()

        f = open(os.path.join(path, 'results', fileSuffix), 'a')
        fcntl.flock(f, fcntl.LOCK_EX)
        f.write(prefix + attackedBin + '\n')
        fcntl.flock(f, fcntl.LOCK_UN)
        f.close()