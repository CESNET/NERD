"""
NERD module for computing FMP scores of network entities.
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

# Currently supported features:
#   0 alerts_1d
#   1 nodes_1d
#   2 alerts_7d
#   3 nodes_7d
#   4 alerts_ewma
#   5 binalerts_ewma
#   6 last_alert_age
# [blacklists]
#   7 tor
#   8 blocklist-de-ssh
#   9 uceprotect
#  10 sorbs-dul
#  11 sorbs-noserver
#  12 sorbs-spam
#  13 spamcop
#  14 spamhaus-pbl
#  15 spamhaus-pbl-isp
#  16 spamhaus-xbl-cbl
# [tags]
#  17 hostname_exists
#  18 dynamic_static
#  19 dsl
#  20 ip_in_hostname


class FMP(NERDModule):
    """
    FMP module assembles feature vectors relevant to general and specific FMP scores of network entities.
    Assembled feature vectors are logged and inserted to the trained data model which yields FMP score.
    The FMP score is also logged along with the feature vector.
    The FMP module logs the information whether an attack was observed from an entity in the last 24 hours for the purpose of retraining data models in the future.
    """
    def __init__(self):
        self.log = logging.getLogger("FMPmodule")
        #self.log.setLevel('DEBUG')

        # Load paths for logging purposes of feature vectors from configuration.
        self.paths = g.config.get("fmp.paths", {"general" : "/data/fmp/general/"})
        for key, value in self.paths.items():
            # Create directories if they do not exist.
            if not os.path.exists(value):
                os.makedirs(value)
            if not os.path.exists(os.path.join(value, "results/")):
                os.makedirs(os.path.join(value, "results/"))

        # Load paths where trained data models are stored.
        self.modelsPaths = g.config.get("fmp.models", {"general" : "/data/fmp/models/general.bin"})
        self.models = {}

        # Load trained data models.
        for fmptype, filename in self.modelsPaths.items():
            # xgb.load_model can segfault if file does not exist, so check it in advance
            if os.path.exists(filename):
                self.models[fmptype] = xgb.Booster({'nthread': 4})
                self.models[fmptype].load_model(filename)
                self.log.info("Successfully loaded xgBoost model '{}' from file {}".format(fmptype, filename))
            else:
                self.log.warning('Unable to find model file "{}" for type "{}".'.format(filename, fmptype))

        # Set print format of feature vectors.
        np.set_printoptions(formatter={'float_kind': lambda x: "{:.4f}".format(x)})

        # Define sequence of blacklists in feature vectors.
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
        transFeatV = np.zeros(21)
        attacked = 0

        i = 0;
        if 'events_meta' in rec:
            metadata = rec['events_meta']
            # Alerts 1d
            featV[i] = attacked = metadata.get('total1', 0)
            i += 1
            # Nodes 1d
            featV[i] = metadata.get('nodes_1d', 0)
            i += 1
            # Alerts 7d
            featV[i] = metadata.get('total7', 0)
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

        np.log1p(featV[:i], out=transFeatV[:i])

        # Last alert age
        featV[i] = (datetime.utcnow() - rec['ts_last_event']).total_seconds() / 86400
        if featV[i] > 7.0:
            featV[i] = float("inf")

        transFeatV[i] = np.exp(-featV[i])
        i += 1

        # Blacklists
        if 'bl' in rec:
            present_blacklists = rec['bl']
            for bl in present_blacklists:
                if bl['n'] in self.watched_bl.keys() and bl['v'] == 1:
                    index = i + self.watched_bl[bl['n']]
                    transFeatV[index] = featV[index] = 1

        i += len(self.watched_bl)

        # Hostname exists
        if 'hostname' in rec and rec['hostname'] != None:
            transFeatV[i] = featV[i] = 1
            i += 1

            if 'tags' in rec:
                tags = rec['tags']

                # Static / dynamic IP
                if 'staticIP' in tags:
                    transFeatV[i] = featV[i] = 1
                elif 'dynamicIP' in tags:
                    transFeatV[i] = featV[i] = -1

                i += 1

                # DSL
                if 'dsl' in tags:
                    transFeatV[i] = featV[i] = 1

                i += 1

                # IP in hostname
                if 'ip_in_hostname' in tags:
                    transFeatV[i] = featV[i] = 1

                i += 1
            else:
                i += 3
        else:
            i += 4

        # Insert transformed feature vector to the trained model.
        dtest = xgb.DMatrix(np.array([transFeatV]))
        fmp = float(self.models['general'].predict(dtest))

        # Update fmp.general in the IP record.
        actions.append(('set', 'fmp.general', fmp))

        # Log the feature vector and the information whether the IP address was reported in the last 24 hours.
        self.logFMP(ip, featV, fmp, attacked, self.paths['general'])

        return actions

    def logFMP(self, ip, fv, fmp, attacked, path):
        # Acquire current UTC time.
        curTime = datetime.utcnow()
        logTime = curTime.strftime("%Y-%m-%dT%H:%M:%S")
        fileSuffix = curTime.strftime("%Y_%m_%d")

        # Create strings to be inserted into log files.
        attackedBin = '1' if attacked > 0 else '0'
        prefix = logTime + ',' + ip + ','
        suffix = ",{:.4f}".format(fmp)

        # Log feature vector and current FMP score.
        try:
            f = open(os.path.join(path, fileSuffix), 'a')
            fcntl.flock(f, fcntl.LOCK_EX)
            f.write(prefix +
                ','.join(
                    [str(int(f)) for f in fv[0:4]] +  # first 4 features are integers
                    ['{:.4f}'.format(f) for f in fv[4:7]] +  # next 3 featerues are floats
                    [str(int(f)) for f in fv[7:]]  # the rest are integers
                )
                + suffix + '\n')
            fcntl.flock(f, fcntl.LOCK_UN)
            f.close()
        except IOError:
            self.log.warning('Unable to log feature vector "{}" to "{}".'.format(fv, os.path.join(path, fileSuffix)))


        # Log the information whether the entity was reported in the last 24 hours.
        try:
            f = open(os.path.join(path, 'results', fileSuffix), 'a')
            fcntl.flock(f, fcntl.LOCK_EX)
            f.write(prefix + attackedBin + '\n')
            fcntl.flock(f, fcntl.LOCK_UN)
            f.close()
        except IOError:
            self.log.warning('Unable to log "{}" to "{}".'.format(fv, os.path.join(path, 'results', fileSuffix)))
