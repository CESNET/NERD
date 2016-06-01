# NERDweb module providing database connection functions.
# All DB operations should be done via this module.

import pymongo
import json
import ctrydata

MONGO_HOST = 'localhost'
MONGO_PORT = 27017
MONGO_DBNAME = 'nerd'

mongo_client = pymongo.MongoClient(MONGO_HOST, MONGO_PORT)
db = self._mongo_client[MONGO_DB_NAME]

def getIPInfo(ip):
    rec = db.ip.findOne({'_id': ip})
    return rec

