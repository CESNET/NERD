"""
NERD - wrapper around MongoDB.

Provides MongoEntityDatabase class -- an abstract layer above the MongoDB 
database system implementing entity database.
"""

import logging
import pymongo
from operator import itemgetter

from common.utils import ipstr2int, int2ipstr

# Defaults (may be overridden by config values mongodb.host, mongodb.port, mongodb.dbname)
DEFAULT_MONGO_HOST = 'localhost'
DEFAULT_MONGO_PORT = 27017
DEFAULT_MONGO_DBNAME = 'nerd'

class UnknownEntityType(ValueError):
    pass

class MongoEntityDatabase():
    """
    EntityDatabase implemented over MongoDB.
    """
    # List of known/supported entity types - currently only IP addresses (both IPv4 and IPv6 are treated the same)
    _supportedTypes = ['ip', 'asn', 'bgppref', 'ipblock', 'org']

    def __init__(self, config):
        """
        Connect to Mongo database.
        """
        self.log = logging.getLogger("MongoDB")
        host = config.get('mongodb.host', DEFAULT_MONGO_HOST)
        port = config.get('mongodb.port', DEFAULT_MONGO_PORT)
        dbname = config.get('mongodb.dbname', DEFAULT_MONGO_DBNAME)
        self.log.info("Connecting to {}:{}/{}".format(host,port,dbname))
        self._mongo_client = pymongo.MongoClient(host, port)
        self._db = self._mongo_client[dbname]

    
    def __del__(self):
        """
        Destructor. Close connection to database.
        """
        self._mongo_client.close()
    

    def getEntityTypes(self):
        """
        Return list of known entity types.
        """
        return self._supportedTypes


    def get(self, etype, key):
        """
        Return record of given entity.
        
        Arguments:
        etype   entity type (str), e.g. 'ip'
        key     entity identifier (str), e.g. '192.0.2.42'
        
        Return the record as JSON document or None if it is not present in the database.
        
        Raise UnknownEntityType if there is not a database collection for given etype.
        """
        if etype not in self._supportedTypes:
            raise UnknownEntityType("There is no collection for entity type "+str(etype))
        
        # IP addresses are stored as int
        if etype == 'ip':
            key = ipstr2int(key)
        
        record = self._db[etype].find_one({'_id': key})
        if not record:
            return None
        
        if etype == 'ip':
            record['_id'] = int2ipstr(record['_id'])
        
        # Hostnames are reversed in DB, reverse it before returning to NERD
        if 'hostname' in record and record['hostname'] is not None:
            record['hostname'] = record['hostname'][::-1]
        
        return record
    
    
    def put(self, etype, key, record):
        """
        Replace record of given entity by the new one.
        
        Arguments:
        etype   entity type (str), e.g. 'ip'
        key     entity identifier (str), e.g. '192.0.2.42'
        record  JSON document with properties of the entity to be stored in DB
        """
        if etype not in self._supportedTypes:
            raise UnknownEntityType("There is no collection for entity type "+str(etype))
        
        # Store IP address as int
        if etype == 'ip':
            key = ipstr2int(key)
            record['_id'] = ipstr2int(record['_id'])
        
        # Store hostname reversed
        if record and 'hostname' in record and record['hostname'] is not None:
            record['hostname'] = record['hostname'][::-1]
        
        self._db[etype].replace_one({'_id': key}, record, upsert=True)


    def find(self, etype, mongo_query, **kwargs):
        """
        Search entities matching given query (in pymongo format).
        
        Return list of keys of matching entities.
        """
        if etype == 'ip':
            return list(map(lambda rec: int2ipstr(rec['_id']), self._db[etype].find(filter=mongo_query, projection={'_id': 1}, **kwargs)))
        else:
            return list(map(itemgetter('_id'), self._db[etype].find(filter=mongo_query, projection={'_id': 1}, **kwargs)))

    def delete(self, etype, key):
        """
        Delete an entity specified with the key.
        """
        if etype not in self._supportedTypes:
            raise UnknownEntityType("There is no collection for entity type "+str(etype))

        if etype == 'ip':
            key = ipstr2int(key)

        self._db[etype].delete_one({'_id': key})
