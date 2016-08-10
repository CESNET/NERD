"""
NERD event database wrapper.

Provides EventDatabase class -- an abstract layer above the database system 
implementing event database.
"""
from __future__ import print_function

import sys
import os
import os.path
import json
import gzip
import logging
import random

# TODO: locking directories

class BadEntityType(ValueError):
    pass

class FileEventDatabase:
    """
    Simple event database storing IDEA record as files.
    """

    def __init__(self, config):
        """
        Initialize all internal structures as neccessary.
        """
        self.log = logging.getLogger('EventDB')
        
        self.dbpath = config.get('eventdb_path')
        if not self.dbpath:
            raise RuntimeError('EventDatabase: Missing configuration: "eventdb_path" not specified.')

#     def __del__(self):
#         """
#         Destructor. Close connection to database.
#         """
#         pass


    def get(self, etype, key, limit=None):
        """
        Return all events where given IP is amoung Sources.
        
        Arguments:
        etype   entity type (str), must be 'ip'
        key     entity identifier (str), e.g. '192.0.2.42'
        limit   max number of returned events
        
        Return a list of IDEA messages (strings).
        
        Raise BadEntityType if etype is not 'ip'.
        """
        if etype != 'ip':
            raise BadEntityType("etype must be 'ip'")
        
        a,b,c,d = key.split('.')
        dir = os.path.join(self.dbpath, a+'.'+b, c+'.'+d)
        
        events = []
        
        # Read all files with event data in the directory a.b/c.d/
        try:
            date_files = [f for f in os.listdir(dir) if f.endswith('.gz') and os.path.isfile(os.path.join(dir, f))]
        except Exception as e:
            # Directory doesn't exist
            return []
        
        for filename in date_files:
            try:
                with gzip.open(os.path.join(dir, filename), 'rb') as f:
                    # Each line in the file should be one IDEA message
                    for i,line in enumerate(f):
                        line = line.decode('utf8').strip()
                        # Check whether it's a valid JSON document (but don't store output)
                        try:
                            json.loads(line)
                        except json.JSONDecodeError as e:
                            self.log.error("Loading events: Invalid JSON on line {} in file {}. The event is skipped.".format(i, filename))
                            continue
                        # Store event as a string exactly as it is in the file
                        events.append(line)
                        if limit and len(events) >= limit:
                            return events
            except Exception as e:
                # In case of error with reading file, just log it and continue
                self.log.exception("Can't load file '{}'.".format(filename))
        
        return events


    def put(self, idea):
        """
        Store an IDEA message into the database.
        
        Arguments:
        idea    IDEA message as a string
        """
        # Get all source IPv4 addresses in the IDEA message
        sources = []
        idea_decoded = json.loads(idea)
        for src in idea_decoded.get('Source', []):
            for srcip in src.get('IP4', []):
                sources.append(srcip)
        
        if not sources:
            return
        
        date = idea_decoded['DetectTime'][:10]
        
        for srcip in sources:
            # Store the record for each address...
            a,b,c,d = srcip.split('.')
            # Get directory and full filename ('/a.b/c.d/date.gz')
            dir = os.path.join(self.dbpath, a+'.'+b, c+'.'+d)
            filename = os.path.join(dir, date) + '.gz'
            
            # Ensure the directory exists (create if not)
            os.makedirs(dir, exist_ok=True)
            # Open gzip file and append the IDEA message at the end.
            # We need to read the whole file and recompress it, otherwise
            # each event would be compressed individually and compression ratio
            # would be very bad.
            #print("EventDB: Writing IDEA message into {}".format(filename))
            # NOTE:
            # Reading and recompression of whole files on every update is too
            # slow, especially for addresses with lots of events (i.e. large
            # files AND frequent updates).
            # Therefore (re)compression is done only sometimes, in most cases,
            # data are only appedned, which is much faster.
            # This is only a temporary hack, until I implement some better 
            # solution. 
            if random.random() < 0.05: # chance 1:20
                # Read whole file, add the event and recompress 
                try:
                    with gzip.open(filename, 'rb') as f:
                        data = f.read()
                except FileNotFoundError as e:
                    data = None
                with gzip.open(filename, 'wb') as f:
            
                    if data is not None:
                        f.write(data)
                    f.write(idea.encode('utf-8') + b'\n')
            else:
                # Only append new event, without reading and recompressing
                with gzip.open(filename, 'ab') as f:
                    f.write(idea.encode('utf-8') + b'\n')

