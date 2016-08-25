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
        Return all events where given IP is among Sources.
        
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
            files = [f for f in sorted(os.listdir(dir)) if os.path.isfile(os.path.join(dir, f))]
        except Exception as e:
            # Directory doesn't exist
            return []
        
        for filename in files:
            if filename.endswith('.gz'):
                open_func = gzip.open
            else:
                open_func = open
            try:
                with open_func(os.path.join(dir, filename), 'rb') as f:
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

        # Store the record for each address...
        for srcip in sources:
            a,b,c,d = srcip.split('.')
            # Get directory and full filename ('/a.b/c.d/date.idea')
            dir = os.path.join(self.dbpath, a+'.'+b, c+'.'+d)
            filename = os.path.join(dir, date) + '.idea' # Add .idea prefix, so when files are sorted alphabetically, it goes after .gz
            
            # Ensure the directory exists (create if not)
            os.makedirs(dir, exist_ok=True)
            
            # Append event to the end of the file (or create new file)
            # (Uncompressed. Although appending to gzip files is possible, 
            # compression algorithm starts over every time, so if each message 
            # is compressed individually, it may result in files even larger
            # than uncompressed ones.)
            with open(filename, 'ab') as f:
                f.write(idea.encode('utf-8') + b'\n')
            
            # If the file is larger than 64kB, compress it into
            # /a.b/c.d/date.gz
            # (the file is written by 64kB blocks, each block compressed as a 
            #  whole, so the compression is effective)
            try:
                statinfo = os.stat(filename)
                if statinfo.st_size > 64*1024:
                    filename2 = os.path.join(dir, date) + '.gz'
                    self.log.info("Compressing 64k block of data to the end of {}.".format(filename2))
                    # Read whole file and delete it
                    with open(filename, 'rb') as f:
                        data = f.read()
                    os.remove(filename)
                    # Write&compress all data to the end of gzip file
                    with gzip.open(filename2, 'ab') as f:
                        f.write(data)
            except FileNotFoundError:
                # Theoretically someone might delete the base file just after
                # its creation, do nothing in such case
                pass

