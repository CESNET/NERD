"""
NERD event database wrapper.

Provides PSQLEventDatabase class -- an abstract layer above the database system 
implementing event database. The events are stored in PostgreSQL database.
"""
from __future__ import print_function

import json
import logging
import datetime
import base64

import psycopg2
from psycopg2.extras import Json, Inet, execute_values

from common.utils import parse_rfc_time


class BadEntityType(ValueError):
    pass

class PSQLEventDatabase:
    """
    Event database storing IDEA record into PostgreSQL.
    """

    def __init__(self, config):
        """
        Initialize all internal structures as necessary.
        """
        self.log = logging.getLogger('EventDB')
        #self.log.setLevel('DEBUG')
        
        # Create database connection
        self.db = psycopg2.connect(database=config.get('eventdb.dbname', 'nerd'),
                                   user=config.get('eventdb.dbuser', 'nerd'),
                                   password=config.get('eventdb.dbpassword', None))

    def __del__(self):
        """
        Destructor. Close connection to database.
        """
        try:
            self.db.close()
        except:
            pass


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
        
        cur = self.db.cursor()
        #cur.execute("SELECT idea FROM events WHERE %s = ANY(sources) ORDER BY detecttime DESC LIMIT %s", (key, limit))
        cur.execute("SELECT e.idea FROM events_sources as es INNER JOIN events as e ON es.message_id = e.id WHERE es.source_ip = %s ORDER BY es.detecttime DESC LIMIT %s", (Inet(key), limit))
        self.db.commit() # Every query automatically opens a transaction, close it.
        
        result = cur.fetchall()
        result = [row[0] for row in result]
        
        return result
        
        # Note, get count (index only): SELECT COUNT(*) FROM events_sources WHERE source_ip = '70.169.27.221';


    def put(self, ideas):
        """
        Store IDEA messages into the database.
        
        Arguments:
        ideas    list of IDEA message parsed into Python-native structures
        """
        def idea2sqlvalues(idea):
            # Auxiliary function parsing IDEA message to VALUES part of SQL query
            # Get ID
            try:
                id = idea['ID']
            except KeyError:
                self.log.error("ID field not found, skipping...")
                return None
            
            # Get all source and target IPv4 addresses in the IDEA message
            sources = [ip for src in idea.get('Source', []) for ip in src.get('IP4', [])]
            targets = [ip for tgt in idea.get('Target', []) for ip in tgt.get('IP4', [])]
            
            # Parse timestamps
            try:
                detecttime = parse_rfc_time(idea['DetectTime'])
            except KeyError:
                self.log.error("Message ID {}: DetectTime not found, skipping...".format(idea.get('ID','N/A')))
                return None
            except ValueError:
                self.log.error("Message ID {}: Unknown format of DetectTime, skipping ...".format(idea.get('ID','N/A')))
                return None
            
            # If EventTime is not present, try WinStartTime instead (similiary for CeaseTime and WinEndTime)
            starttime = idea.get('EventTime', idea.get('WinStartTime', None))
            if starttime:
                starttime = parse_rfc_time(starttime)
            endtime = idea.get('CeaseTime', idea.get('WinEndTime', None))
            if endtime:
                endtime = parse_rfc_time(endtime)
            
            self.log.debug("New event: %s, %s, %s, %s, %s, %s\n%s", id, sources, targets, detecttime, starttime, endtime, idea)
            #print("New event: %s, %s, %s, %s, %s, %s\n%s" % (id, sources, targets, detecttime, starttime, endtime, idea))
            
            return (id, sources, targets, detecttime, starttime, endtime, idea)
        
        # TODO print number of messages in bunch - to check it's really being used
        print("Inserting a batch of {:3d} messages into EventDB".format(len(ideas)), end="\r")

        # Handle \u0000 characters in Attach.Content field.
        # The \u0000 char can't be stored in PSQL - encode the attachment into base64
        for idea in ideas:
            for attachment in idea.get('Attach', []):
                # TEMPORARY/FIXME:
                # one detector sends 'data' instead of 'Content', fix it:
                if 'data' in attachment and not 'Content' in attachment:
                    attachment['Content'] = attachment['data']
                    del attachment['data']

                if 'Content' in attachment and 'ContentEncoding' not in attachment and '\u0000' in attachment['Content']:
                    self.log.info("Attachment of IDEA message {} contains '\\u0000' char - converting attachment to base64.".format(idea.get('ID', '???')))
                    # encode to bytes, then to b64 and back to str
                    attachment['Content'] = base64.b64encode(str(attachment['Content']).encode('utf-8')).decode('ascii')
                    attachment['ContentEncoding'] = 'base64'

#         values = []
#         for idea in ideas:
#             val = idea2values(idea)
#             if val is not None:
#                 values.append(val)
        # This is equivalent to the above, but should be more efficient
        values = list(filter(None, map(idea2sqlvalues, ideas)))
        
        # Get aggregated lists of values to write to events, events_srouces and events_targets tables
        vals_events = [(id, None, None, detecttime, starttime, endtime, Json(idea)) for (id, _, _, detecttime, starttime, endtime, idea) in values]
        vals_sources = [(Inet(source), id, detecttime) for (id, sources, _, detecttime, _, _, _) in values for source in sources]
        vals_targets = [(Inet(target), id, detecttime) for (id, _, targets, detecttime, _, _, _) in values for target in targets]
        
        # Try to store all the records to the database
        cur = self.db.cursor()
        try:
            # execute_values should be much faster than many individual inserts
            execute_values(cur, "INSERT INTO events (id, sources, targets, detecttime, starttime, endtime, idea) VALUES %s",
                vals_events, "(%s, %s, %s, %s, %s, %s, %s)", 100)
            execute_values(cur, "INSERT INTO events_sources (source_ip, message_id, detecttime) VALUES %s",
                vals_sources, "(%s, %s, %s)", 100)
            execute_values(cur, "INSERT INTO events_targets (target_ip, message_id, detecttime) VALUES %s",
                vals_targets, "(%s, %s, %s)", 100)
            self.db.commit()
        except Exception as e:
            self.log.error(str(e))
            if len(values) == 1:
                return
            # If there was more than one message in the batch, try it again, one-by-one
            self.log.error("There was an error during inserting a batch of {} IDEA messages, performing rollback of the transaction and trying to put the messages one-by-one (expect repetition of the error message) ...".format(len(values)))
            # Rollback all non-committed changes
            self.db.rollback()
            
            # Try it again, one by one
            # (otherwise we could throw away whole bunch of messages because of a single bad one)
            cnt_success = 0
            for id, sources, targets, detecttime, starttime, endtime, idea in values:
                cur = self.db.cursor()
                try:
                    cur.execute("""
                        INSERT INTO events 
                        (id, sources, targets, detecttime, starttime, endtime, idea)
                        VALUES (%s, %s, %s, %s, %s, %s, %s)
                        """,
                        #(id, list(map(Inet,sources)), list(map(Inet,targets)), detecttime, starttime, endtime, Json(idea))
                        (id, None, None, detecttime, starttime, endtime, Json(idea))
                    )
                    for source in sources:
                        cur.execute(
                            "INSERT INTO events_sources (source_ip, message_id, detecttime) VALUES (%s, %s, %s)",
                            (Inet(source), id, detecttime)
                        )
                    for target in targets:
                        cur.execute(
                            "INSERT INTO events_targets (target_ip, message_id, detecttime) VALUES (%s, %s, %s)",
                            (Inet(target), id, detecttime)
                        )
                    self.db.commit() # Close transaction (the first command opens it automatically)
                    cnt_success += 1
                except Exception as e:
                    self.log.error(str(e))
                    if str(e).startswith("duplicate"):
                        self.log.error("IDEA: "+str(idea))
                    self.db.rollback() # Rollback all non-committed changes
            self.log.error("{} messages successfully inserted.".format(cnt_success))
                