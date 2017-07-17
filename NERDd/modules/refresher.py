"""
TODO
"""

from core.basemodule import NERDModule
import g

from threading import Thread
import time
import json
import logging
import pymongo
from datetime import datetime, timedelta

MAX_QUEUE_SIZE = 100 # Maximal size of UpdateManager's request queue
                     # (when number of pending requests exceeds this value,
                     # reading of events is paused for a while)


running_flag = True # read_dir function terminates when this is set to False

logger = logging.getLogger('Refresher')

now = datetime.utcnow()

# Module performs given action(s) for each IP address which is result of a MongoDB query

commands = [
    # 3-tuple: expression returning iterable, entity_type, update_requests
    ( "g.db.find('ip', {})", 'ip', [('event', '!refresh_hostname_class', None)] ),
    #( "g.db.find('ip', {'as_maxmind': {'$exists': False}, 'as_rv': {'$exists': False}})", 'ip', [('event', '!refresh_asn', None)] ),
    #( "g.db.find('ip', {'geo': {'$exists': False}})", 'ip', [('event', '!refresh_geo', None)] ),
    #( "g.db.find('ip', {'bl': {'$exists': False}})", 'ip', [('event', '!refresh_localbl', None)] ),
    #( "list(g.db._db.ip.aggregate([{'$group': {'_id': '$as_rv.num'}}, {'$group': {'_id': 0, 'asns': {'$addToSet': '$_id'}}}]))[0]['asns']", 'asn', [] ), # empty request to just create the record if it doesn't exist
    #( "list(g.db._db.ip.aggregate([{'$group': {'_id': '$as_maxmind.num'}}, {'$group': {'_id': 0, 'asns': {'$addToSet': '$_id'}}}]))[0]['asns']", 'asn', [] ), # empty request to just create the record if it doesn't exist
    #( "g.db.find('ip', {}, sort=[('events.total', pymongo.DESCENDING)], skip=0, limit=1000)", 'ip', [('event', '!refresh_dnsbl', None)] ),
#     ( "g.db.find('ip', {'_nru1d': {'$exists': False}}, skip=0, limit=500000)", 'ip', [
#         ('next_step', '_nru4h', ('ts_added', now, timedelta(seconds=4*60*60))),
#         ('next_step', '_nru1d', ('ts_added', now, timedelta(days=1))),
#         ('next_step', '_nru1w', ('ts_added', now, timedelta(days=7))),
#     ] ),
    #( "g.db.find('ip', {'ts_last_event': {'$exists': False}}, skip=0, limit=1000000)", 'ip', [('event', '!set_ts_last_event', None)] ),
    #( "g.db.find('ip', {'_id': ''}, sort=[('ts_added', pymongo.DESCENDING)], skip=0, limit=1000000)", 'ip', [('event', '!refresh_tags', None)] ),
#    ( "g.db.find('ip', {'bl_old': {'$exists': True}}, skip=0, limit=100000)", 'ip', [('event', '!restore_bl_info', None)] ),
]
def get_commands():
    if not commands:
        return None
    cmd = commands.pop(0)
    return cmd


###

# def set_ts_last_event(ekey, rec, updates):
#     last_day = max(d for d in rec['events'].keys() if not d.startswith("total"))
#     last_day = datetime.strptime(last_day, "%Y-%m-%d")
#     return [('set', 'ts_last_event', last_day)]
# 
# g.um.register_handler(set_ts_last_event, 'ip', ('!set_ts_last_event',), ('ts_last_event',))

def restore_bl_info(ekey, rec, updates):
    now = datetime.utcnow()
    actions = []
    for blname,times in rec['bl_old'].items():
        # Is there a record for blname in rec?
        for i, bl_entry in enumerate(rec.get('bl', [])):
            if bl_entry['n'] == blname:
                i = str(i)
                # There already is an entry for blname in rec, update it
                actions.append( ('set', 'bl.'+i+'.v', 1 if now - times[-1] < timedelta(days=7) else 0) )
                actions.append( ('setmax', 'bl.'+i+'.t', times[-1]) )
                actions.append( ('set', 'bl.'+i+'.h', times + bl_entry['h']) )
                break
        else:
            # An entry for blname is not there yet, create it
            if now - times[-1] < timedelta(days=7):
                actions.append( ('append', 'bl', {'n': blname, 'v': 1, 't': times[-1], 'h': times}) )
            else:
                actions.append( ('append', 'bl', {'n': blname, 'v': 0, 'h': times}) )
    actions.append(('remove', 'bl_old', None))
    return actions

g.um.register_handler(restore_bl_info, 'ip', ('!restore_bl_info',), ('bl',))

##############################################################################
# Main module code

class Refresher(NERDModule):
    """
    Module performs given action(s) for each IP address which is result of 
    a MongoDB query.
    TODO: How to get queries and actions? (now it's hardcoded)
    """
    def __init__(self):
        self.log = logging.getLogger("Refresher")
        self.log.setLevel("DEBUG")
    
    def start(self):
        """
        Run the module - used to run own thread if needed.
        
        Called after initialization, may be used to create and run a separate
        thread if needed by the module. Do nothing unless overriden.
        """
        self._poll_thread = Thread(target=self._perform_commands)
        self._poll_thread.daemon = True
        self._poll_thread.start()


    def stop(self):
        """
        Stop the module - used to stop own thread.
        
        Called before program exit, may be used to finalize and stop the 
        separate thread if it is used. Do nothing unless overriden.
        """
        global running_flag
        running_flag = False
        self._poll_thread.join()
        self.log.info("Exitting.")


    def _perform_commands(self):
        while running_flag:
            cmd = get_commands()
            if not cmd:
                time.sleep(2)
                continue
            
            exp, etype, actions = cmd
            
            self.log.info("Expression: {}, etype: {}, actions: {}".format(exp, etype, actions))
            keys = eval(exp) #self._db.find('ip', query)
            #print(keys)
            if not keys:
                self.log.info("Number of results: 0")
                continue
            self.log.info("Number of results: {}, requesting actions...".format(len(keys)))
    
            for i,key in enumerate(keys):
                # If there are already too much requests queued, wait a while
                #print("***** QUEUE SIZE: {} *****".format(self._um.get_queue_size()))
                while g.um.get_queue_size() > MAX_QUEUE_SIZE:
                    time.sleep(0.2)
                
                #print(key, actions)
                g.um.update((etype,key), actions.copy())
                if (i+1) % 1000 == 0:
                    self.log.debug("{} entities updated.".format(i+1))
            
            self.log.info("Done, {} entities updated".format(i+1))

