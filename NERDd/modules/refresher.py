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

MAX_QUEUE_SIZE = 100 # Maximal size of UpdateManager's request queue
                     # (when number of pending requests exceeds this value,
                     # reading of events is paused for a while)


running_flag = True # read_dir function terminates when this is set to False

logger = logging.getLogger('Refresher')


# Module performs given action(s) for each IP address which is result of a MongoDB query

commands = [
    # 3-tuple: expression returning iterable, entity_type, update_requests
    #( "self._db.find('ip', {'as_maxmind': {'$exists': False}, 'as_rv': {'$exists': False}})", 'ip', [('event', '!refresh_asn', None)] ),
    #( "self._db.find('ip', {'geo': {'$exists': False}})", 'ip', [('event', '!refresh_geo', None)] ),
    #( "self._db.find('ip', {'bl': {'$exists': False}})", 'ip', [('event', '!refresh_localbl', None)] ),
    #( "list(self._db._db.ip.aggregate([{'$group': {'_id': '$as_rv.num'}}, {'$group': {'_id': 0, 'asns': {'$addToSet': '$_id'}}}]))[0]['asns']", 'asn', [] ), # empty request to just create the record if it doesn't exist
    #( "list(self._db._db.ip.aggregate([{'$group': {'_id': '$as_maxmind.num'}}, {'$group': {'_id': 0, 'asns': {'$addToSet': '$_id'}}}]))[0]['asns']", 'asn', [] ), # empty request to just create the record if it doesn't exist
    #( "self._db.find('ip', {}, sort=[('events.total', pymongo.DESCENDING)], skip=0, limit=1000)", 'ip', [('event', '!refresh_dnsbl', None)] ),
]
def get_commands():
    if not commands:
        return None
    cmd = commands.pop(0)
    return cmd


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
                    time.sleep(0.5)
                
                #print(key, actions)
                g.um.update((etype,key), actions.copy())
                if (i+1) % 1000 == 0:
                    self.log.debug("{} entities updated.".format(i+1))
            
            self.log.info("Done, {} entities updated".format(i+1))

