"""
NERD update manager.

Provides UpdateManager class - a NERD component which handles updates of entity
records, including chain reaction of updates casued by other updates.
"""
import sys
import os
import threading
# import multiprocessing
import queue
from datetime import datetime, timezone
import time
from collections import defaultdict, deque, Iterable, OrderedDict, Counter
import logging
import traceback

import g
import core.scheduler

ENTITY_TYPES = ['ip', 'asn', 'bgppref', 'ipblock', 'org']

#  Update request specification = list of three-tuples:
#    - [(op, key, value), ...]
#      - ('set', key, value)        - set new value to given key (rec[key] = value)
#      - ('append', key, value)     - append new value to array at key (rec[key].append(key))
#      - ('add_to_set', key, value) - append new value to array at key if it isn't present in the array yet (if value not in rec[key]: rec[key].append(value))
#      - ('extend_set', key, iterable) - append values from iterable to array at key if the value isn't present in the array yet (for value in iterable: if value not in rec[key]: rec[key].append(value))
#      - ('add', key, value)        - add given numerical value to that stored at key (rec[key] += value)
#      - ('sub', key, value)        - subtract given numerical value from that stored at key (rec[key] -= value)
#      - ('setmax', key, value)     - set new value of the key to larger of the given value and the current value (rec[key] = max(value, rec[key]))
#      - ('setmin', key, value)     - set new value of the key to smaller of the given value and the current value (rec[key] = min(value, rec[key]))
#      - ('remove', key, None)      - remove given key (and all subkeys) from the record (parameter is ignored) (do nothing if the key doesn't exist)
#      - ('next_step', key, (key_base, min, step)) - set value of 'key' to the smallest value of 'rec[key_base] + N*step' that is greater than 'min' (used by updater to set next update time); key_base MUST exist in the record!
#      - ('array_update', key, (query, actions)) - apply given actions to specified array item under key, see below for details.
#      - ('array_upsert', key, (query, actions)) - apply given actions to specified array item under key (insert new item if no one matches), see below for details.
#      - ('array_remove', key, query) - remove array item satisfying given query (do nothing if no one matches).
#      - ('event', !name, param)    - do nothing with record, only trigger functions hooked on the event name
#  The tuple is passed to functions watching for updates of given keys / events
#  with given name. Event names must begin with '!' (attribute keys mustn't).
#  Update manager performs the requested update and calls functions hooked on 
#  the attribute/event.
#  A hooked function receives a list of updates that triggered its call, 
#  i.e. a list of 2-tuples (attr_name, new_value) or (event_name, param)
#  (if more than one update triggers the same function, it's called only once). 

# Special action "array_update":
#      - ('update_item', key, (query, actions))
#  "key" must be path to an array of objects (dicts),
#  the item whose values match those in "query" dict is selected
#  all "actions" are performed with the selected object (keys inside those actions should be relative to the object root).
#  If the array does not contain any matching item:
#    - array_update: record is not changed
#    - array_upsert: "query" is added as a new array item.
#  If there are multiple matching events, only the first one is used.
#  "actions" may contain actions of type "update_item" (recursion), it must not contain events.
#  Rationale:
#    Because of DB constraints, keys should always be fixed values. Therefore we often use 
#    arrays of subobjects where one or more attributes of the subobject act as a key.
#    This action type allows to work with such structures.
#  Examples:
#    ('update_item', 'bl', ({n: "blacklistname"} , [('set', 'v', 1), ('set', 't', req_time), ('append', 'h', req_time)]))
#    ('update_item', 'events', ({date: "2017-07-17", cat: "ReconScanning"} , [('add', 'n', 1)]))


# TODO: Let each module (or rather hook function) tell, whether it needs the whole record.
# Many of them probably won't so we can save the load from database
# (we just need to block any other updates, which is now done by keeping the record in _records_being_processed).

# TODO: Vyresit reakci na !NEW pri pridani noveho modulu.
# Spousta modulu reaguje na !NEW, ale pri pridani takoveho modulu do systemu
# se nepridaji nove polozky k existujicim zaznamum (protoze uz existuji),
# ani kdyz jsou updatovatny.
# Bude ptoreba pridat nejakou udalost !NEW_MODULE, ktera se pouzije na vsechny existujici zaznamy v databazi

# TODO:
# Handling of non-IP entities: Modules must call .update() when thay want to make some change in another entity (even of the same type)
# Hooked functions must be registered not only on a specific attribute/event, but also entity type
# Stav:
#  - predelan UpdateManager (mapovani funkce<->atributy je zvlast pro kazdy typ entity)
#  - zmenila se registracni funkce (pridan param etype) -> nutno zmenit vsechny moduly


def get_func_name(func_or_method):
    """Get name of function or method as pretty string."""
    try:
        fname = func_or_method.__func__.__qualname__
    except AttributeError:
        fname = func_or_method.__name__
    return func_or_method.__module__ + '.' + fname



def perform_update(rec, updreq):
    """
    Update a record according to given update reqeust.
    
    updreq - 3-tuple (op, key, value)
    
    Return array with specifications of performed updates (pairs (upated_key,
    new_value) or None.
    (None is returned when nothing was changed, e.g. because op=add_to_set and
    value was already present, or removal of non-existent item was requested)
    """
    op, key, value = updreq
    
    # Process keys with hierarchy, i.e. containing dots (like "events.scan.count")
    # rec will be the inner-most subobject ("events.scan"), key the last attribute ("count")
    # If path doesn't exist in the hierarchy, it's created
    while '.' in key:
        first_key, key = key.split('.',1)
        if first_key.isdecimal(): # index of array
            rec = rec[int(first_key)]
        else: # key of object/dict
            if first_key not in rec:
                rec[first_key] = {}
            rec = rec[first_key]
    
    if op == 'set':
        rec[key] = value
    
    elif op == 'append':
        if key not in rec:
            rec[key] = [value]
        else:
            rec[key].append(value)

    elif op == 'add_to_set':
        if key not in rec:
            rec[key] = [value]
        elif value not in rec[key]:
            rec[key].append(value)
        else:
            return None
    
    elif op == 'extend_set':
        if key not in rec:
            rec[key] = list(value)
        else:
            changed = False
            for val in value:
                if val not in rec[key]:
                    rec[key].append(val)
                    changed = True
            if not changed:
                return None
    
    elif op == 'add':
        if key not in rec:
            rec[key] = value
        else:
            rec[key] += value
    
    elif op == 'sub':
        if key not in rec:
            rec[key] = -value
        else:
            rec[key] -= value
    
    elif op == 'setmax':
        if key not in rec:
            rec[key] = value
        else:
            rec[key] = max(value, rec[key])
    
    elif op == 'setmin':
        if key not in rec:
            rec[key] = value
        else:
            rec[key] = min(value, rec[key])
    
    elif op == 'remove':
        if key in rec:
            del rec[key]
            return [(updreq[1], None)]
        return None
    
    elif op == 'next_step':
        key_base, min, step = value
        base = rec[key_base]
        rec[key] = base + ((min - base) // step + 1) * step 
    
    elif op == 'array_update' or op == 'array_upsert':
        query, actions = value
        if key not in rec:
            rec[key] = []
        array = rec[key]
        # Find the matching item in the array
        for i,item in enumerate(array):
            if all(item[a] == v for a,v in query.items()):
                break
        else:
            if op == 'array_upsert':
                i = len(array)
                item = query
                array.append(query)
            else:
                return None # No matching element found and insert not requested
        # Now, "item" is the selected array item ("i" its index), apply all actions to it
        updates_performed = []
        for action in actions:
            upds = perform_update(item, action)
            # List of all actions must be returned, convert relative keys to absolute
            for inner_key, new_val in upds:
                updates_performed.append((key + '.' + str(i) + '.' + inner_key, new_val))
        return updates_performed
    
    elif op == 'array_remove':
        query = value
        if key not in rec:
            return None
        array = rec[key]
        # Find the matching item in the array
        for i,item in enumerate(array):
            if all(item[a] == v for a,v in query.items()):
                break
        else:
            return None
        # Remove it
        del array[i]
        return [(key + '.' + str(i), None)]
    
    else:
        print("ERROR: perform_update: Unknown operation {}".format(op), file=sys.stderr)
        return None
    
    # Return tuple (updated attribute, new value)
    return [(updreq[1], rec[key])] 


class UpdateManager:
    """
    Manages updates of entity records triggered by NERD modules.
    
    TODO: detailed description
    """

    def __init__(self, config, db):
        """
        Initialize update manager.
        
        Arguments:
        config -- global NERDd configuration (dict)
        db -- instance of EntityDatabase which should be used to load/store 
              entity records.
        """
        self.log = logging.getLogger("UpdateManager")
        #self.log.setLevel('DEBUG')
        
        self.db = db
        
        # Mapping of names of attributes to a list of functions that should be 
        # called when the attrbibute is updated
        # (One such mapping for each entity type)
        self._attr2func = {etype: {} for etype in ENTITY_TYPES}
        
        # Set of attributes thet may be updated by a function
        self._func2attr = {etype: {} for etype in ENTITY_TYPES}

        # Mapping of functions to set of attributes the function watches, i.e.
        # is called when the attribute is changed
        self._func_triggers = {etype: {} for etype in ENTITY_TYPES}
        
        # List of worker threads for processing the update requests
        self._workers = []
        self.num_workers = g.config.get('worker_threads', 8)
        
        # Queues for pending update requests (one for each worker)
        self._request_queues = [queue.Queue() for _ in range(self.num_workers)]
        
        # Number of restarts of threads by watchdog
        self._watchdog_restarts = 0
        # Register watchdog to scheduler
        g.scheduler.register(self.watchdog, second="*/30")

        # Count of update requests processed (per update type)
        self._update_counter = OrderedDict([
            ('ip_new_entity',0), # New entity (usually because of new event)
            ('ip_event',0), # New event added to existing entity
            ('ip_regular_1d',0), # Regular daily update
            ('ip_regular_1w',0), # Regular weekly update
            ('ip_other',0), # Other updates
            ('asn_new_entity',0), # New entity (usually because of new event)
            ('asn_event',0), # New event added to existing entity
            ('asn_regular_1d',0), # Regular daily update
            ('asn_regular_1w',0), # Regular weekly update
            ('asn_other',0), # Other updates
        ])
        self._last_update_counter = self._update_counter.copy()

        # Log number of update requests processed every 2 seconds
        if ("upd_cnt_file" in g.config):
            # Use a new scheduler, because the default one is stopped when
            # NERDd daemon is going to exit, but we want to keep logging
            # till the end
            self.logging_scheduler = core.scheduler.Scheduler()
            self.logging_scheduler.register(self.log_update_counter, second="*/2")
            self.logging_scheduler.start()

#        self.t_handlers = Counter()
#        self.logging_scheduler.register(self.log_t_handlers, second="*/60")


    def log_update_counter(self):
        # Write update counter to file (every 2 sec)
        # Lines 1-5: (IP) total number of updates (per update type)
        # Lines 6-10: (ASN) total number of updates (per update type)
        # Lines 11-15: (IP) number of updates from last period
        # Lines 16-20: (ASN) number of updates from last period
        # Line 21: current length of update request queue
        filename = g.config.get("upd_cnt_file", None)
        if not filename:
            return
        # Write to a temp file and then rename, so at no time there is a partially written file (rename is atomic operation)
        tmp_filename = filename + "_tmp$"
        with open(tmp_filename, "w") as f:
            for _,cnt in self._update_counter.items():
                f.write('{}\n'.format(cnt))
            for (_,last),(_,cnt) in zip(self._last_update_counter.items(), self._update_counter.items()):
                f.write('{}\n'.format(cnt-last))
            f.write("{}\n".format(self.get_queue_size()))
        os.replace(tmp_filename, filename)
        self._last_update_counter = self._update_counter.copy()
    
    def log_t_handlers(self):
        print("Handler function running times:")
        for name,t in self.t_handlers.most_common(10):
            print("{:50s} {:7.3f}".format(name,t))
        self.t_handlers = Counter()


    def _dump_handler_chain(self, etype):
        """
        Dump information about registered handlers (return string).

        What attrs/events they are hooked on and what attrs they may change.
        Used for debugging.
        """
        s = "func_triggers:\n"
        for k,v in self._func_triggers[etype].items():
            s += "{} -> {}\n".format(v,get_func_name(k))
        s += "\nfunc2attr:\n"
        for k,v in self._func2attr[etype].items():
            s += "{} -> {}\n".format(get_func_name(k),v)
        s += "\nattr2func:\n"
        for k,v in self._attr2func[etype].items():
            s += "{} -> {}\n".format(k,list(map(get_func_name,v)))
        return s


    def register_handler(self, func, etype, triggers, changes):
        """
        Hook a function (or bound method) to specified attribute changes/events.

        Arguments:
        func -- function or bound method
        etype -- entity type (only changes of attributes of this etype trigger the func)
        triggers -- set/list/tuple of attributes whose update trigger the call of the method (update of any one of the attributes will do)
        changes -- set/list/tuple of attributes the method call may update (may be None)
        
        Notes:
        Each function must be registered only once. 
        """
        if etype not in ENTITY_TYPES:
            raise ValueError("Unknown entity type '{}'".format(etype))
        
        # _func2attr[etype]: function -> list of attrs it may change
        # _attr2func[etype]: attribute -> list of functions its change triggers
        # _func_triggers[etype]: function -> list of attrs that trigger it
        # There are separate mappings for each entity type.
        
        # Check types (because common error is to pass string instead of 1-tuple)
        if not isinstance(triggers, Iterable) or isinstance(triggers, str):
            raise TypeError('Argument "triggers" must be iterable and must not be str.')
        if changes is not None and (not isinstance(changes, Iterable) or isinstance(changes, str)):
            raise TypeError('Argument "changes" must be iterable and must not be str.')
        
        self._func2attr[etype][func] = tuple(changes) if changes is not None else ()
        self._func_triggers[etype][func] = set(triggers)
        for attr in triggers:
            if attr in self._attr2func[etype]:
                self._attr2func[etype][attr].append(func)
            else:
                self._attr2func[etype][attr] = [func]


    def get_queue_sizes(self):
        """Return current number of requests in each queue."""
        return [q.unfinished_tasks for q in self._request_queues]

    def get_queue_size(self):
        """Return current total number of requests in all queues."""
        return sum(q.unfinished_tasks for q in self._request_queues)    


    def update(self, ekey, update_spec):
        """
        Request an update of one or more attributes of an entity record.
        
        Put given requests into an internal queue to be processed by some of the
        worker threads. Requests may request changes of some attribute or they
        may issue events. 
        
        Arguments:
        ekey -- Entity type and key (2-tuple)
        update_spec -- list of 3-tuples ... (see above) TODO
        """
        # Updates are distributed to worker queues based on a hash of entity key
        index = hash(ekey) % self.num_workers
        self._request_queues[index].put((ekey, update_spec))
        
    
    # TODO cache results (clear cache when register_handler is called)
    def get_all_possible_changes(self, etype, attr):
        """
        Returns all attributes (as a set) that may be changed by a "chain reaction"
        of changes triggered by update of given attrbiute (or event).
        
        Warning: There must be no loops in the sequence of attributes and  
        triggered functions.
        """
        may_change = set() # Attributes that may be changed
        funcs_to_call = set(self._attr2func[etype].get(attr, ()))
        f2a = self._func2attr[etype]
        a2f = self._attr2func[etype]
        while funcs_to_call:
            func = funcs_to_call.pop()
            attrs_to_change = f2a[func]
            may_change.update(attrs_to_change)
            for attr in attrs_to_change:
                funcs_to_call |= set(a2f.get(attr, ()))
        return may_change
    
    
    def _process_update_req(self, ekey, update_requests):
        """
        Main processing function - update attributes or trigger an event.
        
        Arguments:
        ekey -- Entity type and key (2-tuple)
        update_requests -- list of 3-tuples as described above
        
        Return True if a new record was created, False otherwise.
        """ 
        etype = ekey[0]
        
        # Load record corresponding to the key from database.
        # If record doesn't exist, create new.
        # Also create associated auxiliary objects:
        #   call_queue - queue of functions that should be called to update the record.
        #     queue.Queue of tuples (function, list_of_update_spec), where list_of_update_spec is a list of
        #     updates (2-tuples (key, new_value) or (event, param) which tirggered the function.
        #   may_change - set of attributes that may be changed by planned function calls

#        t1 = time.time()

        # Fetch the record from database or create a new one
        new_rec_created = False
        rec = self.db.get(ekey[0], ekey[1])
        if rec is None:
            now = datetime.utcnow()
            rec = {
                'ts_added': now,
                'ts_last_update': now,
            }
            new_rec_created = True
            # New record was created -> add "!NEW" event to update_requests
            #self.log.debug("New record {} was created, injecting event '!NEW'".format(ekey))
            update_requests.insert(0,('event','!NEW',None))
        
        # Short-circuit if update_requests is empty (used to only create a record if it doesn't exist)
        if not update_requests:
            return False
        
        requests_to_process = update_requests
        
#        t2 = time.time()
#        t_handlers = {}
        
        # *** Now we have the record, process the requested updates ***
        
        # auxiliary objects
        call_queue = deque() # planned calls of handler functions due to their hooking to attribute updates  
        may_change = set() # which attributes may change after performing all calls in call_queue
        
        loop_counter = 0 # counter used to stop when looping too long - probably some cycle in attribute dependencies
        
        # *** call_queue loop ***
        while True:
            # *** If any update requests are pending, process them ***
            # (i.e. perform requested changes, add calls to hooked functions to
            # the call_queue and update the set of attributes that may change)
            if requests_to_process:
                # Process update requests (perform updates, put hooked functions to call_queue and update may_change set)
                self.log.debug("UpdateManager: New update requests for {}: {}".format(ekey, requests_to_process))
                for updreq in requests_to_process:
                    op, attr, val = updreq
                    assert(op != 'event' or attr[0] == '!') # if op=event, attr must begin with '!'
                    
                    if op == 'event':
                        #self.log.debug("Initial update: Event ({}:{}).{} (param={})".format(ekey[0],ekey[1],attr,val))
                        updated = [(attr, val)]
                    else:
                        #self.log.debug("Initial update: Attribute update: ({}:{}).{} [{}] {}".format(ekey[0],ekey[1],attr,op,val))
                        updated = perform_update(rec, updreq)
                        if not updated:
                            #self.log.debug("Attribute value wasn't changed.")
                            continue
                    
                    # Add to the call_queue all functions directly hooked to the attribute/event 
                    for func in self._attr2func[etype].get(attr, []):
                        # If the function is already in the queue...
                        for f,updates in call_queue:
                            if f == func:
                                # ... just add upd to list of updates that triggered it
                                # TODO FIXME: what if one attribute is updated several times? It should be in the list only once, with the latest value.
                                updates.extend(updated)
                                break
                        # Otherwise put the function to the queue
                        else:
                            call_queue.append((func, updated))
                
                    # Compute all attribute changes that may occur due to this event and add 
                    # them to the set of attributes to change
                    #self.log.debug("get_all_possible_changes: {} -> {}".format(str(attr), repr(self.get_all_possible_changes(etype, attr))))
                    may_change |= self.get_all_possible_changes(etype, attr)
                    #self.log.debug("may_change: {}".format(may_change))
                
                # All reqests were processed, clear the list
                requests_to_process.clear()
            
            if not call_queue:
                break # No more work to do
            
            # *** Do all function calls planned in the call queue ***
            
#             self.log.debug("call_queue loop iteration {}:\n  call_queue: {}\n  may_change: {}".format(
#                 loop_counter,
#                 list(map(lambda x: (get_func_name(x[0]), x[1]), call_queue)),
#                 may_change)
#             )
            # safety check against infinite looping
            loop_counter += 1
            if loop_counter > 20:
                self.log.warning("Too many iterations when updating {}, something went wrong! Update chain stopped.".format(ekey))
                break
            
            func, updates = call_queue.popleft()
            
            # If the function watches some attributes that may be updated later due 
            # to expected subsequent events, postpone its call.
            if may_change & self._func_triggers[etype][func]:  # nonempty intersection of two sets
                # Put the function call back to the end of the queue
                self.log.debug("call_queue: Postponing call of {}({})".format(get_func_name(func), updates))
                call_queue.append((func, updates))
                continue
            
            # Call the event handler function.
            # Set of requested updates of the record should be returned
            self.log.debug("Calling: {}({}, ..., {})".format(get_func_name(func), ekey, updates))
#            t_handler1 = time.time()
            try:
                reqs = func(ekey, rec, updates)
            except Exception as e:
                self.log.exception("Unhandled exception during call of {}({}, rec, {}). Traceback follows:"
                    .format(get_func_name(func), ekey, updates) )
                reqs = []
#            t_handler2 = time.time()
#            t_handlers[get_func_name(func)] = t_handler2 - t_handler1

            # Set requested updates to requests_to_process
            if reqs:
                requests_to_process.extend(reqs)
            
            # TODO FIXME - toto asi predpoklada, ze urcity atribut muze byt menen jen jednou handler funkci
            # (coz jsem mozna nekde zadal jako nutnou podminku; kazdopadne jestli to tak je, musi to byt nekde velmi jasne uvedeno) 
            # Remove set of possible attribute changes of that function from
            # may_change (they were either already changed (or are in requests_to_process) or they won't be changed)
            #self.log.debug("Removing {} from may_change.".format(self._func2attr[etype][func]))
            may_change -= set(self._func2attr[etype][func])
            #self.log.debug("New may_change: {}".format(may_change))
        
        #self.log.debug("call_queue loop end")
        # FIXME: Temporarily disabled, removing from may_change doesn't work well, the whole algorithm must be reworked
        #assert(len(may_change) == 0)
        
        # Set ts_last_update
        rec['ts_last_update'] = datetime.utcnow()
        
        #self.log.debug("RECORD: {}: {}".format(ekey, rec))
        
#        t3 = time.time()

        # Put the record back to the DB
        self.db.put(ekey[0], ekey[1], rec)
        
#        t4 = time.time()
#        #if t4 - t1 > 1.0:
#        #    self.log.info("Entity {}: load: {:.3f}s, process: {:.3f}s, store: {:.3f}s".format(ekey, t2-t1, t3-t2, t4-t3))
#        #    self.log.info("  handlers:" + ", ".join("{}: {:.3f}s".format(fname, t) for fname, t in t_handlers))
#
#        self.t_handlers.update(t_handlers)
        
        return new_rec_created

    
    def start(self):
        """Run the worker threads."""
        self.log.info("Starting {} worker threads".format(self.num_workers))
        #self._process = multiprocessing.Process(target=self._main_loop)
        self._workers = [ threading.Thread(target=self._worker_func, args=(i,), name="UMWorker-"+str(i)) for i in range(self.num_workers) ]
        for worker in self._workers:
            worker.start()
    
    def stop(self):
        """
        Stop the manager (signal all worker threads to finish and wait).
        
        All modules writing to the request queue should already be stopped.
        If some request is written to the queue after a call of this function,
        it probably won't be performed.
        """
        self.log.info("Telling all workers to stop ...")
        # Thread for printing debug messages about worker status
        threading.Thread(target=self._dbg_worker_status_print, daemon=True).start()
        
        # Wait until all work is done (other modules should be stopped now, but some tasks may still be added as a result of already ongoing processing (e.g. new IP adds new ASN))
        for i in range(self.num_workers):
            self._request_queues[i].join() 
        # Send None to request_queue to signal workers to stop (one for each worker)
        for i in range(self.num_workers):
            self._request_queues[i].put(None) 
        # Wait until all workers stopped (this should be immediate)
        for worker in self._workers:
            worker.join()
        
        # Stop logging scheduler
        self.logging_scheduler.stop()
        # Delete file with updates count log
        filename = g.config.get("upd_cnt_file", None)
        if filename:
            try:
                os.remove(filename)
            except Exception:
                pass
        # Cleanup
        self._workers = []


    def watchdog(self):
        """
        Check whether all workers are running and restart them if not.
        
        Should be called periodically by scheduler.
        Stop whole program after 20 restarts of threads.
        """
        for i,worker in enumerate(self._workers):
            if not worker.is_alive():
                if self._watchdog_restarts < 20:
                    self.log.error("Thread {} is dead, restarting.".format(worker.name))
                    worker.join()
                    new_thread = threading.Thread(target=self._worker_func, args=(i,), name="UMWorker-"+str(i))
                    self._workers[i] = new_thread
                    new_thread.start()
                    self._watchdog_restarts += 1
                else:
                    self.log.critical("Thread {} is dead, more than 20 restarts attempted, giving up...".format(worker.name))
                    g.daemon_stop_lock.release()
                    break


    def _dbg_worker_status_print(self):
        """
        Print status of workers and the request queue every 5 seconds.
        
        Should be run as a separate (deamon) thread.
        Exits when all workers has finished.
        """
        time.sleep(10)
        while True:
            alive_workers = filter(threading.Thread.is_alive, self._workers)
            self.log.info("Queue size: {:3}, records in processing {:3}, workers alive: {}".format(
                self.get_queue_size(),
                len(self._records_being_processed),
                ','.join(map(lambda s: s.name[9:], alive_workers))) # 9 = len("UMWorker-")
            )
            if not alive_workers:
                break
            time.sleep(5)
            
    
    def _worker_func(self, thread_index):
        """
        Main processing function.
        
        Run as a separate thread/process. Read request queue. For each request
        pull corresponding record from database, and call "_process_update_req"
        function.
        
        Requests are assigned to workers based on hash of entity key, so each
        entity is always process by the same worker. Therefore, all requests
        modifying a particular entity are done sequentially and no locking is 
        necessary.
        """
        while True:
            # Get update request from the queue
            # (None object in the queue causes termination of the process, used 
            # to exit the program)
            req = self._request_queues[thread_index].get()
            if req is None:
                self.log.debug("'None' received from queue {} - exitting".format(thread_index))
                self._request_queues[thread_index].task_done()
                break
            ekey, updreq = req
            
#             self.log.debug("New update request: {},{}".format(ekey, updreq))
            
            # Call update method (pass copy of updreq since we need it unchanged for the logging code below)
            new_rec_created = self._process_update_req(ekey, updreq.copy())
            
#             self.log.debug("Task done")
            self._request_queues[thread_index].task_done()
            
            # Increment corresponding update counter
            if ekey[0] in ['ip', 'asn']:
                if new_rec_created:
                    self._update_counter[ekey[0]+'_new_entity'] += 1
                elif any(u == ('add', 'events_meta.total', 1) for u in updreq):
                    self._update_counter[ekey[0]+'_event'] += 1
                elif any(u[1] == '!every1w' for u in updreq):
                    self._update_counter[ekey[0]+'_regular_1w'] += 1
                elif any(u[1] == '!every1d' for u in updreq):
                    self._update_counter[ekey[0]+'_regular_1d'] += 1
                else:
                    self._update_counter[ekey[0]+'_other'] += 1



