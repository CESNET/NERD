"""
NERD update manager.

Provides UpdateManager class - a NERD component which handles updates of entity
records, including chain reaction of updates caused by other updates.
"""
# TODO: split this class into two separate classes
#  - "task distribution" and "performing tasks (doing changes, calling callbacks, etc.)"
import sys
import os
import threading
import queue
from datetime import datetime
import time
from collections import deque, Iterable, OrderedDict, Counter
import logging

import g
import core.scheduler
from common.task_queue import TaskQueueReader, TaskQueueWriter

ENTITY_TYPES = ['ip', 'asn', 'bgppref', 'ipblock', 'org']

#  Update request specification = list of n-tuples:
#    - [(op, key, params...), ...]
#      - ('set', key, value)        - set new value to given key (rec[key] = value)
#      - ('append', key, value)     - append new value to array at key (rec[key].append(key))
#      - ('add_to_set', key, value) - append new value to array at key if it isn't present in the array yet (if value not in rec[key]: rec[key].append(value))
#      - ('extend_set', key, iterable) - append values from iterable to array at key if the value isn't present in the array yet (for value in iterable: if value not in rec[key]: rec[key].append(value))
#      - ('rem_from_set', key, iterable) - remove all values at key which are specified in an array
#      - ('add', key, value)        - add given numerical value to that stored at key (rec[key] += value)
#      - ('sub', key, value)        - subtract given numerical value from that stored at key (rec[key] -= value)
#      - ('setmax', key, value)     - set new value of the key to larger of the given value and the current value (rec[key] = max(value, rec[key]))
#      - ('setmin', key, value)     - set new value of the key to smaller of the given value and the current value (rec[key] = min(value, rec[key]))
#      - ('remove', key)            - remove given key (and all subkeys) from the record (parameter is ignored) (do nothing if the key doesn't exist)
#      - ('next_step', key, key_base, min, step) - set value of 'key' to the smallest value of 'rec[key_base] + N*step' that is greater than 'min' (used by updater to set next update time); key_base MUST exist in the record!
#      - ('array_update', key, query, actions) - apply given actions to specified array item under key, see below for details.
#      - ('array_upsert', key, query, actions) - apply given actions to specified array item under key (insert new item if no one matches), see below for details.
#      - ('array_remove', key, query) - remove array item satisfying given query (do nothing if no one matches).
#      - ('event', !name)    - do nothing with record, only trigger functions hooked on the event name
#  The tuple is passed to functions watching for updates of given keys / events
#  with given name. Event names must begin with '!' (attribute keys mustn't).
#  Update manager performs the requested update and calls functions hooked on 
#  the attribute/event.
#  A hooked function receives a list of updates that triggered its call, 
#  i.e. a list of 2-tuples (attr_name, new_value) or (event_name, param)
#  (if more than one update triggers the same function, it's called only once). 

# Special actions "array_update"/"array_upsert":
#      - ('array_update', key, query, actions)
#  "key" must be path to an array of objects (dicts),
#  the item whose values match those in "query" dict is selected
#  all "actions" are performed with the selected object (keys inside those actions should be relative to the object root).
#  If the array does not contain any matching item:
#    - array_update: record is not changed
#    - array_upsert: "query" is added as a new array item.
#  If there are multiple matching events, only the first one is used.
#  "actions" may contain actions of type "array_update"/"array_upsert" (recursion), it must not contain events.
#  Rationale:
#    Because of DB constraints, keys should always be fixed values. Therefore we often use 
#    arrays of subobjects where one or more attributes of the subobject act as a key.
#    This action type allows to work with such structures.
#  Examples:
#    ('array_update', 'bl', {n: "blacklistname"} , [('set', 'v', 1), ('set', 't', req_time), ('append', 'h', req_time)])
#    ('array_upsert', 'events', {date: "2017-07-17", cat: "ReconScanning"} , [('add', 'n', 1)])


# TODO: Let each module (or rather hook function) tell, whether it needs the whole record.
# Many of them probably won't so we can save the load from database
# (we just need to block any other updates, which is now done by keeping the record in _records_being_processed).


def get_func_name(func_or_method):
    """Get name of function or method as pretty string."""
    try:
        fname = func_or_method.__func__.__qualname__
    except AttributeError:
        fname = func_or_method.__name__
    return func_or_method.__module__ + '.' + fname



def perform_update(rec, updreq):
    """
    Update a record according to given update request.
    
    updreq - n-tuple (op, key, params...)
    
    Return array with specifications of performed updates - pairs (updated_key,
    new_value) or None.
    (None is returned when nothing was changed, e.g. because op=add_to_set and
    value was already present, or removal of non-existent item was requested)
    """
    op = updreq[0]
    key = updreq[1]
    
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
        rec[key] = updreq[2]
    
    elif op == 'append':
        if key not in rec:
            rec[key] = [updreq[2]]
        else:
            rec[key].append(updreq[2])

    elif op == 'add_to_set':
        value = updreq[2]
        if key not in rec:
            rec[key] = [value]
        elif value not in rec[key]:
            rec[key].append(value)
        else:
            return None
    
    elif op == 'extend_set':
        value = updreq[2]
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

    elif op == 'rem_from_set':
        if key in rec:
            rec[key] = list(set(rec[key]) - set(updreq[2]))

    elif op == 'add':
        if key not in rec:
            rec[key] = updreq[2]
        else:
            rec[key] += updreq[2]
    
    elif op == 'sub':
        if key not in rec:
            rec[key] = -updreq[2]
        else:
            rec[key] -= updreq[2]
    
    elif op == 'setmax':
        if key not in rec:
            rec[key] = updreq[2]
        else:
            rec[key] = max(updreq[2], rec[key])
    
    elif op == 'setmin':
        if key not in rec:
            rec[key] = updreq[2]
        else:
            rec[key] = min(updreq[2], rec[key])
    
    elif op == 'remove':
        if key in rec:
            del rec[key]
            return [(updreq[1], None)]
        return None
    
    elif op == 'next_step':
        key_base = updreq[2]
        minimum = updreq[3]
        step = updreq[4]
        base = rec[key_base]
        rec[key] = base + ((minimum - base) // step + 1) * step
    
    elif op == 'array_update' or op == 'array_upsert':
        query = updreq[2]
        actions = updreq[3]
        if key not in rec:
            if op == 'array_upsert':
                rec[key] = []
            else:
                return None # Array doesn't exist and insert not requested
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
            upds = perform_update(item, action) # recursion
            # List of all actions must be returned, convert relative keys to absolute
            for inner_key, new_val in upds:
                updates_performed.append((key + '[' + str(i) + '].' + inner_key, new_val))
        return updates_performed
    
    elif op == 'array_remove':
        query = updreq[2]
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
        return [(key + '[' + str(i) + ']', None)]
    
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

    def __init__(self, config, db, process_index, num_processes):
        """
        Initialize update manager.
        
        Arguments:
        config -- global NERDd configuration (dict)
        db -- instance of EntityDatabase which should be used to load/store 
              entity records.
        process_index -- index of this process (0 to num_processes-1)
        num_processes -- total number of worker processes in the system
        """
        assert(isinstance(process_index, int) and isinstance(num_processes, int))
        assert(num_processes >= 1)
        assert(0 <= process_index < num_processes)

        self.log = logging.getLogger("UpdateManager")
        #self.log.setLevel('DEBUG')
        
        self.process_index = process_index
        self.num_processes = num_processes
        
        self.db = db
        
        self.rabbit_params = config.get('rabbitmq', {})

        self.running = False

        # Mapping of names of attributes to a list of functions that should be 
        # called when the attribute is updated
        # (One such mapping for each entity type)
        self._attr2func = {etype: {} for etype in ENTITY_TYPES}
        
        # Set of attributes that may be updated by a function
        self._func2attr = {etype: {} for etype in ENTITY_TYPES}

        # Mapping of functions to set of attributes the function watches, i.e.
        # is called when the attribute is changed
        self._func_triggers = {etype: {} for etype in ENTITY_TYPES}
        
        # List of worker threads for processing the update requests
        self._worker_threads = []
        self.num_threads = g.config.get('worker_threads', 8)

        # Internal queues for each worker
        # TODO - rozhodnout jak velké maxsize by to mělo být (a jestli je to vůbec nutné, možná není, pokud bude na úrovni RMQ omezen počet nepotvrzených zpráv)
        self._queues = [queue.Queue(10) for _ in range(self.num_threads)]

        # Connections to main task queue
        # Reader - reads tasks from a pair of queues (one pair per process) and distributes them to worker threads
        self._task_queue_reader = TaskQueueReader(self._distribute_task, self.process_index, self.rabbit_params)
        # Writer - allows modules to write new tasks
        self._task_queue_writer = TaskQueueWriter(self.num_processes, self.rabbit_params)

        # Object to store thread-local data (e.g. worker-thread index) (each thread sees different object contents)
        self._current_thread_data = threading.local()

        # Number of restarts of threads by watchdog
        self._watchdog_restarts = 0
        # Register watchdog to scheduler
        g.scheduler.register(self._watchdog, second="*/30")

        # Get EventGroups (of EventCountLogger) for easier event logging
        self.elog_op = g.ecl.get_group("rec_ops", True) # True = return DummyEventGroup if there's no configuration for given group name
        self.elog_by_src = g.ecl.get_group("tasks_by_src", True)

        # This is here for performance debugging - measuring the time spent in each handler function
#        self.t_handlers = Counter()
#        self.logging_scheduler.register(self.log_t_handlers, second="*/60")


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


    def update(self, ekey, update_requests): # TODO: rename to "request update"
        """
        Request an update of one or more attributes of an entity record.
        
        Put given requests into the main task queue to be processed by some of the workers.
        Requests may request changes of some attribute or they may issue events.
        
        Arguments:
        ekey -- Entity type and key (2-tuple)
        update_requests -- list of update_request n-tuples (see the comments in the beginning of file)
        """
        # Put task to priority queue, so this can never block due to full queue
        self._task_queue_writer.put_task(ekey[0], ekey[1], update_requests, "update_manager", priority=True)


    # ############### Task distribution & control functions ###############

    def start(self):
        """Run the worker threads and start consuming from TaskQueue."""
        self.log.info("Connecting to RabbitMQ")
        self._task_queue_reader.connect()
        self._task_queue_writer.connect()

        self.log.info("Starting {} worker threads".format(self.num_threads))
        self.running = True
        self._worker_threads = [
            threading.Thread(target=self._worker_func, args=(i,), name="Worker-{}-{}".format(self.process_index, i)) for
            i in range(self.num_threads)]
        for worker in self._worker_threads:
            worker.start()

        self.log.info("Starting consuming tasks from main queue")
        self._task_queue_reader.start()


    def stop(self):
        """
        Stop the manager
        """
        self.log.info("Waiting for worker threads to finish their current tasks ...")
        # Thread for printing debug messages about worker status
        threading.Thread(target=self._dbg_worker_status_print, daemon=True).start()

        # Stop receiving new tasks from global queue
        self._task_queue_reader.stop()

        # Signalize stop to worker threads
        self.running = False

        # Wait until all workers stopped
        for worker in self._worker_threads:
            worker.join()

        self._task_queue_reader.disconnect()
        self._task_queue_writer.disconnect()

        # Cleanup
        self._worker_threads = []


    def _distribute_task(self, msg_id, etype, eid, updreq, src):
        """
        Puts given task into local queue of the corresponding thread.

        Called by TaskQueueReader when a new task is received from the global queue.

        :param msg_id: unique ID of the message, used to acknowledge it
        :param etype: entity type (e.g. 'ip', 'asn')
        :param eid: entity identifier (e.g. '1.2.3.4', 2852)
        :param updreq: list of update requests (n-tuples)
        """
        # Distribute tasks to worker threads by hash of (etype,ekey)
        index = hash((etype, eid)) % self.num_threads
        self._queues[index].put((msg_id, etype, eid, updreq, src))


    def _worker_func(self, thread_index):
        """
        Main worker function.

        Run as a separate thread. Read its local task queue and calls
        "_process_task" function to process each task.

        Tasks are assigned to workers based on hash of entity key, so each
        entity is always processed by the same worker. Therefore, all requests
        modifying a particular entity are done sequentially and no locking is
        necessary.
        """
        # Store index to thread-local variable
        self._current_thread_data.index = thread_index

        my_queue = self._queues[thread_index]

        # Read and process tasks in a loop.
        # Exit immediately after self.running is set to False, it's not a problem if there are any more tasks waiting
        # in the queue - they won't be acknowledged so they will be re-delivered after restart.
        while self.running:
            # Get message from thread's local queue
            try:
                task = my_queue.get(block=True, timeout=1)
            except queue.Empty:
                continue # check self.running again

            msg_id, etype, eid, updreq, src = task

            self.elog_by_src.log(src)

            # Acknowledge receipt of the task (regardless of success/failre of its processing)
            self._task_queue_reader.ack(msg_id)

            # FIXME: (TEMPORARY) Quick fix to check IP address (should be fixed in MISP receiver, which sometimes sends prefixes instead of IP addresses)
            if etype == "ip" and "/" in eid:
                self.log.error("Prefix instead of IP, skipping task: {}".format(task))
                continue

            # Process the task
            # self.log.debug("Processing task {}: {}/{} {}".format(msg_id, etype, eid, updreq))
            start_time = datetime.now()
            try:
                created = self._process_update_req(etype, eid, updreq.copy())
            except Exception:
                self.log.error("Error has occurred during processing task: {}".format(task))
                raise
            duration = (datetime.now() - start_time).total_seconds()
            #self.log.debug("Task {} finished in {:.3f} seconds.".format(msg_id, duration))
            if duration > 1.0:
                self.log.debug("Task {} took {} seconds: {}/{} {}{}".format(msg_id, duration, etype, eid, updreq, " (new record created)" if created else ""))


    def _watchdog(self):
        """
        Check whether all workers are running and restart them if not.

        Should be called periodically by scheduler.
        Stop whole program after 20 restarts of threads.
        """
        for i, worker in enumerate(self._worker_threads):
            if not worker.is_alive():
                if self._watchdog_restarts < 20:
                    self.log.error("Thread {} is dead, restarting.".format(worker.name))
                    worker.join()
                    new_thread = threading.Thread(target=self._worker_func, args=(i,), name="Worker-{}-{}".format(self.process_index, i))
                    self._worker_threads[i] = new_thread
                    new_thread.start()
                    self._watchdog_restarts += 1
                else:
                    self.log.critical("Thread {} is dead, more than 20 restarts attempted, giving up...".format(worker.name))
                    g.daemon_stop_lock.release()  # Exit program
                    break

    def _dbg_worker_status_print(self):
        """
        Print status of workers and the request queue every 5 seconds.

        Should be run as a separate (daemon) thread.
        Exits when all workers has finished.
        """
        ttl = 10  # Wait for 10 seconds until printing starts
        while True:
            # Check if all workers are dead every second
            time.sleep(1)
            ttl -= 1
            alive_workers = [w for w in self._worker_threads if w.is_alive()]
            if not alive_workers:
                return

            if ttl == 0:
                # Print info and reset counter to 5 seconds
                self.log.info("{} worker threads alive".format(len(alive_workers)))
                ttl = 5



    # ############### Task processing functions ###############

    # TODO cache results (clear cache when register_handler is called)
    def get_all_possible_changes(self, etype, attr):
        """
        Returns all attributes (as a set) that may be changed by a "chain reaction"
        of changes triggered by update of given attribute (or event).
        
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
    
    
    def _process_update_req(self, etype, eid, update_requests):
        """
        Main processing function - update attributes or trigger an event.
        
        Arguments:
        etype - entity type 
        eid - entity ID
        update_requests - list of n-tuples as described above
        
        Return True if a new record was created, False otherwise.
        """ 
        # Load record corresponding to the key from database.
        # If record doesn't exist, create new.
        # Also create associated auxiliary objects:
        #   call_queue - queue of functions that should be called to update the record.
        #     queue.Queue of tuples (function, list_of_update_spec), where list_of_update_spec is a list of
        #     updates (2-tuples (key, new_value) or (event, param) which triggered the function.
        #   may_change - set of attributes that may be changed by planned function calls

#        t1 = time.time()

        # Check whether a new record should not be created in case every operation is 'weak' (starts with '*')
        weak_op = True
        for ndx, updreq in enumerate(update_requests):
            op = updreq[0]
            if op[0] != '*':
                weak_op = False
            else:
                # Remove starting symbol '*'
                update_requests[ndx] = [updreq[0][1:]] + updreq[1:] # first item without first char + all other items

        # Fetch the record from database or create a new one
        new_rec_created = False
        rec = self.db.get(etype, eid)
        if rec is None:
            if weak_op:
                update_requests.clear()
                self.log.debug("Received only weak operations for non-existent entity {} of type {}. Aborting record creation.".format(etype, eid))
            else:
                now = datetime.utcnow()
                rec = {
                    '_id': eid,
                    'ts_added': now,
                    'ts_last_update': now,
                }
                new_rec_created = True
                # New record was created -> add "!NEW" event to update_request
                #self.log.debug("New record ({},{}) was created, injecting event '!NEW'".format(etype,eid))
                update_requests.insert(0,('event','!NEW'))
                self.elog_op.log(etype+'_created')
        
        # Short-circuit if update_requests is empty (used to only create a record if it doesn't exist)
        if not update_requests:
            self.elog_op.log(etype+'_noop') # task with no operations or only weak operations and the record doesn't exist
            return False
        
        requests_to_process = update_requests
        
#        t2 = time.time()
#        t_handlers = {}
        
        # *** Now we have the record, process the requested updates ***
        
        # auxiliary objects
        call_queue = deque() # planned calls of handler functions due to their hooking to attribute updates  
        may_change = set() # which attributes may change after performing all calls in call_queue
        
        loop_counter = 0 # counter used to stop when looping too long - probably some cycle in attribute dependencies
        
        deletion = False
        # *** call_queue loop ***
        while True:
            # *** If any update requests are pending, process them ***
            # (i.e. perform requested changes, add calls to hooked functions to
            # the call_queue and update the set of attributes that may change)
            if requests_to_process:
                # Process update requests (perform updates, put hooked functions to call_queue and update may_change set)
                #self.log.debug("UpdateManager: New update requests for ({},{}): {}".format(etype, eid, requests_to_process))
                for updreq in requests_to_process:
                    op = updreq[0]
                    attr = updreq[1]
                    assert(op != 'event' or attr[0] == '!') # if op=event, attr must begin with '!'
                    
                    if op == 'event':
                        #self.log.debug("Initial update: Event ({}:{}).{} (param={})".format(etype,eid,attr,val))
                        updated = [(attr, None)]

                        # Check whether the event is !DELETE, clear queues and add calls to functions hooked to the !DELETE event
                        if attr == '!DELETE':
                            deletion = True
                            requests_to_process.clear()
                            call_queue.clear()
                            for func in self._attr2func[etype].get(attr, []):
                                call_queue.append((func, updated))
                            break
                    else:
                        #self.log.debug("Initial update: Attribute update: ({}:{}).{} [{}] {}".format(etype,eid,attr,op,val))
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
                
                # All requests were processed, clear the list
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
                self.log.warning("Too many iterations when updating ({}:{}), something went wrong! Update chain stopped.".format(etype,eid))
                break
            
            func, updates = call_queue.popleft()
            
            # If the function watches some attributes that may be updated later due 
            # to expected subsequent events, postpone its call.
            if may_change & self._func_triggers[etype][func]:  # nonempty intersection of two sets
                # Put the function call back to the end of the queue
                #self.log.debug("call_queue: Postponing call of {}({})".format(get_func_name(func), updates))
                call_queue.append((func, updates))
                continue
            
            # Call the event handler function.
            # Set of requested updates of the record should be returned
            #self.log.debug("Calling: {}(({}, {}), rec, {})".format(get_func_name(func), etype, eid, updates))
#            t_handler1 = time.time()
            try:
                reqs = func((etype, eid), rec, updates)
            except Exception as e:
                self.log.exception("Unhandled exception during call of {}(({}, {}), rec, {}). Traceback follows:"
                    .format(get_func_name(func), etype, eid, updates) )
                g.ecl['errors'].log('error_in_module')
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
        
#        t3 = time.time()

        # Remove or update processed database record
        if deletion:
            self.db.delete(etype, eid)
            self.log.debug("Entity '{}' of type '{}' was removed from the database.".format(eid, etype))
            self.elog_op.log(etype+'_removed')
        else:
            self.db.put(etype, eid, rec)
            self.elog_op.log(etype+'_updated') # normal record update

        
#        t4 = time.time()
#        #if t4 - t1 > 1.0:
#        #    self.log.info("Entity ({}:{}): load: {:.3f}s, process: {:.3f}s, store: {:.3f}s".format(etype, eid, t2-t1, t3-t2, t4-t3))
#        #    self.log.info("  handlers:" + ", ".join("{}: {:.3f}s".format(fname, t) for fname, t in t_handlers))
#
#        self.t_handlers.update(t_handlers)
        
        return new_rec_created



    # ############### Debug/logging functions ###############

    def dump_handler_chain(self, etype):
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

    def log_t_handlers(self):
        print("Handler function running times:")
        for name, t in self.t_handlers.most_common(10):
            print("{:50s} {:7.3f}".format(name, t))
        self.t_handlers = Counter()


