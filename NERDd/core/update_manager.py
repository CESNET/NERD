"""
NERD update manager.

Provides UpdateManager class - a NERD component which handles updates of entity
records, including chain reaction of updates casued by other updates.
"""
import threading
# import multiprocessing
import queue
from datetime import datetime, timezone
import time
from collections import defaultdict, deque

#  Update request specification = list of three-tuples:
#    - [(op, key, value), ...]
#      - ('set', key, value)        - set new value to given key (rec[key] = value)
#      - ('append', key, value)     - append new value to array at key (rec[key].append(key))
#      - ('add_to_set', key, value) - append new value to array at key if it isn't present in the array yet (if value not in rec[key]: rec[key].append(value))
#      - ('extend_set', key, iterable) - append values from iterable to array at key if the value isn't present in the array yet (for value in iterable: if value not in rec[key]: rec[key].append(value))
#      - ('add', key, value)        - add given numerical value to that stored at key (rec[key] += value)
#      - ('sub', key, value)        - add given numerical value to that stored at key (rec[key] -= value)
#      - ('event', !name, param)    - do nothing with record, only trigger functions hooked on the event name
#  The tuple is passed to functions watching for updates of given keys / events
#  with given name. Event names must begin with '!' (attribute keys mustn't).
#  Update manager performs the requested update and calls functions hooked on 
#  the attribute/event.
#  Hooked function receives list if update specifiers (the three tuples) that
#  triggered its call (if more than one update triggers the same function, it's
#  called only once). 

# TODO: (?)
#  call handler function with parameters:
#    attributes_changed (list of tuples (attr_name, new_value))
#    events (list of tuples (event_name, param))
#  instead of update request specification (which is too complex and contains information irrelevant to hooked functions)

# TODO: Let each module (or rather hook function) tell, whether it needs the whole record.
# Many of them probably won't so we can save the load from database
# (we just need to block any other updates, which is now done by keeping the record in _records_being_processed).

# TODO: Vyresit reakci na !NEW pri pridani noveho modulu.
# Spousta modulu reaguje na !NEW, ale pri pridani takoveho modulu do systemu
# se nepridaji nove polozky k existujicim zaznamum (protoze uz existuji),
# ani kdyz jsou updatovatny.


def print_func(func_or_method):
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
    
    Return specification of performed updates - either updreq or None
    (None is returned when nothing was changed, either because op=add_to_set and
    value was already in the array, or unknown operation was requested)
    """
    op, key, value = updreq
    
    # Process keys with hierarchy, i.e. containing dots (like "events.scan.count")
    # rec will be the inner-most subobject ("events.scan"), key the last attribute ("count")
    # If path doesn't exist in the hierarchy, it's created
    while '.' in key:
        first_key, key = key.split('.',1)
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
                    rec[key].append(value)
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
    
    else:
        print("perform_update: Unknown operation {}".fomrat(op), file=sys.stderr)
        return None
    
    return updreq


class UpdateManager:
    """
    Manages updates of entity records triggered by NERD modules.
    
    TODO: detailed description
    """

    def __init__(self, db):
        """
        Initialize update manager.
        
        Arguments:
        db -- instance of EntityDatabase which should be used to load/store 
              entity records.
        """
        self.db = db
        
        # Mapping of names of attributes to a list of functions that should be 
        # called when the attrbibute is updated
        self._attr2func = {}
        
        # Set of attributes thet may be updated by a function
        self._func2attr = {}

        # Mapping of functions to set of attributes the function watches, i.e.
        # is called when the attribute is changed
        self._func_triggers = {}
        
        # Initialize a queue for pending update requests
        self._request_queue = queue.Queue()#multiprocessing.JoinableQueue()
        
        # Temporary storage of records being updated.
        # Mapping of "ekey" to the following 4-tuple:
        #     (record [JSON-like object], 
        #      event handler call queue [queue.Queue containing tuples (func, event)],
        #      attributes that may change due to planned handler calls [set]
        #     )
        self._records_being_processed = {}
    
    
    def register_handler(self, func, triggers, changes):
        """
        Hook a function (or bound method) to specified attribute changes/events.

        Arguments:
        func -- function or bound method
        triggers -- attributes whose update trigger the call of the method (update of any one of the attributes will do)
        changes -- set/list/tuple of attributes the method call may update
        
        Notes:
        Each function must be registered only once. 
        """
        # _func2attr: function -> list of attrs it may change
        # _attr2func: attribute -> list of functions its change triggers
        # _func_triggers: function -> list of attrs that trigger it
        
        self._func2attr[func] = tuple(changes) if changes is not None else ()
        self._func_triggers[func] = set(triggers)
        for attr in triggers:
            if attr in self._attr2func:
                self._attr2func[attr].append(func)
            else:
                self._attr2func[attr] = [func]

    def update(self, ekey, update_spec):
        """
        Request an update of one or more attributes of an entity record.
        
        Put given request into an internal queue to be processed by some of the
        worker threads.
        
        Arguments:
        ekey -- Entity type and key (2-tuple)
        update_spec -- list of 3-tuples ... (see above) TODO
        """
        # TODO check data validity
        self._request_queue.put((ekey, update_spec))
        
    
    # TODO cache results (clear cache when register_handler is called)
    def get_all_possible_changes(self, attr):
        """
        Returns all attributes (as a set) that may be changed by a "chain reaction"
        of changes triggered by update of given attrbiute (or event).
        
        Warning: There must be no loops in the sequence of attributes and  
        triggered functions.
        """
        may_change = set() # Attributes that may be changed
        funcs_to_call = set(self._attr2func.get(attr, ()))
        while funcs_to_call:
            func = funcs_to_call.pop()
            attrs_to_change = self._func2attr[func]
            may_change.update(attrs_to_change)
            for attr in attrs_to_change:
                funcs_to_call |= set(self._attr2func.get(attr, ()))
        return may_change
    
    
    def _process_update_req(self, ekey, update_requests):
        """
        Main processing function - update attributes or trigger an event.
        
        May be called asynchronously by NERD modules to request changes in
        attributes of given entity.
        
        Arguments:
        ekey -- Entity type and key (2-tuple)
        update_requests -- update_spec as described above (3-tuples,... TODO)
        """
        
        # Load record corresponding to the key -- either from database, or from
        # temporary storage of records being currently updated)
        # If record doesn't exist, create new.
        # Also load/create associated auxiliary objects:
        #   call_queue - queue of functions that should be called to update the record.
        #     queue.Queue of tuples (function, list_of_update_spec), where list_of_update_spec is a list of
        #     updates (3-tuples op,key,value) which tirggered the function.
        #   may_change - set of attributes that may be changed by planned function calls
        # TODO locking (lock records_being_processed)
        if ekey in self._records_being_processed:
            rec, call_queue, may_change = self._records_being_processed[ekey]
        else:
            # Fetch record from database or create new one
            rec = self.db.get(ekey[0], ekey[1])
            if rec is None:
                now = datetime.now(tz=timezone.utc)
                rec = {
                    'ts_added': now,
                    'ts_last_update': now,
                }
                # New record was created -> add "!NEW" event to attrib_updates
                print("New record {} was created, injecting event '!NEW'".format(ekey))
                update_requests.insert(0,('event','!NEW',None))
            
            # Create auxiliary objects
            call_queue = deque()
            may_change = set()
            # Store it all in the temporary storage
            self._records_being_processed[ekey] = (rec, call_queue, may_change)
        
        
        # Perform requested updates.
        for updreq in update_requests:
            op, attr, val = updreq
            assert(op != 'event' or attr[0] == '!') # if op=event, attr must begin with '!'
            
            if op == 'event':
                print("Initial update: Event ({}:{}).{} (param={})".format(ekey[0],ekey[1],attr,val))
            else:
                print("Initial update: Attribute update: ({}:{}).{} [{}] {}".format(ekey[0],ekey[1],attr,op,val))
                upd = perform_update(rec, updreq)
                if upd is None:
                    print("Attribute value wasn't changed.")
                    continue
            
            # Add to the call_queue all functions directly hooked to the attribute/event 
            for func in self._attr2func.get(attr, []):
                # If the function is already in the queue, just add updreq to list of updates that triggered it
                for f,upds in call_queue:
                    if f == func:
                        upds.append(updreq)
                        break
                else:
                    call_queue.append((func, [updreq]))
        
            # Compute all attribute changes that may occur due to this event and add 
            # them to the set of attributes to change
            print("get_all_possible_changes: {} -> {}".format(str(attr), repr(self.get_all_possible_changes(attr))))
            may_change |= self.get_all_possible_changes(attr)
            print("may_change: {}".format(may_change))
        
        
        # Process planned calls in the queue until it's empty
        loop_counter = 0 # counter used to stop when looping too long - probably some cycle in attribute dependencies
        while call_queue:
            print("call_queue loop iteration {}:\n  call_queue: {}\n  may_change: {}".format(
                loop_counter,
                list(map(lambda x: (print_func(x[0]), x[1]), call_queue)),
                may_change)
            )
            # safety check against infinite looping
            loop_counter += 1
            if loop_counter > 10:
                print("WARNING: Too many iterations when updating {}, something went wrong! Update chain stopped.".format(ekey))
                break
            
            func, updates = call_queue.popleft()
            
            # If the function watches some attributes that may be updated later due 
            # to expected subsequent events, postpone its call.
            if may_change & self._func_triggers[func]:  # nonempty intersection of two sets
                # Put the function call back to the end of the queue
                print("call_queue: Postponing call of {}({})".format(print_func(func), updates))
                call_queue.append((func, updates))
                continue
            
            # Call the event handler function.
            # Set of requested updates of the record should be returned
            print("Calling: {}({}, ..., {})".format(print_func(func), ekey, updates))
            update_reqs = func(ekey, rec, updates)
            if update_reqs is None:
                update_reqs = []
            
            # Perform the updates
            for updreq in update_reqs:
                op, attr, val = updreq
                assert(op != 'event' or attr[0] == '!') # if op=event, attr must begin with '!'
                
                if op == 'event':
                    print("Update chain: Event ({}:{}).{} (param={})".format(ekey[0],ekey[1],attr,val))
                else:
                    print("Update chain: Attribute update: ({}:{}).{} [{}] {}".format(ekey[0],ekey[1],attr,op,val))
                    upd = perform_update(rec, updreq)
                    if upd is None:
                        print("Attribute value wasn't changed.")
                        continue
            
                # Add to the call_queue all functions directly hooked to the attribute/event 
                for hooked_func in self._attr2func.get(attr, []):
                    # If the function is already in the queue, just add updreq to list of updates that triggered it
                    for f,upds in call_queue:
                        if f == hooked_func:
                            upds.append(updreq)
                            break
                    else:
                        call_queue.append((hooked_func, [updreq]))
        
            # Remove set of possible attribute changes of that function from 
            # may_change (they were either already changed or they won't be changed)
            print("Removing {} from may_change.".format(self._func2attr[func]))
            may_change -= set(self._func2attr[func])
            print("New may_change: {}".format(may_change))
        
        print("call_queue loop end")
        assert(len(may_change) == 0)
        
        # Set ts_last_update
        rec['ts_last_update'] = datetime.now(tz=timezone.utc)
        
        print("RECORD: {}: {}".format(ekey, rec))
        
        # Put the record back to the DB and delete call_queue for this ekey
        self.db.put(ekey[0], ekey[1], rec)
        del self._records_being_processed[ekey]

    
    def start(self):
        """Run the main manager functions as a separate thread/process."""
        #self._process = multiprocessing.Process(target=self._main_loop)
        self._process = threading.Thread(target=self._main_loop)
        self._process.start()
    
    def stop(self):
        """Stop the manager."""
        self._request_queue.put(None) # Send None to break the infinite loop
        self._request_queue.join()
        self._process.join()
    
    def _main_loop(self):
        """
        Main processing function.
        
        Run as a separate process. Read update request queue. For each request
        pull corresponding record from database, and call "_process_update_req"
        function.
        
        [During the updating process, the record is "locked" and cannot be
        updated by any other updating process.]
        (TODO: allow asychronous updates even during running update process)
        """
        while True:
            # Get update request from the queue
            # (None object in the queue causes termination of the process, used 
            # to exit the program)
            req = self._request_queue.get()
            if req is None:
                print("UpdateManager: 'None' recevied from main queue - exitting")
                self._request_queue.task_done()
                break
            ekey, attrib_updates = req
            
            print()
            print("UpdateManager: New update request: {},{}".format(
                    ekey, attrib_updates
                  ))
            
            # Call update method
            self._process_update_req(ekey, attrib_updates)
            
            print("UpdateManager: Task done")
            self._request_queue.task_done()
    
        

