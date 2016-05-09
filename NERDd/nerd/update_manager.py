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

# 
# # Processing function specification:
# Watches: set of events / attribute changes this function should be triggered on
# Changes: set of attributes this function may change
# 
# 
# mapping event2func: Mapping of events/attrchanges to function that should be called
# mapping func_watch: Mapping of functions to all events/attrchanges attributes it may be triggered by (= "Watches" param of the function definition)
# 
# # TODO cache results
# def get_all_possbile_changes(event):
#     """
#     Returns all attributes (as a set) that may be changed by a "chain reaction"
#     of changes triggered by given event.
#     
#     Warning: There must be no loops in the sequence of events and triggered 
#     functions.
#     """
#     may_change = set() # Attributes that may be changed
#     funcs_to_call = set(event2func[event])
#     while funcs_to_call:
#         func = funcs_to_call.pop()
#         may_change.add(func.Changes)
#         funcs_to_call.add(event2func[func.Changes])
#     return may_change
# 
# 
# # Temporary storage of records being updated.
# # Mapping of "ekey" to following 3-tuple:
# #     (record [JSON-like object], 
# #      event handler call queue [queue.Queue containing tuples (func, event)],
# #      attributes that may change due to planned handler calls [set],
# #      thread processing the events [Thread] )
# records_being_processed = {}
# 
# def update(ekey, updates=None):
#     """
#     Main event processing function.
#     
#     ...
#     
#     ekey -- Entity type and key (2-tuple)
#     event -- specification of the event (either string or set of changed attributes)
#     updates -- (optional) set of updates to perform on given entity record
#     """
#     # Load record (either from database, or from temporary storage of records 
#     # currently being updated)
#     # TODO locking
#     if ekey not in records_being_processed:
#         # Fetch record from database and store it temporarily together with
#         # a new queue for event handler calls. 
#         records_being_processed[ekey] = (db.get(ekey, create=True), queue.Queue(), set(), None)
#     
#     # rec - the record being processed
#     # call_queue - queue of functions that should be called to update the record
#     #     (queue.Queue of tuples (function,event), where event is description of
#     #     the event which tirggered the function) TODO: what if there's more such events
#     # may_change - set of attributes that may be changed by planned function calls
#     # thread - Thread used to run the updating functions
#     rec, call_queue, may_change, thread = records_being_processed[ekey]
#     
#     # Add to the queue all functions directly hooked to the given event 
#     for func in event2funcs.get(event, [])
#         call_queue.put((func,event))
#     
#     # Compute all attribute changes that may occur due to this event and add 
#     # them to the set of attributes to change
#     may_change |= get_all_possible_changes(event)
#     
#     # ???
#     # processed), create and run it
#     #if thread is None:
#     
#     # Process updates directly given as parameter,
#     # add to call_queue the functions hooked to updated attributes,
#     # and update may_change accordingly
#     ...
#     
#     # Process planned calls in the queue until it's empty
#     while call_queue:
#         assert(not may_change.empty())
#         
#         func,event = call_queue.get()
#         
#         # If the function watches some attributes that may be updated later due 
#         # to expected subsequent events, postpone its call.
#         if may_change & func_watches[func]:  # nonempty intersection of two sets   # TODO may_change -> function creating events from attributes
#             # Put the function call back to the end of the queue
#             call_queue.put((func, event))
#             continue
#             
#         # Call the event handler function.
#         # Set of requested updates of the record should be returned
#         updates = func(ekey, event)
#         
#         # TODO perform the updates
#         print(updates)
#         
#         # Remove set of possible attribute changes of that function from 
#         # may_change (they were either already changed or they won't be changed)
#         may_change -= func_changes[func]
#     
#     assert(may_change.empty())
# 
#     # Put the record back to the DB and delete call_queue for this ekey
#     db.update(ekey, rec)
#     del records_being_processed[ekey]
# 

def print_func(func_or_method):
    try:
        fname = func_or_method.__func__.__qualname__
    except AttributeError:
        fname = func_or_method.__name__
    return func_or_method.__module__ + '.' + fname


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

    def update(self, ekey, attrib_updates):
        """
        Request an update of one or more attributes of an entity record.
        
        Put given request into an internal queue to be processed by some of the
        worker threads.
        
        Arguments:
        ekey -- Entity type and key (2-tuple)
        attrib_updates -- list of 2-tuples (attribute, value) specifying new
            values of attributes that should be updated.
            If an attribute strats with '!' (it's an "event") the value is 
            ignored and the attribute is not stored, but it can still be used
            to trigger some handler function(s).
        """
        # TODO change list of 2-tuples do dict?
        # TODO check data validity
        self._request_queue.put((ekey, attrib_updates))
        
    
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
    
    
    def _process_update_req(self, ekey, attrib_updates):
        """
        Main processing function - update attributes or trigger an event.
        
        May be called asynchronously by NERD modules to request changes in
        attributes of given entity.
        
        Arguments:
        ekey -- Entity type and key (2-tuple)
        attrib_updates -- list of 2-tuples (attribute, value) specifying new
            values of attributes that should be updated.
            If an attribute strats with '!' (it's an "event") the value is 
            ignored and the attribute is not stored, but it can still be used
            to trigger some handler function(s).
        """
        
        # Load record corresponding to the key -- either from database, or from
        # temporary storage of records being currently updated)
        # If record doesn't exist, create new.
        # Also load/create associated auxiliary objects:
        #   call_queue - queue of functions that should be called to update the record
        #     (queue.Queue of tuples (function,event), where event is description of
        #     the event which tirggered the function) TODO: what if there's more such events
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
                attrib_updates.insert(0,('!NEW',None))
            
            # Create auxiliary objects
            call_queue = deque()
            may_change = set()
            # Store it all in the temporary storage
            self._records_being_processed[ekey] = (rec, call_queue, may_change)
        
        
        # Perform requested updates.
        for attr,val in attrib_updates:
            if attr[0] == '!':
                print("Initial update: Event ({}:{}).{}".format(ekey[0],ekey[1],attr))
            else:
                print("Initial update: New attribute value: ({}:{}).{} = {}".format(ekey[0],ekey[1],attr,val))
                rec[attr] = val
            
            # Add to the call_queue all functions directly hooked to the attribute/event 
            for func in self._attr2func.get(attr, []):
                # If the function is already in the queue, just add attr to list of attrs that triggered it
                for f2,attrs in call_queue:
                    if f2 == func:
                        if attr not in attrs: # don't duplicate attrs
                            attrs.append(attr)
                        break
                else:
                    call_queue.append((func, [attr]))
        
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
            if loop_counter > 100:
                print("WARNING: Too many iterations when updating {}, something went wrong! Update chain stopped.".format(ekey))
                break
            
            func, attrs = call_queue.popleft()
            
            # If the function watches some attributes that may be updated later due 
            # to expected subsequent events, postpone its call.
            if may_change & self._func_triggers[func]:  # nonempty intersection of two sets
                # Put the function call back to the end of the queue
                print("call_queue: Postponing call of {}({})".format(print_func(func), attrs))
                call_queue.append((func, attrs))
                continue
            
            # Call the event handler function.
            # Set of requested updates of the record should be returned
            print("Calling: {}({}, ..., {})".format(print_func(func), ekey, attrs))
            updates = func(ekey, rec, attrs)
            if updates is None:
                updates = {}
            
            # TODO perform the updates instead of prints
            for attr,val in updates.items():
                if attr[0] == '!':
                    print("Update chain: Event ({}:{}).{}".format(ekey[0],ekey[1],attr))
                else:
                    print("Update chain: New attribute value: ({}:{}).{} = {}".format(ekey[0],ekey[1],attr,val))
                    rec[attr] = val
            
                # Add to the call_queue all functions directly hooked to the updated attributes 
                for f in self._attr2func.get(attr, []):
                    # If the function is already in the queue, just add attr to list of attrs that triggered it
                    for f2,attrs in call_queue:
                        if f2 == f:
                            if attr not in attrs: # don't duplicate attrs
                                attrs.append(attr)
                            break
                    else:
                        call_queue.append((f, [attr]))
            
            # Remove set of possible attribute changes of that function from 
            # may_change (they were either already changed or they won't be changed)
            print("Removing {} from may_change.".format(self._func2attr[func]))
            may_change -= set(self._func2attr[func])
            print("New may_change: {}".format(may_change))
        
        print("call_queue loop end")
        assert(len(may_change) == 0)
    
        # Put the record back to the DB and delete call_queue for this ekey
        self.db.update(ekey[0], ekey[1], rec)
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
                print("UpdateManager: None recevied - exitting")
                self._request_queue.task_done()
                break
            ekey, attrib_updates = req
            
            print()
            print("UpdateManager: New request update: {},{}".format(
                    ekey, attrib_updates
                  ))
            
            # Call update method
            self._process_update_req(ekey, attrib_updates)
            
            print("UpdateManager: Task done")
            self._request_queue.task_done()
    
        

