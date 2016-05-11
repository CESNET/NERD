#!/usr/bin/env python3

from time import sleep

import nerd.db
import nerd.module
import nerd.update_manager
import nerd.test_module

############

if __name__ == "__main__":

    print("Main: Start")
    
    # Create main NERDd components
    db = nerd.db.EntityDatabase({})
    update_manager = nerd.update_manager.UpdateManager(db)
    
    # Instantiate modules
    modules = [
        nerd.test_module.TestModule(update_manager),
    ]
    
    # Run update manager thread/process
    print("Main: Starting UpdateManager")
    update_manager.start()
    
    # Run modules that have their own threads/processes
    # (if they don't have, start() should do nothing)
    for module in modules:
        module.start()
    
    ####
    
    sleep(1)
    
    # Simulate some update requests
    update_manager.update(('ip', '195.113.228.57'), [('set','X',123)])
    update_manager.update(('ip', '195.113.144.230'), [('event','!sleep',2)])
    update_manager.update(('ip', '147.229.9.23'), [('set','B',1),('set','X',321)])
    sleep(5)
    update_manager.update(('ip', '195.113.228.57'), [('set','B',8),('set','X',5555)])
    
    sleep(5)
    
    print("Main: Stopping running components")
    for module in modules:
        module.stop()
    update_manager.stop()
    
    
    # Print records from DB
    print("Main: Finished.")
    print(db.get('ip', '195.113.228.57'))
    print(db.get('ip', '195.113.144.230'))
    print(db.get('ip', '147.229.9.23'))

    
#     while len(threads) > 0:
#         try:
#             # Join all threads using a timeout so it doesn't block
#             # Filter out threads which have been joined or are None
#             threads = filter(lambda (m,t): t.isAlive(), threads)
#             for m,t in threads:
#                 t.join(1)
#         except KeyboardInterrupt:
#             if second_interrupt:
#                 print("Second interrupt caught, stopping immediately")
#                 break
#             # Tell to all live threads to stop
#             print("KeyboardInterrupt, stopping running modules ...")
#             for m,t in threads:
#                 if t.isAlive() and hasattr(m, 'stop'):
#                     m.stop()
#             second_interrupt = True
#     
    print("Main thread exitting")





