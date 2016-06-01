#!/usr/bin/env python3

import sys
from time import sleep

import core.config
#import core.db
import core.mongodb
import core.update_manager
import modules.base
# TODO load everything automatically (or everything specified in config)
#import modules.test_module
import modules.event_receiver
import modules.dns
import modules.geolocation

############

DEFAULT_CONFIG_FILE = "./nerd.cfg"

############


if __name__ == "__main__":

    print("Main: Start")
    
    # Load configuration
    # TODO parse arguments using ArgParse
    if len(sys.argv) >= 2:
        cfg_file = sys.argv[1]
    else:
        cfg_file = DEFAULT_CONFIG_FILE
    config = core.config.read_config(cfg_file)
    
    # Create main NERDd components
    #db = core.db.EntityDatabase({})
    db = core.mongodb.MongoEntityDatabase(config)
    update_manager = core.update_manager.UpdateManager(config, db)
    
    # Instantiate modules
    # TODO create all modules automatically (loop over all modules.* and find all objects derived from NERDModule)
    module_list = [
        modules.event_receiver.EventReceiver(config, update_manager),
        #modules.test_module.TestModule(config, update_manager),
        modules.dns.DNSResolver(config, update_manager),
        modules.geolocation.Geolocation(config, update_manager),
    ]
    
    # Run update manager thread/process
    print("Main: Starting UpdateManager")
    update_manager.start()
    
    # Run modules that have their own threads/processes
    # (if they don't have, start() should do nothing)
    for module in module_list:
        module.start()
    
    ####
    
    #sleep(1)
    
    # Simulate some update requests
#     update_manager.update(('ip', '195.113.228.57'), [('set','X',123)])
#     update_manager.update(('ip', '195.113.144.230'), [('event','!sleep',1)])
#     update_manager.update(('ip', '147.229.9.23'), [('set','B',1),('set','X',321)])
#     sleep(2)
#     update_manager.update(('ip', '195.113.228.57'), [('set','B',8),('set','X',5555)])
    
    print()
    print("-------------------------------------------------------------------")
    print("Reading events from "+str(config.get('warden_filer_path'))+"/incoming")
    print()
    print("*** Enter anything to quit ***")
    try:
        input()
    except KeyboardInterrupt:
        pass
    
    print("Main: Stopping running components")
    for module in module_list:
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





