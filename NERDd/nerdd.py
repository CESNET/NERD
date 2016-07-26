#!/usr/bin/env python3

import sys
from time import sleep
import logging

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
import modules.dnsbl
import core.eventdb

############

DEFAULT_CONFIG_FILE = "./nerd.cfg"

LOGFORMAT = "%(asctime)-15s,%(threadName)s,%(name)s,[%(levelname)s],%(message)s"
LOGDATEFORMAT = "%Y-%m-%dT%H:%M:%S"

############


if __name__ == "__main__":

    # Initialize logging mechanism
    logging.basicConfig(level=logging.INFO, format=LOGFORMAT, datefmt=LOGDATEFORMAT)
    logger = logging.getLogger()
    
    logger.info("NERDd start")
    
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
    eventdb = core.eventdb.FileEventDatabase(config)
    update_manager = core.update_manager.UpdateManager(config, db)
    
    # Instantiate modules
    # TODO create all modules automatically (loop over all modules.* and find all objects derived from NERDModule)
    #  or take if from configuration
    module_list = [
        modules.event_receiver.EventReceiver(config, update_manager, eventdb),
        #modules.test_module.TestModule(config, update_manager),
        modules.dns.DNSResolver(config, update_manager),
        modules.geolocation.Geolocation(config, update_manager),
        modules.dnsbl.DNSBLResolver(config, update_manager),
    ]
    
    # Run update manager thread/process
    logger.info("Starting UpdateManager")
    update_manager.start()
    
    # Run modules that have their own threads/processes
    # (if they don't, the start() should do nothing)
    for module in module_list:
        module.start()
    
    print("-------------------------------------------------------------------")
    print("Reading events from "+str(config.get('warden_filer_path'))+"/incoming")
    print()
    print("*** Enter anything to quit ***")
    try:
        input()
    except KeyboardInterrupt:
        pass
    
    logger.info("Stopping running components ...")
    for module in module_list:
        module.stop()
    update_manager.stop()
    
    logger.info("Finished, main thread exitting.")
    logging.shutdown()

