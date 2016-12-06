#!/usr/bin/env python3

import sys
import os
from time import sleep
import logging

# Add to path the "one directory above the current file location"
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')))
import common.config
#import core.db
import core.mongodb
import core.update_manager
import modules.base
# TODO load everything automatically (or everything specified in config)
#import modules.test_module
import modules.event_receiver
import modules.dns
import modules.geolocation
import modules.asn
import modules.dnsbl
import modules.local_bl
import modules.shodan
import modules.refresher
import common.eventdb_psql

############

DEFAULT_CONFIG_FILE = "../etc/nerdd.cfg"

LOGFORMAT = "%(asctime)-15s,%(threadName)s,%(name)s,[%(levelname)s] %(message)s"
LOGDATEFORMAT = "%Y-%m-%dT%H:%M:%S"

############


if __name__ == "__main__":

    # Initialize logging mechanism
    logging.basicConfig(level=logging.INFO, format=LOGFORMAT, datefmt=LOGDATEFORMAT)
    log = logging.getLogger()
    
    log.info("NERDd start")
    
    # Load configuration
    # TODO parse arguments using ArgParse
    if len(sys.argv) >= 2:
        cfg_file = sys.argv[1]
    else:
        cfg_file = DEFAULT_CONFIG_FILE
    # Read NERDd-specific config (nerdd.cfg)
    log.info("Loading config file {}".format(cfg_file))
    config = common.config.read_config(cfg_file)
    # Read common config (nerd.cfg) and combine them together
    common_cfg_file = os.path.join(os.path.dirname(os.path.abspath(cfg_file)), config.get('common_config'))
    log.info("Loading config file {}".format(common_cfg_file))
    config.update(common.config.read_config(common_cfg_file))
    
    # Disable INFO and DEBUG messages from requests.urllib3 library, wihch is used by some modules
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)

    # Create main NERDd components
    #db = core.db.EntityDatabase({})
    db = core.mongodb.MongoEntityDatabase(config)
    #eventdb = common.eventdb.FileEventDatabase(config)
    eventdb = common.eventdb_psql.PSQLEventDatabase(config)
    update_manager = core.update_manager.UpdateManager(config, db)
    
    # Instantiate modules
    # TODO create all modules automatically (loop over all modules.* and find all objects derived from NERDModule)
    #  or take if from configuration
    module_list = [
        modules.event_receiver.EventReceiver(config, update_manager, eventdb),
        #modules.refresher.Refresher(config, update_manager, db),
        #modules.test_module.TestModule(config, update_manager),
        modules.dns.DNSResolver(config, update_manager),
        modules.geolocation.Geolocation(config, update_manager),
        modules.asn.ASN(config, update_manager),
        modules.dnsbl.DNSBLResolver(config, update_manager),
        modules.local_bl.LocalBlacklist(config, update_manager),
        modules.shodan.Shodan(config, update_manager),
    ]
    
    # Run update manager thread/process
    log.info("Starting UpdateManager")
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
    
    log.info("Stopping running components ...")
    for module in module_list:
        module.stop()
    update_manager.stop()
    
    log.info("Finished, main thread exitting.")
    logging.shutdown()

