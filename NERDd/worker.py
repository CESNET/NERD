#!/usr/bin/env python3

import sys
import os
from time import sleep
import logging
import threading
import signal

# EventCountLogger - count number of events across multiple processes using shared counters in Redis
from event_count_logger import EventCountLogger

def main(cfg_file, process_index):

    ################################################
    # Initialize logging mechanism
    
    LOGFORMAT = "%(asctime)-15s,%(threadName)s,%(name)s,[%(levelname)s] %(message)s"
    LOGDATEFORMAT = "%Y-%m-%dT%H:%M:%S"
    
    logging.basicConfig(level=logging.INFO, format=LOGFORMAT, datefmt=LOGDATEFORMAT)
    log = logging.getLogger()
    
    # Disable INFO and DEBUG messages from requests.urllib3 library, wihch is used by some modules
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    
    ################################################
    # Load core components
    
    # Add to path the "one directory above the current file location" to find modules from "common"
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')))
    
    import common.config
    import common.eventdb_mentat
    import core.mongodb
    import core.update_manager
    import core.scheduler
    
    ################################################
    # Load configuration
    
    # Read NERDd-specific config (nerdd.yml)
    log.debug("Loading config file {}".format(cfg_file))
    config = common.config.read_config(cfg_file)

    config_base_path = os.path.dirname(os.path.abspath(cfg_file))

    # Read common config (nerd.cfg) and combine them together
    common_cfg_file = os.path.join(config_base_path, config.get('common_config'))
    log.debug("Loading config file {}".format(common_cfg_file))
    config.update(common.config.read_config(common_cfg_file))

    # Read event_logging config (and store it separately)
    ecl_config_file = os.path.join(config_base_path, config.get('event_logging_config'))
    log.debug("Loading config file {}".format(ecl_config_file))
    ecl_config = common.config.read_config(ecl_config_file)

    # Get number of processes from config
    num_processes = config.get('worker_processes')

    assert (isinstance(num_processes, int) and num_processes > 0), "Number of processes ('num_processes' in config) must be a positive integer"
    assert (isinstance(process_index, int) and process_index >= 0), "Process index can't be negative"
    assert (process_index < num_processes), "Process index must be less than total number of processes"

    log.info("***** NERD worker {}/{} start *****".format(process_index, num_processes))

    ################################################
    # Create instances of core components
    # Save them to "g" ("global") module so they can be easily accessed from everywhere
    
    import g
    g.config = config
    g.config_base_path = config_base_path
    g.ecl_config = ecl_config
    g.ecl_config_file = ecl_config_file
    g.ecl = EventCountLogger(g.ecl_config.get("groups"), g.ecl_config.get("redis"))
    g.scheduler = core.scheduler.Scheduler()
    g.db = core.mongodb.MongoEntityDatabase(config)
    g.um = core.update_manager.UpdateManager(config, g.db, process_index, num_processes)
    
    # EventDB may be local PSQL (default), external Mentat instance or None
    # (commented out, it's currently only used in warden_receiver, which not a part of worker)
    # EVENTDB_TYPE = config.get('eventdb', 'psql')
    # if EVENTDB_TYPE == 'psql':
    #     import common.eventdb_psql
    #     g.eventdb = common.eventdb_psql.PSQLEventDatabase(config)
    # elif EVENTDB_TYPE == 'mentat':
    #     import common.eventdb_mentat
    #     g.eventdb = common.eventdb_mentat.MentatEventDBProxy(config)
    # else:
    #     class DummyEventDB:
    #         def get(*args, **kwargs):
    #             return []
    #         def put(*args, **kwargs):
    #             return None
    #     g.eventdb = DummyEventDB()
    #     log.error("Unknown 'eventdb' configured, events won't be stored")

    
    ################################################
    # Load all plug-in modules
    # (all modules can now use core components in "g")
    
    # TODO load all modules automatically (or just modules specified in config)
    import modules.update_planner
    import modules.cleaner
    import modules.dns
    import modules.geolocation
    import modules.dnsbl
    import modules.redis_bl
    import modules.shodan
    import modules.eml_asn_rank
    import modules.event_counter
    import modules.hostname
    import modules.caida_as_class
    import modules.bgp_rank
    import modules.event_type_counter
    import modules.tags
    import modules.reputation
    import modules.whois
    import modules.passive_dns
    import modules.fmp
    import modules.reserved_ip
    import modules.ttl_updater
    
    # Instantiate modules
    # TODO create all modules automatically (loop over all modules.* and find all objects derived from NERDModule)
    #  or take if from configuration
    module_list = [
        modules.update_planner.UpdatePlanner(),
        modules.cleaner.Cleaner(),
        modules.event_counter.EventCounter(),
        modules.dns.DNSResolver(),
        modules.geolocation.Geolocation(),
        modules.whois.WhoIS(),
        modules.dnsbl.DNSBLResolver(),
        modules.redis_bl.RedisBlacklist(),
        modules.shodan.Shodan(),
        modules.eml_asn_rank.EML_ASN_rank(),
        modules.reputation.Reputation(),
        modules.hostname.HostnameClass(),
        modules.caida_as_class.CaidaASclass(),
        modules.bgp_rank.CIRCL_BGPRank(),
        modules.event_type_counter.EventTypeCounter(),
        modules.tags.Tags(),
        modules.passive_dns.PassiveDNSResolver(),
        modules.fmp.FMP(),
        modules.reserved_ip.ReservedIPTags(),
        modules.ttl_updater.TTLUpdater(),
    ]
    
    
    # Lock used to control when the program stops.
    g.daemon_stop_lock = threading.Lock()
    g.daemon_stop_lock.acquire()
    
    # Signal handler releasing the lock on SIGINT or SIGTERM
    def sigint_handler(signum, frame):
        log.debug("Signal {} received, stopping worker".format({signal.SIGINT: "SIGINT", signal.SIGTERM: "SIGTERM"}.get(signum, signum)))
        g.daemon_stop_lock.release()
    signal.signal(signal.SIGINT, sigint_handler)
    signal.signal(signal.SIGTERM, sigint_handler)
    signal.signal(signal.SIGABRT, sigint_handler)
    
    ################################################
    # Initialization completed, run ...
    
    # import yappi
    # # yappi.set_clock_type("Wall")
    # log.info("Profiler start")
    # yappi.start()
    
    # Run update manager thread
    log.info("***** Initialization completed, starting all modules *****")
    g.running = True
    
    # Run modules that have their own threads (TODO: are there any?)
    # (if they don't, the start() should do nothing)
    for module in module_list:
        module.start()
    
    g.um.start()
    
    # Run scheduler
    g.scheduler.start()
    
    
    # Wait until someone wants to stop the program by releasing this Lock.
    # It may be a user by pressing Ctrl-C or some program module.
    # (try to acquire the lock again, effectively waiting until it's released by signal handler or another thread)
    g.daemon_stop_lock.acquire()
    
    # yappi.stop()
    # log.info("Profiler end")
    # yappi.get_func_stats().save('profile_output', type="pstat")
    
    ################################################
    # Finalization & cleanup
    
    # Set signal handlers back to their defaults, so the second Ctrl-C closes the program immediately
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    signal.signal(signal.SIGABRT, signal.SIG_DFL)
    
    log.info("Stopping running components ...")
    g.running = False
    g.scheduler.stop()
    g.um.stop()
    for module in module_list:
        module.stop()
    
    log.info("***** Finished, main thread exiting. *****")
    logging.shutdown()


if __name__ == "__main__":
    import argparse

    # Parse arguments
    parser = argparse.ArgumentParser(
        prog="worker.py",
        description="Main worker process of the NERD system. There are usually multiple workers running in parallel."
    )
    parser.add_argument('process_index', metavar='INDEX', type=int,
        help='Index of the worker process')
    parser.add_argument('-c', '--config', metavar='FILENAME', default='/etc/nerd/nerdd.yml',
        help='Path to configuration file (default: /etc/nerd/nerdd.yml)')
    args = parser.parse_args()

    # Run main code
    main(args.config, args.process_index)
