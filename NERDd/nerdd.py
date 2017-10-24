#!/usr/bin/env python3

import sys
import os
from time import sleep
import logging
import threading
import signal

# Add to path the "one directory above the current file location" to find modules from "common"
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')))

DEFAULT_CONFIG_FILE = "../etc/nerdd.yml"


################################################
# Initialize logging mechanism

LOGFORMAT = "%(asctime)-15s,%(threadName)s,%(name)s,[%(levelname)s] %(message)s"
LOGDATEFORMAT = "%Y-%m-%dT%H:%M:%S"

logging.basicConfig(level=logging.INFO, format=LOGFORMAT, datefmt=LOGDATEFORMAT)
log = logging.getLogger()

# Disable INFO and DEBUG messages from requests.urllib3 library, wihch is used by some modules
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)

log.info("***** NERDd start *****")

################################################
# Load core components

import common.config
import common.eventdb_psql
import core.mongodb
import core.update_manager
import core.scheduler

################################################
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


################################################
# Create instances of core components
# Save them to "g" ("global") module so they can be easily accessed from everywhere

import g
g.config = config
g.scheduler = core.scheduler.Scheduler()
g.db = core.mongodb.MongoEntityDatabase(config)
g.eventdb = common.eventdb_psql.PSQLEventDatabase(config)
g.um = core.update_manager.UpdateManager(config, g.db)


################################################
# Load all NERD modules
# (all modules can now use core components in "g")

# TODO load all modules automatically (or just modules specified in config)
#import modules.test_module
import modules.event_receiver
import modules.updater
import modules.cleaner
import modules.dns
import modules.geolocation
import modules.dnsbl
import modules.local_bl
import modules.shodan
import modules.eml_asn_rank
import modules.refresher
import modules.event_counter
import modules.hostname
import modules.caida_as_class
import modules.event_type_counter
import modules.tags
import modules.reputation
import modules.whois

# Instantiate modules
# TODO create all modules automatically (loop over all modules.* and find all objects derived from NERDModule)
#  or take if from configuration
module_list = [
    modules.event_receiver.EventReceiver(),
    modules.updater.Updater(),
    modules.cleaner.Cleaner(),
    #modules.refresher.Refresher(),
    modules.event_counter.EventCounter(),
    modules.dns.DNSResolver(),
    modules.geolocation.Geolocation(),
    modules.whois.WhoIS(),
    modules.dnsbl.DNSBLResolver(),
    modules.local_bl.LocalBlacklist(),
    modules.shodan.Shodan(),
    modules.eml_asn_rank.EML_ASN_rank(),
    modules.reputation.Reputation(),
    modules.hostname.HostnameClass(),
    modules.caida_as_class.CaidaASclass(),
    modules.event_type_counter.EventTypeCounter(),
    modules.tags.Tags(),
]


# Lock used to control when the program stops.
g.daemon_stop_lock = threading.Lock()
g.daemon_stop_lock.acquire()

# Signal handler releasing the lock on SIGINT or SIGTERM
def sigint_handler(signum, frame):
    log.debug("Signal {} received, stopping daemon".format({signal.SIGINT: "SIGINT", signal.SIGTERM: "SIGTERM"}.get(signum, signum)))
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

# Run update manager thread/process
log.info("***** Initialization completed, starting all modules *****")
g.um.start()
g.running = True

# Run modules that have their own threads/processes
# (if they don't, the start() should do nothing)
for module in module_list:
    module.start()

# Run scheduler
g.scheduler.start()


print("-------------------------------------------------------------------")
print("Reading events from "+str(config.get('warden_filer_path'))+"/incoming")
print()
print("*** Press Ctrl-C to quit ***")

# Wait until someone wants to stop the program by releasing this Lock.
# It may be a user by pressing Ctrl-C or some program module.
# (try to acquire the lock again, effectively waiting until it's released by signal handler or another thread)
g.daemon_stop_lock.acquire()

# yappi.stop()
# log.info("Profiler end")
# yappi.get_func_stats().save('profile_output', type="pstat")

################################################
# Finalization & cleanup

signal.signal(signal.SIGINT, signal.SIG_DFL)
signal.signal(signal.SIGTERM, signal.SIG_DFL)
signal.signal(signal.SIGABRT, signal.SIG_DFL)

log.info("Stopping running components ...")
g.running = False
g.scheduler.stop()
for module in module_list:
    module.stop()
g.um.stop()

log.info("***** Finished, main thread exitting. *****")
logging.shutdown()
