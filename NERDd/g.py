# Empty module for storage of program-global variables - references to 
# configuration and instances of core components.
# Most of the contents of this module are set at run-time during initialization.

# Global flag telling if the daemon is running
running = False

# Enable performance debugging (must be manually set to True here; TODO: move to config)
# (used in core/update_manager.py and modules/dnsbl.py)
# May result in many log messages, only enable if you have issues with performance (task processing takes too long)
DEBUG_PERFORMANCE = False
