"""Abstract class for NERD module"""

# Each handler function should have the following prototype:
#
# def <name>(self, ekey, rec, updates):
#
# Arguments:
# ekey -- two-tuple of entity type and key, e.g. ('ip', '192.0.2.42')
# rec -- record currently assigned to the key
# updates -- list of all attributes whose update triggerd this call and their 
#   new values (or events and their parameters) as a list of 2-tuples:
#   [(attr, val), (!event, param), ...]
# 
# Returns:
# List of update requests, i.e. 3-tuples describing requested attribute updates
# or events (for details, see comment at the beginning of update_manager.py).

class NERDModule:
    """
    Abstract class for NERD modules.
    """
    def __init__(self, update_manager):
        pass
    
    def start(self):
        """
        Run the module - used to run own thread if needed.
        
        Called after initialization, may be used to create and run a separate
        thread if needed by the module. Do nothing unless overriden.
        """
        pass
    
    def stop(self):
        """
        Stop the module - used to stop own thread.
        
        Called before program exit, may be used to finalize and stop the 
        separate thread if it is used. Do nothing unless overriden.
        """
        pass
    