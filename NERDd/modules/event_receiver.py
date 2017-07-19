"""
NERD module for receiving IDEA messages about detected security events.

Fetches IDEA messages dropped to a specified directory and updates entity 
records accordingly.
"""

from core.basemodule import NERDModule
import g

from threading import Thread
import time
import random
import os
import sys
import socket
import json
import logging
import datetime

from common.utils import parse_rfc_time

MAX_QUEUE_SIZE = 1000 # Maximal size of UpdateManager's request queue
                     # (when number of pending requests exceeds this value,
                     # reading of events is paused for a while)


running_flag = True # read_dir function terminates when this is set to False

logger = logging.getLogger('EventReceiver')

def read_dir(path):
    """
    Indefinitely watches given directory for new files. Each incoming file is
    read, parsed as JSON, and yield to caller (function behaves as a generator).
    """

    class NamedFile(object):
        """ Wrapper class for file objects, which allows and tracks filename
            changes.
        """
    
        def __init__(self, pth, name, fd=None):
            self.name = name
            self.path = pth
            if fd:
                self.f = os.fdopen(fd, "w+b")
            else:
                self.f = None
    
    
        def __str__(self):
            return "%s(%s, %s)" % (type(self).__name__, self.path, self.name)
    
    
        def get_path(self, basepath=None, name=None):
            return os.path.join(basepath or self.path, name or self.name)
    
    
        def open(self, mode):
            return open(self.get_path(), mode)
    
    
        def moveto(self, destpath):
            os.rename(self.get_path(), self.get_path(basepath=destpath))
            self.path = destpath
    
    
        def rename(self, newname):
            os.rename(self.get_path(), self.get_path(name=newname))
            self.name = newname
    
    
        def remove(self):
            os.remove(self.get_path())
    
    
    class SafeDir(object):
        """ Maildir like directory for safe file exchange.
            - Producers are expected to drop files into "temp" under globally unique
              filename and rename it into "incoming" atomically (newfile method)
            - Workers pick files in "incoming", rename them into "temp",
              do whatever they want, and either discard them or move into
              "errors" directory
        """
    
        def __init__(self, p):
            self.path = self._ensure_path(p)
            self.incoming = self._ensure_path(os.path.join(self.path, "incoming"))
            self.errors = self._ensure_path(os.path.join(self.path, "errors-worker"))
            self.temp = self._ensure_path(os.path.join(self.path, "temp-worker"))
            self.hostname = socket.gethostname()
            self.pid = os.getpid()
    
    
        def __str__(self):
            return "%s(%s)" % (type(self).__name__, self.path)
    
    
        def _ensure_path(self, p):
            try:
                os.mkdir(p)
            except OSError:
                if not os.path.isdir(p):
                    raise
            return p
    
    
        def get_incoming(self):
            return [NamedFile(self.incoming, n) for n in os.listdir(self.incoming)]
    
    def get_dir_list(sdir, owait_poll_time, owait_timeout, nfchunk):
        nflist = sdir.get_incoming()
        timeout = time.time() + owait_timeout
        while len(nflist)<nfchunk and time.time()<timeout and running_flag:
            time.sleep(owait_poll_time)
            nflist = sdir.get_incoming()
        return nflist

    #######
    # End of definitions of auxiliary classes and functions.
    # Body of read_dir function follows ...

    sdir = SafeDir(path)
    poll_time = 1 #config.get("poll_time", 5)
    owait_poll_time = 1 #config.get("owait_poll_time", 1)
    owait_timeout = poll_time #config.get("owait_timeout", poll_time)
    done_dir = None #config.get("done_dir", None)
    nfchunk = 100 # min number of files read at once by get_dir_list
    oneshot = False

    while running_flag:
        nflist = get_dir_list(sdir, owait_poll_time, owait_timeout, nfchunk)
        while running_flag and not nflist:
            # No new files, wait and try again
            time.sleep(poll_time)
            nflist = get_dir_list(sdir, owait_poll_time, owait_timeout, nfchunk)

        #nfindex = 0
        #count_ok = count_err = count_local = 0
        for nf in nflist:
            if not running_flag:
                break
            # prepare event array from files
            try:
                nf.moveto(sdir.temp)
            except Exception:
                continue    # Silently go to next filename, somebody else might have interfered
            try:
                # Read file and yield record
                with nf.open("r") as fd:
                    data = fd.read()
                event = json.loads(data)
                yield (data,event)
                # Cleanup
                if done_dir:
                    nf.moveto(done_dir)
                else:
                    nf.remove()
            except Exception as e:
                logger.exception("Exception during loading event, file={}".format(str(nf)))
                nf.moveto(sdir.errors)
                #count_local += 1


##############################################################################
# Test of read_dir

if __name__ == "__main__":
    path = "./drop_events_here" 
    print("Watching for files in {}".format(os.path.join(path, "incoming")))
    for event in read_dir(path):
        print("------------------------------------------------------------")
        print(json.dumps(event, indent=2))
        


##############################################################################
# Main module code

class EventReceiver(NERDModule):
    """
    Receiver of security events. Receives events as IDEA files in given directory.
    """
    def __init__(self):
        self.log = logging.getLogger("EventReceiver")
        self._drop_path = g.config.get('warden_filer_path')
    
    def start(self):
        """
        Run the module - used to run own thread if needed.
        
        Called after initialization, may be used to create and run a separate
        thread if needed by the module. Do nothing unless overriden.
        """
        self._recv_thread = Thread(target=self._receive_events)
        self._recv_thread.daemon = True
        self._recv_thread.start()
    
    def stop(self):
        """
        Stop the module - used to stop own thread.
        
        Called before program exit, may be used to finalize and stop the 
        separate thread if it is used. Do nothing unless overriden.
        """
        global running_flag
        running_flag = False
        self.log.info("Going to exit, waiting for event-reading thread ...")
        self._recv_thread.join()
        self.log.info("Exitting.")
    
    def _receive_events(self):
        # Infinite loop reading events as files in given directory
        # (termiated by setting running_flag to False)
        for (rawdata, event) in read_dir(self._drop_path):
            # Store the event to Event DB
            #g.eventdb.put(rawdata) # pass as string for old filesystem-database
            g.eventdb.put(event) # pass as parsed JSON for PSQL version
            try:
                if "Test" in event["Category"]:
                    continue # Ignore testing messages
                for src in event.get("Source", []):
                    for ipv4 in src.get("IP4", []):
                        # TODO check IP address validity

                        self.log.debug("EventReceiver: Updating IPv4 record {}".format(ipv4))
                        cat = '+'.join(event["Category"]).replace('.', '')
                        # Parse and reformat detect time
                        detect_time = parse_rfc_time(event["DetectTime"]) # Parse DetectTime
                        date = detect_time.strftime("%Y-%m-%d") # Get date as a string
                        
                        # Get end time of event
                        if "CeaseTime" in event:
                            end_time = parse_rfc_time(event["CeaseTime"])
                        elif "WinEndTime" in event:
                            end_time = parse_rfc_time(event["WinEndTime"])
                        elif "EventTime" in event:
                            end_time = parse_rfc_time(event["EventTime"])
                        else:
                            end_time = detect_time

                        node = event["Node"][-1]["Name"]
                        
                        g.um.update(
                            ('ip', ipv4),
                            [
                                ('array_upsert', 'events', ({'date': date, 'node': node, 'cat': cat}, [('add', 'n', 1)])),
                                ('add', 'events_meta.total', 1),
                                ('set', 'ts_last_event', end_time),
                            ]
                        )
                        
                    for ipv6 in src.get("IP6", []):
                        self.log.debug("IPv6 address in Source found - skipping since IPv6 is not implemented yet.")# The record follows:\n{}".format(str(event)), file=sys.stderr)
            except Exception as e:
                self.log.error("ERROR in parsing event: {}".format(str(e)))
                pass
            
            # If there are already too much requests queued, wait a while
            #print("***** QUEUE SIZE: {} *****".format(g.um.get_queue_size()))
            while g.um.get_queue_size() >= MAX_QUEUE_SIZE:
                time.sleep(0.2)
            
