"""
NERD module for receiving IDEA messages about detected security events.

Fetches IDEA messages dropped to a specified directory and updates entity 
records accordingly.
"""

if __name__ != "__main__":
    # import only when not runnning standalone (i.e. testing)
    from .base import NERDModule

from threading import Thread
import time
import random
import os
import sys
import socket
import json
import logging

MAX_QUEUE_SIZE = 100 # Maximal size of UpdateManager's request queue
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
    
    
    #     def _get_new_name(self, device=0, inode=0):
    #         return "%s.%d.%f.%d.%d.idea" % (
    #             self.hostname, self.pid, time.time(), device, inode)
    # 
    # 
    #     def newfile(self):
    #         """ Creates file with unique filename within this SafeDir.
    #             - hostname takes care of network filesystems
    #             - pid distinguishes two daemons on one machine
    #               (we are not multithreaded, so this is enough)
    #             - time in best precision supported narrows window within process
    #             - device/inode makes file unique on particular filesystem
    #             In fact, device/inode is itself enough for uniqueness, however
    #             if we mandate wider format, users can use simpler form with
    #             random numbers instead of device/inode, if they choose to,
    #             and it will still ensure reasonable uniqueness.
    #         """
    # 
    #         # Note: this simpler device/inode algorithm replaces original,
    #         #       which checked uniqueness among all directories by atomic
    #         #       links.
    # 
    #         # First find and open name unique within temp
    #         tmpname = None
    #         while not tmpname:
    #             tmpname = self._get_new_name()
    #             try:
    #                 fd = os.open(os.path.join(self.temp, tmpname), os.O_CREAT | os.O_RDWR | os.O_EXCL)
    #             except OSError as e:
    #                 if e.errno != errno.EEXIST:
    #                     raise   # other errors than duplicates should get noticed
    #                 tmpname = None
    #         # Now we know device/inode, rename to make unique within system
    #         stat = os.fstat(fd)
    #         newname = self._get_new_name(stat.st_dev, stat.st_ino)
    #         nf = NamedFile(self.temp, tmpname, fd)
    #         nf.rename(newname)
    #         return nf
    
    
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
    def __init__(self, config, update_manager, eventdb):
        self.log = logging.getLogger("EventReceiver")
        self._um = update_manager
        self._drop_path = config.get('warden_filer_path')
        if not self._drop_path:
            raise RuntimeError("EventReceiver: Missing configuration: warden_filer_path not specified.")
        self._eventdb = eventdb
    
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
            store_event = False
            try:
                for src in event.get("Source", []):
                    for ipv4 in src.get("IP4", []):
                        store_event = True

                        # TODO check IP address validity

                        self.log.debug("EventReceiver: Updating IPv4 record {}".format(ipv4))
                        cat = '+'.join(event["Category"]).replace('.', '')
                        # TODO parse and reformat time, solve timezones
                        # (but IDEA defines dates to conform RFC3339 but there is no easy (i.e. built-in) way to parse it in Python, maybe in Py3.6,
                        #  according to http://bugs.python.org/issue15873)
                        date = event["DetectTime"][:10]
                        node = event["Node"][-1]["Name"]
                        key_cat = 'events.'+date+'.'+cat
                        key_node = 'events.'+date+'.nodes'
                        self._um.update(
                            ('ip', ipv4),
                            [
                                ('add', key_cat, 1),
                                ('add_to_set', key_node, node),
                                ('add', 'events.total', 1),
                            ]
                        )
                        
                    for ipv6 in src.get("IP6", []):
                        self.log.debug("IPv6 address in Source found - skipping since IPv6 is not implemented yet.")# The record follows:\n{}".format(str(event)), file=sys.stderr)
            except Exception as e:
                self.log.error("ERROR in parsing event: {}".format(str(e)))
                pass
            
            if store_event:
                #print("------------------------------------------------------------")
                #print("EventReceiver: Loaded event:")
                #print(json.dumps(event))
                #print(rawdata)
                #print("** EventReceiver: skipped / enqueued sources: {:6d} / {:6d}".format(skipped, enqueued))
                
                # Also store the event to the event DB
                try:
                    self._eventdb.put(rawdata)
                except Exception as e:
                    self.log.error("ERROR storing event:", e)
            
            # If there are already too much requests queued, wait a while
            #print("***** QUEUE SIZE: {} *****".format(self._um.get_queue_size()))
            while self._um.get_queue_size() > MAX_QUEUE_SIZE:
                time.sleep(0.5)
            


"""
Struktura "events":

events: {
    <category>: {
        <date (DetectTime)>: number
    }
}

Například:

events: {
    "Recon_Scanning": {
        "2016-05-27": 5,
        "2016-05-26": 7,
        "2016-05-25": 2,
    },
    "Attempt_Login": {
        "2016-05-27": 1,
        "2016-05-26": 2,
    }
}
events_cnt: 17

Jak efektivně odmazávat?



"""

