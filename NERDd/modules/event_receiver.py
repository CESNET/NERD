"""
NERD module for receiving IDEA messages about detected security events.

Fetches IDEA messages dropped to a specified directory and updates entity 
records accordingly.
"""

from core.basemodule import NERDModule
import g

from threading import Thread
import multiprocessing as mp
import time
import random
import os
import sys
import socket
import json
import logging
import datetime
import pika # RabbitMQ client

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

def dbwriter(queue, config):
    """
    Process for writing events to PSQL EventDB
    
    Pull new events from Queue and stores them to EventDB. Runs as separate
    process, because storing events is quite CPU demanding.
    """
    # Ignore SIGINT - process should be terminated from the main process
    import signal
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    
    # Create instance of EventDB (PSQL wrapper)
    # It's easier to create it here again than copy the one from main process to this one
    import common.eventdb_psql
    eventdb = common.eventdb_psql.PSQLEventDatabase(config)
    
    event_set = []
    
    while True:
        event = queue.get()
        if event is None:
            print("EventDB process exiting")
            break
        event_set.append(event)
        if len(event_set) >= 100 or queue.empty():
            eventdb.put(event_set)
            event_set = []


class EventReceiver(NERDModule):
    """
    Receiver of security events. Receives events as IDEA files in given directory.
    """
    def __init__(self):
        self.log = logging.getLogger("EventReceiver")
        self._drop_path = g.config.get('warden_filer_path')
        # Number of separate DB-writer processes to spawn (only if PSQL-type of eventdb is set)
        if g.config.get('eventdb', 'psql') == 'psql':
            self.write_to_eventdb = True
            self._n_dbwriters = g.config.get('eventdb_psql.dbwriter_processes', 0)
            if self._n_dbwriters > 0:
                # Create multiprocessing context
                self.mpctx = mp.get_context('spawn') # Create processes using 'spawn', 'fork' doesn't work well in multithreaded applications (and not at all in Windows)
                # Queue for sending events to DB-writer (max size is set, so eventRecevier gets blocked if DB-writer is too slow)
                self.event_queue = self.mpctx.Queue(maxsize=100)
        else:
            self.write_to_eventdb = False
        
        # Initialize RabbitMQ connection (if queue name is given)
        self.rmq_queue_name = g.config.get('eventdb_psql.forward_to_queue', None)
        if self.rmq_queue_name:
            rmq_creds = pika.PlainCredentials('guest', 'guest')
            self.rmq_params = pika.ConnectionParameters('localhost', 5672, '/', rmq_creds)
            self.rmq_connect(self.rmq_params)
        else:
            self.rmq_channel = None
    
    def start(self):
        """
        Run the module - used to run own thread if needed.
        
        Called after initialization, may be used to create and run a separate
        thread if needed by the module. Do nothing unless overriden.
        """
        self._recv_thread = Thread(target=self._receive_events)
        self._recv_thread.daemon = True
        self._recv_thread.start()
        if self.write_to_eventdb and self._n_dbwriters > 0:
            # Run EventDB writing processes
            self._dbwriter_procs = []
            for i in range(self._n_dbwriters):
                self._dbwriter_procs.append(self.mpctx.Process(target=dbwriter, args=(self.event_queue, g.config)))
            for i in range(self._n_dbwriters):
                self._dbwriter_procs[i].start()
    
    def stop(self):
        """
        Stop the module - used to stop own thread.
        
        Called before program exit, may be used to finalize and stop the 
        separate thread if it is used. Do nothing unless overridden.
        """
        global running_flag
        running_flag = False
        self.log.info("Going to exit, waiting for event-reading thread ...")
        self._recv_thread.join()
        
        # Signal EventDB process to stop (send None to queue)
        if self.write_to_eventdb and self._n_dbwriters > 0:
            self.log.info("Waiting for EventDB-writing process to finish ...")
            for i in range(self._n_dbwriters):
                self.event_queue.put(None)
            for i in range(self._n_dbwriters):
                self._dbwriter_procs[i].join()
        self.log.info("Exitting.") 
        
        if self.rmq_channel is not None:
            self.rmq_channel.close()

    def rmq_connect(self, rmq_params):
        """Connecto to RabbitM server and prepare a channel"""
        rmq_conn = pika.BlockingConnection(rmq_params)
        self.rmq_channel = rmq_conn.channel()
        # we don't declare any queue here, it should be declared statically using rabbitmqctl or web Management

    def _receive_events(self):
        # Infinite loop reading events as files in given directory
        # (termiated by setting running_flag to False)
        for (rawdata, event) in read_dir(self._drop_path):
            #t1 = time.time()
            # Store the event to EventDB
            if self.write_to_eventdb:
                if self._n_dbwriters > 0:
                    # pass it to the Queue for separate DB-writing process
                    #print("EventDB Writer queue length: {:3d}".format(self.event_queue.qsize()), end="\r")
                    self.event_queue.put(event)
                else:
                    # no separate processes - store it directly
                    g.eventdb.put([event])
            #t2 = time.time()
            
            # Send copy of the IDEA message to RabbitMQ queue (currently used by experimental GRIP system)
            # Does nothing if given queue doesn't exist
            if self.rmq_channel is not None:
                try:
                    self.rmq_channel.basic_publish(exchange='', routing_key=self.rmq_queue_name, body=rawdata)
                except pika.exceptions.ConnectionClosed:
                    self.log.warning("Connection to RabbitMQ server lost, reconnecting ...")
                    self.rmq_connect(self.rmq_params)
                    self.rmq_channel.basic_publish(exchange='', routing_key=self.rmq_queue_name, body=rawdata)

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
                                ('array_upsert', 'events', {'date': date, 'node': node, 'cat': cat}, [('add', 'n', 1)]),
                                ('add', 'events_meta.total', 1),
                                ('set', 'ts_last_event', end_time),
                            ]
                        )
                        
                    for ipv6 in src.get("IP6", []):
                        self.log.debug("IPv6 address in Source found - skipping since IPv6 is not implemented yet.")# The record follows:\n{}".format(str(event)), file=sys.stderr)
            except Exception as e:
                self.log.error("ERROR in parsing event: {}".format(str(e)))
                pass
            
            #t3 = time.time()
            
            # If there are already too much requests queued, wait a while
            #print("***** QUEUE SIZE: {} *****".format(g.um.get_queue_size()))
            while g.um.get_queue_size() >= MAX_QUEUE_SIZE:
                time.sleep(0.2)
            
            #t4 = time.time()
            #g.um.t_handlers.update({'_event_recevier': t3-t1})
            #self.log.info("Event {}: storage: {:.3f}s, process: {:.3f}s, put_to_queue: {:.3f}s".format(event["ID"], t2-t1, t3-t2, t4-t3))
                        
