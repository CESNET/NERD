"""
NERD module querying various blacklists using DNSBL.

Requirements:
- "pycares" package
"""

import ipaddress
from .base import NERDModule
import pycares
import select
import socket
import logging
import threading
from datetime import datetime

# TODO:
# - counter of requests per day + limit and automatic stop of querying (to avoid blocking by blacklist providers)


# From pycares example "cares-select.py"
# https://github.com/saghul/pycares/blob/master/examples/cares-select.py
# (processes pending requests in a channel)
def _wait_channel(channel):
    while True:
        read_fds, write_fds = channel.getsock()
        if not read_fds and not write_fds:
            break
        timeout = channel.timeout()
        if not timeout:
            channel.process_fd(pycares.ARES_SOCKET_BAD, pycares.ARES_SOCKET_BAD)
            continue
        rlist, wlist, xlist = select.select(read_fds, write_fds, [], timeout)
        for fd in rlist:
            channel.process_fd(fd, pycares.ARES_SOCKET_BAD)
        for fd in wlist:
            channel.process_fd(pycares.ARES_SOCKET_BAD, fd)


def _make_result_handler(bl, results):
    """
    Create callback function using given blacklist spec and writing to given
    results array.
    (note: if you don't understand this way of making a function, google 
    "python closure")
    
    bl - blacklist configuration (name, zone, dict{result -> blacklist_id})
    results - list to put blacklist_ids
    """
    def handler(res, err):
        """
        Callback for processing results.
        
        res - list of results (tuples hostname,ttl)
        err - error code
        """
        if res is not None:
            for r in res:
                blacklist_id = bl[2].get(r.host, None)
                if blacklist_id:
                    results.append(blacklist_id)
    return handler

def reverse_ip(ip):
    """
    Return reversed IP string for use in DNSBL query.
    
    100.20.3.4 -> 4.3.20.100
    2001:db8::1000 -> 0.0.0.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2
    """
    if ':' in ip:
        # IPv6
        full_ip6 = ipaddress.IPv6Address(ip).exploded
        return '.'.join(reversed(full_ip6.replace(':','')))
    else:
        # IPv4
        return '.'.join(reversed(ip.split('.')))
    

class DNSBLResolver(NERDModule):
    """
    DNSBL blacklist querying module.
    
    Queries newly added IP addresses to configured blacklists using DNSBL 
    technique.
    
    Event flow specification:
      !NEW -> query_blacklists -> bl.*
    
    TODO: periodic re-checking (but it might cause a lot more queries and 
      for example spamhaus allows only 300,000 queries per day for free
      -> we'll need paid subscription)
    """
    
    def __init__(self, config, update_manager):
        self.log = logging.getLogger('DNSBL')
        # Configuration of blacklists is inspired by DNSBL.py from sources 
        # of python3-adns
        # (https://github.com/trolldbois/python3-adns/blob/master/DNSBL.py)
        # TODO: add possibility to add description to each blacklist to frontend
        self.blacklists = config.get('dnsbl.blacklists')
        if self.blacklists is None:
            self.log.critical("Blacklists not specified ('dnsbl.blacklists') missing in configuration. DNSBL module disabled.")

        self.nameservers = config.get('dnsbl.nameservers', [])
        if self.nameservers:
            self.log.info("Using nameserver(s) at {}.".format(', '.join(self.nameservers)))
        else:
            self.log.info("Using system default nameserver(s).")

        # Limit number of requests per day to avoid getting blocked by blacklist
        # providers
        if config.get('dnsbl.max_requests') and config.get('dnsbl.req_cnt_file'):
            self.max_req_count = int(config.get('dnsbl.max_requests'))
            self.req_cnt_file = config.get('dnsbl.req_cnt_file')
            self.log.info("Maximal number of DNSBL requests per day set to {}.".format(self.max_req_count))
        else:
            self.max_req_count = float('inf')
            self.req_cnt_file = None
        self.req_counter = 0
        self.req_counter_lock = threading.Lock() # query_blacklists() must be thread safe, therefore access to req_counter must use locking
        
        update_manager.register_handler(
            self.query_blacklists, # function (or bound method) to call
            ('!NEW',), # tuple/list/set of attributes to watch (their update triggers call of the registered method)
            ('bl',) # tuple/list/set of attributes the method may change # TODO maybe there should be all particular fields enumerated (but it would be beterr if I coiuld write 'bl.*')
        )
        self.log.debug("DNSBLResolver initialized")
    
    
    def start(self):
        if not self.req_cnt_file:
            return
        # Load counter of DNS requests made
        datestr = datetime.now().strftime("%Y%m%d")
        try:
            with open(self.req_cnt_file + datestr, "r") as f:
                self.req_counter = int(f.read())
        except IOError:
            self.req_counter = 0
            self.write_req_count()
        if self.req_counter >= self.max_req_count:
            self.log.warning("Maximal request count reached - no more DNSBL requests will be made today.")
    
    def write_req_count(self):
        if not self.req_cnt_file:
            return
        # Store counter of DNS requests
        datestr = datetime.now().strftime("%Y%m%d")
        with open(self.req_cnt_file + datestr, "w") as f:
            f.write(str(self.req_counter))
    
    stop = write_req_count # Store req_counter when NERD is going to stop
    
    def query_blacklists(self, ekey, rec, updates):
        """
        Query all configured blacklists and update the set of blacklists
        the address is listed on, togerther with the time of query.
        Updates 'bl' attribute.
        
        Arguments:
        ekey -- two-tuple of entity type and key, e.g. ('ip', '192.0.2.42')
        rec -- record currently assigned to the key
        updates -- list of all attributes whose update triggerd this call and  
          their new values (or events and their parameters) as a list of 
          2-tuples: [(attr, val), (!event, param), ...]
        
        Returns:
        List of following update requests (one for every blacklist the address 
        was found on):
          ('append', 'bl.'+<blacklist_id>, time)
        """
        etype, key = ekey
        if etype != 'ip':
            return None
        
        # Limit of the number of requests per day
        self.req_counter_lock.acquire()
        if self.req_counter >= self.max_req_count:
            if self.req_counter == self.max_req_count:
                self.log.warning("Maximal request count reached - no more DNSBL requests will be made today.")
            self.req_counter += 1
            self.req_counter_lock.release()
            return None
        self.req_counter_lock.release()
        
        ip = ekey[1]
        revip = reverse_ip(ip)

        self.log.debug("Querying blacklists for {}".format(ekey))
        
        channel = pycares.Channel(servers=self.nameservers)
        results = []
        
        req_time = datetime.now()
        
        # Create queries to all blacklists
        for bl in self.blacklists:
            channel.query(revip + '.' + bl[1], pycares.QUERY_TYPE_A,
                _make_result_handler(bl, results)
            )
        # Send all queries and wait for results
        #(they are handled by self._process_result callback)
        _wait_channel(channel)
        
        self.req_counter_lock.acquire()
        self.req_counter += 1
        if self.req_counter % 1000:
            self.write_req_count()
        self.req_counter_lock.release()
        
        self.log.debug("DNSBL for {}: {}".format(ip, results))
        
        update_requests = []
        for bl_id in results:
            update_requests.append(('append', 'bl.'+bl_id, req_time))
        
        return update_requests
