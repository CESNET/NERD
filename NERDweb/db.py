# NERDweb module providing database connection functions.
# All DB operations should be done via this module.

import random
import json
import ctrydata

def getIPInfo(ip):
    events30 = int(random.expovariate(1.0/20.0))
    events7 = random.randint(0,events30)
    events1 = random.randint(0,events7)
    info = {
        'ip': ip,
        # Hostname got by reverse DNS query
        'hostname': ''.join(
                random.choice('abcdefghijklmnopqrstuvwxyz0123456789---')
                for _ in range(int(random.triangular(1,20,6)))
            ) + '.example.' + random.choice(['com','com','org','net']),
        # Geolocation information- country code and name
        'geo': {
            'ctry_code': random.choice(ctrydata.names.keys()),
        },
        # Autonomous system
        'as_num': 'AS' + str(random.randint(1000,65000)),
        'as_name': ''.join(
                random.choice('abcdefghijklmnopqrstuvwxyz    ')
                for _ in range(int(random.triangular(5,32,12)))
            ),
        # Vector describing reported events (for now, number of reports
        # in last 30, 7, 1 days)
        'events': {
            'last_30d': events30,
            'last_7d': events7,
            'last_1d': events1,
        },
        # Tor exit node - True with 5% chance
        'tor': (random.random() > 0.95),
        # Open[DNSresolver/NTP/SNMP]
        'open_dns': (random.random() < 0.08),
        'open_ntp': (random.random() < 0.05),
        'open_snmp': (random.random() < 0.02),
        # Blacklists the address is present on
        'blacklists': random.sample(blacklists, int(random.triangular(1,10,1))) if random.random() < 0.5 else [],
        # Open ports and other info from Shodan
        'shodan_ports': random.sample([21,22,23,25,80,443,5000,5060,7547,4567,8080], random.randint(1,5)) \
                        if random.random() < 0.3 else [],
        'shodan_os': random.choice(['Linux 3.x','Linux 2.6.x','Windows 7 or 8','HP-UX 11.x','Windows XP']) \
                        if random.random() < 0.2 else '',
        # Device type (guessed from other information)
        'device_type': random.choice(['server','workstation','home net','mobile','CGNAT','wifi hotspot','router','printer','IoT device'])
                        if random.random() < 0.5 else '',
    }
    return info



blacklists = [
    "all.s5h.net",
    "b.barracudacentral.org",
    "bl.spamcop.net",
    "block.dnsbl.sorbs.net",
    "cart00ney.surriel.com",
    "cbl.abuseat.org",
    "dnsbl.sorbs.net",
    "dnsbl-1.uceprotect.net",
    "dnsbl-2.uceprotect.net",
    "dnsbl-3.uceprotect.net",
    "dul.dnsbl.sorbs.net",
    "escalations.dnsbl.sorbs.net",
    "black.junkemailfilter.com",
    "http.dnsbl.sorbs.net",
    "ips.backscatterer.org",
    "l2.apews.org",
    "misc.dnsbl.sorbs.net",
    "new.dnsbl.sorbs.net",
    "old.dnsbl.sorbs.net",
    "pbl.spamhaus.org",
    "recent.dnsbl.sorbs.net",
    "sbl.spamhaus.org",
    "smtp.dnsbl.sorbs.net",
    "socks.dnsbl.sorbs.net",
    "spam.dnsbl.sorbs.net",
    "ubl.unsubscore.com",
    "web.dnsbl.sorbs.net",
    "xbl.spamhaus.org",
    "zen.spamhaus.org",
    "zombie.dnsbl.sorbs.net",
    "rbl.megarbl.net",
    "bl.mailspike.net",
]
