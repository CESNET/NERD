"""
NERD: auxiliary/utilitiy functions and classes
"""
import re
import datetime

ipv4_re = re.compile(r"^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$")

def ipstr2int(s):
    res = ipv4_re.match(s)
    if res is None:
        raise ValueError('Invalid IPv4 format: {!r}'.format(s))
    a1, a2, a3, a4 = res.groups()
    # Check if octets are between 0 and 255 is omitted for better performance
    return int(a1) << 24 | int(a2) << 16 | int(a3) << 8 | int(a4)

def int2ipstr(i):
    return '.'.join((str(i >> 24), str((i >> 16) & 0xff), str((i >> 8) & 0xff), str(i & 0xff)))


# Regex for RFC 3339 time format
timestamp_re = re.compile(r"^([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt ]([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]+))?([Zz]|(?:[+-][0-9]{2}:[0-9]{2}))$")

def parse_rfc_time(time_str):
    """Parse time in RFC 3339 format and return it as naive datetime in UTC."""
    res = timestamp_re.match(time_str)
    if res is not None:
        year, month, day, hour, minute, second = (int(n or 0) for n in res.group(*range(1, 7)))
        us_str = (res.group(7) or "0")[:6].ljust(6, "0")
        us = int(us_str)
        zonestr = res.group(8)
        zoneoffset = 0 if zonestr in ('z', 'Z') else int(zonestr[:3])*60 + int(zonestr[4:6])
        zonediff = datetime.timedelta(minutes=zoneoffset)
        return datetime.datetime(year, month, day, hour, minute, second, us) - zonediff
    else:
        raise ValueError("Wrong timestamp format")