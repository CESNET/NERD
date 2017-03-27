"""
NERD: auxiliary/utilitiy functions and classes
"""
import re
import datetime

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