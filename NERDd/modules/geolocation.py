"""
NERD module getting geographical location of an IP address using MaxMind's
GeoLite2 database.

Requirements:
- "geolite2" package

Acknowledgment:
This product includes GeoLite2 data created by MaxMind, available from
http://www.maxmind.com.
"""

from .base import NERDModule

import geoip2.database
import geoip2.errors

# Path to GeoLite2-City.mmdb
#GEOLITE_DB_PATH = "f:/CESNET/GeoIP/GeoLite2-City.mmdb"
GEOLITE_DB_PATH = "/data/geoip/GeoLite2-City.mmdb"

class Geolocation(NERDModule):
    """
    Geolocation module.
    
    Queries newly added IP addresses in MaxMind's GeoLite2 database to get its
    (approximate) geographical location.
    Stores the following attributes:
      geo.ctry  # Country (2-letter ISO code)
      geo.city  # City (English name)
      geo.tz    # Timezone (Text specification, e.g. 'Europe/Prague')
    
    Event flow specification:
      !NEW -> geoloc -> geo.{ctry,city,tz}
    """
    
    def __init__(self, update_manager):
        # Instantiate DB reader (i.e. open GeoLite database)
        self._reader = geoip2.database.Reader(GEOLITE_DB_PATH)
        # TODO: error handlig (can't open file)
        
        update_manager.register_handler(
            self.geoloc,
            ('!NEW',),
            ('geo.ctry','geo.city','geo.tz')  # TODO allow to set 'geo.*'?
        )
    
    def geoloc(self, ekey, rec, updates):
        """
        Query GeoLite2 DB to get country, city and timezone of the IP address.
        If address isn't found, don't set anything.
        
        Arguments:
        ekey -- two-tuple of entity type and key, e.g. ('ip', '192.0.2.42')
        rec -- record currently assigned to the key
        updates -- specification of updates that triggerd this call
          3-tuple (op, attr, val) or ('event', name, param)
        
        Returns:
        List of 3-tuples describing requested attribute updates or events.
        """
        etype, key = ekey
        if etype != 'ip':
            return None
        
        try:
            result = self._reader.city(key)
        except geoip2.errors.AddressNotFoundError:
            return None
        
        
        print(result.country)
        print(result.city)
        print(result.location)
        ctry = result.country.iso_code
        city = result.city.names.get('en', None)
        tz = result.location.time_zone
        #lon = result.location.longitude
        #lat = result.location.latitude
        
        return [
            ('set', 'geo.ctry', ctry),
            ('set', 'geo.city', city),
            ('set', 'geo.tz', tz),
        ]
        
