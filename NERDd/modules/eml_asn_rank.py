"""
NERD module querying ASN ranking API of "The Email Laundry (EML)" company.
"""

from core.basemodule import NERDModule
import g

import logging
import requests

class EML_ASN_rank(NERDModule):
    """
    EML ASN rank module.
    
    Queries newly added ASNs in EML's API for their ASN rank.
    
    Event flow specification:
      asn: !NEW -> get_rank -> eml_rank
    """
    
    def __init__(self):
        self.log = logging.getLogger('EML_ASN_rank')
        #self.log.setLevel("DEBUG")
        self.url = g.config.get('eml_api.url', None)
        self.apikey = g.config.get('eml_api.key', None)
        if not self.url or not self.apikey:
            self.log.warning("API URL or key not set, EML ASN rank module disabled.")
            return
        
        g.um.register_handler(
            self.get_rank,
            'asn',
            ('!NEW','!refresh_eml_rank'),
            ('eml_rank',)
        )
    
    def get_rank(self, ekey, rec, updates):
        """
        Query the EML API to get ASN rank.
        
        Arguments:
        ekey -- two-tuple of entity type and key, e.g. ('ip', '192.0.2.42')
        rec -- record currently assigned to the key
        updates -- list of all attributes whose update triggered this call and  
          their new values (or events and their parameters) as a list of 
          2-tuples: [(attr, val), (!event, param), ...]

        
        Returns:
        List of update requests.
        """
        etype, key = ekey
        if etype != 'asn':
            return None
        
        try:
            r = requests.get('{}asn/{}?key={}'.format(self.url, key, self.apikey))
            r.raise_for_status()
            data = r.json()
            rank = float(data['asnrankinfo']['asnrank'])
        except Exception as e:
            self.log.error("Can't get rank for AS{}: {}".format(key, repr(e)))
            return None
        
        return [('set', 'eml_rank', rank)]
