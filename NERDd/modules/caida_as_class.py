"""
NERD module tries to determinate bussines type of IP according to ASN and caida database. 
"""

from .base import NERDModule

import datetime
import logging
import os

class CaidaASclass(NERDModule):
    """
    CaidaASclass module.
    Parses Caida AS classification list of ASN and determinates bussiness usage of IP.

    Event flow specification:
    [ip] 'as_maxmind.num' and 'as_rv.num' -> determinate_type() -> 'caida_as_class.v' and 'caida_as_class.c'
    """
    def __init__(self, config, update_manager):
        self.log = logging.getLogger("CaidaASclass")
        caida_file_path = config.get("caida.caida_file")
        
        self.caida_dict = self.parse_list(caida_file_path)
	
        update_manager.register_handler(
	    self.determinate_type,
	    'ip',
	    ('as_maxmind.num','as_rv.num'),
	    ('caida_as_class.v', 'caida_as_class.c')
        )
    
    def parse_list(self, path):
        self.log.debug("Start parsing Caida list stored at path {}.".format(path))
        ASN_dictionary = {}
        
        try:
            with open(path) as f :
                for line in f:
                    if not line.startswith("#"):
                        line = line.strip() 
                        data = line.split("|")
                        ASN_data = {"source": data[1] , "class": data[2]}
                        try:
                            asn_num = int(data[0])
                            ASN_dictionary[asn_num] = ASN_data                  
                        except ValueError:
                            self.log.error("Can't parse line starting with '{}' - it's not number.".format(data[0]))
        except EnvironmentError as e:
            self.log.error("Can't parse Caida list file ({}): {} .".format(path, str(e)))
            return {}
       
        self.log.info("Parsed Caida ASN list (path: {}) as dictionary with {} ASNs.".format(path, len(ASN_dictionary))) 
        return ASN_dictionary


    def search_in_dict(self, asn):
        if asn in self.caida_dict:
            return self.caida_dict[asn]
        return None

    def determinate_type(self, ekey, rec, updates):
        etype, key = ekey
        if etype != 'ip':
            return None
        
        if "as_maxmind" in rec and "as_rv" in rec:
            as_maxmind = rec["as_maxmind"]
            as_rv = rec["as_rv"]
            if as_maxmind["num"] == as_rv["num"]:
                res = self.search_in_dict(as_maxmind["num"])
                if res is not None:
                    if res["source"] == "CAIDA_class":
                        self.log.debug("IP {} (ASN: {}) is {} according to CAIDA classification with 70% probability (source: {}).".format(key,as_maxmind["num"], res["class"], res["source"]))
                        return [('set', 'caida_as_class.v', res["class"]),('set', 'caida_as_class.c', 0.7)]
                    else:
                        self.log.debug("IP {} (ASN: {}) is {} according to CAIDA classification (source: {}).".format(key,as_maxmind["num"], res["class"], res["source"]))
                        return [('set', 'caida_as_class.v', res["class"])]
                else:
                    self.log.debug("ASN {} hasn't been found in caida ASN list.".format(as_maxmind["num"]))
                    return [('set', 'caida_as_class.v', 'unknown')] 
            else:
                res_maxmind = self.search_in_dict(as_maxmind["num"])
                res_rv = self.search_in_dict(as_rv["num"])
                if res_maxmind is not None and res_rv is not None:
                    if res_maxmind["class"] == res_rv["class"]:
                        if res_maxmind["source"] == "CAIDA_class" and res_rv["source"] == "CAIDA_class":
                            self.log.debug("IP {} (ASN_maxmind: {} and ASN_rv: {}) is {} according to CAIDA classification with 70% probability (source: {}).".format(key,as_maxmind["num"], as_rv["num"], res_rv["class"], res_rv["source"]))
                            return [('set', 'caida_as_class.v', res_rv["class"]),('set', 'caida_as_class.c', 0.7)]
                        else:
                            self.log.debug("IP {} (ASN_maxmind: {} and ASN_rv: {}) is {} according to CAIDA classification (sources: {} and {}).".format(key,as_maxmind["num"], as_rv["num"], res_rv["class"], res_rv["source"], res_maxmind["source"]))
                            return [('set', 'caida_as_class.v', res_rv["class"])]
                    else:
                        self.log.debug("IP {} has different ASNs (ASN_maxmind: {} and ASN_rv: {}) and type can't be determinated ({} or {}).".format(key,as_maxmind["num"], as_rv["num"], res_maxmind["class"], res_rv["class"]))
                        return [('set', 'caida_as_class.v', 'unknown')]
                elif res_maxmind is not None:
                    if res_maxmind["source"] == "CAIDA_class":
                        self.log.debug("IP {} (ASN: {}) is {} according to CAIDA classification with 70% probability (source: {}).".format(key,as_maxmind["num"], res_maxmind["class"], res_maxmind["source"]))
                        return [('set', 'caida_as_class.v', res_maxmind["class"]),('set', 'caida_as_class.c', 0.7)]
                    else:
                        self.log.debug("IP {} (ASN: {}) is {} according to CAIDA classification (source: {}).".format(key,as_maxmind["num"], res_maxmind["class"], res_maxmind["source"]))
                        return [('set', 'caida_as_class.v', res_maxmind["class"])]
                elif res_rv is not None:
                    if res_rv["source"] == "CAIDA_class":
                        self.log.debug("IP {} (ASN: {}) is {} according to CAIDA classification with 70% probability (source: {}).".format(key,as_rv["num"], res_rv["class"], res_rv["source"]))
                        return [('set', 'caida_as_class.v', res_rv["class"]),('set', 'caida_as_class.c', 0.7)]
                    else:
                        self.log.debug("IP {} (ASN: {}) is {} according to CAIDA classification (source: {}).".format(key,as_rv["num"], res_rv["class"], res_rv["source"]))
                        return [('set', 'caida_as_class.v', res_maxmind["class"])]
                else:
                    self.log.debug("ASNs {} and {} haven't been found in caida ASN list.".format(as_maxmind["num"], as_rv["num"]))
                    return [('set', 'caida_as_class.v', 'unknown')] 
        elif "as_maxmind" in rec:
            as_maxmind = rec["as_maxmind"]
            res = self.search_in_dict(as_maxmind["num"])
            if res is not None:
                if res["source"] == "CAIDA_class":
                    self.log.debug("IP {} (ASN: {}) is {} according to CAIDA classification with 70% probability (source: {}).".format(key,as_maxmind["num"], res["class"], res["source"]))
                    return [('set', 'caida_as_class.v', res["class"]),('set', 'caida_as_class.c', 0.7)]
                else:
                    self.log.debug("IP {} (ASN: {}) is {} according to CAIDA classification (source: {}).".format(key,as_maxmind["num"], res["class"], res["source"]))
                    return [('set', 'caida_as_class.v', res["class"])]
            else:
                self.log.debug("ASN {} hasn't been found in caida ASN list.".format(as_maxmind["num"]))
                return [('set', 'caida_as_class.v', 'unknown')] 
        elif "as_rv" in rec:
            as_rv = rec["as_rv"]
            res = self.search_in_dict(as_rv["num"])
            if res is not None:
                if res["source"] == "CAIDA_class":
                    self.log.debug("IP {} (ASN: {}) is {} according to CAIDA classification with 70% probability (source: {}).".format(key,as_rv["num"], res["class"], res["source"]))
                    return [('set', 'caida_as_class.v', res["class"]),('set', 'caida_as_class.c', 0.7)]
                else:
                    self.log.debug("IP {} (ASN: {}) is {} according to CAIDA classification (source: {}).".format(key,as_rv["num"], res["class"], res["source"]))
                    return [('set', 'caida_as_class.v', res["class"])]
            else:
                self.log.debug("ASN {} hasn't been found in caida ASN list.".format(as_rv["num"]))
                return [('set', 'caida_as_class.v', 'unknown')] 
        
        self.log.debug("No ASNs have been found for IP {}.".format(key))
        return [('set', 'caida_as_class.v', 'unknown')] 
         
