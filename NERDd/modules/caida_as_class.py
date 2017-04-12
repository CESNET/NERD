"""
NERD module tries to classify IPs according to their business type. It uses ASN and caida classification list  <www.caida.org/data/as-classification>. 
"""

from core.basemodule import NERDModule

import g

import datetime
import logging
import os

class CaidaASclass(NERDModule):
    """
    CaidaASclass module.
    Parses Caida AS classification list of ASN and determines bussiness usage of IP.

    Event flow specification:
    [ip] 'as_maxmind.num' and 'as_rv.num' -> determine_type() -> 'caida_as_class.v' and 'caida_as_class.c'
    """
    
    def __init__(self):
        self.log = logging.getLogger("CaidaASclass")
        self.caida = g.config.get("caida", None)
        if not self.caida or not self.caida.get("caida_file", False):
            self.log.warning("Configuration for CaidaASclass module not found - module is disabled.")
            return
        
        self.caida_dict = self.parse_list(self.caida.get("caida_file"))
        if not self.caida_dict:
            return

        g.um.register_handler(
            self.determine_type,
            'ip',
            ('as_maxmind.num','as_rv.num'),
            ('caida_as_class.v', 'caida_as_class.c')
        )
    
    def parse_list(self, path):
        """
        Parses caida list from given file and returns it as a dictionary.
        
        Arguments:
        path -- path of file with list of ASes, their sources and classes
        
        Return:
        Dictionary with AS number as a key and dictionary with source and class (class name from configuration file is used if is set) as a value
        """

        self.log.debug("Start parsing Caida list stored at path {}.".format(path))
        ASN_dictionary = {}
        
        try:
            with open(path) as f :
                for line in f:
                    if not line.startswith("#"):
                        line = line.strip() 
                        data = line.split("|")
                        ASN_data = {}
                        if "classes" in self.caida and data[2] in self.caida["classes"] and "value" in self.caida["classes"][data[2]]:
                            ASN_data = {"source": data[1] , "class": self.caida["classes"][data[2]]["value"]}
                        else:
                            ASN_data = {"source": data[1] , "class": data[2]}
                        try:
                            asn_num = int(data[0])
                            ASN_dictionary[asn_num] = ASN_data
                        except ValueError:
                            self.log.error("Can't parse line starting with '{}' - it's not number.".format(data[0]))
        except Exception as e:
            self.log.error("Can't parse Caida list file ({}): {} .".format(path, str(e)))
            return {}
       
        self.log.info("Parsed Caida ASN list (path: {}) as dictionary with {} ASNs.".format(path, len(ASN_dictionary))) 
        return ASN_dictionary


    def search_in_dict(self, asn):
        """
        Searches given AS number in dictionary and returns source, class and confidence
        
        Arguments:
        asn -- AS number
        
        Return:
        Dictionary with source, class and confidence (can be specified in configuration file for each class- otherwise confidence set to 1) for AS
        returns None if AS is not found in dict  
        """

        if asn in self.caida_dict:
            res = self.caida_dict[asn]
            if "sources" in self.caida and res["source"] in self.caida["sources"] and "confidence" in self.caida["sources"][res["source"]]:
                res["confidence"] = self.caida["sources"][res["source"]]["confidence"]
                return res
            else:
                res["confidence"] = 1
                return res
        return None

    def determine_type(self, ekey, rec, updates):
        """
        Classifies IP according to its AS number

        Arguments:
        ekey -- two-tuple of entity type and key, e.g. ('ip', '192.0.2.42')
        rec -- record currently assigned to the key
        updates -- list of all attributes whose update triggered this call and
                   their new values (or events and their parameters) as a list of
                   2-tuples: [(attr, val), (!event, param), ...]

        Return:
        List of update requests.
        """
        etype, key = ekey
        if etype != 'ip':
            return None
        
        # AS numbers from both sources are set in IP record
        if "as_maxmind" in rec and "as_rv" in rec:
            as_maxmind = rec["as_maxmind"]
            as_rv = rec["as_rv"]
            # Both AS numbers are same -> find AS in dict and if found create update request 
            if as_maxmind["num"] == as_rv["num"]:
                res = self.search_in_dict(as_maxmind["num"])
                if res is not None:
                    self.log.debug("IP {} (ASN: {}) has class: {} (source: {}, confidence: {}) according to CAIDA.".format(key,as_maxmind["num"], res["class"], res["source"], res["confidence"]))
                    ret = [('set', 'caida_as_class.v', res["class"])]
                    if res["confidence"] != 1:
                        ret.append(('set', 'caida_as_class.c', res["confidence"]))
                    return ret
            # AS numbers are not same -> if class is same or only AS number from one AS source is found in dict return result else set class to unknown
            else:
                res_maxmind = self.search_in_dict(as_maxmind["num"])
                res_rv = self.search_in_dict(as_rv["num"])
                if res_maxmind is not None and res_rv is not None:
                    if res_maxmind["class"] == res_rv["class"]:
                        confidence = res_maxmind["confidence"] if res_maxmind["confidence"] > res_rv["confidence"] else res_rv["confidence"]
                        self.log.debug("IP {} (ASN_maxmind: {} and ASN_rv: {}) has class: {} (sources: {} and {}, confidence: {}) according to CAIDA.".format(key,as_maxmind["num"], as_rv["num"], res_rv["class"], res_maxmind["source"], res_rv["source"], confidence))
                        ret = [('set', 'caida_as_class.v', res_rv["class"])]
                        if confidence != 1:
                            ret.append(('set', 'caida_as_class.c', confidence))
                        return ret
                    else:
                        self.log.debug("IP {} has different ASNs (ASN_maxmind: {} and ASN_rv: {}) and type can't be determined ({} or {}).".format(key,as_maxmind["num"], as_rv["num"], res_maxmind["class"], res_rv["class"]))
                        return [('set', 'caida_as_class.v', 'unknown')]
                elif res_maxmind is not None:
                    self.log.debug("IP {} (ASN: {}) has class: {} (source: {}, confidence: {}) according to CAIDA.".format(key,as_maxmind["num"], res_maxmind["class"], res_maxmind["source"], res_maxmind["confidence"]))
                    ret = [('set', 'caida_as_class.v', res_maxmind["class"])]
                    if res_maxmind["confidence"] != 1:
                        ret.append(('set', 'caida_as_class.c', res_maxmind["confidence"]))
                    return ret
                elif res_rv is not None:
                    self.log.debug("IP {} (ASN: {}) has class: {} (source: {}, confidence: {}) according to CAIDA.".format(key,as_rv["num"], res_rv["class"], res_rv["source"], res_rv["confidence"]))
                    ret = [('set', 'caida_as_class.v', res_rv["class"])]
                    if res_rv["confidence"] != 1:
                        ret.append(('set', 'caida_as_class.c', res_rv["confidence"]))
                    return ret
        
        # Only AS number from AS maxmind source is set in IP record -> if AS number is found in dict create update request
        elif "as_maxmind" in rec:
            as_maxmind = rec["as_maxmind"]
            res = self.search_in_dict(as_maxmind["num"])
            if res is not None:
                self.log.debug("IP {} (ASN: {}) has class: {} (source: {}, confidence: {}) according to CAIDA.".format(key,as_maxmind["num"], res["class"], res["source"], res["confidence"]))
                ret = [('set', 'caida_as_class.v', res["class"])]
                if res["confidence"] != 1:
                    ret.append(('set', 'caida_as_class.c', res["confidence"]))
                return ret
        
        # Only AS number from AS rv source is set in IP record -> if AS number is found in dict create update request
        elif "as_rv" in rec:
            as_rv = rec["as_rv"]
            res = self.search_in_dict(as_rv["num"])
            if res is not None:
                self.log.debug("IP {} (ASN: {}) has class: {} (source: {}, confidence: {}) according to CAIDA.".format(key,as_rv["num"], res["class"], res["source"], res["confidence"]))
                ret = [('set', 'caida_as_class.v', res["class"])]
                if res["confidence"] != 1:
                    ret.append(('set', 'caida_as_class.c', res["confidence"]))
                return ret
        
        # No ASNs set for IP or ASN is not in caida file -> set caida_as_class value to unknown 
        if "as_rv" not in rec and "as_maxmind" not in rec: 
            self.log.debug("No ASNs have been found for IP {}.".format(key))
        else:
            rv = rec["as_rv"]["num"] if "as_rv" in rec else "None"
            maxmind = rec["as_maxmind"]["num"] if "as_maxmind" in rec else "None"
            self.log.debug("ASN (ASN_maxmind: {}, ASN_rv: {}) hasn't been found in caida ASN list.".format(maxmind, rv))
        return [('set', 'caida_as_class.v', 'unknown')] 
