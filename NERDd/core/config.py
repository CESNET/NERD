"""
NERDd - config file reader
"""
import json

def hierarchical_get(self, key, default=None):
    """
    Return self[key] or "default" if key is not found. Allow hierarchical keys.
    
    Key may be a path (in dot notation) into a hierarchy of dicts. For example
      dictionary.get('abc.x.y')
    is equivalent to
      dictionary['abc']['x']['y']
    If some of the keys in the path is not present, default value is returned 
    instead.
    """
    d = self
    try:
        while '.' in key:
            first_key, key = key.split('.', 1)
            d = d[first_key]
        return d[key]
    except KeyError:
        return default
    
class DictWithHierarchicalGet(dict):
    get = hierarchical_get


def read_config(file):
    """
    Read configuration file and return config as a dict-like object.
    
    The configuration file shoud contain a valid JSON document. Comments may be 
    included as lines starting with # (optionally preceded by whitespaces).
    This function reads the file and converts it to an dict-like object.
    The only difference from normal dict is its "get" method, which allows
    hierarchical keys (e.g. 'abc.x.y'). See doc of "hierarchical_get" function
    for more information.
    """
    with open(file, "r") as f:
        stripcomments = "\n".join((l for l in f if not l.lstrip().startswith(("#"))))
        conf_dict = json.loads(stripcomments)
    return DictWithHierarchicalGet(conf_dict)
