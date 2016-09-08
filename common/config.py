"""
NERDd - config file reader
"""
import json
import re

class NoDefault:
    pass

class MissingConfigError(Exception):
    pass

def hierarchical_get(self, key, default=NoDefault):
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
        if default is NoDefault:
            raise MissingConfigError("Mandatory configuration element is missing: " + key)
        else:
            return default
    
class DictWithHierarchicalGet(dict):
    get = hierarchical_get


def read_config(file):
    """
    Read configuration file and return config as a dict-like object.
    
    The configuration file shoud contain a valid JSON document, with the 
    following exceptions:
    - Comments may be included as lines starting with '#' (optionally preceded 
      by whitespaces).
    - There may be a comma after the last item of an object or list.
    - Top level object is added automatically (i.e. '{' and '}' are added at the
      beginning and the end of the whole file before passing to JSON parser)

    This function reads the file and converts it to an dict-like object.
    The only difference from normal dict is its "get" method, which allows
    hierarchical keys (e.g. 'abc.x.y'). See doc of "hierarchical_get" function
    for more information.
    """
    with open(file, "r") as f:
        # Read file and replace whole-line comments with empty line
        # (lines are not completely removed to keep correct line numbers in error messages)
        configstr = "".join((line if not line.lstrip().startswith("#") else "\n") for line in f)
        # Add { and } around the string
        configstr = '{' + configstr + '}'
        # Remove commas before closing braces/brackets
        configstr = re.sub(',(?=\s*[}\]])', '', configstr)
        # Load as JSON
        conf_dict = json.loads(configstr)
    return DictWithHierarchicalGet(conf_dict)
