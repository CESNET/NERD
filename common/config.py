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

def hierarchical_update(self, other):
    """
    Update HierarchicalDict with other dictionary and merge common keys.
    
    If there is a key in both current and the other dictionary and vlaues of
    both keys are dictionaries, they are merged together.
    Example:
      HierarchicalDict({'a': {'b': 1, 'c': 2}}).update({'a': {'b': 10, 'd': 3}})
      ->
      HierarchicalDict({'a': {'b': 10, 'c': 2, 'd': 3}})
    
    Changes the dictionary directly, returns None.
    """
    other = dict(other)
    for key in other.keys():
        if key in self:
            if isinstance(self[key], dict) and isinstance(other[key], dict):
                # The key is present in both dicts and both key values are dicts -> merge them
                hierarchical_update(self[key], other[key])
            else:
                # One of the key values is not a dict -> overwrite the value 
                # in self by the one from other (like normal "update" does)
                self[key] = other[key]
        else:
            # key is not present in self -> set it to value from other
            self[key] = other[key]


class HierarchicalDict(dict):
    get = hierarchical_get
    update = hierarchical_update
    def __repr__(self):
        return 'HierarchicalDict({})'.format(dict.__repr__(self))
    def copy(self):
        return HierarchicalDict(dict.copy(self))


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
    return HierarchicalDict(conf_dict)



# ***** Unit tests *****
# TODO 'update' is tested only, test 'get' as well

if __name__ == '__main__':
    import unittest
    from copy import deepcopy
    class HierarchicalUpdateTest(unittest.TestCase):
        def runTest(self):
            # Testing dicts
            d1 = HierarchicalDict({
                'a': 'a',
                'b': {
                    'b1': 1,
                    'b2': [1,2,3],
                },
                'c': {
                    'c1': {
                        'c1x': 'qwer',
                        'c1y': 'asdf',
                    },
                    'c2': 2,
                }
            })
            d2 = HierarchicalDict({
                'b': {
                    'b1': 12345,
                    'b3': 'BBB',
                    'b4': {
                        'b4a': None
                    },
                },
                'c': {
                    'c2': {
                        'c20': None
                    },
                },
                'd': 'x',
                'e': {}
            })
            d3 = {
                'a': 'A',
            }
            d4 = [('c', ['test']), ('d', 'y')]
            d5 = {'c': {'c1': {'c1z': None}}}
            d_empty = {}
            
            # Expected results
            d1d2 = HierarchicalDict({
                'a': 'a',
                'b': {
                    'b1': 12345,
                    'b2': [1,2,3],
                    'b3': 'BBB',
                    'b4': {
                        'b4a': None
                    },
                },
                'c': {
                    'c1': {
                        'c1x': 'qwer',
                        'c1y': 'asdf',
                    },
                    'c2': {
                        'c20': None
                    },
                },
                'd': 'x',
                'e': {}
            })
            d2d3d4 = HierarchicalDict({
                'a': 'A',
                'b': {
                    'b1': 12345,
                    'b3': 'BBB',
                    'b4': {
                        'b4a': None
                    },
                },
                'c': ['test'],
                'd': 'y',
                'e': {}
            })
            d1d5 = HierarchicalDict({
                'a': 'a',
                'b': {
                    'b1': 1,
                    'b2': [1,2,3],
                },
                'c': {
                    'c1': {
                        'c1x': 'qwer',
                        'c1y': 'asdf',
                        'c1z': None,
                    },
                    'c2': 2,
                }
            })
            
            # Tests
            res = deepcopy(d1)
            res.update(d2)
            self.assertEqual(res, d1d2, "Update of d1 by d2 failed")
            
            res = deepcopy(d2)
            res.update(d3)
            res.update(d4)
            self.assertEqual(res, d2d3d4, "Update of d2 by d3 and d4 failed")
            
            res = deepcopy(d1)
            res.update(d5)
            self.assertEqual(res, d1d5, "Update of d1 by d5 failed")
            
            res = deepcopy(d1)
            res.update(d_empty)
            res.update([])
            res.update(HierarchicalDict())
            self.assertEqual(res, d1, "dict has changed after update by empty dict")
    
    unittest.main()
            