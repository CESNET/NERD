"""NERD module for testing UpdateManager"""

from core.basemodule import NERDModule
import time

class TestModule (NERDModule):
    """
    Testing NERD module.
    
    Event flow specification:
      !NEW -> setType -> type, type_desc
      !NEW -> setA -> A
      A -> setB -> B
      A, B -> setC -> C
      !sleep -> sleep -> None
    """
    
    def __init__(self):
        g.um.register_handler(
            self.setB, # function (or bound method) to call
            ('A',), # tuple/list/set of attributes to watch (their update triggers call of the registered method)
            ('B',) # tuple/list/set of attributes the method may change
        )
        g.um.register_handler(
            self.setA, 'ip', ('!NEW',), ('A',) 
        )
        g.um.register_handler(
            self.setType, 'ip', ('!NEW',), ('type','type_desc') 
        )
        g.um.register_handler(
            self.setC, 'ip', ('A','B'), ('C') 
        )
        g.um.register_handler(
            self.sleep, 'ip', ('!sleep',), None 
        )
    
    def setB(self, ekey, rec, updates):
        """
        Set a 'B' attribute to the value of an 'A' attribute concatenated with 
        'extended by B'.
        
        Arguments:
        etype, key -- entity type and key (e.g. 'ip', '192.0.2.42')
        rec -- record currently assigned to the key
        updates -- specification of updates that triggerd this call
          3-tuple (op, attr, val) or ('event', name, param)
        
        Returns:
        List of 3-tuples describing requested attribute updates or events.
        """
        return [('set', 'B', rec['A'] + ' extended by B')]
    
    def setA(self, ekey, rec, updates):
        return [('set', 'A', 'Value of A')]
    
    def setType(self, ekey, rec, updates):
        return [
            ('set', 'type', ekey[0]),
            ('set', 'type_desc', 'This is record of type {}'.format(ekey[0])),
        ]
    
    def setC(self, ekey, rec, updates):
        update_reqs = []
        for op,key,val in updates:
            update_reqs.append(('add_to_set', 'C', '{} changed'.format(key)))
        return update_reqs
    
    def sleep(self, ekey, rec, updates):
        for event in updates:
            assert(event[1] == '!sleep')
            print()
            print("Sleeping ...")
            print("zZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZ")
            print()
            time.sleep(event[2])
        return None
