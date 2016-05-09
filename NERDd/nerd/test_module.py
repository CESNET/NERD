"""NERD module for testing UpdateManager"""

from .module import NERDModule
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
    
    def __init__(self, update_manager):
        update_manager.register_handler(
            self.setB, # function (or bound method) to call
            ('A',), # tuple/list/set of attributes to watch (their update triggers call of the registered method)
            ('B',) # tuple/list/set of attributes the method may change
        )
        update_manager.register_handler(
            self.setA, ('!NEW',), ('A',) 
        )
        update_manager.register_handler(
            self.setType, ('!NEW',), ('type','type_desc') 
        )
        update_manager.register_handler(
            self.setC, ('A','B'), ('C') 
        )
        update_manager.register_handler(
            self.sleep, ('!sleep',), None 
        )
    
    def setB(self, ekey, rec, attributes_changed):
        """
        Set a 'B' attribute to the value of an 'A' attribute concatenated with 
        'extended by B'.
        
        Arguments:
        etype, key -- entity type and key (e.g. 'ip', '192.0.2.42')
        rec -- record currently assigned to the key
        attributes_changed -- a set of attributes whose change has triggerd this call
        
        Returns:
        dict describing attribute changes {attr_name -> new_value}
        """
        return {'B': rec['A'] + ' extended by B'}
    
    def setA(self, ekey, rec, attributes_changed):
        return {'A': 'Value of A'}
    
    def setType(self, ekey, rec, attributes_changed):
        return {
            'type': ekey[0],
            'type_desc': 'This is record of type {}'.format(ekey[0])
        }
    
    def setC(self, ekey, rec, attributes_changed):
        upd = {}
        if 'A' in attributes_changed:
            upd['C'] = 'A changed'
        if 'B' in attributes_changed:
            upd['C'] = 'B changed'
        return upd
    
    def sleep(self, ekey, rec, attributes_changed):
        time.sleep(2)
        return None
