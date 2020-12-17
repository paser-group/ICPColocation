import graph
import unittest 
import _test_constants
import parser 
import orchestra 

'''
Note to self: 
everytime we use var_tracker_list from `graph` , we need to clear this list as it is global ... code in graph.py does not clear it 
'''

class TestCrossScriptTaint( unittest.TestCase ):
    def testCrossScriptClassCount(self):            
        _, dict_clas, _, _, _, _, _ = parser.executeParser( _test_constants._cross_taint_script_1 ) 
        self.assertEqual(  7 , len(dict_clas)  ,  _test_constants._cross_taint_msg_1 ) 

    def testCrossScriptAttrCountV1(self):            
        _, dict_clas, _, _, _, _, _ = parser.executeParser( _test_constants._cross_taint_script_1 ) 
        self.assertEqual(  5 , len(dict_clas[2][-1])  ,  _test_constants.common_error_string + str(5) ) 

    def testCrossScriptAttrCountV2(self):            
        _, dict_clas, _, _, _, _, _ = parser.executeParser( _test_constants._cross_taint_script_1 ) 
        self.assertEqual(  0 , len(dict_clas[1][-1])  ,  _test_constants.common_error_string + str(0) ) 

    def testCrossScriptAttrCountV3(self):            
        _, dict_clas, _, _, _, _, _ = parser.executeParser( _test_constants._cross_taint_script_1 ) 
        self.assertEqual(  1 , len(dict_clas[7][-1])  ,  _test_constants.common_error_string + str(1) ) 

    def testCrossScriptVarCount(self):            
        _, dict_clas, _, _, _, _, _ = parser.executeParser( _test_constants._cross_taint_script_1 ) 
        self.assertEqual(  0 , len(dict_clas[5][-2])  ,  _test_constants.common_error_string + str(0) ) 

    def testCrossScriptReff(self):            
        _, dict_clas, _, _, _, _, _ = parser.executeParser( _test_constants._cross_taint_script_1 ) 
        scripts2Track = orchestra.getReferredScripts( dict_clas , _test_constants._cross_taint_script_1 )
        self.assertEqual(  6 , len( scripts2Track )  ,  _test_constants.common_error_string + str(6) ) 

    def testCrossScriptSecret(self):            
        _, dict_clas, _, _, _, _, _ = parser.executeParser( _test_constants._cross_taint_script_1 ) 
        scripts2Track = orchestra.getReferredScripts( dict_clas , _test_constants._cross_taint_script_1 ) 
        secret_dict  = orchestra.getCrossScriptSecret( scripts2Track, dict_clas ) 

if __name__ == '__main__':
    unittest.main()
