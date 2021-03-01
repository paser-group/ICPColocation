import unittest 
import _test_constants
import parser 
import orchestra 
import constants 
import graph 
import taintpup_main

class TestAggregation( unittest.TestCase ):

    def testTupleCountV1( self ): 
        _, dict_clas, dict_all_attr, dict_all_vari, _, _, _ = parser.executeParser( _test_constants._aggregate_script_ip )         
        invalid_ip_dict_attr, invalid_ip_dict_vars  = orchestra.finalizeInvalidIPs( dict_all_attr, dict_all_vari ) 
        invalid_ip_taint_dict  = graph.trackTaint( constants.OUTPUT_INVALID_IP_KW, invalid_ip_dict_vars, dict_all_attr, dict_all_vari )        
        scripts2Track          = orchestra.getReferredScripts( dict_clas , _test_constants._aggregate_script_ip ) 
        cross_ip_dict          = orchestra.getCrossScriptInvalidIP( scripts2Track, dict_clas ) 
        inavlid_ip_tuple       = ( invalid_ip_taint_dict, cross_ip_dict, invalid_ip_dict_attr, invalid_ip_dict_vars )        
        
        self.assertEqual(  1 , taintpup_main.getCountFromTuple( inavlid_ip_tuple ) , _test_constants.common_error_string + str(1) ) 


    def testTupleCountV2( self ): 
        res_tup  = orchestra.doFullTaintForSingleScript( _test_constants._aggregate_script_http )
        _, _, _, http_tuple, _, _, _, _, _ = res_tup        
        self.assertEqual(  6 , taintpup_main.getCountFromTuple( http_tuple ) , _test_constants.common_error_string + str(2) ) 


if __name__ == '__main__':
    unittest.main()