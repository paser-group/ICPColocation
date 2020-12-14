import graph
import unittest 
import _test_constants
import parser 
import orchestra 

class TestTaintGraph( unittest.TestCase ):

    def testMultiLevelTaint( self ): 
        _, _, _, dict_of_all_variables, _, _ , _ = parser.executeParser( _test_constants._multi_taint_script_name )
        sink_var =  graph.doMultipleTaint( _test_constants._multi_taint_var_input ,  dict_of_all_variables ) 
        self.assertEqual(  sink_var , _test_constants._multi_taint_var_output, _test_constants._multi_taint_var_error_msg) 

    def testLiveness(self):
        _, _, _, dict_of_all_variables, _, _ , _ = parser.executeParser( _test_constants._liveness_script_name )
        for var2test in _test_constants._liveness_var_input_list:
            self.assertTrue( graph.checkLiveness( var2test, dict_of_all_variables ) ,_test_constants._liveness_error_msg  )
    
    def testSecretUname(self):            
        _, _, dict_all_attr, dict_all_vari, _, _, _ = parser.executeParser( _test_constants._single_taint_script_name ) 
        _, secret_dict_vars =  orchestra.finalizeHardCodedSecrets( dict_all_attr, dict_all_vari )  
        self.assertTrue( _test_constants._single_taint_var in  secret_dict_vars , _test_constants._single_taint_error_true)
        self.assertEqual( secret_dict_vars[_test_constants._single_taint_var][-1] , _test_constants._single_taint_type, _test_constants._single_taint_error_msg ) 
        secret_taint_dict = graph.trackTaint( _test_constants.OUTPUT_SECRET_KW, secret_dict_vars, dict_all_attr, dict_all_vari )
        self.assertTrue( _test_constants._single_taint_dict_key in  secret_taint_dict , _test_constants._single_taint_error_true)

if __name__ == '__main__':
    unittest.main()

    