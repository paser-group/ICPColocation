import unittest 
import _test_constants
import parser 
import orchestra 

class TestSmells( unittest.TestCase ):

    def testSuspiciousComment( self ): 
        susp_ls = parser.getSuspComments( _test_constants._susp_script_name )
        self.assertEqual(  5 , len(susp_ls) , _test_constants._susp_error_msg) 

    def testMissingDefaultPresence( self ): 
        _, _, _, _, dict_switch, _, _ = parser.executeParser( _test_constants._missing_default_script_name ) 
        no_default_count = orchestra.finalizeSwitches( dict_switch  )
        self.assertEqual(  1 , no_default_count , _test_constants._missing_default_msg) 

    def testPresentDefault( self ): 
        _, _, _, _, dict_switch, _, _ = parser.executeParser( _test_constants._present_default_script_name ) 
        no_default_count = orchestra.finalizeSwitches( dict_switch  )
        self.assertEqual(  0 , no_default_count , _test_constants._present_default_msg) 


    def testInavlidIPPresence( self ): 
        _, _, dict_all_attr, dict_all_vari, _, _, _ = parser.executeParser( _test_constants._invalid_ip_script_name1 ) 
        ip_attr, ip_vars = orchestra.finalizeInvalidIPs( dict_all_attr, dict_all_vari )
        self.assertEqual(  0 , len(ip_attr) , _test_constants._invalid_ip_msg0 ) 
        self.assertEqual(  1 , len(ip_vars) , _test_constants._invalid_ip_msg1 ) 

    def testInavlidIPAbsence( self ): 
        _, _, dict_all_attr, dict_all_vari, _, _, _ = parser.executeParser( _test_constants._invalid_ip_script_name3 ) 
        ip_attr, ip_vars = orchestra.finalizeInvalidIPs( dict_all_attr, dict_all_vari )
        self.assertEqual(  0 , len(ip_vars) , _test_constants._invalid_ip_msg0 ) 
        self.assertEqual(  1 , len(ip_attr) , _test_constants._invalid_ip_msg1 ) 

    def testHTTPForVariables( self ): 
        _, _, dict_all_attr, dict_all_vari, _, _, _ = parser.executeParser( _test_constants._http_var_script_name ) 
        http_attr, http_vars = orchestra.finalizeHTTP( dict_all_attr, dict_all_vari )
        self.assertEqual(  3 , len(http_vars) , _test_constants._http_msg_1 ) 
        self.assertEqual(  0 , len(http_attr) , _test_constants._http_msg_0 )  

    def testHTTPForAttributes( self ): 
        _, _, dict_all_attr, dict_all_vari, _, _, _ = parser.executeParser( _test_constants._http_attr_script_name ) 
        http_attr, http_vars = orchestra.finalizeHTTP( dict_all_attr, dict_all_vari )
        self.assertEqual(  1 , len(http_vars) , _test_constants._http_msg_1 ) 
        self.assertEqual(  1 , len(http_attr) , _test_constants._http_msg_1 )  

    def testWeakCrypto( self ): 
        _, _, _, _, _, _, dict_func = parser.executeParser( _test_constants._weak_cryp_script_name ) 
        dict_ = orchestra.finalizeWeakEncrypt( dict_func )
        self.assertEqual(  1 , len(dict_) , _test_constants._weak_cryp_msg_ ) 

    def testEmptyPasswordForVariables( self ): 
        _, _, dict_all_attr, dict_all_vari, _, _, _ = parser.executeParser( _test_constants._empty_pass_script_name ) 
        _attr, _vars = orchestra.finalizeEmptyPassword( dict_all_attr, dict_all_vari )
        self.assertEqual(  1 , len(  _vars ) , _test_constants._empty_pass_msg_ ) 

    def testDefaultAdmin( self ): 
        _, _, _, dict_all_vari, _, _, _ = parser.executeParser( _test_constants._default_adm_script_name ) 
        _vars = orchestra.finalizeDefaults(  dict_all_vari )
        self.assertEqual(  1 , len(  _vars ) , _test_constants._default_adm_msg_ ) 

    def testHardcodedUser( self ): 
        self.assertTrue( orchestra.isValidUserName( _test_constants._secret_uname ) , _test_constants._secret_flag_status  ) 

    def testHardcodedPass( self ): 
        self.assertTrue( orchestra.isValidPassword( _test_constants._secret_password ) , _test_constants._secret_flag_status  ) 

    def testHardcodedSecret( self ): 
        _, _, dict_all_attr, dict_all_vari, _, _, _ = parser.executeParser( _test_constants._secret_script_name ) 
        _attr, _vars = orchestra.finalizeHardCodedSecrets( dict_all_attr, dict_all_vari )
        self.assertEqual(  2 , len(  _vars ) , _test_constants._secret_msg_ ) 


    def testHardcodedUname( self ): 
        _, _, dict_all_attr, dict_all_vari, _, _, _ = parser.executeParser( _test_constants._username_script_name ) 
        _attr, _vars = orchestra.finalizeHardCodedSecrets( dict_all_attr, dict_all_vari )
        self.assertEqual(  2 , len(  _attr ) , _test_constants._secret_msg_ ) 

if __name__ == '__main__':
    unittest.main()