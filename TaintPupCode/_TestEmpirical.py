import unittest 
import _test_constants
import EmpiricalAnalysis 


class TestEmpiricalAnalysis( unittest.TestCase ):

    def testInvalidIPEffects(self):     
        affectCount = EmpiricalAnalysis.mineNotUsedSmells( _test_constants._empirical_script_ip )[0] 
        self.assertEqual(2, affectCount ,  _test_constants.common_error_string + str(2)  )   

    def testHTTPEffects(self):     
        affectCount = EmpiricalAnalysis.mineNotUsedSmells( _test_constants._empirical_script_http )[1] 
        self.assertEqual(6, affectCount ,  _test_constants.common_error_string + str(6)  )   

    def testSecretEffects(self):     
        affectCount = EmpiricalAnalysis.mineNotUsedSmells( _test_constants._empirical_script_secret )[2] 
        self.assertEqual(19, affectCount ,  _test_constants.common_error_string + str(19)  )   

    def testEmptyPassEffects(self):     
        affectCount = EmpiricalAnalysis.mineNotUsedSmells( _test_constants._empirical_script_empty )[3] 
        self.assertEqual(24, affectCount ,  _test_constants.common_error_string + str(24)  )   

    def testDefaultAdminEffects(self):     
        affectCount = EmpiricalAnalysis.mineNotUsedSmells( _test_constants._empirical_script_d_adm )[4] 
        self.assertEqual(1, affectCount ,  _test_constants.common_error_string + str(1)  ) 

    def testWeakCryptoEffects(self):     
        affectCount = EmpiricalAnalysis.mineNotUsedSmells( _test_constants._empirical_script_md5 )[5] 
        self.assertEqual(1, affectCount ,  _test_constants.common_error_string + str(1)  ) 


if __name__ == '__main__':
    unittest.main()
