import unittest 
import _test_constants
import orchestra 


class TestIntegration( unittest.TestCase ):

    def testSingleScriptStructure(self):     
        scriptName  = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/fuel-plugin-influxdb-grafana-2018-06/deployment_scripts/puppet/manifests/hiera.pp' 
        icp_tuple   =  orchestra.doFullTaintForSingleScript( scriptName )       
        self.assertEqual(9, len(icp_tuple) ,  _test_constants.common_error_string + str(9)  )   

    def testSingleScriptMissingDefault(self):     
        scriptName  = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/fuel-library-2018-06/deployment/puppet/openstack_tasks/manifests/roles/cinder.pp' 
        icp_tuple   =  orchestra.doFullTaintForSingleScript( scriptName )       
        self.assertEqual(1, icp_tuple[1] ,  _test_constants.common_error_string + str(1)  )   

    # def testFullDirectory(self):     
    #     dirName          = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/' 
    #     icp_dict_per_dir =  orchestra.orchestrateWithTaint( dirName )       
    #     self.assertEqual(2840, len(icp_dict_per_dir) ,  _test_constants.common_error_string + str(2840)  )                       



if __name__ == '__main__':
    unittest.main()
