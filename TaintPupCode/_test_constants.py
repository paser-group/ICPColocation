'''
Akond Rahman 
Dec 13, 2020 
Constants needed to do testing 
'''

common_error_string = 'DOES NOT MATCH:::Should be '

_multi_taint_script_name    = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/FixFalsePositive/sample-puppet-scripts/onos-dasboard.pp' 
_multi_taint_var_input      = '$password'
_multi_taint_var_output     = '$json_message'
_multi_taint_var_error_msg  = common_error_string + _multi_taint_var_output 

_liveness_script_name    = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/packstack-2018-06/packstack/puppet/modules/packstack/manifests/keystone/gnocchi.pp'
_liveness_var_input_list = [  '$auth_name', '$password', '$public_url', '$admin_url', '$internal_url', '$public_url_s3', '$admin_url_s3', '$internal_url_s3' ]
_liveness_error_msg      = common_error_string + 'TRUE' 

_single_taint_script_name = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-ec2api-2018-06/manifests/db/postgresql.pp' 
_single_taint_var         = 'user' 
_single_taint_dict_key    = 'user' 
_single_taint_type        = 'USERNAME' 
_single_taint_error_true  = common_error_string + 'TRUE' 
_single_taint_error_msg   = common_error_string + 'user' 
OUTPUT_SECRET_KW          = 'HARD_CODED_SECRET'

_susp_script_1 = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/wiki-pupp/puppet-2018-06/modules/profile/manifests/planet.pp'
_susp_script_2 = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/wiki-pupp/puppet-2018-06/manifests/realm.pp' 
_susp_error_msg   = common_error_string + '5'


_missing_default_script_name =  'test.api.pp' 
_missing_default_script2     = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/wiki-pupp/puppet-2018-06/modules/profile/manifests/locales/all.pp'
_missing_default_script3     = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-tripleo-2018-06/manifests/profile/base/pacemaker.pp'
_missing_default_script4     = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/fuel-library-2018-06/deployment/puppet/openstack_tasks/manifests/roles/cinder.pp'
_missing_default_script5     = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/fuel-library-2018-06/deployment/puppet/openstack_tasks/manifests/openstack_cinder/openstack_cinder.pp'
_missing_default_script6     = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-tripleo-2018-06/manifests/profile/pacemaker/database/mysql_bundle.pp'
_missing_default_script7     = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-tripleo-2018-06/manifests/haproxy.pp'
_missing_default_script8     = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/fuel-library-2018-06/deployment/puppet/openstack_tasks/manifests/ceilometer/controller.pp'
_missing_default_script9     = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-tripleo-2018-06/manifests/profile/base/gnocchi/api.pp'
_missing_default_script10    = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-tripleo-2018-06/manifests/profile/base/glance/api.pp'
_missing_default_msg         = common_error_string + '1'
_present_default_script_name = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/FixFalsePositive/sample-puppet-scripts/manifests/params.switch.case.pp'
_present_default_msg         = common_error_string + '0'

_invalid_ip_script_name1 = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/FixFalsePositive/sample-puppet-scripts/manifests/init1.pp' 
_invalid_ip_script_name2 = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/FixFalsePositive/sample-puppet-scripts/manifests/init2.pp' 
_invalid_ip_script_name3 = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/packstack-2018-06/packstack/puppet/modules/packstack/manifests/magnum.pp'
_invalid_ip_msg1         = common_error_string + '1'
_invalid_ip_msg0         = common_error_string + '0'

_http_var_script_name    = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/FixFalsePositive/sample-puppet-scripts/manifests/auth.pp' 
_http_msg_1              = common_error_string + '1'
_http_msg_0              = common_error_string + '0'
_http_attr_script_name   = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/FixFalsePositive/sample-puppet-scripts/onos-dasboard.pp'

_weak_cryp_script_name    = 'test.api.pp' 
_weak_cryp_msg_           = common_error_string + '3'


_empty_pass_script_name    = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/FixFalsePositive/sample-puppet-scripts/manifests/oozie.pp' 
_empty_pass_msg_           = common_error_string + '1'

_default_adm_script_name   = 'test.api.pp' 
_default_adm_msg_          = common_error_string + '1'

_secret_script_name   = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/FixFalsePositive/sample-puppet-scripts/onos-dasboard.pp' 
_secret_msg_          = common_error_string + '2'
_secret_uname         = 'karaf'
_secret_password      = 'karaf'
_secret_flag_status   = 'TRUE'


_username_script_name   = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/FixFalsePositive/sample-puppet-scripts/manifests/oozie/database/mysql.pp' 

_taintedHttp_script_v1 = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/packstack-2018-06/packstack/puppet/modules/packstack/manifests/keystone/magnum.pp'
_tainted_http_msg_v1   = common_error_string + '3'
_taintedHttp_script_v2 = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/packstack-2018-06/packstack/puppet/modules/packstack/manifests/keystone/manila.pp'
_tainted_http_msg_v2   = common_error_string + '5'
_taintedHttp_script_v3 = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/packstack-2018-06/packstack/puppet/modules/packstack/manifests/keystone/cinder.pp'
_tainted_http_msg_v3   = common_error_string + '9'

OUTPUT_HTTP_KW         = 'INSECURE_HTTP'

_cross_taint_script_1  = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-trove-2018-06/examples/site.pp'
_cross_taint_msg_1     =  common_error_string + '7'
_cross_taint_script_2  = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-magnum-2018-06/examples/magnum.pp' 
_cross_taint_script_3  = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-keystone-2018-06/examples/v3_basic.pp'
_cross_taint_script_4  = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-ironic-2018-06/examples/ironic.pp'
_cross_taint_script_5  = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-ceilometer-2018-06/examples/site.pp'
_cross_taint_script_6  = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-neutron-2018-06/examples/neutron.pp'
_cross_taint_script_7  = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-vitrage-2018-06/examples/vitrage.pp'
_cross_taint_script_8  = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-gnocchi-2018-06/examples/site.pp'

_cross_taint_script_ip = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-sahara-2018-06/examples/basic.pp' 
_cross_taint_script_http = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-ceilometer-2018-06/examples/site.pp'

_weak_crypt_script     = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/FixFalsePositive/sample-puppet-scripts/test.pp' 


_empirical_script_ip     = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/wiki-pupp/puppet-2018-06/modules/memcached/manifests/init.pp'
_empirical_script_http   = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/wiki-pupp/vagrant-2018-06/puppet/modules/role/manifests/raita.pp' 
_empirical_script_secret = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/wiki-pupp/puppet-2018-06/modules/aptrepo/manifests/init.pp'
_empirical_script_empty  = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/wiki-pupp/translatewiki-2018-06/puppet/modules/users/manifests/init.pp'
_empirical_script_d_adm  = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/wiki-pupp/puppet-2018-06/modules/superset/manifests/init.pp'
_empirical_script_md5    = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/wiki-pupp/puppet-2018-06/modules/postgresql/manifests/user.pp'