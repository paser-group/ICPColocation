'''
Akond Rahman 
Dec 13, 2020 
Constants needed to do testing 
'''

common_error_string = 'DOES NOT MATCH:::Should be '

_multi_taint_script_name    = '../puppet-scripts/onos-dasboard.pp' 
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

