'''
Akond Rahman 
Jan 23, 2021
Script to mine empirical results 
'''

import orchestra


def reportSmellUsage( tup_, smell_type ):
    within_use_count, cross_use_count , used_var_count   = 0, 0 , 0
    total_affected_attribute_count = 0 
    print('='*50)
    print(smell_type)
    print('='*50)
    if len( tup_ ) == 4:
        # the block with cross script taint detection
        within_taint_dict, cross_taint_dict, attr_dict, dict_vars = tup_ 
        used_var_count = len(within_taint_dict) + len(cross_taint_dict) 
        for _, v_ in within_taint_dict.items(): 
            within_use_count = within_use_count + len(v_) 
        for _, v_ in cross_taint_dict.items(): 
            cross_use_count = cross_use_count + len(v_) 

        print('*'*25)
        print('VARIABLE_WITH_SMELL_COUNT:::' + str (len( dict_vars )  ) )
        print('VARIABLE_IN_USE_COUNT:::'     + str (  used_var_count  ) )
        print('*'*25)
        print('WITHIN_VAR_USE_COUNT:::'      + str( within_use_count  ) )
        print('*'*25)
        print('CROSS_VAR_USE_COUNT:::'       + str( cross_use_count  ) )
        print('*'*25)
        # var_use_count = within_use_count     + cross_use_count ## commenting as in cross script taints, attributes flow into classes as variables
        var_use_count = within_use_count
        print('TOTAL_VAR_USE_COUNT:::'       + str( var_use_count  ) )
        print('TOTAL_ATTR_USE_COUNT:::'      + str( len(attr_dict)  ) ) 
        total_affected_attribute_count       = len(attr_dict) + var_use_count
        print('TOTAL_EFFECT_COUNT:::'        + str( total_affected_attribute_count  ) ) 
        print('*'*25)

    elif ( len(tup_) == 2 ) and ( smell_type == 'DEFAULT_ADMIN' ) :
        within_taint_dict, var_with_smell_dict = tup_ 
        used_var_count = len(within_taint_dict) 
        for _, v_ in within_taint_dict.items(): 
            within_use_count = within_use_count + len(v_) 
        print('*'*25)
        print('VARIABLE_WITH_SMELL_COUNT:::' + str (len( var_with_smell_dict )  ) )
        print('VARIABLE_IN_USE_COUNT:::'     + str (  used_var_count  ) )
        print('*'*25)
        print('WITHIN_VAR_USE_COUNT:::'      + str( within_use_count  ) )
        print('TOTAL_VAR_USE_COUNT:::'       + str( within_use_count  ) )
        print('TOTAL_EFFECT_COUNT:::'        + str( within_use_count  ) ) 
        total_affected_attribute_count       = within_use_count 
        print('*'*25)
    elif ( len(tup_) == 2 ) and ( smell_type == 'WEAK_CRYPTO' ) :
        within_taint_dict, var_with_smell_dict = tup_ 
        used_var_count = len(within_taint_dict) 
        # print(within_taint_dict) 
        for _, v_ in within_taint_dict.items(): 
            within_use_count = within_use_count + len(v_) 
        print('*'*25)
        print('VARIABLE_WITH_SMELL_COUNT:::' + str (len( var_with_smell_dict )  ) )
        print('VARIABLE_IN_USE_COUNT:::'     + str (  used_var_count  ) )
        print('*'*25)
        print('WITHIN_VAR_USE_COUNT:::'      + str( within_use_count  ) )
        print('TOTAL_VAR_USE_COUNT:::'       + str( within_use_count  ) )
        print('TOTAL_EFFECT_COUNT:::'        + str( within_use_count  ) ) 
        total_affected_attribute_count       = within_use_count 
        print('*'*25)
    print('='*50)
    return total_affected_attribute_count

def mineNotUsedSmells(pp_file):
    res_tuple = orchestra.doFullTaintForSingleScript( pp_file  )
    _, _, ip_tuple, http_tuple, secret_tuple, empty_pass_tuple, default_admin_tuple, weak_cryp_tuple, _ = res_tuple
    '''
    for suspicious comments and missing default no taint propagation
    resource dict not needed here 
    '''
    invalid_ip_affect_cnt = reportSmellUsage( ip_tuple, 'INVALID_IP' )
    http_affect_cnt       = reportSmellUsage( http_tuple, 'INSECURE_HTTP' )
    secret_affect_cnt     = reportSmellUsage( secret_tuple, 'HARD_CODED_SECRET' )
    empt_pass_affect_cnt  = reportSmellUsage( empty_pass_tuple, 'EMPTY_PASSWORD' )
    default_adm_affect_cnt= reportSmellUsage( default_admin_tuple, 'DEFAULT_ADMIN' )
    weak_cryp_affect_cnt  = reportSmellUsage( weak_cryp_tuple, 'WEAK_CRYPTO' )

    return invalid_ip_affect_cnt , http_affect_cnt , secret_affect_cnt, empt_pass_affect_cnt, default_adm_affect_cnt, weak_cryp_affect_cnt


def reportHopUsage( tup_, smell_type ):
    within_use_count, cross_use_count , used_var_count   = 0, 0 , 0
    total_affected_attribute_count = 0 
    print('='*50)
    print(smell_type)
    print('='*50)
    if len( tup_ ) == 4:
        # the block with cross script taint detection
        within_taint_dict, cross_taint_dict, _, _ = tup_ 



def mineSmellHops(pp_file):
    res_tuple = orchestra.doFullTaintForSingleScript( pp_file  )
    _, _, ip_tuple, http_tuple, secret_tuple, empty_pass_tuple, _, weak_cryp_tuple, _ = res_tuple
    '''
    for suspicious comments and missing default no taint propagation
    resource dict not needed here 
    default admin has no hops by definition of how it flows 
    '''
    # invalid_ip_hop_cnt = reportHopUsage( ip_tuple, 'INVALID_IP' )


    # return invalid_ip_hop_cnt 


if __name__=='__main__':
    # scriptName = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/wiki-pupp/puppet-2018-06/modules/statistics/manifests/user.pp'
    # scriptName   = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/wiki-pupp/puppet-2018-06/modules/memcached/manifests/init.pp'
    scriptName = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/wiki-pupp/vagrant-2018-06/puppet/modules/role/manifests/raita.pp'
    mineNotUsedSmells( scriptName )