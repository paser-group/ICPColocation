'''
Akond Rahman 
Jan 23, 2021
Script to mine empirical results 
'''

import orchestra
import constants 


def reportSmellUsage(  tup_, smell_type ):
    res_holder = []
    within_use_count, cross_use_count , used_var_count, affected_by_var_count   = 0, 0 , 0, 0
    total_affected_attribute_count = 0 
    if len( tup_ ) == 4:
        # the block with cross script taint detection
        within_taint_dict, cross_taint_dict, attr_dict, dict_vars = tup_ 
        used_var_count = len(within_taint_dict) + len(cross_taint_dict) 
        for _, v_ in within_taint_dict.items(): 
            within_use_count = within_use_count + len(v_) 
        for _, v_ in cross_taint_dict.items(): 
            cross_use_count = cross_use_count + len(v_) 

        var_with_smell_count = len( dict_vars )
        ## commenting as in cross script taints, attributes flow into classes as variables that are elaredy detected as part of within script taints 
        # var_use_count = within_use_count     + cross_use_count 
        affected_by_var_count = within_use_count
        total_affected_attribute_count       = len(attr_dict) + affected_by_var_count

    elif ( len(tup_) == 2 ) and ( smell_type == constants.OUTPUT_DEFAULT_ADMIN_KW ) :
        within_taint_dict, var_with_smell_dict = tup_ 
        used_var_count = len(within_taint_dict) 
        for _, v_ in within_taint_dict.items(): 
            within_use_count = within_use_count + len(v_) 
        affected_by_var_count = within_use_count
        var_with_smell_count = len( var_with_smell_dict )
        total_affected_attribute_count       = within_use_count 
    elif ( len(tup_) == 2 ) and ( smell_type == constants.OUTPUT_WEAK_ENCR_KW ) :
        within_taint_dict, var_with_smell_dict = tup_ 
        used_var_count = len(within_taint_dict) 
        # print(within_taint_dict) 
        for _, v_ in within_taint_dict.items(): 
            within_use_count = within_use_count + len(v_) 
        affected_by_var_count = within_use_count
        var_with_smell_count = len( var_with_smell_dict )
        total_affected_attribute_count       = within_use_count 

    res_holder.append( ( smell_type,  var_with_smell_count, used_var_count, within_use_count, cross_use_count, affected_by_var_count, total_affected_attribute_count )  )
    return res_holder 

def mineNotUsedSmells(res_tuple):
    _, _, ip_tuple, http_tuple, secret_tuple, empty_pass_tuple, default_admin_tuple, weak_cryp_tuple, _ = res_tuple
    '''
    for suspicious comments and missing default no taint propagation
    resource dict not needed here 
    '''
    invalid_ip_affect_ls = reportSmellUsage(  ip_tuple, constants.OUTPUT_INVALID_IP_KW )
    http_affect_ls       = reportSmellUsage(  http_tuple, constants.OUTPUT_HTTP_KW )
    secret_affect_ls     = reportSmellUsage(  secret_tuple, constants.OUTPUT_SECRET_KW )
    empt_pass_affect_ls  = reportSmellUsage(  empty_pass_tuple, constants.OUTPUT_EMPTY_KW )
    default_adm_affect_ls= reportSmellUsage(  default_admin_tuple, constants.OUTPUT_DEFAULT_ADMIN_KW )
    weak_cryp_affect_ls  = reportSmellUsage(  weak_cryp_tuple, constants.OUTPUT_WEAK_ENCR_KW )

    return invalid_ip_affect_ls , http_affect_ls , secret_affect_ls, empt_pass_affect_ls, default_adm_affect_ls, weak_cryp_affect_ls 


def mineHopUsage(  tup_, smell_type ):
    hop_holder  = []
    if (len(tup_) == 4):  
        # the block with cross script taint detection
        within_taint_dict, _, _, _ = tup_ # skiping cross script tracking, as within script trackign already detects how many hops 
    elif ( len(tup_) == 2  ):
        # the block with within script taint detection
        within_taint_dict, _  = tup_ # skiping cross script tracking, as within script trackign already detects how many hops         
    for var_name, var_track_data in within_taint_dict.items(): 
        for var_data_tuple in var_track_data:
            var_hop_count = var_data_tuple[-1]
            hop_holder.append( ( smell_type,  var_name,  var_hop_count ) )
    # print(hop_holder)
    return hop_holder


def searchResourceForAttr(res_dic, att_nam, var_nam ):
    reso_data_holder = []
    for _, v_  in res_dic.items():
        reso_name, reso_type,  _, _, attrib_per_reso_dict = v_ 
        for _, v1_ in attrib_per_reso_dict.items():
            _, _, attr_, val_ = v1_ 
            # print( attr_, att_nam, var_nam, val_   )
            if  ( att_nam in attr_ )  and ( var_nam in val_ ) :

                reso_data_holder.append(  ( reso_name, reso_type, val_ ) )
    return reso_data_holder

def searchResourceForDefaultAdmin( res_dic, var_nam ): 
    reso_data_holder = []
    for _, v_  in res_dic.items():
        reso_name, reso_type,  _, _, attrib_per_reso_dict = v_ 
        for _, v_ in attrib_per_reso_dict.items():
            _, _,  _, val_ = v_ 
            # print(  var_nam, val_   )
            if  ( var_nam in val_ ) :
                reso_data_holder.append(  ( reso_name, reso_type, val_ ) )
    return reso_data_holder    

def mineAffectedResources( resource_dict, tup_, smell_type ):
    reso_holder  = []
    smell_dict_attr = {}
    if (len(tup_) == 4):  
        # the block with cross script taint detection
        within_taint_dict, _, smell_dict_attr, _ = tup_ # skiping cross script tracking, as within script trackign already detects how many hops 
    elif ( len(tup_) == 2  ):
        # the block with within script taint detection
        within_taint_dict, smell_dict_attr  = tup_ # skiping cross script tracking, as within script trackign already detects how many hops         
    
    if smell_type == constants.OUTPUT_DEFAULT_ADMIN_KW: 
        for var_name, var_track_data in within_taint_dict.items(): 
            reso_list =  searchResourceForDefaultAdmin( resource_dict,  var_name )
            for tu_ in reso_list:
                res_nam, res_typ, _ = tu_ 
                if( any(z_ in res_nam for z_ in constants.INVALID_RESO_NAME_KEYWORDS )  == False  ): 
                    reso_holder.append(  ( res_nam, res_typ, constants.DUMMY_FUNC_ASSIGNEE, var_name , smell_type  )  )
    elif smell_type == constants.OUTPUT_WEAK_ENCR_KW :
        for var_name, var_track_data in within_taint_dict.items(): 
            for var_data_tuple in var_track_data:
                attr_name = var_data_tuple[2] 
                reso_list = searchResourceForAttr( resource_dict, attr_name , var_name )
                for tu_ in reso_list:
                    res_nam, res_typ, _ = tu_ 
                    if( any(z_ in res_nam for z_ in constants.INVALID_RESO_NAME_KEYWORDS )  == False  ): 
                        reso_holder.append(  ( res_nam, res_typ, constants.DUMMY_FUNC_ASSIGNEE, var_name , smell_type  )  )
    else: 
        for var_name, var_track_data in within_taint_dict.items(): 
            for var_data_tuple in var_track_data:
                # print(var_data_tuple)
                attr_name = var_data_tuple[0]
                '''
                HACK 
                '''
                if  (constants.HACK_USER == var_name or constants.HACK_ADMIN_USER == var_name ) :
                    var_name = constants.DOLLAR_SYMBOL + var_name 
                elif  (constants.HACK_ADMIN_USER == var_name) :
                    var_name = constants.DOLLAR_SYMBOL + constants.LCURL_SYMBOL + var_name 
                reso_list = searchResourceForAttr( resource_dict, attr_name , var_name )
                for tu_ in reso_list:
                    res_nam, res_typ, _ = tu_ 
                    if( any(z_ in res_nam for z_ in constants.INVALID_RESO_NAME_KEYWORDS )  == False  ): 
                        reso_holder.append(  ( res_nam, res_typ, attr_name, var_name , smell_type  )  )
    
    if smell_type !=  constants.OUTPUT_WEAK_ENCR_KW :
        for _, attr_smell_data in smell_dict_attr.items():
            attr_name, attr_value, _ =  attr_smell_data 
            reso_list = searchResourceForAttr( resource_dict, attr_name , attr_value )        
            for tu_ in reso_list:
                res_nam, res_typ, _ = tu_ 
                if( any(z_ in res_nam for z_ in constants.INVALID_RESO_NAME_KEYWORDS )  == False  )  : 
                    reso_holder.append(  ( res_nam, res_typ, attr_name, attr_value , smell_type  )  )
    # print(reso_holder) 
    # for tup in reso_holder:
    #     print( tup[1], tup[2],  tup[3])
    '''
    currently reso_holder does not handle duplicates ... need to handle them in post processing 
    '''
    return reso_holder

def mineSmellyResources(pp_res_tuple):
    _, _, ip_tuple, http_tuple, secret_tuple, empty_pass_tuple, default_admin_tuple, weak_cryp_tuple, dict_reso = pp_res_tuple
    invalid_ip_resource_ls, http_resource_ls, secret_resource_ls, empty_pass_resource_ls, weak_crp_resource_ls = [], [], [], [], []
    '''
    for suspicious comments and missing default no taint propagation
    resource dict not needed here 
    default admin has no hops by definition of how it flows 
    '''
    invalid_ip_resource_ls = mineAffectedResources( dict_reso,  ip_tuple, constants.OUTPUT_INVALID_IP_KW )
    http_resource_ls       = mineAffectedResources( dict_reso,  http_tuple, constants.OUTPUT_HTTP_KW ) 
    secret_resource_ls     = mineAffectedResources( dict_reso,  secret_tuple, constants.OUTPUT_SECRET_KW )
    empty_pass_resource_ls = mineAffectedResources( dict_reso,  empty_pass_tuple, constants.OUTPUT_EMPTY_KW )
    d_admin_resource_ls    = mineAffectedResources( dict_reso,  default_admin_tuple, constants.OUTPUT_DEFAULT_ADMIN_KW )
    weak_crp_resource_ls   = mineAffectedResources( dict_reso,  weak_cryp_tuple, constants.OUTPUT_WEAK_ENCR_KW )

    return invalid_ip_resource_ls, http_resource_ls, secret_resource_ls, empty_pass_resource_ls, d_admin_resource_ls, weak_crp_resource_ls


def mineSmellHops(pp_res_tuple ):
    _, _, ip_tuple, http_tuple, secret_tuple, empty_pass_tuple, _, weak_cryp_tuple, _ = pp_res_tuple
    '''
    for suspicious comments and missing default no taint propagation
    resource dict not needed here 
    default admin has no hops by definition of how it flows 
    '''
    invalid_ip_hop_ls = mineHopUsage(  ip_tuple, constants.OUTPUT_INVALID_IP_KW )
    http_hop_ls       = mineHopUsage(  http_tuple, constants.OUTPUT_HTTP_KW )
    secret_hop_ls     = mineHopUsage(  secret_tuple, constants.OUTPUT_SECRET_KW )
    empty_pass_hop_ls = mineHopUsage(  empty_pass_tuple, constants.OUTPUT_EMPTY_KW )
    weak_cryp_hop_ls  = mineHopUsage(  weak_cryp_tuple, constants.OUTPUT_WEAK_ENCR_KW )

    return invalid_ip_hop_ls , http_hop_ls, secret_hop_ls, empty_pass_hop_ls, weak_cryp_hop_ls






if __name__=='__main__': 
    scriptName = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/wiki-pupp/puppet-2018-06/modules/statistics/manifests/user.pp'
    # scriptName   = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/wiki-pupp/puppet-2018-06/modules/memcached/manifests/init.pp'
    # scriptName = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/wiki-pupp/vagrant-2018-06/puppet/modules/role/manifests/raita.pp'
    
    # mineNotUsedSmells( scriptName )

    mineSmellHops( scriptName )