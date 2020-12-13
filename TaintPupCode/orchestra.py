'''
Akond Rahman 
Dec 09, 2020
Orchestrate parser and graph generator 
'''

import constants 
import parser 
import os 
from collections import Counter 
import graph 
import requests 

def getPuppetFiles(path_to_dir):
    valid_  = [] 
    for root_, dirs, files_ in os.walk( path_to_dir ):
       for file_ in files_:
           full_p_file = os.path.join(root_, file_)
           if(os.path.exists(full_p_file)):
             if (full_p_file.endswith( constants.PP_EXTENSION  )):
               valid_.append(full_p_file)
    return valid_ 

def finalizeSusps(ls):
    return len(ls) 

def finalizeSwitches( dic_ ): 
    no_default_count = 0 
    for k_, v_ in dic_.items():
        branches = v_[-1]
        default_flag = False 
        for branch_count, branch_content in branches.items():
            if constants.CASE_DEFAULT_KEYWORD in branch_content[-1]:
                default_flag = True 
        if default_flag == False : 
            no_default_count += 1 
    return no_default_count


def sanitizeConfigVals(config_data):
    valid_config_data = constants.VALID_CONFIG_DEFAULT 
    if(constants.IP_ADDRESS_PATTERN in config_data) and (constants.YUM_KW not in config_data) :
        valid_config_data = config_data.replace(constants.QUOTE_SYMBOL, constants.NULL_SYMBOL)
    elif(  constants.HTTP_PATTERN in config_data ):
        valid_config_data = config_data.replace(constants.WHITESPACE_SYMBOL, constants.NULL_SYMBOL)
    elif(  constants.XTRA_HTTP_PATTERN in config_data ):
        valid_config_data = config_data.replace(constants.WHITESPACE_SYMBOL, constants.NULL_SYMBOL)
    data_value =  valid_config_data.strip() 
    data_ascii = sum([ ord(y_) for y_ in data_value ])     
    return data_ascii



def finalizeInvalidIPs(attr_dict, dict_vars):
    output_attrib_dict, output_variable_dict = {}, {}
    for attr_key, attr_data in attr_dict.items():
        attr_name  = attr_data[-2] 
        attr_value = attr_data[-1]
        attr_ascii = sanitizeConfigVals( attr_value )
        if attr_ascii == 330 or attr_ascii == 425: # 330 is the total of '0.0.0.0', 425  is the total of '0.0.0.0/0'
            output_attrib_dict[attr_name] = (attr_value, attr_ascii)  # keeping ascii for debugging in taint tracking 
    for var_name, var_data in dict_vars.items():
        var_value = var_data[-1]
        var_ascii = sanitizeConfigVals( var_value )
        if var_ascii == 330 or var_ascii == 425:  
            output_variable_dict[var_name] = (var_value, var_ascii) 
    return  output_attrib_dict, output_variable_dict # dict will help in taint tracking 

def extraHTTPCheck(_valu):
    flag_ = True
    if(constants.LOCALHOST_KEYWORD in _valu) or (constants.CONCAT_KEYWORD in _valu) or ( constants.LOCAL_IP_KEYWORD in _valu ) or ( constants.DOLLAR_SYMBOL in _valu):
        flag_ = True 
    else: 
        third_slash_loc, cnt  = 0 , 0
        for z in range( len(_valu) ):
            if _valu[z] == constants.SLASH_SYMBOL :
                cnt += 1 
            if cnt == 3: 
                third_slash_loc = z 
        url_string = _valu[0:z]
        url_list   = url_string.split(constants.COLON_SYMBOL)
        http_part  = url_list[0] + constants.AN_S + constants.COLON_SYMBOL
        url_string = http_part + constants.NULL_SYMBOL.join( url_list[1:] )
        try:
            r = requests.head( url_string  ) 
            if r.status_code < 400:
                flag_ = True 
        except Exception as e_:
            flag_ = False 

    return flag_

def finalizeHTTP(attr_dict, dict_vars):
    output_attrib_dict, output_variable_dict = {}, {}
    for attr_key, attr_data in attr_dict.items():
        attr_name  = attr_data[-2] 
        attr_value = attr_data[-1]
        attr_ascii = sanitizeConfigVals( attr_value )
        if (attr_ascii >= 600) and ( constants.HTTP_PATTERN in attr_value) and (extraHTTPCheck( attr_value ) ): # 600 is the total of 'http://'
            output_attrib_dict[attr_name] = (attr_value, attr_ascii)  # keeping ascii for debugging in taint tracking 
    for var_name, var_data in dict_vars.items():
        var_value = var_data[-1]
        var_ascii = sanitizeConfigVals( var_value )
        if (var_ascii >= 600) and ( constants.HTTP_PATTERN in var_value) and (extraHTTPCheck( var_value) ): # 600 is the total of 'http://'
            output_variable_dict[var_name] = (var_value, var_ascii) 
        elif constants.XTRA_HTTP_PROTO_KW in var_name and  (var_ascii ==  448 or var_ascii == 526) : ### need to handle $magnum_protocol = 'http', ascii for 'http' is 448
            output_variable_dict[var_name] = (var_value, var_ascii)             

    return output_attrib_dict, output_variable_dict # dict will help in taint tracking 

def finalizeWeakEncrypt(func_dict):
    weak_count  = 0 
    weak_dict   = {}
    for func_count, func_data in func_dict.items():
        func_name = func_data[0] 
        if constants.MD5_KEYWORD in func_name: 
            weak_dict += 1 
            weak_dict[weak_count] = func_name , constants.MD5_KEYWORD            
        elif  constants.SHA1_KEYWORD in func_name:
            weak_dict += 1 
            weak_dict[weak_count] = func_name, constants.SHA1_KEYWORD
    return weak_dict

def checkIfValidSecret(single_config_val):
    flag2Ret = False 
    config_val = single_config_val.strip() 
    if ( any(x_ in config_val for x_ in constants.INVALID_SECRET_CONFIG_VALUES ) ):
        flag2Ret = False 
    else:
        if(  len(config_val) > 2 ) and ( constants.QUOTE_SYMBOL in config_val ) :
            flag2Ret = True 
    return flag2Ret

def checkIfEmptyPass(single_config_val):
    flag2Ret = False 
    if ( any(x_ in single_config_val for x_ in constants.INVALID_SECRET_CONFIG_VALUES ) ):
        flag2Ret = False 
    else:
        single_config_val = single_config_val.strip() 
        if(  len(single_config_val) == 2 ) and ( constants.QUOTE_SYMBOL in single_config_val ) : ## we want to detect stuff like $password = ''
            flag2Ret = True 
    return flag2Ret

def isValidUserName(uName): 
    valid = True
    if( any(z_ in uName for z_ in constants.FORBIDDEN_USER_VALUES) ): 
        valid = False  
    return valid

def isValidKeyName(keyName): 
    valid = True
    if( any(z_ in keyName for z_ in constants.FORBIDDEN_KEY_VALUES) ): 
        valid = False  
    return valid

def isValidPassword(pName): 
    valid = True
    if( any(z_ in pName for z_ in constants.FORBIDDEN_PASS_VALUES) ): 
        valid = False  
    return valid

def finalizeHardCodedSecrets( attr_dict, vars_dict ):
    secret_attr_dict , secret_var_dict = {}, {} 
    for attr_key, attr_data in attr_dict.items():
        attr_name  = attr_data[-2] 
        attr_value = attr_data[-1]
        attr_name  = attr_name.strip() 
        if(any(x_ in attr_name for x_ in constants.SECRET_PASSWORD_LIST )) and (checkIfValidSecret ( attr_value ) ) and (isValidPassword( attr_name )):        
            secret_attr_dict[attr_name] =  attr_value, constants.OUTPUT_PASS_KW
        elif(any(x_ in attr_name for x_ in constants.SECRET_USER_LIST )) and (checkIfValidSecret ( attr_value ) ) and (isValidUserName( attr_name ) ) :        
            secret_attr_dict[attr_name] =  attr_value, constants.OUTPUT_USER_KW
        elif(any(x_ in attr_name for x_ in constants.SECRET_KEY_LIST )) and (checkIfValidSecret ( attr_value ) ) and (isValidKeyName( attr_name ) ) :        
            secret_attr_dict[attr_name] =  attr_value , constants.OUTPUT_TOKEN_KW
    for var_name, var_data in vars_dict.items():
        var_value  = var_data[-1]
        var_name   = var_name.strip() 
        if(any(x_ in var_name for x_ in constants.SECRET_PASSWORD_LIST )) and (checkIfValidSecret ( var_value ) ) and ( isValidPassword( var_name ) ):        
            secret_var_dict[var_name] = var_value, constants.OUTPUT_PASS_KW
        elif(any(x_ in var_name for x_ in constants.SECRET_USER_LIST )) and (checkIfValidSecret ( var_value ) ) and (isValidUserName( var_name ) ):        
            secret_var_dict[var_name] = var_value, constants.OUTPUT_USER_KW 
        elif(any(x_ in var_name for x_ in constants.SECRET_KEY_LIST )) and (checkIfValidSecret ( var_value ) ) and (isValidKeyName( var_name ) ) :        
            secret_var_dict[var_name] = var_value, constants.OUTPUT_TOKEN_KW
    return secret_attr_dict, secret_var_dict  

def finalizeEmptyPassword( attr_dict, vars_dict ):
    empty_attr_dict , empty_var_dict = {}, {} 
    for attr_key, attr_data in attr_dict.items():
        attr_name  = attr_data[-2] 
        attr_value = attr_data[-1]
        attr_name  = attr_name.strip() 
        if(any(x_ in attr_name for x_ in constants.SECRET_PASSWORD_LIST )) and (checkIfEmptyPass ( attr_value ) ):        
            empty_attr_dict[attr_name] =  attr_value, constants.OUTPUT_EMPTY_KW
    for var_name, var_data in vars_dict.items():
        var_value  = var_data[-1]
        var_name   = var_name.strip() 
        if(any(x_ in var_name for x_ in constants.SECRET_PASSWORD_LIST )) and (checkIfEmptyPass ( var_value ) ):        
            empty_var_dict[var_name] = var_value, constants.OUTPUT_EMPTY_KW
    return empty_attr_dict, empty_var_dict  

def checkIfAdmin(single_config_val):
    flag2Ret = False 
    if ( any(x_ in single_config_val for x_ in constants.INVALID_SECRET_CONFIG_VALUES ) ):
        flag2Ret = False 
    else:
        if(  len(single_config_val) > 0 ) and ( constants.QUOTE_SYMBOL in single_config_val )  and ( constants.ADMIN_KEYWORD in single_config_val) : 
            flag2Ret = True 
    return flag2Ret

def finalizeDefaults( vars_dict ):
    default_var_dict = {} 
    for var_name, var_data in vars_dict.items():
        var_value  = var_data[-1]
        var_name   = var_name.strip() 
        if(any(x_ in var_name for x_ in constants.SECRET_USER_LIST )) and (checkIfAdmin ( var_value ) ):        
            default_var_dict[var_name] = var_value, constants.OUTPUT_DEFAULT_ADMIN_KW 
    return default_var_dict      

def orchestrateWithoutTaint(dir_):
    all_pupp_files = getPuppetFiles(  dir_ )
    for pupp_file in all_pupp_files:
        dict_reso, dict_clas, dict_all_attr, dict_all_vari, dict_switch, list_susp_comm, dict_func = parser.executeParser( pupp_file ) 

        susp_cnt       = finalizeSusps( list_susp_comm )
        switch_cnt     = finalizeSwitches( dict_switch )
        weak_crypt_dic = finalizeWeakEncrypt( dict_func ) 
        default_admin_dict   = finalizeDefaults( dict_all_vari )

        invalid_ip_dict_attr, invalid_ip_dict_vars  = finalizeInvalidIPs( dict_all_attr, dict_all_vari ) 
        tot_invalid_ip_cnt = len(invalid_ip_dict_attr) + len(invalid_ip_dict_vars)

        http_dict_attr, http_dict_vars = finalizeHTTP( dict_all_attr, dict_all_vari )
        tot_http_cnt = len(http_dict_attr) + len(http_dict_vars)

        
        secret_dict_attr, secret_dict_vars = finalizeHardCodedSecrets( dict_all_attr, dict_all_vari )
        total_secret_count = len(secret_dict_attr) + len(secret_dict_vars) 
        
        empty_pwd_attr, empty_pwd_vars = finalizeEmptyPassword( dict_all_attr, dict_all_vari  )
        tot_empty_pass_count = len( empty_pwd_attr ) + len(empty_pwd_vars)


        print( pupp_file, susp_cnt, switch_cnt , tot_invalid_ip_cnt, tot_http_cnt, len(weak_crypt_dic )  , total_secret_count , tot_empty_pass_count , len(default_admin_dict ) )
        print('-'*100)


def orchestrateWithTaint(dir_):
    all_pupp_files = getPuppetFiles(  dir_ )
    for pupp_file in all_pupp_files:
        dict_reso, dict_clas, dict_all_attr, dict_all_vari, dict_switch, list_susp_comm, dict_func = parser.executeParser( pupp_file ) 

        susp_cnt       = finalizeSusps( list_susp_comm )
        switch_cnt     = finalizeSwitches( dict_switch )
        weak_crypt_dic = finalizeWeakEncrypt( dict_func ) 
        default_admin_dict   = finalizeDefaults( dict_all_vari )

        invalid_ip_dict_attr, invalid_ip_dict_vars  = finalizeInvalidIPs( dict_all_attr, dict_all_vari ) 
        invalid_ip_taint_dict = graph.trackTaint( constants.OUTPUT_INVALID_IP_KW, invalid_ip_dict_vars, dict_all_attr, dict_all_vari )
        
        http_dict_attr, http_dict_vars = finalizeHTTP( dict_all_attr, dict_all_vari )
        http_taint_dict = graph.trackTaint( constants.OUTPUT_HTTP_KW, http_dict_vars, dict_all_attr, dict_all_vari )

        secret_dict_attr, secret_dict_vars = finalizeHardCodedSecrets( dict_all_attr, dict_all_vari )
        secret_taint_dict                  = graph.trackTaint( constants.OUTPUT_SECRET_KW, secret_dict_vars, dict_all_attr, dict_all_vari )

        empty_pwd_attr, empty_pwd_vars = finalizeEmptyPassword( dict_all_attr, dict_all_vari  )
        empty_pwd_taint_dict           = graph.trackTaint( constants.OUTPUT_EMPTY_KW, empty_pwd_vars, dict_all_attr, dict_all_vari )        


        # if  'packstack/manifests/keystone/' in pupp_file:
        print( 'INVALID_IP:::ATTR:{} \n DETCTED_DICT:{} \n TAINTED_DICT:{}'.format( invalid_ip_dict_attr,  invalid_ip_dict_vars , invalid_ip_taint_dict )  )
        print( 'HTTP:::ATTR_DICT:{} \n DETECTED_DICT:{} \n TAINTED_DICT:{}'.format( http_dict_attr, http_dict_vars, http_taint_dict )  )
        # print( empty_pwd_vars, empty_pwd_taint_dict ) 
        print( 'SECRETS:::VAR_DETECTED_DICT:{} \n TAINTED_DICT:{} \n SECRETS:::ATTR_DETECTED_DICT:{}'.format( secret_dict_vars, secret_taint_dict, secret_dict_attr )  )
        print( pupp_file )
        # print( dict_all_vari )

        print('-'*100)

        


if __name__=='__main__':
    test_pp_dir = '../puppet-scripts/'
    # orchestrateWithoutTaint( test_pp_dir )

    orchestrateWithTaint( test_pp_dir )
