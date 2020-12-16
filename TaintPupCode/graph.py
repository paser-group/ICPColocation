'''
Akond Rahman 
Dec 09, 2020 
Leverage parser output to generate graphs 
'''
import os 
import constants 
import parser 
var_tracker_list  = [] 

def checkLiveness( var_ , all_vari_dict ): 
    aliveFlag = True 
    '''
    all_vari_dict has a different format than smell_vari_dict 
    '''
    for var_name_, var_data in all_vari_dict.items():
        var_value  = var_data[-1]
        var_name_  = var_name_.strip() 
        '''
        need to check if variable value is being changed from RHS and re-assigned agin 
        like $a = $a + 1 , for this aliveFlag is False for $a 
        '''
        if( var_ == var_name_ ) :
            if( var_ in var_value ):
                aliveFlag = False 
    return aliveFlag 

def trackTaint( smell_type, smell_dict_var, all_attrib_dict, all_vari_dict ):
    graphDict = {}
    if(len(smell_dict_var) > 0 ):
        for var_count, var_data in smell_dict_var.items():
            var_name,  var_value, var_ascii = var_data 
            '''
            first check if variable is used in an expression 
            '''
            if( checkLiveness( var_name, all_vari_dict ) ): 
                # print( var_name  + ' is alive ' )
                '''
                Now we have support for mutltiple taint tracking 
                '''
                multi_taint_var_name = doMultipleTaint( var_name, all_vari_dict  )
                var_tracker_list.clear() ## clear cache once you are done, var_tracker_list is a global variable and clear everytime 
                for attr_cnt, attr_data in all_attrib_dict.items():
                    '''
                    all_attrib_dict has a different format than smell_attrib_dict 
                    '''
                    attr_name  = attr_data[-2] 
                    attr_value = attr_data[-1] 
                    # print(var_name , multi_taint_var_name, attr_value)   
                    enh_var_name =  constants.DOLLAR_SYMBOL + constants.LPAREN_SYMBOL + var_name.replace(constants.DOLLAR_SYMBOL, constants.NULL_SYMBOL )  + constants.RPAREN_SYMBOL  ##need to handle ${url}
                    if( var_name in attr_value ) or (enh_var_name in attr_value) or (multi_taint_var_name in attr_value):  
                        '''
                        one variable can be used for multiple attributes 
                        '''
                        if var_name not in graphDict:
                            graphDict[var_name] = [(attr_name, attr_value , smell_type) ] 
                        else: 
                            graphDict[var_name] = graphDict[var_name] + [ (attr_name, attr_value , smell_type)  ]
    return graphDict 


def constructLHSRHSPairs( var_to_track,  var_dic ):
    '''
    var_dic has a different format than smell_attrib_dict as it is all_var_dict 
    '''
    for var_, var_data  in var_dic.copy().items(): 
        lhs , rhs = var_ , var_data[-1] 
        enh_var_to_track = var_to_track.replace(constants.DOLLAR_SYMBOL, constants.NULL_SYMBOL) 
        if  (var_to_track in rhs) or (enh_var_to_track in rhs) :  
            if var_to_track in var_dic:
                del var_dic[var_to_track]
                constructLHSRHSPairs( lhs, var_dic ) 
                var_tracker_list.append( lhs  )
        else: 
            pass 
     



def doMultipleTaint(var_to_track, all_var_dict):
    var2ret = constants.MULTI_TAINT_NONSENSE 
    '''
    algorithm : keep track of LHS for which RHS exists using a queue 
    then return the latest inserted element of the queue 
    '''
    constructLHSRHSPairs( var_to_track,   all_var_dict ) 
    if len( var_tracker_list ) > 0: 
        var2ret = var_tracker_list[0] 
    return var2ret 

def getReferredScriptName(cls_name, module_name):
    cls_name = cls_name.replace( constants.RESOURCE_KEYWORD , constants.NULL_SYMBOL)
    cls_name = cls_name.replace( constants.LPAREN_SYMBOL , constants.NULL_SYMBOL)
    cls_name = cls_name.replace( constants.NEWLINE_CONSTANT , constants.NULL_SYMBOL)
    cls_name = cls_name.replace( constants.WHITESPACE_SYMBOL , constants.NULL_SYMBOL)
    cls_name = cls_name.replace( constants.QUOTE_SYMBOL , constants.NULL_SYMBOL)
    splitted_list = cls_name.split( constants.COLON_SYMBOL * 2  )  ## synatx is ::<module_name>::script
    splitted_list = [z_ for z_ in splitted_list if len(z_) > 0  and z_ != module_name ]
    # print(cls_name)
    # print(splitted_list) 
    reff_script_path = constants.SLASH_SYMBOL.join( splitted_list )
    # print( reff_script_path )
    # print('='*50)
    return  reff_script_path 


def getReferredScripts( class_dic , script_path): 
    scripts2track      = []
    script_module_path = script_path.replace( constants._DATASET_PATH ,  constants.NULL_SYMBOL )
    script_module_name = script_module_path.split( constants.SLASH_SYMBOL )[0] 
    script_module_name = script_module_name.replace( constants.PUPPET_KW, constants.NULL_SYMBOL )
    script_module_name = script_module_name.replace( constants.MONTH_DATA_KW, constants.NULL_SYMBOL ) 
    for class_index, class_data in class_dic.items(): 
        class_attrs = class_data[-1] 
        class_name  = class_data[0]
        reff_path =getReferredScriptName( class_name, script_module_name )
        full_script_path = constants._DATASET_PATH + constants.PUPPET_KW + script_module_name + constants.MONTH_DATA_KW + constants.SLASH_SYMBOL + constants.MANIFESTS_KW + constants.SLASH_SYMBOL  + reff_path + constants.PP_EXTENSION
        if  os.path.exists( full_script_path ) : 
            scripts2track.append( full_script_path  ) 
    return scripts2track
    

if __name__=='__main__':
    # script_name = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/fuel-plugin-onos-2018-06/deployment_scripts/puppet/manifests/onos-dashboard.pp'
    script_name = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/FixFalsePositive/sample-puppet-scripts/onos-dasboard.pp' 
    dict_of_resources, dict_of_classes, dict_of_all_attribs, dict_of_all_variables, dict_of_switch_cases, list_of_susp_comments , dict_of_funcs = parser.executeParser( script_name )
    # print( dict_of_all_variables )
    sink_var = doMultipleTaint( '$password' ,  dict_of_all_variables )
    print(sink_var) 