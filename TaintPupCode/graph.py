'''
Akond Rahman 
Dec 09, 2020 
Leverage parser output to generate graphs 
'''
import constants 

def checkLiveness( var_ , all_vari_dict ): 
    aliveFlag = True 
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
        for var_name, var_data in smell_dict_var.items():
            var_value, var_ascii = var_data 
            if( checkLiveness( var_name, all_vari_dict ) ): 
                # print( var_name  + ' is alive ' )
                for attr_key, attr_data in all_attrib_dict.items():
                    attr_name  = attr_data[-2] 
                    attr_value = attr_data[-1] 
                    enh_var_name =  constants.DOLLAR_SYMBOL + constants.LPAREN_SYMBOL + var_name.replace(constants.DOLLAR_SYMBOL, constants.NULL_SYMBOL )  + constants.RPAREN_SYMBOL  ##need to handle ${url}
                    if( var_name in attr_value ) or (enh_var_name in attr_value) :  
                        '''
                        one variable can be used for multiple attributes 
                        '''
                        if var_name not in graphDict:
                            graphDict[var_name] = [(attr_name, attr_value , smell_type) ] 
                        else: 
                            graphDict[var_name] = graphDict[var_name] + [ (attr_name, attr_value , smell_type)  ]
    return graphDict 
