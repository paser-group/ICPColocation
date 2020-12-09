'''
Akond Rahman 
Dec 09, 2020 
Levarage Built-in Puppet Parser 
'''

import os 
import subprocess 
import constants 

def getContentAsList(path2File):
    data = None 
    with open(path2File, constants.FILE_READ_MODE) as file_:
        data = file_.read()
    data_ls = data.split(constants.NEWLINE_CONSTANT) 
    return data_ls 

def readAsStr(file_):
    file = open(file_, constants.FILE_READ_MODE) 
    full_str = file.read()
    file.close()
    return full_str


def parseComments( file_ ):  
    output_dict , comment_files = {}, []
    data_as_ls = getContentAsList( file_ )  
    comment_as_ls = [z for z in data_as_ls if constants.COMMENT_SYMBOL in z] 
    for comment in comment_as_ls:
        comment = comment.lower() 
        if(any(x_ in comment for x_ in constants.CWE_SUSP_COMMENT_LIST )) and ( constants.DEBUG_KW not in comment ) :
            comment_files.append(  comment )
    
    output_dict[file_] = comment_files
    return output_dict 

def getContentWithStack( parsed_out_file_str ):
    paren_stack = [] 
    tracker_list = []
    for char_index in range(len(parsed_out_file_str)):
        curr_char = parsed_out_file_str[char_index]
        if constants.LPAREN_SYMBOL in curr_char:
                paren_stack.append( char_index )
        if constants.RPAREN_SYMBOL in curr_char:
            if (len(paren_stack) > 0  ):
                returned_elem  = paren_stack.pop(  )
                tracker_list.append(  (returned_elem, char_index) )
    return tracker_list , parsed_out_file_str

def getAttributes(all_locs, all_as_str): 
    attribDict = {}
    for loc_tup in all_locs:
        loc_str = all_as_str[loc_tup[0]+1:loc_tup[-1]]  
        if constants.NEWLINE_CONSTANT not in loc_str and (loc_str.count( constants.ATTRIBUTE_SYMBOL ) == 1 ) : 
            if constants.ATTRIBUTE_SYMBOL in loc_str:
                # print(loc_tup[0], loc_tup[-1], loc_str) 
                key_, value_ = loc_str.split( constants.ATTRIBUTE_SYMBOL  )
                key_, value_ = key_.strip(), value_.strip()
                attribDict[key_] = (loc_tup[0], loc_tup[-1], value_) 
                # print('='*25) 
    return attribDict

def getVars(all_locs, all_as_str): 
    varDict = {}
    for loc_tup in all_locs:
        loc_str = all_as_str[loc_tup[0]+1:loc_tup[-1]]  
        if constants.NEWLINE_CONSTANT not in loc_str: 
            if constants.EQUAL_SYMBOL in loc_str and constants.ATTRIBUTE_SYMBOL not in loc_str : 
                rest_str = loc_str.replace(constants.EQUAL_SYMBOL, constants.NULL_SYMBOL) 
                rest_str = rest_str[1:]
                key_, val_ = rest_str.split(constants.WHITESPACE_SYMBOL)[0], constants.WHITESPACE_SYMBOL.join(rest_str.split(constants.WHITESPACE_SYMBOL)[1:] )
                varDict[key_] = ( loc_tup[0], loc_tup[1], val_  )
    return varDict 

def getResoName( reso_locs, reso_str, the_name = constants.DEFAULT_RESO_NAME ):
    name_cnt_tracker = 0 
    for loc_tup in reso_locs:
        name_cnt_tracker += 1 
        loc_str = reso_str[loc_tup[0]+1:loc_tup[-1]]  
        if( name_cnt_tracker == len(reso_locs) ):
            splitted_strs  = loc_str.split( constants.NEWLINE_CONSTANT )
            the_name = splitted_strs[0]
    return the_name

def getResoType(reso_str):
    reso_kw =  reso_str.split( constants.NEWLINE_CONSTANT  )[0]
    reso_type = reso_kw.split( constants.WHITESPACE_SYMBOL )[-1] 
    return reso_type 

def getResources(all_locs, all_as_str):
    resoDict = {}
    reso_index = 0 
    for loc_tup in all_locs:
        loc_str = all_as_str[loc_tup[0]+1:loc_tup[-1]] 
        if constants.RESOURCE_KEYWORD in loc_str and constants.ARROWHEAD_SYMBOL not in loc_str:     
            reso_index += 1 
            reso_locs,  reso_content = getContentWithStack( loc_str  )  
            attrib_per_reso_dict = getAttributes( reso_locs, reso_content )
            reso_name  = getResoName( reso_locs, reso_content )
            reso_type  = getResoType( reso_content )
            resoDict[ reso_index ] = ( reso_name, reso_type,  loc_tup[0], loc_tup[-1], attrib_per_reso_dict  )
    return resoDict     


def getClassName( all_locs, all_strs , class_name = constants.DEFAULT_CLASS_NAME, inherit_name = constants.DEFAULT_INHERIT_NAME ):
    name_start_pos, name_end_pos = all_locs[0]
    temp_inherit_name = all_strs[name_start_pos + 1 :name_end_pos]
    temp_class_name = all_strs[0 : name_start_pos ]
    if ( constants.CLASS_KEYWORD in temp_class_name ):
        class_name = class_name.replace( constants.CLASS_KEYWORD, constants.NULL_SYMBOL  )        
    if ( constants.INHERITS_KEYWORD in temp_inherit_name ):
        inherit_name = inherit_name.replace( constants.INHERITS_KEYWORD, constants.NULL_SYMBOL  )        
    class_name,  inherit_name = class_name.strip() ,  inherit_name.strip()
    return  class_name,  inherit_name


def getClasses(all_locs, all_as_str):
    classDict = {}
    class_index = 0 
    for loc_tup in all_locs:
        loc_str = all_as_str[loc_tup[0]+1:loc_tup[-1]] 
        if constants.CLASS_KEYWORD in loc_str :     
            class_index += 1 
            class_locs,  class_content = getContentWithStack( loc_str  )  
            class_name, inherit_name = getClassName( class_locs, class_content ) 
            var_per_class_dict = getVars( class_locs, class_content )  
            '''
            Needed to handle arameters and parameters 
            '''
            if constants.ARAMETERS_KEYWORD in var_per_class_dict: del var_per_class_dict[ constants.ARAMETERS_KEYWORD ]          
            if constants.PARAMETERS_KEYWORD in var_per_class_dict: del var_per_class_dict[ constants.PARAMETERS_KEYWORD ]
            classDict[ class_index ] = ( class_name, inherit_name, loc_tup[0], loc_tup[-1], var_per_class_dict )
    return classDict    

def mineParseOutput(parser_output_file):
    full_file_as_str = readAsStr( parser_output_file )
    # print(full_file_as_str) 
    locations, full_content_as_str = getContentWithStack( full_file_as_str )
    dict_of_resources = getResources( locations, full_content_as_str )
    dict_of_classes  = getClasses( locations, full_content_as_str ) 
    print( dict_of_classes )  


def executeParser(pp_file):
    try:
        command2exec = constants.NATIVE_PUPPET_PARSER_CMD +  constants.WHITESPACE_SYMBOL + pp_file + constants.WHITESPACE_SYMBOL + constants.REDIRECT_SYMBOL + constants.WHITESPACE_SYMBOL + constants.TEMP_LOG_FILE 
        subprocess.check_output([constants.BASH_CMD, constants.BASH_FLAG, command2exec])
    except subprocess.CalledProcessError as e_:
        print( str(e_) )
    num_lines = sum(1 for line in open( constants.TEMP_LOG_FILE , constants.FILE_READ_MODE ))
    # print(num_lines) 
    mineParseOutput( constants.TEMP_LOG_FILE )
    os.remove( constants.TEMP_LOG_FILE )


if __name__=='__main__':
    test_pp_file = 'test.api.pp'
    
    # file_comment_dict = parseComments( test_pp_file )

    executeParser( test_pp_file )
