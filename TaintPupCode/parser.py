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

if __name__=='__main__':
    test_pp_file = 'test.api.pp'
    file_comment_dict = parseComments( test_pp_file )
