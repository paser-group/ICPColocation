'''
Akond Rahman 
Dec 09, 2020
Orchestrate parser and graph generator 
'''

import constants 
import parser 
import os 
from collections import Counter 

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


def orchestrate(dir_):
    all_pupp_files = getPuppetFiles(  dir_ )
    for pupp_file in all_pupp_files:
        dict_reso, dict_clas, dict_all_attr, dict_all_vari, dict_switch, list_susp_comm = parser.executeParser( pupp_file ) 
        susp_count   = finalizeSusps( list_susp_comm )
        switch_count = finalizeSwitches( dict_switch )
        print( pupp_file, susp_count, switch_count )


if __name__=='__main__':
    test_pp_dir = '../puppet-scripts/'
    orchestrate( test_pp_dir )
