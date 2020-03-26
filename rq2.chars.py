'''
Akond Rahman 
Mar 26 2020 
Thursday 
Characterizing scripts 
'''
import pandas as pd 
import numpy as np 
from collections import Counter 
from mlxtend.preprocessing import TransactionEncoder
from mlxtend.frequent_patterns import apriori
from mlxtend.frequent_patterns import association_rules
import os 
import main_static_metric_extactor

def getFilesWithSameColocations(df_param):
    file_names = np.unique( df_param['FILEPATH'].tolist() )
    file_count = len(file_names) 
    colocate_dict, file_dict  = {}, {}
    for file_name in file_names:
        per_file_df = df_param[df_param['FILEPATH']==file_name]
        icp_list    = per_file_df['TYPE'].tolist()    
        icp_count_dic =  dict( Counter(icp_list) )
        for k_, v_ in icp_count_dic.items():
            if v_  > 1:
                if k_ not in colocate_dict:
                    colocate_dict[k_] = [v_]
                    file_dict[k_]     = [file_name]
                else:
                    colocate_dict[k_] = colocate_dict[k_] + [v_]                    
                    file_dict[k_]     = file_dict[k_] + [file_name]          
    return file_dict 


def getFilesWithDiffColocations(colocation_df):
    diff_file_list = []
    file_names = np.unique( colocation_df['FILEPATH'].tolist() )    
    for file_name in file_names:
        per_file_df = colocation_df[colocation_df['FILEPATH']==file_name]
        icp_list    = per_file_df['TYPE'].tolist()
        icp_dict = dict( Counter(icp_list) )
        if len(icp_dict) > 1:
            for k_, v_ in icp_dict.items():
                diff_file_list.append( file_name )
    diff_file_list = list( np.unique(diff_file_list) )
    return diff_file_list 

def getColocationMapping(colocation_file, full_file):
    colocation_df = pd.read_csv(colocation_file)
    full_df       = pd.read_csv(full_file) 

    NO_ICP_DF           = full_df[full_df['TOTAL'] < 1 ]
    files_with_no_icps  = np.unique( NO_ICP_DF['FILE_NAME'].tolist()  )
    files_with_no_icps  = [x_.replace('/Users/akond/SECU_REPOS/', '/Users/arahman/PRIOR_NCSU/SECU_REPOS/') for x_ in files_with_no_icps ]

    ONLY_ONE_ICP_DF     = full_df[full_df['TOTAL'] == 1 ]
    files_with_only_one = np.unique( ONLY_ONE_ICP_DF['FILE_NAME'].tolist()  )
    files_with_only_one  = [x_.replace('/Users/akond/SECU_REPOS/', '/Users/arahman/PRIOR_NCSU/SECU_REPOS/') for x_ in files_with_only_one ]

    MORE_THAN_ONE_ICP_DF = full_df[full_df['TOTAL'] > 1 ]
    files_with_more_one  = np.unique( MORE_THAN_ONE_ICP_DF['FILE_NAME'].tolist()  )
    files_with_more_one  = [x_.replace('/Users/akond/SECU_REPOS/', '/Users/arahman/PRIOR_NCSU/SECU_REPOS/') for x_ in files_with_more_one ]

    SAME_COLOCATION_DICT = getFilesWithSameColocations(colocation_df) 
    files_with_same_colocation = list (SAME_COLOCATION_DICT.values())[0] 
    files_with_same_colocation  = [x_.replace('/Users/akond/SECU_REPOS/', '/Users/arahman/PRIOR_NCSU/SECU_REPOS/') for x_ in files_with_same_colocation ]

    files_with_diff_colocation = getFilesWithDiffColocations(colocation_df) 
    files_with_diff_colocation  = [x_.replace('/Users/akond/SECU_REPOS/', '/Users/arahman/PRIOR_NCSU/SECU_REPOS/') for x_ in files_with_diff_colocation ]

    only_files_with_diff_colocation =  [z_ for z_ in files_with_diff_colocation if z_ not in files_with_same_colocation]
    # print( only_files_with_diff_colocation )
    only_files_with_same_colocation =  [z_ for z_ in files_with_same_colocation if z_ not in files_with_diff_colocation]
    # print( only_files_with_same_colocation )
    return files_with_no_icps, files_with_only_one, files_with_more_one, files_with_same_colocation, files_with_diff_colocation, only_files_with_same_colocation, only_files_with_diff_colocation

def getMetricsForAllScripts(none_list, only_one_list, atleast_two): 
    all_file_metrics = []
    atleast_one = only_one_list + atleast_two 
    for file_ in none_list:
        if(os.path.exists(file_)):
            attribute, command, comment, ensure, _file, file_mode, hard_code_, include, sloc, require, ssh_auth, url_ = main_static_metric_extactor.getAllStaticMetricForSingleFile(file_) 
            all_file_metrics.append( (file_, attribute, command, comment, ensure, _file, file_mode, hard_code_, include, sloc, require, ssh_auth, url_, 'NEUTRAL') ) 
    for file_ in atleast_one:
        if(os.path.exists(file_)):
            attribute, command, comment, ensure, _file, file_mode, hard_code_, include, sloc, require, ssh_auth, url_ = main_static_metric_extactor.getAllStaticMetricForSingleFile(file_) 
            all_file_metrics.append( (file_, attribute, command, comment, ensure, _file, file_mode, hard_code_, include, sloc, require, ssh_auth, url_, 'INSECURE') ) 
    metric_df = pd.DataFrame( all_file_metrics ) 
    metric_df.columns = ['FILE_PATH', 'ATTR', 'CMD', 'COMMENT', 'ENS', 'FILE', 'FILE_MODE', 'HARD_CODE', 'INCL', 'SLOC', 'REQ', 'SSH', 'URL', 'STATUS' ]
    return metric_df





if __name__=='__main__':
    colocation_file = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/ICP_Localization/RAW_DATASETS/COLOCATION_INPUT_MOZI.csv'
    full_file       = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/ICP_Localization/RAW_DATASETS/V2_ALL_MOZILLA_PUPPET.csv'

    # colocation_file = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/ICP_Localization/RAW_DATASETS/COLOCATION_INPUT_OSTK.csv'
    # full_file       = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/ICP_Localization/RAW_DATASETS/V2_ALL_OPENSTACK_PUPPET.csv'

    # colocation_file = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/ICP_Localization/RAW_DATASETS/COLOCATION_INPUT_WIKI.csv'
    # full_file       = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/ICP_Localization/RAW_DATASETS/V2_ALL_WIKIMEDIA_PUPPET.csv'

    print('~'*100) 
    full_file_tuple  = getColocationMapping(colocation_file, full_file) 
    script_metric_df = getMetricsForAllScripts(full_file_tuple[0], full_file_tuple[1], full_file_tuple[2] ) 
    print(script_metric_df.head()) 
    print(script_metric_df.shape) 
    print('~'*100)     