'''
Akond Rahman 
Mar 26 2020 
Thursday 
Characterizing scripts 
'''
import pandas as pd 
import numpy as np 
from collections import Counter 

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

def getColocationMapping(colocation_file, full_file):
    colocation_df = pd.read_csv(colocation_file)
    full_df       = pd.read_csv(full_file) 

    NO_ICP_DF           = full_df[full_df['TOTAL'] < 1 ]
    files_with_no_icps  = np.unique( NO_ICP_DF['FILE_NAME'].tolist()  )

    ONLY_ONE_ICP_DF     = full_df[full_df['TOTAL'] == 1 ]
    files_with_only_one = np.unique( ONLY_ONE_ICP_DF['FILE_NAME'].tolist()  )

    MORE_THAN_ONE_ICP_DF = full_df[full_df['TOTAL'] > 1 ]
    files_with_more_one  = np.unique( MORE_THAN_ONE_ICP_DF['FILE_NAME'].tolist()  )

    SAME_COLOCATION_DICT = getFilesWithSameColocations(colocation_df) 
    files_with_same_colocation = SAME_COLOCATION_DICT.values() 



if __name__=='__main__':
    colocation_file = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/ICP_Localization/RAW_DATASETS/COLOCATION_INPUT_MOZI.csv'
    full_file       = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/ICP_Localization/RAW_DATASETS/V2_ALL_MOZILLA_PUPPET.csv'

    # dataset_file = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/ICP_Localization/RAW_DATASETS/COLOCATION_INPUT_OSTK.csv'    

    # dataset_file = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/ICP_Localization/RAW_DATASETS/COLOCATION_INPUT_WIKI.csv'    
    print('~'*100) 
    getColocationMapping(colocation_file, full_file) 
    print('~'*100)     