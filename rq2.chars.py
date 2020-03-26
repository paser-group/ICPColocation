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
    arm_list_of_list = [] 
    file_names = np.unique( colocation_df['FILEPATH'].tolist() )    
    for file_name in file_names:
        per_file_df = colocation_df[colocation_df['FILEPATH']==file_name]
        icp_list    = per_file_df['TYPE'].tolist()
        arm_list_of_list.append(icp_list) 

    te = TransactionEncoder()
    te_ary = te.fit(arm_list_of_list).transform(arm_list_of_list)
    df = pd.DataFrame(te_ary, columns=te.columns_)
    frequent_itemsets = apriori(df, min_support=0.0001, use_colnames=True)   ## do not change: min_support=0.0001 

    dict_itemsets = dict( frequent_itemsets.to_dict() ) 
    support_dict = dict_itemsets['support']
    itemset_dict = dict_itemsets['itemsets']    
    identifiers  = support_dict.keys()
    len_items_dict, colocation_dict, file_dict  = {}, {}, {}
    for ID in identifiers:
        support_val = support_dict[ID]
        itemset_val = itemset_dict[ID]
        itemset_len = len(itemset_val) 
        # support count for security smell
        if itemset_len > 1:
            if itemset_len not in len_items_dict:
                len_items_dict[itemset_len] = [support_val] 
                colocation_dict[itemset_len] = [itemset_val]
            else: 
                len_items_dict[itemset_len] = len_items_dict[itemset_len]   +  [support_val]        
                colocation_dict[itemset_len] = colocation_dict[itemset_len] + [itemset_val] 
        # support count for files 
    return  colocation_dict 


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

    DIFF_COLOCATION_DICT = getFilesWithDiffColocations(colocation_df) 
    files_with_diff_colocation = DIFF_COLOCATION_DICT.values() 


if __name__=='__main__':
    colocation_file = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/ICP_Localization/RAW_DATASETS/COLOCATION_INPUT_MOZI.csv'
    full_file       = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/ICP_Localization/RAW_DATASETS/V2_ALL_MOZILLA_PUPPET.csv'

    # dataset_file = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/ICP_Localization/RAW_DATASETS/COLOCATION_INPUT_OSTK.csv'    

    # dataset_file = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/ICP_Localization/RAW_DATASETS/COLOCATION_INPUT_WIKI.csv'    
    print('~'*100) 
    getColocationMapping(colocation_file, full_file) 
    print('~'*100)     