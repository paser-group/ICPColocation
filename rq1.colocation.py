'''
Akond Rahman 
Mar 25 2020 
Find out which categories colocate and their frequency 
'''
# reff: http://rasbt.github.io/mlxtend/user_guide/frequent_patterns/association_rules/
import pandas as pd
from mlxtend.preprocessing import TransactionEncoder
from mlxtend.frequent_patterns import apriori
from mlxtend.frequent_patterns import association_rules
import numpy as np 


def doColocation(arm_list_of_list):
    te = TransactionEncoder()
    te_ary = te.fit(arm_list_of_list).transform(arm_list_of_list)
    df = pd.DataFrame(te_ary, columns=te.columns_)
    frequent_itemsets = apriori(df, min_support=0.0001, use_colnames=True)
    # print( dir( frequent_itemsets)  )    
    dict_itemsets = dict( frequent_itemsets.to_dict() ) 
    # print(dict_itemsets) 
    support_dict = dict_itemsets['support']
    itemset_dict = dict_itemsets['itemsets']    
    identifiers  = support_dict.keys()
    len_items_dict = {}
    for ID in identifiers:
        support_val = support_dict[ID]
        itemset_val = itemset_dict[ID]
        itemset_len = len(itemset_val) 
        if itemset_len not in len_items_dict:
            len_items_dict[itemset_len] = [support_val] 
        else: 
            len_items_dict[itemset_len] = len_items_dict[itemset_len]   +  [support_val]             

    print(len_items_dict) 

    # support_list = []
    # for _, v_ in support_dict.items():
    #     support_list.append(v_) 
    # print(min(support_list), max(support_list)) 


def weakCrypto(single_val):
    categ = ''
    if single_val=='SECURITY:::BASE64:::' or single_val=='SECURITY:::MD5:::':
        categ = 'SECURITY:::WEAKCRYPTO:::'
    else:
        categ = single_val 
    return categ


def filterDataframe(file_df):
    filtered_df = file_df[file_df['TYPE']!= 'SECURITY:::HARD_CODED_SECRET_USER_NAME:::']
    filtered_df = filtered_df[filtered_df['TYPE']!= 'SECURITY:::HARD_CODED_SECRET_PASSWORD:::']

    filtered_df['TYPE'] = filtered_df['TYPE'].apply(weakCrypto)
    return filtered_df 

def findColocation(file_name):
    arm_list = []
    file_df = pd.read_csv(file_name) 
    file_df = filterDataframe( file_df )

    file_names = np.unique( file_df['FILEPATH'].tolist() )
    for file_name in file_names:
        per_file_df = file_df[file_df['FILEPATH']==file_name]
        icp_list    = per_file_df['TYPE'].tolist()
        arm_list.append(icp_list) 
    # print(arm_list) 
    doColocation( arm_list )


if __name__=='__main__':
    dataset_file = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/ICP_Localization/RAW_DATASETS/COLOCATION_INPUT_MOZI.csv'

    # dataset_file = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/ICP_Localization/RAW_DATASETS/COLOCATION_INPUT_OSTK.csv'    

    # dataset_file = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/ICP_Localization/RAW_DATASETS/COLOCATION_INPUT_WIKI.csv'    
    findColocation(dataset_file)
