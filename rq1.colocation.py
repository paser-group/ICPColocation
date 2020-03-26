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
from collections import Counter


def singleColocation(df_):
    file_names = np.unique( df_['FILEPATH'].tolist() )
    file_count = len(file_names) 
    colocate_dict, file_dict  = {}, {}
    for file_name in file_names:
        per_file_df = df_[df_['FILEPATH']==file_name]
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
    # print(colocate_dict) 
    print('='*50)
    print('Smell-wise calculation')
    print('='*50)
    for k, v in colocate_dict.items():
        type_df = df_[df_['TYPE']==k]
        type_count, _ = type_df.shape 
        type_colocated = sum(v) 
        type_perc    = round(float( type_colocated )/float(type_count), 5) * 100
        print('TYPE:{}, ALL:{}, COLOCATED:{}, PERC:{}'.format(k, type_count, type_colocated, type_perc))
        print('-'*25) 
    print('='*50)
    print('File-wise calculation')
    print('='*50)
    for k, v in file_dict.items():
        type_df = df_[df_['TYPE']==k]
        type_count     = len( np.unique( type_df['FILEPATH'].tolist() ) )
        type_colocated = len( np.unique(v)  ) 
        type_perc    = round(float( type_colocated )/float(type_count), 5) * 100
        print('TYPE:{}, ALL:{}, COLOCATED:{}, PERC:{}'.format(k, type_count, type_colocated, type_perc))
        print('-'*25) 
    print('='*50)           


def multiColocationARM(arm_df, file_count):
    for row in arm_df.itertuples():
        len_itemset = len(list( row[2]) ) 
        if len_itemset > 1:
            print('*'*25)
            print('File analysis ... ')
            print('*'*25)
            print('TYPE:{}, PERC:{}'.format( list(row[2]) , round( row[1]  , 5) * 100 ) )
            print('*'*25)
    dict_itemsets = dict( arm_df.to_dict() ) 
    # print(dict_itemsets) 
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
    

    return len_items_dict, colocation_dict 


        
def doColocation(arm_list_of_list, tx_cnt):
    te = TransactionEncoder()
    te_ary = te.fit(arm_list_of_list).transform(arm_list_of_list)
    df = pd.DataFrame(te_ary, columns=te.columns_)
    frequent_itemsets = apriori(df, min_support=0.0001, use_colnames=True)   ## do not change: min_support=0.0001 
    multiColocationARM(frequent_itemsets, tx_cnt) 

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
    file_count = len(file_names) 
    
    for file_name in file_names:
        per_file_df = file_df[file_df['FILEPATH']==file_name]
        icp_list    = per_file_df['TYPE'].tolist()
        arm_list.append(icp_list) 
    doColocation( arm_list , file_count ) 
    doDifferentColocation( file_df  )


if __name__=='__main__':
    dataset_file = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/ICP_Localization/RAW_DATASETS/COLOCATION_INPUT_MOZI.csv'

    # dataset_file = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/ICP_Localization/RAW_DATASETS/COLOCATION_INPUT_OSTK.csv'    

    # dataset_file = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/ICP_Localization/RAW_DATASETS/COLOCATION_INPUT_WIKI.csv'    
    findColocation(dataset_file)
