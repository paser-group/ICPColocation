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


def findColocation(file_name):
    arm_list = []
    file_df = pd.read_csv(file_name) 
    file_names = np.unique( file_df['FILEPATH'].tolist() )
    for file_name in file_names:
        per_file_df = file_df[file_df['FILEPATH']==file_name]
        icp_list    = per_file_df['TYPE'].tolist()
        arm_list.append(icp_list) 
    print(arm_list) 


if __name__=='__main__':
    dataset_file = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/ICP_Localization/RAW_DATASETS/COLOCATION_INPUT_MOZI.csv'
    findColocation(dataset_file)
