'''
Akond Rahman 
Mar 26 2020 
Thursday 
Characterizing scripts 
'''
from scipy import stats
import pandas as pd
import numpy as np
import cliffsDelta
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
    metric_df.columns = ['FILE_PATH', 'ATTR', 'CMD', 'COMMENT', 'ENS', 'FILE', 'FILE_MODE', 'HARD_CODE', 'INCL', 'SLOC', 'REQ', 'SSH', 'URL', 'ICP_STATUS' ]
    return metric_df


def getColocatedAllScripts(none_list, only_one_list, atleast_two): 
    all_file_flags = []
    for file_ in none_list:
        if(os.path.exists(file_)):
            all_file_flags.append( (file_, 'NEUTRAL') ) 
    for file_ in only_one_list:
        if(os.path.exists(file_)):
            all_file_flags.append( (file_, 'ONLY_ONE') ) 
    for file_ in atleast_two:
        if(os.path.exists(file_)):
            all_file_flags.append( (file_, 'MORE_THAN_ONE') )             
    _df = pd.DataFrame( all_file_flags ) 
    _df.columns = ['FILE_PATH', 'COLOCATED_STATUS' ]
    return _df


def getSameDiffAllScripts(none_, one_, two_, same_, diff_):
    all_file_flags = []
    rest_diff = [z_ for z_ in two_ if ( (z_ not in diff_)  and  ( z_ not in same_)  )   ] 
    for file_ in diff_:
        if(os.path.exists(file_)):
            all_file_flags.append( (file_, 'COLO_DIFF') )     
    for file_ in rest_diff:
        if(os.path.exists(file_)):
            all_file_flags.append( (file_, 'COLO_DIFF') )     
    for file_ in same_:
        if(os.path.exists(file_)):
            all_file_flags.append( (file_, 'COLO_SAME') )  
    for file_ in one_:
        if(os.path.exists(file_)):
            all_file_flags.append( (file_, 'INSECURE') )     
    for file_ in none_:
        if(os.path.exists(file_)):
            all_file_flags.append( (file_, 'NEUTRAL') )         
                        
    _df = pd.DataFrame( all_file_flags ) 
    _df.columns = ['FILE_PATH', 'SAME_DIFF_STATUS' ]
    return _df

def dataGen():
    # colocation_file = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/ICP_Localization/RAW_DATASETS/COLOCATION_INPUT_MOZI.csv'
    # full_file       = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/ICP_Localization/RAW_DATASETS/V2_ALL_MOZILLA_PUPPET.csv'
    # output_file     = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/ICP_Localization/RAW_DATASETS/COLOCATED_MOZILLA.csv'

    # colocation_file = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/ICP_Localization/RAW_DATASETS/COLOCATION_INPUT_OSTK.csv'
    # full_file       = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/ICP_Localization/RAW_DATASETS/V2_ALL_OPENSTACK_PUPPET.csv'
    # output_file     = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/ICP_Localization/RAW_DATASETS/COLOCATED_OPENSTACK.csv'

    # colocation_file = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/ICP_Localization/RAW_DATASETS/COLOCATION_INPUT_WIKI.csv'
    # full_file       = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/ICP_Localization/RAW_DATASETS/V2_ALL_WIKIMEDIA_PUPPET.csv'
    # output_file     = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/ICP_Localization/RAW_DATASETS/COLOCATED_WIKIMEDIA.csv'

    print('~'*100) 
    print(colocation_file) 
    full_file_tuple  = getColocationMapping(colocation_file, full_file) 
    script_metric_df = getMetricsForAllScripts(full_file_tuple[0], full_file_tuple[1], full_file_tuple[2] ) 
    colocation_df    = getColocatedAllScripts(full_file_tuple[0], full_file_tuple[1], full_file_tuple[2] )     
    same_diff_df     = getSameDiffAllScripts(full_file_tuple[0], full_file_tuple[1], full_file_tuple[2], full_file_tuple[4], full_file_tuple[5] )         

    temp_df = script_metric_df.merge( colocation_df, on = ['FILE_PATH']) 
    full_df = temp_df.merge( same_diff_df , on = ['FILE_PATH'] )
    print( full_df.head() ) 
    print('-'*50)        
    print( script_metric_df.shape,  colocation_df.shape, same_diff_df.shape, full_df.shape  ) 
    full_df.to_csv(output_file, index=False, encoding='utf-8')
    print('-'*50)        
    print('~'*100)         

def pairwiseComp(ls_file):
    for dataset_file in ls_file:
        name = dataset_file.split('/')[-1]
        print("Dataset:", name )
        df2read = pd.read_csv(dataset_file)

        features = df2read.columns
        dropcols = ['FILE_PATH', 'ICP_STATUS', 'COLOCATED_STATUS', 'SAME_DIFF_STATUS']
        features2see = [x_ for x_ in features if x_ not in dropcols]
        for feature_ in features2see:
            data_for_feature = df2read[feature_]
            median_, mean_, total_ = np.median(data_for_feature), np.mean(data_for_feature), sum(data_for_feature)
            print("Feature:{}, [ALL DATA] median:{}, mean:{}, sum:{}".format(feature_, median_, mean_, total_  ) )
            print('='*50)
            defective_vals_for_feature     = df2read[df2read['ICP_STATUS']=='INSECURE'][feature_]
            non_defective_vals_for_feature = df2read[df2read['ICP_STATUS']=='NEUTRAL'][feature_]
            '''
            summary time
            '''
            print('THE FEATURE IS:', feature_ )
            print('='*25)
            print("INSECURE:::[MEDIAN]:{}, [MEAN]:{}, [MAX]:{}, [MIN]:{}".format(np.median(list(defective_vals_for_feature)), np.mean(list(defective_vals_for_feature)), max(list(defective_vals_for_feature) ), min(list(defective_vals_for_feature) )   ) )
            print("NEUTRAL :::[MEDIAN]:{}, [MEAN]:{}, [MAX]:{}, [MIN]:{}".format(np.median(list(non_defective_vals_for_feature)), np.mean(list(non_defective_vals_for_feature)),  max(list(non_defective_vals_for_feature)),  min(list(non_defective_vals_for_feature)) ) )
            
            try:
                TS, p = stats.mannwhitneyu(list(defective_vals_for_feature), list(non_defective_vals_for_feature), alternative='greater')
            except ValueError:
                TS, p = 0.0, 1.0 
            cliffs_delta = cliffsDelta.cliffsDelta(list(defective_vals_for_feature), list(non_defective_vals_for_feature))
            print('Feature:{}, p-value:{}, cliffs:{}'.format(feature_, p, cliffs_delta) )
            print('='*50)
        print('*'*100)


if __name__=='__main__':
    '''
    dataGen()
    Generation of data done ... do analysis 
    '''

    mozi_file     = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/ICP_Localization/RAW_DATASETS/COLOCATED_MOZILLA.csv'
    ostk_file     = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/ICP_Localization/RAW_DATASETS/COLOCATED_OPENSTACK.csv'
    wiki_file     = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/ICP_Localization/RAW_DATASETS/COLOCATED_WIKIMEDIA.csv'

    pairwiseComp([mozi_file, ostk_file, wiki_file])