'''
Akond Rahman 
Dec 09, 2020 
Main file to pass in repos 
'''
import orchestra 
import pandas as pd 
import constants 
import pickle
import time 
import  datetime 
import EmpiricalAnalysis 

def getCountFromTuple(tu_):
    cnt  = 0 
    taint_dic, _, attrib_dic , _ = tu_  # we will not use non-tainted security smells so skipping last element of tuple 
    # we will not consider cross dict as we are calculating within script smells 
    # one hard-coded secret can be assigned in more places , so get the list 
    for name_, data_ in taint_dic.items(): 
        cnt = cnt + len( data_ )
    # all attribute secrets are tracked as dictionary index 
    cnt = cnt + len(attrib_dic) 
    return cnt 

def getCountFromDic(dic_):
    cnt  = 0 
    # one hard-coded secret can be assigned in more places , so get the list 
    for name_, data_ in dic_.items(): 
        cnt = cnt + len( data_ )
    return cnt 


def processResults( res_dic, res_csv_name, res_pkl_name ):
    res_holder  = [] 
    insights_not_used_holder, insights_hop_holder, insights_reso_holder = [] , [], []
    for file_name, scan_results in res_dic.items():
        # last element of scan results is dict of resources : will be used later 
        susp_cnt, switch_cnt, ip_tuple, http_tuple, secret_tuple, empty_pass_tuple, default_admin_tuple, weak_cry_tuple, _ = scan_results
        
        ip_count       = getCountFromTuple( ip_tuple )
        http_count     = getCountFromTuple( http_tuple )
        secret_count   = getCountFromTuple( secret_tuple  )
        empty_pass_cnt = getCountFromTuple( empty_pass_tuple )
        
        default_taint_dict, _ = default_admin_tuple # last one is default admin without taint , will not go directly to count
        weak_cry_dic_taint, _ = weak_cry_tuple # last one is weak crypto without taint , will not go directly to count
        dflt_adm_cnt   = getCountFromDic( default_taint_dict )
        weak_cry_cnt   = getCountFromDic( weak_cry_dic_taint )
        
        total_count    = sum( [susp_cnt, switch_cnt, ip_count, http_count, secret_count, empty_pass_cnt, dflt_adm_cnt, weak_cry_cnt] )
        
        full_res_tup   = ( file_name, susp_cnt, switch_cnt, ip_count, http_count, secret_count, empty_pass_cnt, dflt_adm_cnt, weak_cry_cnt, total_count )
        res_holder.append( full_res_tup ) 
        # print( full_res_tup )
        # print('='*80)
        '''
        extra insights zone , segment#1: not used zone 
        '''
        notUsedTuple  =  EmpiricalAnalysis.mineNotUsedSmells(scan_results )
        for list_ in notUsedTuple:
            insights_not_used_holder = insights_not_used_holder + list_ 
        '''
        extra insights zone , segment#2: hop zone 
        '''
        hopTuple  =  EmpiricalAnalysis.mineSmellHops (scan_results )
        for list_ in hopTuple:
            insights_hop_holder = insights_hop_holder + list_ 
        '''
        extra insights zone , segment#3: resource zone 
        '''
        resoTuple  =  EmpiricalAnalysis.mineSmellyResources (scan_results )
        for list_ in resoTuple:
            insights_reso_holder = insights_reso_holder + list_ 


    df_ = pd.DataFrame( res_holder )
    df_.to_csv( res_csv_name, header= constants.CSV_HEADER , index=False, encoding= constants.CSV_ENCODING )
    pickle.dump( res_dic, open( res_pkl_name , constants.PKL_WRITE_MODE ) )

def giveTimeStamp():
  tsObj = time.time()
  strToret = datetime.datetime.fromtimestamp(tsObj).strftime(constants.TIME_FORMAT) 
  return strToret

if __name__=='__main__':
    t1 = time.time()
    print('Started at:', giveTimeStamp() )
    print('*'*100 )

    # dataset_dir = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/'
    # results_csv = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/FixFalsePositive/output/V1_OSTK.csv'
    # results_pkl = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/FixFalsePositive/output/V1_OSTK.pkl'    

    # dataset_dir = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/mozi-pupp/'
    # results_csv = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/FixFalsePositive/output/V1_MOZI.csv'
    # results_pkl = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/FixFalsePositive/output/V1_MOZI.pkl'    
    
    # dataset_dir = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/wiki-pupp/' 
    # results_csv = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/FixFalsePositive/output/V1_WIKI.csv'
    # results_pkl = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/FixFalsePositive/output/V1_WIKI.pkl'
    # # 

    
    full_res_dic  = orchestra.orchestrateWithTaint( dataset_dir )    
    processResults( full_res_dic, results_csv, results_pkl  )
    
    print('*'*100 )
    print('Ended at:', giveTimeStamp() )
    print('*'*100 )
    t2 = time.time()
    time_diff = round( (t2 - t1 ) / 60, 5) 
    print('Duration: {} minutes'.format(time_diff) )
    print( '*'*100  )        