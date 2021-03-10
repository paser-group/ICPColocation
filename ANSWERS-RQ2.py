'''
Akond Rahman 
Mar 07, 2021 
Answer to RQ2
'''
import pandas as pd 
import numpy as np 


def getHopCount( file_ ):
    print('*'*50)
    print('H-O-P-C-O-U-N-T')
    print('*'*50)
    print( file_ )
    print('*'*50)
    overall_hops = []
    df_ = pd.read_csv( file_ )
    smells = np.unique( df_['SMELL_TYPE'].tolist() )
    for smell_ in smells:
        per_smell_hops = [] 
        smell_df = df_[df_['SMELL_TYPE']==smell_] 
        scripts  = np.unique(  smell_df['FILE_NAME'].tolist() )
        for script in scripts:
            hop_cnt_per_script =  smell_df[smell_df['FILE_NAME']==script]['HOP_COUNT'].tolist()
            per_smell_hops = per_smell_hops + hop_cnt_per_script
            overall_hops   = overall_hops + hop_cnt_per_script
        print('*'*50)
        print('SMELL:{}, MIN:{}, MEDIAN:{}, MAX:{}'.format( smell_, min(per_smell_hops), np.median( per_smell_hops ), max(per_smell_hops)  )  )
        print('*'*50)
    print('ALL, MIN:{}, MEDIAN:{}, MAX:{}'.format(  min( overall_hops ), np.median( overall_hops ), max( overall_hops )  )  )    
    print('*'*50)        


def getValidTaints( file_ ):
    print('*'*50)
    print('V-A-L-I-D-T-A-I-N-T')
    print('*'*50)
    print( file_ )
    print('*'*50)
    overall_used_vars, overall_smelly_count, overall_used_count = [], [], []
    df_ = pd.read_csv( file_ )
    smells = np.unique( df_['SMELL_TYPE'].tolist() )
    for smell_ in smells:
        per_smell_used_vars, per_smell_smellY_count, per_smell_used_count = [] , [], []
        smell_df = df_[df_['SMELL_TYPE']==smell_] 
        scripts  = np.unique(  smell_df['FILE_NAME'].tolist() )
        for script in scripts:
            smelly_vars_per_script =  smell_df[smell_df['FILE_NAME']==script]['SMELLY_VARS'].tolist()[0]
            used_vars_per_script   =  smell_df[smell_df['FILE_NAME']==script]['USED_SMELLY_VARS'].tolist()[0]
            if smelly_vars_per_script > 0 :
                valid_prop_taint       = round( float(used_vars_per_script) / float(smelly_vars_per_script) , 5) * 100
                per_smell_used_vars.append( valid_prop_taint ) 
                overall_used_vars.append( valid_prop_taint )
                per_smell_smellY_count.append( smelly_vars_per_script )
                overall_smelly_count.append( smelly_vars_per_script )
                per_smell_used_count.append( used_vars_per_script )
                overall_used_count.append( used_vars_per_script )
        if len(per_smell_used_vars) > 0 :
            print('SMELL:{}, MIN:{}, MEDIAN:{}, MAX:{}'.format( smell_, min(per_smell_used_vars), np.median( per_smell_used_vars ), max(per_smell_used_vars)  )  )
            valid_prop_smell = round(float(sum(per_smell_used_count)) / float(sum(per_smell_smellY_count)), 5) * 100
            print('SMELL:{}, TOTAL:{}, VALID-PROP:{}'.format( smell_, sum(per_smell_smellY_count) , valid_prop_smell  ) )
            print('*'*50)
    print('ALL, MIN:{}, MEDIAN:{}, MAX:{}'.format(  min( overall_used_vars ), np.median( overall_used_vars ), max( overall_used_vars )  )  )    
    overall_prop_smell = round(float(sum(overall_used_count)) / float(sum(overall_smelly_count)), 5) * 100
    print('ALL, TOTAL:{}, VALID-PROP:{}'.format(  sum(overall_smelly_count), overall_prop_smell  )  )
    print('*'*50)  


if __name__ == '__main__':
    # ORG_ = 'WIKI'
    # ORG_ = 'OSTK'
    # ORG_ = 'MOZI'    
    # ORG_ = 'GITLAB'
    # ORG_ = 'GITHUB'        

    notused_file_name = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/FixFalsePositive/output/NOTUSED_'  + ORG_  + '.csv'
    hopcnt_file_name  = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/FixFalsePositive/output/HOPCOUNT_' + ORG_  + '.csv'

    getHopCount( hopcnt_file_name )
    getValidTaints( notused_file_name )