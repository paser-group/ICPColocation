'''
Akond Rahman 
Mar 06, 2021 
Script to answer RQ3 
'''
import pandas as pd 
import numpy as np 
from collections import Counter 

def resoSemantics( reso_resu_file, attr_file_name ):
    reso_types = []
    attr_df  = pd.read_csv( attr_file_name )
    non_zero_df = attr_df[attr_df['TOTAL_AFFECTED_ATTRI'] > 0 ]
    legit_scripts  = np.unique( non_zero_df['FILE_NAME'].tolist() )
    print('*'*50)
    print(reso_resu_file)
    reso_df          = pd.read_csv( reso_resu_file )
    filtered_reso_df = reso_df[reso_df['RESOURCE_TYPE']!='block']
    smell_types      = np.unique( filtered_reso_df['SMELL_TYPE'].tolist() )
    for smell in smell_types:
        smell_df = reso_df[reso_df['SMELL_TYPE']==smell]
        for script_ in legit_scripts:
            script_df  = smell_df[smell_df['FILE_NAME']==script_]
            reso_types = reso_types +  list( np.unique( script_df['RESOURCE_TYPE'].tolist() ) )
        print('*'*50)
        print( 'SMELL:{}, TYPES:{}  '.format( smell,  dict( Counter(  reso_types ) ) )         )
        print('*'*50)

def resoCountPerScript( reso_resu_file, attr_file_name ):
    attr_df  = pd.read_csv( attr_file_name )
    non_zero_df = attr_df[attr_df['TOTAL_AFFECTED_ATTRI'] > 0 ]
    legit_scripts  = np.unique( non_zero_df['FILE_NAME'].tolist() )
    print('*'*50)
    print(reso_resu_file)
    print("AFFECTED_RESOURCES")
    print('*'*50)
    reso_df          = pd.read_csv( reso_resu_file )
    filtered_reso_df = reso_df[reso_df['RESOURCE_TYPE']!='block']
    smell_types      = np.unique( filtered_reso_df['SMELL_TYPE'].tolist() )
    for smell in smell_types:
        per_script_reso_list = []
        smell_df       = reso_df[reso_df['SMELL_TYPE']==smell]
        smelly_scripts = np.unique(  smell_df['FILE_NAME'].tolist()  )
        for per_script in smelly_scripts:
            if per_script in legit_scripts:
                script_df =  smell_df[smell_df['FILE_NAME']==per_script]
                resources =  np.unique( script_df['RESOURCE_NAME'].tolist() )
                per_script_reso_list.append( len(resources) ) 
        print('*'*50)
        print('SMELL:{}, MIN:{}, MEDIAN:{}, MAX:{}'.format( smell, min(per_script_reso_list), np.median(per_script_reso_list), max(per_script_reso_list) )  )
        print('*'*50)                
    


def attribCountPerScript(attr_resu_file): 
    df_ = pd.read_csv( attr_resu_file )
    non_zero_df = df_[df_['TOTAL_AFFECTED_ATTRI'] > 0 ]
    smells      = np.unique(  non_zero_df['SMELL_TYPE'].tolist() )
    print('*'*50)
    print(attr_resu_file)
    print('*'*50)
    print("AFFECTED_ATTRIBUTES")
    print('*'*50)
    for smell_ in smells:
        collector   = [] 
        smell_df = non_zero_df[non_zero_df['SMELL_TYPE']==smell_]
        scripts  = np.unique( smell_df['FILE_NAME'].tolist() )
        for script in scripts:
            script_attrib_list = smell_df[smell_df['FILE_NAME']==script]['TOTAL_AFFECTED_ATTRI'].tolist()
            for script_attrib_cnt in script_attrib_list:
                collector.append( script_attrib_cnt )
        print('*'*50)
        # print(collector)
        print('SMELL:{}, MIN:{}, MEDIAN:{}, MAX:{}'.format( smell_, min(collector), np.median(collector), max(collector) )  )
        print('*'*50)



if __name__=='__main__':
    # org_name       = 'WIKI'
    # org_name       = 'GITLAB'
    # org_name       = 'MOZI'
    # org_name       = 'OSTK'
    # org_name       = 'GITHUB'

    reso_file_name = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/FixFalsePositive/output/RESOURCE_' + org_name  + '.csv'
    attr_file_name = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/FixFalsePositive/output/NOTUSED_'  + org_name  + '.csv'    
    
    resoSemantics( reso_file_name , attr_file_name )
    resoCountPerScript( reso_file_name , attr_file_name )
    attribCountPerScript( attr_file_name )