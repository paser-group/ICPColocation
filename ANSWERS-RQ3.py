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
    all_reso_count = []
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
                all_reso_count.append( len(resources) )
        print('*'*50)
        print('SMELL:{}, MIN:{}, MEDIAN:{}, MAX:{}'.format( smell, min(per_script_reso_list), np.median(per_script_reso_list), max(per_script_reso_list) )  )
        print('*'*50)                
    print('ALL, MIN:{}, MEDIAN:{}, MAX:{}'.format(  min(all_reso_count), np.median(all_reso_count), max(all_reso_count) )  )
    print('*'*50)                    


def attribCountPerScript(attr_resu_file): 
    all_attr_count = []
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
                all_attr_count.append( script_attrib_cnt )
        print('*'*50)
        # print(collector)
        print('SMELL:{}, MIN:{}, MEDIAN:{}, MAX:{}'.format( smell_, min(collector), np.median(collector), max(collector) )  )
        print('*'*50)
    print('ALL, MIN:{}, MEDIAN:{}, MAX:{}'.format(  min(all_attr_count), np.median(all_attr_count), max(all_attr_count) )  )
    print('*'*50)                            


def getsemCount( reso_titles ):
    
    user_cnt, data_storage, file_, web_service , net , pkg = 0 , 0 , 0, 0 ,0 , 0 
    for tit in reso_titles:
        if ( 'sql'  in  tit ) or ('elasti' in tit ) or ('swift' in tit ) or ('cinder' in tit ) or ('memcache' in tit ) or ('redis' in tit ) or ('db' in tit ) or ('etcd' in tit ) or ('kibana' in tit ):
            data_storage = data_storage + 1 
        elif ('file' in tit ) or ('exec' in tit ) :
            file_ = file_ + 1 
        elif ('dns' in tit ) or ('vlan' in tit ) or ('vtp' in tit ) or ('firewall' in tit ) or ('nfv' in tit ):
            net = net + 1 
        elif ('package' in tit ) or ('service' in tit ) or ('nova' in tit ) or ('yum' in tit )or ('repo' in tit ) or ('apt' in tit ) or ('proxy' in tit ) or ('distro' in tit ) or ('install' in tit ): 
            pkg = pkg + 1 
        elif ('apache' in tit) or ('mod' in tit) or ('www' in tit) or ('http' in tit)  or ('url' in tit ) or ('wp' in tit)  or ('wordpress' in tit ) :
            web_service = web_service + 1 
        elif ('user' in tit ) or ('auth' in tit ) or ('token' in tit ) or ('admin' in tit ) or ('cert' in tit ) or ('password' in tit ) or ('ssl' in tit ) or ('ca' in tit ) or ('cred' in tit ):
            user_cnt = user_cnt + 1           
        # else: 
        #     data_storage = data_storage + 1   

    return user_cnt, data_storage, file_, web_service , net , pkg 
    


def getSemanticFreq( org_, file_ ):
    print('='*100)
    print(org_) 
    print('='*100)
    df_           = pd.read_csv( file_ )
    reso_titles   = df_['RESOURCE_NAME'].tolist()
    reso_types    = df_['RESOURCE_TYPE'].tolist() 
    tot_title_cnt = len( reso_titles )

    user_cnt, data_storage, file_, web_service , net , pkg  = getsemCount( reso_titles )
    t_user_cnt, t_data_storage, t_file_, t_web_service , t_net , t_pkg  = getsemCount( reso_types  ) 

    tot_usr  = user_cnt + t_user_cnt 
    tot_data = data_storage + t_data_storage
    tot_file = file_ + t_file_ 
    tot_web  = web_service + t_web_service
    tot_net  = net + t_net
    tot_pkg  = pkg + t_pkg 

    perc_usr =  round( float(tot_usr) / float(tot_title_cnt) *100 , 3) 
    perc_dat =  round( float(tot_data) / float(tot_title_cnt) *100 , 3) 
    perc_fil =  round( float(tot_file) / float(tot_title_cnt) *100 , 3) 
    perc_web =  round( float(tot_web) / float(tot_title_cnt) *100 , 3) 
    perc_net =  round( float(tot_net) / float(tot_title_cnt) *100 , 3) 
    perc_pkg =  round( float(tot_pkg) / float(tot_title_cnt) *100 , 3)         

    print('='*100)
    print('Total affected resources:', tot_title_cnt )
    print('='*100)    
    print('USER:{}, DATA_STORAGE:{}, FILE:{}, WEB:{}, NET:{}, PKG:{}'.format( perc_usr, perc_dat, perc_fil, perc_web, perc_net, perc_pkg  ) )
    print('='*100)    
    


def getLOCOnly( out_fil ):
    print('-'*100)    
    print(out_fil)
    print('-'*100)
    out_df = pd.read_csv( out_fil )
    all_pp_scripts =  np.unique( out_df['SCRIPT'].tolist() )
    print('Count:', len(all_pp_scripts) )
    print('-'*100)    
    tot_loc = 0 
    for pp in all_pp_scripts:
        try:
            pp_loc = sum(1 for line in open( pp , 'r', encoding= 'latin-1' )) 
        except UnicodeDecodeError:
            pp_loc = 10 
        tot_loc = tot_loc + pp_loc 
    print('Size:', tot_loc )        
    print('-'*100)    




if __name__=='__main__':
    # org_name       = 'GITHUB'
    # org_name       = 'GITLAB'
    # org_name       = 'MOZI'
    # org_name       = 'OSTK'
    # org_name       = 'WIKI'

    # reso_file_name = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/FixFalsePositive/output/RESOURCE_' + org_name  + '.csv'
    # attr_file_name = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/FixFalsePositive/output/NOTUSED_'  + org_name  + '.csv'    
    
    # output_file = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/FixFalsePositive/output/V9_WIKI.EVALUATION.csv'
    # getLOCOnly( output_file  )  ## for summary stats 

    # attribCountPerScript( attr_file_name )
    # resoSemantics( reso_file_name , attr_file_name )  ## for RQ3, part 2.a 
    # resoCountPerScript( reso_file_name , attr_file_name ) ## for RQ3, part 1 
    # getSemanticFreq(org_name, reso_file_name )  ## for RQ3, part 2.b




