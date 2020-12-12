'''
Akond Rahman 
Dec 09, 2020 
Main file to pass in repos 
'''
import orchestra 

if __name__=='__main__':
    # dataset_dir = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/'
    # dataset_dir = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/mozi-pupp/'
    # dataset_dir = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/wiki-pupp/' 
    # 


    dataset_dir = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-octavia-2018-06/'
    orchestra.orchestrateWithTaint( dataset_dir )    