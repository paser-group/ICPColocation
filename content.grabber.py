'''
Content extractor ... unrealted to the project 
Akond Rahman 
June 09, 2020 
'''
import os 

def getContent(file_name):
    _text = ''
    with open(file_name, 'r', encoding='latin-1') as file_:
        _text = file_.read() 
    return _text    


def dumpContentIntoFile(strP, fileP):
  fileToWrite = open( fileP, 'w')
  fileToWrite.write(strP )
  fileToWrite.close()
  return str(os.stat(fileP).st_size)

def dumpContent(dir_, ext , out_fil):
    count = 0 
    full_content = ''
    for root_, _, filenames in os.walk(dir_):
        for file_ in filenames:
            full_path_file = os.path.join(root_, file_) 
            if (full_path_file.startswith('.')==False) and (os.path.exists( full_path_file ) ) :
                if ( full_path_file.endswith(  ext )   ):
                    count += 1 
                    txt_content = getContent(full_path_file)
                    per_file_content = '='*50 + '\n' + full_path_file + '\n' + '='*50 + txt_content + '\n' + 'Count:' + str(count) + '\n' + 'Decision:' + '\n' + '='*50 + '\n'
                    full_content = full_content + per_file_content  
    bytes_ = dumpContentIntoFile( full_content, out_fil )
    print('Dumped a file of {} bytes'.format( bytes_ ) ) 


if __name__=='__main__':
    pupp_dire = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/'
    chef_dire = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-chef/'
    ansi_dire = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-ansi/'      

    dumpContent(pupp_dire, '.pp',    'FULL_PUPPET_CONTENT_2020.txt')
    dumpContent(chef_dire, '.rb',    'FULL_CHEF_CONTENT_2020.txt')
    dumpContent(ansi_dire, '.yaml',  'FULL_ANSIBLE1_CONTENT_2020.txt')   
    dumpContent(ansi_dire, '.yml',  'FULL_ANSIBLE2_CONTENT_2020.txt')      