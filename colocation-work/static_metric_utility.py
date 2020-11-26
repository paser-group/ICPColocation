'''
Feb 18, 2017
Akond Rahman
utility stuff for metric extraction code
'''
import os, csv, numpy as np
theCompleteCategFile='/Users/akond/Documents/AkondOneDrive/OneDrive/IaC-Defect-Categ-Project/output/New.Categ.csv'


def getPuppetFileDetails():
    dictOfAllFiles={}
    dict2Ret={}
    with open(theCompleteCategFile, 'rU') as file_:
      reader_ = csv.reader(file_)
      next(reader_, None)
      for row_ in reader_:
        repo_of_file       = row_[1]
        categ_of_file      = row_[3]
        full_path_of_file  = row_[4]
        if full_path_of_file not in dictOfAllFiles:
            dictOfAllFiles[full_path_of_file] = [[ categ_of_file ], repo_of_file]
        else:
            dictOfAllFiles[full_path_of_file][0] = dictOfAllFiles[full_path_of_file][0] + [ categ_of_file ]
    for k_, v_ in dictOfAllFiles.items():
       uniq = np.unique(v_[0])
       if ((len(uniq)==1) and (uniq[0]=='N')):
         dict2Ret[k_] = ('0', v_[1])
       else:
         dict2Ret[k_] = ('1', v_[1])
    return dict2Ret




def dumpContentIntoFile(strP, fileP):
  fileToWrite = open( fileP, 'w');
  fileToWrite.write(strP );
  fileToWrite.close()
  return str(os.stat(fileP).st_size)


def createDataset(str2Dump, datasetNameParam):
   headerOfFile0='org,file_,'
   #headerOfFile1='pkg_usg,url_usg,file_usg,location_usg,SLOC,location_per_sloc,incl_usg,req_usg,ens_usg,unless_usg,before_usg,'
   headerOfFile1='url_usg,file_usg,location_usg,SLOC,req_usg,ens_usg,'
   #headerOfFile2='dependency,dependency_per_sloc,define_usg,reff_usg,cond_usg,namenode_usg,cron_usg,param_usg,hard_code,'
   headerOfFile2='dependency,reff_usg,hard_code,'
   #headerOfFile3='hard_code_per_sloc,comment_cnt,comm_cnt_per_SLOC,run_int,command_cnt,path_cnt,ssh_auth_cnt,file_mode_cnt,'
   headerOfFile3='hard_code_per_sloc,comment_cnt,command_cnt,file_mode_cnt,'
   #headerOfFile4='role_cnt,secu_cnt,secu_cnt_per_SLOC,svc_cnt,nameserver_cnt,ip_cnt,virt_cnt,net_cnt,net_cnt_per_SLOC,'
   headerOfFile4='secu_cnt,'
   #headerOfFile5='LINT_ERR_CNT,LINT_ERR_RATE,LINT_WARN_CNT,LINT_WARN_RATE,'
   #headerOfFile5='LINT_WARN_RATE,'
   #headerOfFile6='tot_churn_SLOC,churn_per_SLOC,churn_del_per_SLOC,tot_churn_per_del_churn,churnday_per_SLOC,tot_churn_cnt,'
   headerOfFile6='tot_churn_SLOC,churn_per_SLOC,churn_del_per_SLOC,tot_churn_cnt,'
   headerOfFile7='defect_status'

   #headerStr = headerOfFile0 + headerOfFile1 + headerOfFile2 + headerOfFile3 + headerOfFile4 + headerOfFile5 + headerOfFile6 + headerOfFile7
   headerStr = headerOfFile0 + headerOfFile1 + headerOfFile2 + headerOfFile3 + headerOfFile4  + headerOfFile6 + headerOfFile7

   str2Write = headerStr + '\n' + str2Dump
   return dumpContentIntoFile(str2Write, datasetNameParam)
