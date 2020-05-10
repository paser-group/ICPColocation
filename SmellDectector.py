import os
import SourceModel.SM_File


def getQualGenratedMetricForFile(fully_qualaified_path_to_file):
   fileObj                  = SourceModel.SM_File.SM_File(fully_qualaified_path_to_file)

   reff_usg_for_file        = fileObj.getReffCount()
   command_count_for_file   = fileObj.getCommandCount()
   comm_count_for_file      = fileObj.getLinesOfComments()
   ens_usg_for_file         = fileObj.getOnlyEnsureCount()   
   file_usg_for_file        = fileObj.getNoOfFileDeclarations()   
   file_mode_count_for_file = fileObj.getFileModeCount()
   hard_code_for_file       = len(fileObj.getHardCodedStatments())   
   incl_usg_for_file        = fileObj.getOnlyIncludeClassesCount()   
   lines_for_file           = sum(1 for line in open(fully_qualaified_path_to_file))
   req_usg_for_file         = fileObj.getOnlyRequireCount()
   ssh_auth_count_for_file  = fileObj.getSSHAuthCount()
   url_usg_for_file         = fileObj.getURLUsages()
   
   return reff_usg_for_file , command_count_for_file , comm_count_for_file , ens_usg_for_file, file_usg_for_file, file_mode_count_for_file , hard_code_for_file, incl_usg_for_file, lines_for_file, req_usg_for_file, ssh_auth_count_for_file, url_usg_for_file

