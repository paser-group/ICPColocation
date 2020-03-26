'''
Akond , Feb 17, 2017
Placeholder for all metric extraction: static, process, chrun
'''
import SmellDectector


def getAllStaticMetricForSingleFile(full_path_param):
  puppet_specific_metric_for_file =  SmellDectector.getQualGenratedMetricForFile(full_path_param)
  print("Generated the Puppet specific metrics for:", full_path_param) 
  print("-"*50)
  return puppet_specific_metric_for_file 
