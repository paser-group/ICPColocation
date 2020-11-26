cat("\014") 
options(max.print=1000000)
t1 <- Sys.time()


# DS_FILE   <- "/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/ICP_Localization/RAW_DATASETS/COLOCATED_MOZILLA.csv"
# DS_FILE   <- "/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/ICP_Localization/RAW_DATASETS/COLOCATED_OPENSTACK.csv"
# DS_FILE   <- "/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/ICP_Localization/RAW_DATASETS/COLOCATED_WIKIMEDIA.csv"

DATAFRAME <- read.csv(DS_FILE)

### ICP_STATUS ... Column# index is 14
print("--------ICP_STATUS_START-------")
ICP_STATUS_DATAFRAME <- DATAFRAME[ -c(1, 15, 16) ]
# print(head(ICP_STATUS_DATAFRAME))

logit_results <- glm(ICP_STATUS ~ ., data = ICP_STATUS_DATAFRAME, family = "binomial")
summary(logit_results) 

print("--------ICP_STATUS_END-------")

### COLOCATED_STATUS ... Column# index is 15
print("--------COLOCATED_STATUS_START-------")
COLOCATED_STATUS_DATAFRAME <- DATAFRAME[ -c(1, 14, 16) ]
# print(head(COLOCATED_STATUS_DATAFRAME))

logit_results <- glm(COLOCATED_STATUS ~ ., data = COLOCATED_STATUS_DATAFRAME, family = "binomial")
summary(logit_results)
print("--------COLOCATED_STATUS_END-------")

### SAME_DIFF_STATUS ... Column# index is 16
print("--------SAME_DIFF_STATUS_START-------")
SAME_DIFF_DATAFRAME <- DATAFRAME[ -c(1, 14, 15) ]

logit_results <- glm(SAME_DIFF_STATUS ~ ., data = SAME_DIFF_DATAFRAME, family = "binomial")
summary(logit_results)
print("--------SAME_DIFF_END-------")
print("THE DATASET WAS ...")
print(DS_FILE) 

t2 <- Sys.time()
print(t2 - t1)  
rm(list = setdiff(ls(), lsf.str()))