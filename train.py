import ember
import os
import numpy as np
from ember.features import PEFeatureExtractor
import lightgbm as lgb

#   This directory needs to store the EMBER train and test .dat files
ember_dir="/data/ember2018/"


#   Create EMBER extractor
extractor = PEFeatureExtractor(2)
ndim = extractor.dim

#   Point to where the data is stored
variant_data_directory="kipple-data/data/"
#   Point to where the counts are stored
variant_count_directory="kipple-data/records/"

#   We'll now stage the variants for training
#   This block of code can be customized to which variant data you want to train on

#   This variable stores the length of each memmap'd data array
dat_to_length={}
#   Store the total number of variants we'll be training on
num_to_be_added=0


#   This array is used to ignore specific variants
#   Basically, we look at the filename and if we see any of these keywords, we skip it
skip_variants=[
    "random"                 #   Unused example
    #"msf",                  #   Discard msfvenom variants
    #"pad",                  #   Discard SecML padding variants
    #"malware",              #   Discard malware_rl variants
    #"sorel"                 #   Discard sorel variants
]


#   Now iterate through each record
for record in os.listdir(variant_count_directory):
    #   First, skip it if it's in one of the skip folders
    skip=False
    for name in skip_variants:
        if name in record:
            skip=True
    if skip:
        continue

    #   Get the number of lines in the array
    #with open(variant_count_directory + record, 'rb') as f:
    #    vals=int(f.readlines()[0])
    vals=sum(1 for line in open(variant_count_directory + record))
    num_to_be_added=num_to_be_added+vals

    #   Store this number with the specific file we're looking at
    dat_to_length[record.rstrip().split(".")[0]]=vals

#   Store the total number of variants we're adding    
Q=num_to_be_added

#   Now we'll load the EMBER training data
#   Assumes you've already got it in memmap'd form!
X_train_path = os.path.join(ember_dir, "X_train.dat")
y_train_path = os.path.join(ember_dir, "y_train.dat")
y_train = np.memmap(y_train_path, dtype=np.float32, mode="r")
N = y_train.shape[0]
X_train = np.memmap(X_train_path, dtype=np.float32, mode="r", shape=(N, ndim))

#   Now we'll initialize two new memmap'd arrays that we'll use for the actual training
#   Note the number of rows is N + Q, where N is number of EMBER entries and Q is number of variants
x_adv_train=np.memmap("x_train_adversarial.dat", dtype=np.float32, mode="w+",shape=(N + Q, ndim))
#   Note that "y" retains the label:
#       0  --> benign
#       1  --> malicious
#       -1 --> unknown
y_adv_train=np.memmap("y_train_adversarial.dat", dtype=np.float32, mode="w+",shape=N + Q)

#   Now we copy over the EMBER data into the new array
#   We'll put some examples of how to do this, but the kipple work has three paradigms:
#       1. (retraining)           Retain original EMBER scores
#       2. (portfolio/all)        Include all EMBER data as benign/score each as 0s
#       3. (portfolio/benign)     Include ONLY benign EMBER data as benign, discarding others
#   Below are some examples for each of the three options
    
#   For all cases we copy the features regardless of the score
x_adv_train[:N, :]=X_train[:N, :]

#   OPTION 1: Retraining
#       Just copy the scores
#y_adv_train[:N]=y_adv_train[:N]

#   OPTION 2: Portfolio/All
#       Just set it to 0
#y_adv_train[:N]=0

#   OPTION 3: Portfolio/Benign
#       The score if it's 0; set it to -1 otherwise
for i in range(0, N):
    #   If it's benign, keep it
    if y_train[i] == 0:
        y_adv_train[i]=0
    #   Otherwise, set it to -1 and ignore
    else:
        y_adv_train[i]=-1

#   Delete the arrays from memory to make things easier
del y_train, X_train

#   Now we fill up the arrays with variants data
#   This variable stores where we are
cur_N=N

#   Open each dat file
for dat_file in os.listdir(variant_data_directory):
    #   Check to see if we're skipping it same as for records
    skip=False
    for name in skip_variants:
        if name in record:
            skip=True
    if skip:
        continue
    #   Strip out trailing newlines
    dat=dat_file.rstrip()
    #   Get the current size
    cur_size=dat_to_length[dat.split(".")[0]]
    #   Create a temp array to load it into
    areader = np.memmap(variant_data_directory + dat, dtype=np.float32, mode="r", shape=(cur_size, ndim))
    #   Update size for where we'll be after adding        
    new_N=cur_N+cur_size
    #   Add the features in    
    x_adv_train[cur_N:new_N,:]=areader[:,:]
    #   Add the label
    #       NOTE! We didn't include the code, but you could put a check here to discard evasive variants
    #       The idea would be to run a classifier on the current feature and set score to -1 if it doesn't evade    
    y_adv_train[cur_N:new_N]=1
    #   Update size
    cur_N=new_N
    #   Delete to free up memory
    del areader

#   Data loaded! Now we can train
#   Parameters are hardcoded -- long story
params={
    'bagging_fraction': 0.5,
    'boosting_type': 'gbdt',
    'feature_fraction': 0.5,
    'learning_rate': 0.005,
    'num_iterations': 1000,
    'num_leaves': 1024,
    'objective': 'binary'
}
#   Ignore rows where the label is -1
train_rows = (y_adv_train != -1)
lgbm_dataset = lgb.Dataset(x_adv_train[train_rows], y_adv_train[train_rows])
lgbm_model = lgb.train(params, lgbm_dataset)
#   Save it
lgbm_model.save_model("new_model.txt")
