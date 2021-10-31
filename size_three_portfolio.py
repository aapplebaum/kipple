import ember
import os
import numpy as np
from ember.features import PEFeatureExtractor
import lightgbm as lgb
import gzip
import math

#   This script will help generate a portfolio and identify the right thresholds for each model
#   It does this by checking each potential threshold combination for each model configuration against two sets of data:
#       One, the EMBER test malware data
#       and Two, a custom folder of malware
#   We assume that you have three models to combine
#   We'll refer to each three as slot_0, slot_1, and slot_2
#   By default we assume slot_0 is the initial model and is hardcoded
#   But the script will go through each combination of values for slot_1 and slot_2 that you identify


#   This directory should point to where the EMBER data is stored in memmap'd form
data_dir="/data/ember2018/"

#   This directory should point to where the second set of malware is stored
malware_folder_path="/exes/mlsec2019/"

#   This directory should point to where the models are stored
model_dir="kipple-models/models/"

#   This string holds the name for the initial model/slot_0
slot_0="initial.txt.gz"

#   This array will contain the names of all models you want to test in slot 1
#   Must be held in the model_dir folder
slot_1=["variants_all.txt.gz"]

#   This array will contain the names of all models you want to test in slot 2
#   Must be held in the model_dir folder
slot_2=["msf_benign.txt.gz", "undetect_benign.txt.gz"]

#   Initialize the extractor + number of dimensions
extractor = PEFeatureExtractor(feature_version=2, print_feature_warning=False)
ndim = extractor.dim

#   Load the initial model
model_gz_path=model_dir + slot_0
with gzip.open(model_gz_path, 'rb') as f:
    mdel = f.read().decode('ascii')
slot_0_model = lgb.Booster(model_str=mdel)

#   This will store the scores from slot_0 on each benign value
slot_0_benign=[]

#   We'll now load the EMBER test data
X_test_path = os.path.join(data_dir, "X_test.dat")
y_test_path = os.path.join(data_dir, "y_test.dat")
ember_y_test = np.memmap(y_test_path, dtype=np.float32, mode="r")
ember_N = ember_y_test.shape[0]
ember_X_test = np.memmap(X_test_path, dtype=np.float32, mode="r", shape=(ember_N, ndim))

print("Loading scores for: " + slot_0)
#   Now we'll store the slot_0 score for each EMBER benign entry
for i in range(0, ember_N):
    if ember_y_test[i] == 0:
        slot_0_benign.append(slot_0_model.predict([ember_X_test[i]])[0])
#   Sort the values
slot_0_benign.sort()

#   Now we'll store the cutoffs, ranging between 1% FP and 0% FP every .05%
#   (i.e., we store the cutoff for 1% FP, 0.95% FP, 0.9% FP, 0.85% FP, ..., 0.05% FP, 0% FP
slot_0_cutoffs={}
for i in range(0, 20):
    pct=.99 + i/2000
    idx=math.ceil(pct * len(slot_0_benign)) - 1
    slot_0_cutoffs[i]=slot_0_benign[idx] + .0001
#   Delete the storage array to save memory
del slot_0_benign
#   Add an extra value to effectively test what happens when this model is off
slot_0_cutoffs[20]=2

#   We're now going to run the slot_0 model against each EMBER malware and custom malware sample
#   We'll store the results of each prediction by index so we can call it later
#   These arrays will map each malware instance to the score for the slot_0 model
#   Note that for EMBER we just use "i" as the index, but for the custom malware we use the filanem
slot_0_ember={}
slot_0_mlsec={}
#   Run through each EMBER malware
num_ember=0
for i in range(0, ember_N):
    if ember_y_test[i] == 1:
        #   Store the result based on index
        slot_0_ember[i]=slot_0_model.predict([ember_X_test[i]])[0]
    num_ember=num_ember+1

#   Run through each custom malware instance
mlsec_N=0
for file_name in os.listdir(malware_folder_path):
    cur_path=malware_folder_path + file_name.rstrip()
    #   Get the feature array
    file_data=open(cur_path, "rb").read()
    features=np.array(extractor.feature_vector(file_data), dtype=np.float32)
    #   Now store the score, mapping it to the filename
    slot_0_mlsec[file_name.rstrip()]=slot_0_model.predict([features])[0]
    mlsec_N=mlsec_N+1

#   We're now going to do the same thing for each of the other models
#       (i.e., storing the cutoffs + results for each EMBER/malware sample)
#   These dictionaries map the model name to its own sub-dictionary
#   The sub-dictionary follows the same format as above
cutoff_mapper={}
mlsec_mapper={}
ember_mapper={}

#   Iterate through each model in slot_1 and slot_2
for model_name in slot_1 + slot_2:
    print("Loading scores for:: " + str(model_name.rstrip()))
    #   Load the model
    with gzip.open(model_dir + model_name, 'rb') as ret_file:
        cur_model=lgb.Booster(model_str=ret_file.read().decode('ascii'))
    #   Initialize the storage for each model
    cutoff_mapper[model_name]={}
    mlsec_mapper[model_name]={}
    ember_mapper[model_name]={}
    #   First pass: find the FP rate values    
    #   This follows the same as above but just renaming variables
    benign_storage=[]
    for i in range(0, ember_N):
        if ember_y_test[i] == 0:
            benign_storage.append(cur_model.predict([ember_X_test[i]])[0])
        #   Store the values for the malware right away; no need to pass through twice
        if ember_y_test[i] == 1:
            ember_mapper[model_name][i]=cur_model.predict([ember_X_test[i]])[0]
    #   Sort the values
    benign_storage.sort()
    #   Break out the thresholds similar to above
    for i in range(0, 20):
        pct=.99 + i/2000
        idx=math.ceil(pct * len(benign_storage)) - 1
        cutoff_mapper[model_name][i]=benign_storage[idx] + .0001
    cutoff_mapper[model_name][20]=2
    del benign_storage
    #   Now store the custom malware results
    #   Note that this would be more efficient if you stored the feature arrays and just called from there
    #   Original kipple code did this, but for simplicities sake we use the below
    for file_name in os.listdir(malware_folder_path):
        cur_path=malware_folder_path + file_name.rstrip()
        #   Get the feature array
        file_data=open(cur_path, "rb").read()
        features=np.array(extractor.feature_vector(file_data), dtype=np.float32)
        #   Now store the score, mapping it to the filename
        mlsec_mapper[model_name][file_name.rstrip()]=cur_model.predict([features])[0]


#   Now scores are loaded
#   Initialize the results array
with open("triples.csv", "w") as the_file:
    the_file.write("slot_1, slot_2, slot_0_cutoff, slot_1_cutoff, slot_2_cutoff, ember, mlsec\n")

#   Now we need to iterate through each combination of thresholds
#   Here we need to ensure that the total FP rate is less than 1%
#   So, we choose cutoffs such that FP(slot_0) + FP(slot_1) + FP(slot_2) = 1%
#   In practice, this will probably come out to a FP rate of less than 1% because there's likely FP overlap
#   However, this will guarantee we won't be over 1%, which we're prioritizing for
for model_1 in slot_1:
    #   Load the model so we can run it
    with gzip.open(model_dir + model_1, 'rb') as ret_file:
        cur_model_1=lgb.Booster(model_str=ret_file.read().decode('ascii'))
    #   Iterate through each cutoff for slot_0
    for i in range(0, 21):
        p_cutoff=slot_0_cutoffs[i]
        #   iterate through each cutoff for slot_1
        #   note that we can use some math to guarantee that we don't choose thresholds that sum >1
        for j in range(20 - i, 21):
            m1_cutoff=cutoff_mapper[model_1][j]
            k=40 - i
            k=k - j
            #   do the same for slot_2
            for model_2 in slot_2:
                with gzip.open(model_dir + model_2, 'rb') as ret_file:
                    cur_model_2=lgb.Booster(model_str=ret_file.read().decode('ascii'))
                m2_cutoff=cutoff_mapper[model_2][k]
                #   Alright! We have our cutoffs, now just get the results
                success_ember=0
                success_mlsec=0
                #   run through ember
                for x in range(0, ember_N):
                    if ember_y_test[x] != 1:
                        continue
                    if slot_0_ember[x] > p_cutoff:
                        success_ember=success_ember+1
                    elif ember_mapper[model_1][x] > m1_cutoff:
                        success_ember=success_ember+1
                    elif ember_mapper[model_2][x] > m2_cutoff:
                        success_ember=success_ember+1
                #   run through mlsec
                for file_name in os.listdir(malware_folder_path):                    
                    x=file_name.rstrip()
                    if slot_0_mlsec[x] > p_cutoff:
                        success_mlsec=success_mlsec+1
                    elif mlsec_mapper[model_1][x] > m1_cutoff:
                        success_mlsec=success_mlsec+1
                    elif mlsec_mapper[model_2][x] > m2_cutoff:
                        success_mlsec=success_mlsec+1
                dsuccess_ember=str(round(100*success_ember/num_ember))
                dsuccess_mlsec=str(round(100*success_mlsec/mlsec_N))
                dpret_cutoff=str(round(1000*p_cutoff)/1000)
                dcur_model_cutoff=str(round(1000*m1_cutoff)/1000)
                dm2=str(round(1000*m2_cutoff)/1000)
                with open("triples.csv", "a") as the_file:
                    the_file.write(model_1 + "," + model_2 + "," + dpret_cutoff + "," + dcur_model_cutoff + "," + dm2 + "," + dsuccess_ember + "," + dsuccess_mlsec+"\n")
