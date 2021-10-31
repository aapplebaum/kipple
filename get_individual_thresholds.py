#   This script will output threshold information
import math
import os
import ember
import numpy as np
from ember.features import PEFeatureExtractor
import lightgbm as lgb
import gzip

#   Declare the extractor
extractor=PEFeatureExtractor(feature_version=2, print_feature_warning=False)
ndim = extractor.dim

#   Load the EMBER test
#   This assumes you've already stored the EMBER data as memmap'd .dat files!
data_dir="/data/ember2018/"
print("Reading in ember test data...")
X_test_path = os.path.join(data_dir, "X_test.dat")
y_test_path = os.path.join(data_dir, "y_test.dat")
y_test = np.memmap(y_test_path, dtype=np.float32, mode="r")
N = y_test.shape[0]
X_test = np.memmap(X_test_path, dtype=np.float32, mode="r", shape=(N, ndim))

#   Pointer to a folder with adversarial example data in it
malware_folder_path="/exes/mlsec2019/"

#   Iterate over each model in the models folder
for model_name in os.listdir("kipple-models/models/"):
    print("Now working on " + model_name.rstrip())
    #   Load the model    
    with gzip.open("kipple-models/models/" + model_name.rstrip(), "rb") as f:
        tmp=f.read().decode('ascii')
        current_model=lgb.Booster(model_str=tmp)
    
    #   Store an array of all benign scores
    benign_scores=[]
    
    #   Read through the EMBER test data
    for i in range(0, N):
        #   Skip if malicious or unknown
        if y_test[i] < 0 or y_test[i] > 0:
            continue
        benign_scores.append(current_model.predict([X_test[i]])[0])
    
    #   Sort the scores
    benign_scores.sort()
    
    #   Get the cutoffs
    fp_10_cutoff=benign_scores[math.ceil((90/100) * len(benign_scores) - 1)] + .00001
    fp_2_cutoff=benign_scores[math.ceil((98/100) * len(benign_scores) - 1)] + .00001
    fp_1_cutoff=benign_scores[math.ceil((99/100) * len(benign_scores) - 1)] + .00001
    fp_01_cutoff=benign_scores[math.ceil((999/1000) * len(benign_scores) - 1)] + .00001
    fp_001_cutoff=benign_scores[math.ceil((9999/10000) * len(benign_scores) - 1)] + .00001
    print("     10% FP cutoff:    " + str(fp_10_cutoff))
    print("     2% FP cutoff:     " + str(fp_2_cutoff))
    print("     1% FP cutoff:     " + str(fp_1_cutoff))
    print("     0.1% FP cutoff:   " + str(fp_01_cutoff))
    print("     0.01% FP cutoff:  " + str(fp_001_cutoff))
    
    with open("results.md", "a") as f:
        f.write("| " + model_name.rstrip() + " | ")
        f.write(str(round(1000*fp_10_cutoff)/1000) + " | ")
        f.write(str(round(1000*fp_2_cutoff)/1000) + " | ")
        f.write(str(round(1000*fp_1_cutoff)/1000) + " | ")
        f.write(str(round(1000*fp_01_cutoff)/1000) + " | ")
        f.write(str(round(1000*fp_001_cutoff)/1000) + " | ")

    print("  Running on EMBER")    
    #   Now look at EMBER malicious test
    total_malicious=0
    correct_fp10=0
    correct_fp2=0
    correct_fp1=0
    correct_fp01=0
    correct_fp001=0
    for i in range(0, N):
        #   Skip if malicious or unknown
        if y_test[i] < 1:
            continue
        #   Get the score
        cur_score=current_model.predict([X_test[i]])[0]
        total_malicious=total_malicious+1
        if cur_score > fp_10_cutoff:
            correct_fp10 = correct_fp10 + 1
        if cur_score > fp_2_cutoff:
            correct_fp2 = correct_fp2 + 1
        if cur_score > fp_1_cutoff:
            correct_fp1 = correct_fp1 + 1
        if cur_score > fp_01_cutoff:
            correct_fp01 = correct_fp01 + 1
        if cur_score > fp_001_cutoff:
            correct_fp001 = correct_fp001 + 1
    print("     10% FP EMBER accuracy:      " + str(correct_fp10 / total_malicious))
    print("     2% FP EMBER accuracy:       " + str(correct_fp2 / total_malicious))
    print("     1% FP EMBER accuracy:       " + str(correct_fp1 / total_malicious))
    print("     0.1% FP EMBER accuracy:     " + str(correct_fp01 / total_malicious))
    print("     0.01% FP EMBER accuracy:    " + str(correct_fp001 / total_malicious))

    with open("results.md", "a") as f:
        f.write(str(round(1000 * correct_fp10 / total_malicious)/10) + " | ")
        f.write(str(round(1000 * correct_fp2 / total_malicious)/10) + " | ")
        f.write(str(round(1000 * correct_fp1 / total_malicious)/10) + " | ")
        f.write(str(round(1000 * correct_fp01 / total_malicious)/10) + " | ")
        f.write(str(round(1000 * correct_fp001 / total_malicious)/10) + " | ")

    #   Now look at a folder of variants
    print("  Running on Variants")
    malware_folder_path="/exes/mlsec2019/"
    total_malicious=0
    correct_fp10=0
    correct_fp2=0
    correct_fp1=0
    correct_fp01=0
    correct_fp001=0

    for file_name in os.listdir(malware_folder_path):
        cur_path=malware_folder_path + file_name.rstrip()
        #   Get the feature array
        file_data=open(cur_path, "rb").read()
        features=np.array(extractor.feature_vector(file_data), dtype=np.float32)
        cur_score=current_model.predict([features])[0]
        total_malicious=total_malicious+1
        if cur_score > fp_10_cutoff:
            correct_fp10 = correct_fp10 + 1
        if cur_score > fp_2_cutoff:
            correct_fp2 = correct_fp2 + 1
        if cur_score > fp_1_cutoff:
            correct_fp1 = correct_fp1 + 1
        if cur_score > fp_01_cutoff:
            correct_fp01 = correct_fp01 + 1
        if cur_score > fp_001_cutoff:
            correct_fp001 = correct_fp001 + 1
    print("     10% FP variants accuracy:      " + str(correct_fp10 / total_malicious))
    print("     2% FP variants accuracy:       " + str(correct_fp2 / total_malicious))
    print("     1% FP variants accuracy:       " + str(correct_fp1 / total_malicious))
    print("     0.1% FP variants accuracy:     " + str(correct_fp01 / total_malicious))
    print("     0.01% FP variants accuracy:    " + str(correct_fp001 / total_malicious))

    with open("results.md", "a") as f:
        f.write(str(round(1000 * correct_fp10 / total_malicious)/10) + " | ")
        f.write(str(round(1000 * correct_fp2 / total_malicious)/10) + " | ")
        f.write(str(round(1000 * correct_fp1 / total_malicious)/10) + " | ")
        f.write(str(round(1000 * correct_fp01 / total_malicious)/10) + " | ")
        f.write(str(round(1000 * correct_fp001 / total_malicious)/10) + " | ")

    #   Now look at a folder of variants
    print("  Running on Variants")
    malware_folder_path="/exes/KIPPLE_PAPER/data/evaded/malconv/"
    total_malicious=0
    correct_fp10=0
    correct_fp2=0
    correct_fp1=0
    correct_fp01=0
    correct_fp001=0
    for file_name in os.listdir(malware_folder_path):
        cur_path=malware_folder_path + file_name.rstrip()
        #   Get the feature array
        file_data=open(cur_path, "rb").read()
        features=np.array(extractor.feature_vector(file_data), dtype=np.float32)
        cur_score=current_model.predict([features])[0]
        total_malicious=total_malicious+1
        if cur_score > fp_10_cutoff:
            correct_fp10 = correct_fp10 + 1
        if cur_score > fp_2_cutoff:
            correct_fp2 = correct_fp2 + 1
        if cur_score > fp_1_cutoff:
            correct_fp1 = correct_fp1 + 1
        if cur_score > fp_01_cutoff:
            correct_fp01 = correct_fp01 + 1
        if cur_score > fp_001_cutoff:
            correct_fp001 = correct_fp001 + 1
    print("     10% FP variants accuracy:      " + str(correct_fp10 / total_malicious))
    print("     2% FP variants accuracy:       " + str(correct_fp2 / total_malicious))
    print("     1% FP variants accuracy:       " + str(correct_fp1 / total_malicious))
    print("     0.1% FP variants accuracy:     " + str(correct_fp01 / total_malicious))
    print("     0.01% FP variants accuracy:    " + str(correct_fp001 / total_malicious))

    with open("results.md", "a") as f:
        f.write(str(round(1000 * correct_fp10 / total_malicious)/10) + " | ")
        f.write(str(round(1000 * correct_fp2 / total_malicious)/10) + " | ")
        f.write(str(round(1000 * correct_fp1 / total_malicious)/10) + " | ")
        f.write(str(round(1000 * correct_fp01 / total_malicious)/10) + " | ")
        f.write(str(round(1000 * correct_fp001 / total_malicious)/10) + " | ")
        f.write("\n")




    




