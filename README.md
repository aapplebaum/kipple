# kipple: Towards accessible, robust malware classification #
Welcome to kipple! kipple is a set of resources that accompany my entry in the [2021 ML Security Evasion Competition](https://mlsec.io/). While kipple only scored third place in the defensive track, through publishing the materials behind it, I hope to help inspire other researchers in the space as well as make the topic more accessible for newcomers.

kipple materials are divided into four components:

* The data that kipple was built from, hosted in the [kipple-data submodule](https://github.com/aapplebaum/kipple-data);
* The models built during the construction of the 2021 MLSEC kipple entry, hosted in the [kipple-models submodule](https://github.com/aapplebaum/kipple-models);
* Scripts used to build and evaluate kipple, hosted  in this repository; and
* Resources -- i.e., papers and presentations -- for understanding kipple, hosted in this repository.

This project is a work in progress! While my hope is to update it occassionally (see below), it is also a _personal_ project, and so updates will likely be sporadic.

## Downloading Kipple ##
kipple's components are presently stored in separate GitHub repositories; because the data and models are each quite large (~300MB and ~500MB respectively), I want to ensure users can select the pieces they want to use. To download **everything** you can use the following command:
```
git clone https://github.com/aapplebaum/kipple.git --recursive
```

## Requirements ##
Almost all of the scripts and code associated with kipple reference the EMBER project -- you can access the data and install it here: https://github.com/elastic/ember. 

## Scripts ##
This repository is home to three scripts to help make training a robust model easier for users. Each script is heavily commented and, hopefully, written in a way to make it clear what the intention of each is; the hope being that others can modify them as they see fit. Within the [kipple-models submodule](https://github.com/aapplebaum/kipple-models) there are two files that show how to use the models as well as the data.

### train.py ###
```train.py``` shows an example of how to build a GBDT model using the EMBER data alongside the data within ```kipple-data```. Some of the commented out code shows how to run different configurations.

### get_individual_thresholds.py ###
```get_individual_thresholds.py``` iterates through each model within ```kipple-models``` and computes the numeric threshold for a set of false positive values, and then computes the accuracy of each model at each threshold against the EMBER malware test data as well as a folder of malware of your choosing.

### size_three_portfolio.py ###
```size_three_portfolio.py``` runs through a set of model combinations to identify thresholds that yield 1% false positive rate.

## MLSEC 2021 Entry ##
The kipple entry into MLSEC 2021 used a portfolio approach of three models:

* [initial](https://github.com/aapplebaum/kipple-models/blob/main/models/initial.txt.gz) with a threshold of 0.898
* [variants-all](https://github.com/aapplebaum/kipple-models/blob/main/models/variants_all.txt.gz) with a threshold of 0.028
* [undetect-benign](https://github.com/aapplebaum/kipple-models/blob/main/models/undetect_benign.txt.gz) with a threshold of 0.85

In addition to the static detection with the files above, it also leveraged the default stateful implementation from the [sample defender provided as part of the competition](https://github.com/Azure/2021-machine-learning-security-evasion-competition/blob/main/defender/defender/models/ember_model.py#L114). The only tweak was to add in prediction that used all three models, and then to store malware if and only if it violated _variants_all_, modifying [this line](https://github.com/Azure/2021-machine-learning-security-evasion-competition/blob/main/defender/defender/models/ember_model.py#L151).

### False Positive Performance ###
The initial kipple entry had a high false positive rate on the local benign corpus I was using -- this turned out to be because the msfvenom detector (_undetect-benign_) was flagging all of the benign binaries. Digging in deeper, this was because the msfvenom script was using these binaries for templates, and so the classifier had been trained on things that looked _very much_ like those specific binaries.

To fix this, the final submission ultimately used an unnecessarily large 0.85 threshold for the _undetect-benign_ classifier, and had a hardcoded set of MD5s of known-benign files.

## To-dos ##
1. Extend the ```train.py``` script to show how to train over a local set of binaries.
2. Add an example script showing how to save a memmap'd array for quicker analysis.
3. Upload an alternative representation of the adversarial samples not hardcoded to the memmap'd array.
4. Upload scripts used to generate adversarial variants (maybe).
5. Upload data and models based on other obfuscation techniques (e.g., crypters, packers).
6. Add more information on retraining on evasive adversarial samples (not just all the samples).

## Citing ##
If you want to cite kipple in your work, the following citation (or a variant of it) should work:
```
A. Applebaum, "kipple: Towards robust, accessible malware classification", CAMLIS, 2021.
```
And if you do use kipple -- please feel free to let me know!

## References ##
There are **many** good and helpful references in this space! The following tools in particular were used to help construct the data behind kipple:

* [EMBER](https://github.com/elastic/ember)
* [Malware RL](https://github.com/bfilar/malware_rl)
* [SecML Malware](https://github.com/pralab/secml_malware)
* [VirusShare](https://virusshare.com/)
* [SoReL 20M](https://github.com/sophos-ai/SOREL-20M)
* [msfvenom](https://www.offensive-security.com/metasploit-unleashed/msfvenom/)
* [The 2021 MLSEC default model implementation](https://github.com/Azure/2021-machine-learning-security-evasion-competition)

Some other cool resources I haven't finished tinkering with include:

* [toucanstrike](https://github.com/pralab/toucanstrike)
* [MAB-malware](https://github.com/weisong-ucr/MAB-malware)

Lastly, check out the blog posts of some of the other competitors in the MLSEC 2021 competition:
* [The CUJO AI announcement](https://cujo.com/announcing-the-winners-of-the-2021-machine-learning-security-evasion-competition/)
* [Fabrício Ceschin and Marcus Botacin's first place (attacker + defender) entry](https://secret.inf.ufpr.br/2021/09/29/adversarial-machine-learning-malware-detection-and-the-2021s-mlsec-competition/)
* [Alejandro Mosquera's second place (defender + attacker) entry](https://zenodo.org/record/5534783#.YX8cu2DMKUm)
* [Alexey Antonov, Alexey Kogtenkov, and Maxim Golovkin's attacker track writeup](https://securelist.com/how-we-took-part-in-mlsec-and-almost-won/104699/)
