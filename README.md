# DSE-with-IO-Locality
This repository contains several amortized/de-amortized DSE schemes with IO locality. The open-source is based on our following paper:

Priyanka Mondal, Javad Ghareh Chamani, Ioannis Demertzis, Dimitrios Papadopoulos. "I/O-Efficient Dynamic Searchable Encryption meets Forward & Backward Privacy", USENIX Security 2024


### Pre-requisites: ###
Our schemes were tested with the following configuration
- 64-bit Ubuntu 18.04
- g++ = 5.5

### Getting Started ###
To build schemes, execute

    make clean
    make

This will produce a sample application based on the target scheme in ./dist/Debug/GNU-Linux/ folder. You can select your target scheme by uncommenting its corresponding constructor in the main.cpp file. To execute the sample application provided by us, simply execute  the following command in the scheme's root folder

    ./dist/Debug/GNU-Linux/osse   #for OSSE sample application    

### SSD Configuration ###
To change the configuration for SSD setting instead of HDD, run the following command in the root of the project:

    grep -rli 'sudo hdparm -A 0 \/dev\/sda' * | xargs -i@ sed -i 's/sudo hdparm -A 0 \/dev\/sda/nvme set-feature -f 6 -v 0 \/dev\/nvme0n1/g' @

### Contact ###
Feel free to reach out to me to get help in setting up our code or any other queries you may have related to our paper: jgc@cse.ust.hk

