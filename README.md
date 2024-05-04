# DSE-with-IO-Locality
This repository contains several amortized/de-amortized DSE schemes with IO locality. The open-source is based on our following paper:

Priyanka Mondal, Javad Ghareh Chamani, Ioannis Demertzis, Dimitrios Papadopoulos. "I/O-Efficient Dynamic Searchable Encryption meets Forward & Backward Privacy", USENIX Security 2024


### Pre-requisites: ###
Our schemes were tested with the following configuration
- 64-bit Ubuntu 18.04
- g++ = 5.5
- nvme-cli (it is needed for SSD experiments)

### Getting Started ###
To build schemes, execute

    make clean
    make

This will produce an executable file named io-dse in ./dist/Debug/GNU-Linux/ folder. 

    ./dist/Debug/GNU-Linux/io-dse

### Structure of Files: ###

Each scheme consist of at least 4 separete classes: Controller, Client, Server, and Storage. These classes handle the schemes procedures accordingly. Controller provides DSE scheme interface (setup, search, and update) while Client and Server implements the logic of the scheme. Storage is responsible for managing disk accesses and all caching related procedures.
For example, the files corresponding to SDa[PiBAS] are as follows:
Controller: AmortizedPiBAS
Client: AmortizedBASClient
Server: AmortizedBASServer
Storage: Storage

Note that some schemes use multiple classes from different schemes. E.g., in SDa[2C], there is one controller (AmortizedTwoChoice), one client (TwoChoiceWithOneChoiceClient), two servers (OneChoiceServer, TwoChoiceWithOneChoiceServer) and three storages (Storage, OneChoiceStorage, and TwoChoiceWithOneChoiceStorage)

### Execution: ###
The execution of ./dist/Debug/GNU-Linux/io-dse shows its needed arguments as follow:
        
Usage: io-dse SCHEME_NAME HARDWARE CACHE_SIZE

SCHEME_NAME:
Amortized Schemes: SDa[PiBAS] / SDa[1C] / SDa[2C] / SDa[NlogN] / SDa[3N] / SDa[6N]
DeAmortized Schemes: SDd[PiBAS] / L-SDd[1C] / L-SDd[NlogN] / L-SDd[3N] / L-SDd[6N]

HARDWARE: HDD, SSD, Memory        

CACHE_SIZE (in percentage): integer between 0 and 100   

The first argument SCHEME_NAME determines the target scheme which can be any of the amoritzed and de-amortized mentioned schemes. The second argument denotes the disk/memory configuration. Finally, CACHE_SIZE which is a number between 0 and 100 determines the amount of allowed cache in the execution.
By providing the above arguemnts, the program reads config.txt file and sets up a dataset according to the configurations mentioned in the file. Then, it and executes some searches based on the settings mentioned in the file and runs a single update operation (for all schemes except L-SDd[NlogN], L-SDd[3N], L-SDd[6N] only when the cache size is 0) and measures their exeuction time.
All parameters used in the paper can be set using the above arguments and the settings provided in the config file. However, for changing the block size, you need to change AES_KEY_SIZE in the types.hpp file and recompile the code.

### Configuration File ###
The configuration file consist of few lines as follows and the application uses this information to randomly generate a dataset accordingly:
N
K
num_of_queries
q1
q2
.
.
.
qn

N shows the total number of dataset size (number of key-value pairs in PiBAS).
K shows the total number of distinct keywords in the dataset
num_of_queries shows how many search queries the user wants to measure and q1 to qn represent the result size of search query. For example consider the following example (which is the same as the paper's dataset with size = 2^23):

8388606
10000
9
1
10
100
1000
10000
100000
1000000
2000000
5000000

It shows that we have a dataset with size 2^23 -2 and it contains 10K distinct keywords. Using this configuration we will be able to run 9 queries with result sizes equal to 1, 10, ..., 5M
The following two configurations represent the real datasets used in Figure 15 of the paper. Note that you need to uncomment line 79 and comment line 80 of the main file.

6123275
10000
6
704368
66666
44471
13546
6257
136


6123275
10000
6
615506
63367
22076
5280
1475
217


### Contact ###
Feel free to reach out to me to get help in setting up our code or any other queries you may have related to our paper: jgc@cse.ust.hk
