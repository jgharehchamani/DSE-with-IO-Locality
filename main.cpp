//#include "Amortized.h"
#include "AmortizedOneChoice.h"
#include "AmortizedTwoChoice.h"
#include "Utilities.h"
#include <algorithm>
#include <iostream>
#include <vector>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include "AmortizedPiBAS.h"
#include "AmortizedNlogN.h"
#include "DeAmortizedSDdBAS.h"
#include "DeAmortizedSDdGeneral.h"
#include "DeAmortizedSDdNlogN.h"
#include <typeinfo>
#include "DSEScheme.h"

using namespace std;

int main(int argc, char** argv) {
    string schemeName = "";
    if (argc < 4) {
        cout << "io-dse: missing arguments" << endl << endl;
        cout << "Usage: dse SCHEME_NAME HARDWARE CACHE_SIZE" << endl << endl;
        cout << "SCHEME_NAME:" << endl;
        cout << "Amortized Schemes: SDa[PiBAS] / SDa[1C] / SDa[2C] / SDa[NlogN] / SDa[3N] / SDa[6N]" << endl;
        cout << "DeAmortized Schemes: SDd[PiBAS] / L-SDd[1C] / L-SDd[NlogN] / L-SDd[3N] / L-SDd[6N]" << endl << endl;
        cout << "HARDWARE: \t" << "HDD, SSD, Memory" << endl << endl;        
        cout << "CACHE_SIZE (in percentage): \t" << "integer between 0 and 100" << endl << endl;
        return 0;
    }
    schemeName = argv[1];
    string hardware = argv[2];    
    int cacheSize = atoi(argv[3]);
    
    if(hardware=="HDD"){
        Utilities::HDD_CACHE = true;
        Utilities::SSD_CACHE = false;
        Utilities::KERNEL_CACHE = true;        
    }else if (hardware=="SSD"){
        Utilities::HDD_CACHE = false;
        Utilities::SSD_CACHE = true;
        Utilities::KERNEL_CACHE = true;        
    }else if (hardware=="Memory"){
        Utilities::HDD_CACHE = false;
        Utilities::SSD_CACHE = false;
        Utilities::KERNEL_CACHE = false;
    }
    
    if(cacheSize>=0 and cacheSize <= 100){
        Utilities::CACHE_PERCENTAGE = (double)cacheSize/100.0;
    }

//    schemeName = "SDa[PiBAS]";

    vector<TC<int> > testCases;
    uint keywordLength = 7;
    bool setup = true;
    string filename = "config.txt";
    if (argc == 2) {
        filename = string(argv[1]);
    }
    Utilities::readConfigFile(argc, argv, filename, testCases);
    std::vector<pair<string, int> > tests;
    std::vector<int> ops; //0=ins 1=del
    system(("rm " + Utilities::rootAddress + " -rf").c_str());
    system(("mkdir " + Utilities::rootAddress).c_str());
    system("ulimit -n 1000000");

    int randomFolderSize = 10;
    string oldAddress = Utilities::rootAddress;
    if (Utilities::useRandomFolder) {
        string ins = to_string(rand() % randomFolderSize);
        Utilities::rootAddress = oldAddress + ins + "/";
        cout << "reading from instance:" << ins << endl;
    }

    //    tests = Utilities::generateTestCases(testCases, keywordLength, 14, "Column5.txt", ops);
    tests = Utilities::generateTestCases(testCases, keywordLength, 14, ops);


    DSEScheme* scheme;
    if (schemeName == "SDa[PiBAS]") {
        scheme = new AmortizedPiBAS(testCases[0].N, false, true);
    } else if (schemeName == "SDa[1C]") {
        scheme = new AmortizedOneChoice(testCases[0].N, false, true);
    } else if (schemeName == "SDa[2C]") {
        scheme = new AmortizedTwoChoice(testCases[0].N, false, true);
    } else if (schemeName == "SDa[NlogN]") {
        Utilities::JUMP_SIZE = 1;
        scheme = new AmortizedNlogN(testCases[0].N, false, true);
    } else if (schemeName == "SDa[3N]") {
        Utilities::JUMP_SIZE = 8;
        scheme = new AmortizedNlogN(testCases[0].N, false, true);
    } else if (schemeName == "SDa[6N]") {
        Utilities::JUMP_SIZE = 4;
        scheme = new AmortizedNlogN(testCases[0].N, false, true);
    } else if (schemeName == "SDd[PiBAS]") {
        scheme = new DeAmortizedSDdBAS(false, testCases[0].K, testCases[0].N, false, true);
    } else if (schemeName == "L-SDd[1C]") {
        scheme = new DeAmortizedSDdGeneral(testCases[0].N, false, true);
    } else if (schemeName == "L-SDd[NlogN]") {
        Utilities::JUMP_SIZE = 1;
        scheme = new DeAmortizedSDdNlogN(testCases[0].N, false, true);
    } else if (schemeName == "L-SDd[3N]") {
        Utilities::JUMP_SIZE = 8;
        scheme = new DeAmortizedSDdNlogN(testCases[0].N, false, true);
    } else if (schemeName == "L-SDd[6N]") {
        Utilities::JUMP_SIZE = 4;
        scheme = new DeAmortizedSDdNlogN(testCases[0].N, false, true);
    }


    scheme->beginSetup();
    cout << "Setting Up the randomly generated key-value pairs in the scheme." << endl;


    map<string, int> tester;
    double time = 0;
    for (int j = 0; j < tests.size(); j++) {
        if (j % 100000 == 0) {
            cout << "Inserted " << j << "/" << tests.size() << " of key-value pairs" << endl;
        }
        scheme->update(OP::INS, tests[j].first, tests[j].second, setup);
        if (tester.count(tests[j].first) == 0)
            tester[tests[j].first] = 0;
        tester[tests[j].first]++;
    }
    scheme->endSetup();
    cout << "End of setting up initial key-value pairs" << endl;

    setup = false;
    if(hardware=="HDD"){
        Utilities::DROP_CACHE = true;
    }else if (hardware=="SSD"){
        Utilities::DROP_CACHE = true;
    }else if (hardware=="Memory"){
        Utilities::DROP_CACHE = false;
    }
    cout << "Start of the evaluation for a dataset with (N=" << testCases[0].N << ", K=" << testCases[0].K << ")" << endl;
    cout << "-------------------------------------------------" << endl;
    for (uint j = 0; j < testCases[0].Qs.size(); j++) {

        if (Utilities::useRandomFolder) {
            Utilities::rootAddress = oldAddress + to_string(rand() % randomFolderSize) + "/";
        }
        //auto item = testCases[i].filePairs[testCases[i].testKeywords[j]];

        cout << "Search for Keyword " << testCases[0].testKeywords[j] << " with result size=" << testCases[0].Qs[j] << endl;
        for (int z = 0; z < 1; z++) {
            Utilities::startTimer(500);
            vector<int> res = scheme->search(testCases[0].testKeywords[j]);
            time = Utilities::stopTimer(500);
            cout << "Total Search Computation Time (microseconds):" << scheme->totalSearchTime << endl;
            assert(testCases[0].Qs[j] - testCases[0].delNumber[j] == res.size());
            cout << "-------------------------------------------------" << endl;
        }
    }

    if (schemeName != "L-SDd[NlogN]" && schemeName != "L-SDd[3N]" && schemeName != "L-SDd[6N]" && cacheSize==0) {
        Utilities::startTimer(500);
        scheme->update(OP::INS, "Test-KW-1", 101, false);
        time = Utilities::stopTimer(500);
        cout << "Update Computation Time (microseconds):" << scheme->totalUpdateTime << endl;
        auto res = scheme->search("Test-KW-1");
        assert(res.size() == 1);
    }
    return 0;
}
