#ifndef TWOCHOICEWITHTUNABLELOCALITYSTORAGE_H
#define TWOCHOICEWITHTUNABLELOCALITYSTORAGE_H

#include <string>
#include <map>
#include <vector>
#include <array>
#include "Server.h"
#include <iostream>
#include <sstream>
#include "Server.h"
#include "Utilities.h"
#include "Types.hpp"
#include "AES.hpp"
#include <unordered_map>
#include <iostream>
#include <fstream>
//#include <stxxl/vector>
//#include <stxxl/unordered_map>

using namespace std;

class TwoChoiceWithTunableLocalityStorage {
private:
    bool inMemoryStorage;
    bool profile = false;
    vector<string> filenames;
    vector<string> stashfilenames;
    prf_type nullKey;
    string fileAddressPrefix = "/tmp/";
    long dataIndex;
    vector<long> numberOfBins;
    vector<long> sizeOfEachBin;
    long KEY_VALUE_SIZE = (2 * AES_KEY_SIZE);
    vector< vector<prf_type> > data;

public:
    long readBytes = 0;
    long SeekG = 0;
    double cacheTime;
    long searchTime = 0;
    TwoChoiceWithTunableLocalityStorage(bool inMemory, long dataIndex, string fileAddressPrefix, bool profile);
    bool setup(bool overwrite);
    void insertAll(long dataIndex, vector<vector<prf_type> > ciphers);
    void insertAll(int index, vector<vector< prf_type > > ciphers, bool append, bool firstRun);
    void insertStash(long dataIndex, vector<prf_type> ciphers);
    vector<prf_type> getAllData(long dataIndex);
    void clear(long index);
    vector<prf_type> find(long index, prf_type mapKey, long cnt);
    virtual ~TwoChoiceWithTunableLocalityStorage();
    void printStashSizes();
};

#endif /* TWOCHOICEWITHTUNABLELOCALITYSTORAGE_H */

