#ifndef TWOCHOICEWITHONECHOICESTORAGE_H
#define TWOCHOICEWITHONECHOICESTORAGE_H

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

class TwoChoiceWithOneChoiceStorage {
public:
    bool inMemoryStorage;
    bool profile = false;
    vector<string> filenames;
    vector<FILE*> filehandles;
    vector<string> stashfilenames;
    prf_type nullKey;
    string fileAddressPrefix; //= "/tmp/";
    long dataIndex;
    vector<long> numberOfBins;
    vector<long> sizeOfEachBin;
    vector< vector< vector<prf_type> > > data;
    double cacheTime = 0;
    double getCounterTime = 0;
    long setupHeadPos = 0;
    bool isInCache(long index, long pos);
    //stxxl::VECTOR_GENERATOR< pair<prf_type, prf_type>, 4, 8, 1 * 1024 * 1024, stxxl::RC, stxxl::lru >::result** diskData;

public:
    long readBytes = 0;
    long SeekG = 0;
    long searchTime = 0;
    TwoChoiceWithOneChoiceStorage(bool inMemory, long dataIndex, string fileAddressPrefix, bool profile);
    bool setup(bool overwrite);
    void insertAll(long index, vector<vector< prf_type > > ciphers, bool append, bool firstRun, bool setupMode = false);
    void insertStash(long dataIndex, vector<prf_type> ciphers);
    vector<prf_type > getAllData(long dataIndex);
    vector<prf_type> getStash(long index);
    void clear(long index);
    vector<prf_type> find(long index, prf_type mapKey, long cnt);
    virtual ~TwoChoiceWithOneChoiceStorage();
    void printStashSizes();
    void loadCache();
};

#endif /* TWOCHOICEWITHONECHOICESTORAGE_H */

