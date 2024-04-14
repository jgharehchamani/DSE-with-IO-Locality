#ifndef NLOGNWITHOPTIMALLOCALITYSTORAGE_H
#define NLOGNWITHOPTIMALLOCALITYSTORAGE_H

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

using namespace std;

class NlogNWithOptimalLocalityStorage {
public:
    bool inMemoryStorage;
    bool profile = false;
    vector<vector<string>> filenames;
    prf_type nullKey;
    string fileAddressPrefix; //= "/tmp/";
    long dataIndex;
    vector< vector<prf_type> > data;
    double cacheTime = 0;
    double getCounterTime = 0;

public:
    long readBytes = 0;
    long SeekG = 0;
    NlogNWithOptimalLocalityStorage(bool inMemory, long dataIndex, string fileAddressPrefix, bool profile);
    bool setup(bool overwrite);
    void insertAll(long index, long instance, vector<vector< prf_type > > ciphers, bool append, bool firstRun);
    vector<prf_type > getAllData(long dataIndex);
    vector<prf_type > getAllData(long dataIndex, long instance);
    void clear(long index);
    vector<prf_type> find(long index, long level, long instance, prf_type mapKey, long cnt, long attempt);
    virtual ~NlogNWithOptimalLocalityStorage();
};

#endif /* NLOGNWITHOPTIMALLOCALITYSTORAGE_H */

