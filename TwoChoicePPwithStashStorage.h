#ifndef TWOCHOICESTORAGE_H
#define TWOCHOICESTORAGE_H

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

class TwoChoicePPwithStashStorage {
public:
    bool inMemoryStorage;
    bool profile = false;
    vector<string> filenames;
    vector<string> stashes;
    vector<vector<string>> stashfilenames;
    vector<vector<long>> cuckooStashLen;
    vector<vector<vector<string>>> cuckoofilenames;
    prf_type nullKey;
    string fileAddressPrefix = "/tmp/";
    long dataIndex;
    vector<long> numberOfBins;
    vector<long> sizeOfEachBin;
    vector< vector<prf_type> > data;
    double cacheTime;
    //stxxl::VECTOR_GENERATOR< pair<prf_type, prf_type>, 4, 8, 1 * 1024 * 1024, stxxl::RC, stxxl::lru >::result** diskData;

public:
    long readBytes = 0;
    long SeekG = 0;
    TwoChoicePPwithStashStorage(bool inMemory, long dataIndex, string fileAddressPrefix, bool profile);
    bool setup(bool overwrite);
    void insertAll(long dataIndex, vector<vector< prf_type> > ciphers, bool append = false, bool firstRun = false);
    void insertStash(long dataIndex, vector<prf_type> ciphers);
    pair<prf_type, vector<prf_type>> insertCuckooHT(long index, long tableNum, long cuckooID, long hash, prf_type keyw, vector<prf_type> fileids);
    vector<prf_type> getAllData(long dataIndex);
    vector<prf_type> getStash(long index);
    void insertCuckooStash(long index, long tableNum, vector<prf_type> ctCiphers);
    vector<prf_type> getCuckooHT(long index);
    vector <prf_type> cuckooSearch(long index, long tableNum, long h[2]);
    void clear(long index);
    vector<prf_type> find(long index, prf_type mapKey, long cnt);
    virtual ~TwoChoicePPwithStashStorage();
};

#endif /* TWOCHOICESTORAGE_H */

