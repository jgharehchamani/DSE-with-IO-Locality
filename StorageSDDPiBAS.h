#ifndef STORAGESDDPIBAS_H
#define STORAGESDDPIBAS_H


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
#include<cstring>
//#include <stxxl/vector>
//#include <stxxl/unordered_map>

using namespace std;

class StorageSDDPiBAS {
public:
    bool inMemoryStorage;
    bool profile = false;
    double cacheTime = 0;
    double getCounterTime = 0;
    //    vector< unordered_map<prf_type, prf_type, PRFHasher> > data;
    vector< vector<pair<prf_type, prf_type> > > data;
    //  stxxl::unordered_map<prf_type, prf_type, PRFHasher, CompareLess, SUB_BLOCK_SIZE, SUB_BLOCKS_PER_BLOCK>** diskData;
    vector<string> filenames;
    vector<long> sizes;
    vector<long> tails;
    long dataIndex;
    prf_type nullKey;
    string fileAddressPrefix;
    vector<FILE*> filehandles;
    bool isInCache(long index, long pos);

public:
    bool setupMode = false;
    long seekgCount = 0;
    long KEY_VALUE_SIZE = (2 * AES_KEY_SIZE + sizeof (long) + sizeof (long));
    StorageSDDPiBAS(bool inMemory, long dataIndex, string fileAddressPrefix, bool profile);
    bool setup(bool overwrite);
    void insert(long dataIndex, map<prf_type, prf_type> ciphers, bool setupMode = false);
    vector<prf_type> getAllData(long dataIndex);
    void clear(long index);
    prf_type find(long index, prf_type mapKey, bool& found);
    pair<prf_type, prf_type> getPos(long index, int pos);
    virtual ~StorageSDDPiBAS();
    string getName(long dataIndex);
    void rename(long toIndex, string inputFileName, long size, long tail);
    void resetup(long index);
    void closeHandle(long index);
    void loadCache();
    //    vector<pair<pair<prf_type, prf_type>, pair<long, long> > > getAllDataForCopy(long dataIndex, long& tail, long& size);
    //    void insertAll(long dataIndex, vector<pair<pair<prf_type, prf_type>, pair<long, long> > > ciphers, long tail, long size);


};


#endif /* STORAGESDDPIBAS_H */

