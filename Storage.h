#ifndef STORAGE_H
#define STORAGE_H

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

class Storage {
public:
    bool inMemoryStorage;
    bool profile = false;
    double cacheTime = 0;
    double getCounterTime = 0;
    vector< vector<pair<prf_type, prf_type> > > data;
    //  stxxl::unordered_map<prf_type, prf_type, PRFHasher, CompareLess, SUB_BLOCK_SIZE, SUB_BLOCKS_PER_BLOCK>** diskData;
    vector<string> filenames;
    vector<FILE*> filehandles;
    long dataIndex;
    prf_type nullKey;
    string fileAddressPrefix;
    bool setupMode = false;

    bool isInCache(long index, long pos);

public:
    long seekgCount = 0;
    long KEY_VALUE_SIZE = (2 * AES_KEY_SIZE + sizeof (long));
    Storage(bool inMemory, long dataIndex, string fileAddressPrefix, bool profile);
    bool setup(bool overwrite);
    void insert(long dataIndex, map<prf_type, prf_type> ciphers, bool setupMode = false, bool firstInsert = false);
    void insert(long dataIndex, unordered_map<prf_type, prf_type, PRFHasher> ciphers, bool setupMode = false, bool firstInsert = false);
    vector<prf_type> getAllData(long dataIndex);
    unordered_map<prf_type, prf_type, PRFHasher>* getAllDataPairs(long dataIndex);
    void clear(long index);
    prf_type find(long index, prf_type mapKey, bool& found);
    virtual ~Storage();
    void insert(int key, int value);
    void insert(string key, int value);
    bool get(int key, int& value);
    bool get(string key, int& value);
    bool erase(long index, prf_type mapKey, bool& found);
    bool replace(long index, prf_type mapKey, bool& found, prf_type newVal);
    void erase(string key);
    void erase(int key);
    void replace(int key, int value);
    void replace(string key, int value);
    bool setup(bool overwrite, int index);
    void insert(prf_type key, prf_type value);
    string getName(long dataIndex);
    void rename(long toIndex, string inputFileName);
    void resetup(long index);
    void closeHandle(long index);
    void loadCache();


};

#endif /* STORAGE_H */

