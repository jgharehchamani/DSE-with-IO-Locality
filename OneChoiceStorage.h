#ifndef ONECHOICESTORAGE_H
#define ONECHOICESTORAGE_H

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

class OneChoiceStorage {
public:
    bool inMemoryStorage;
    bool profile = false;
    double cacheTime = 0;
    vector<string> filenames;
    vector<FILE*> filehandles;
    prf_type nullKey;
    string fileAddressPrefix = Utilities::rootAddress;
    long dataIndex;
    vector<long> numberOfBins;
    vector<long> sizeOfEachBin;
    vector< vector< vector<prf_type> > > data;
    long setupHeadPos = 0;
    bool isInCache(long index, long pos);
    //  stxxl::VECTOR_GENERATOR< prf_type, 4, 8, 1 * 1024 * 1024, stxxl::RC, stxxl::lru >::result** diskData;

public:
    long readBytes = 0;
    long searchTime = 0;
    long SeekG = 0;
    bool setupMode = false;
    OneChoiceStorage(bool inMemory, long dataIndex, string fileAddressPrefix, bool profile);
    bool setup(bool overwrite);
    void insertAll(long dataIndex, vector<vector< prf_type> > ciphers, bool append = false, bool firstRun = false, bool setupMode = false);
    void insertAll(long dataIndex, vector< prf_type> ciphers, bool append = false, bool firstRun = false, bool setupMode = false);
    vector<vector<prf_type> >* getAllData(long dataIndex);
    vector<prf_type> getAllDataFlat(long dataIndex);
    void clear(long index);
    vector<prf_type> find(long index, prf_type mapKey, long cnt);
    virtual ~OneChoiceStorage();
    string getName(long dataIndex);
    void rename(long toIndex, string inputFileName);
    void resetup(long index);
    void closeHandle(long index);
    void loadCache();


};

#endif /* ONECHOICESTORAGE_H */
