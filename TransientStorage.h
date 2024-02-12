#ifndef TRANSIENTSTORAGE_H
#define TRANSIENTSTORAGE_H

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
#include <fcntl.h>
//#include <stxxl/vector>
//#include <stxxl/unordered_map>

using namespace std;

class TransientStorage {
public:
    bool inMemoryStorage;
    bool profile = false;
    double cacheTime = 0;
    double getCounterTime = 0;
    vector< unordered_map<prf_type, prf_type, PRFHasher> > data;
    //  stxxl::unordered_map<prf_type, prf_type, PRFHasher, CompareLess, SUB_BLOCK_SIZE, SUB_BLOCKS_PER_BLOCK>** diskData;
    vector<string> filenames;
    vector<FILE*> filehandles;
    long dataIndex;
    prf_type nullKey;
    string fileAddressPrefix;
    bool setupMode = false;
    bool switchToOPEN = true;

public:
    long seekgCount = 0;
    int counter = 0;
    long KEY_VALUE_SIZE = (4 * AES_KEY_SIZE);
    TransientStorage(bool inMemory, long dataIndex, string fileAddressPrefix, bool profile);
    //    bool setup(bool overwrite);
    void insertPairList(long dataIndex, map<long, pair<prf_type, prf_type> > ciphers);
    void insertPair(long dataIndex, pair<prf_type, prf_type> cipher);
    void insertPairAndInt(long dataIndex, prf_type p1, prf_type p2, unsigned int p3);
    void insertIntAtTheEnd(long dataIndex, int pos, unsigned int p3);
    void setPair(long dataIndex, long index, pair<prf_type, prf_type> cipher);
    void insertTriple(long dataIndex, prf_type p1, prf_type p2, prf_type p3);
    void insertTripleAndInt(long dataIndex, prf_type p1, prf_type p2, prf_type p3, unsigned int p4);
    void insertEntry(long dataIndex, prf_type cipher);
    void insertEntryVector(long dataIndex, vector<prf_type> ciphers, long beginIndex, long count);
    void insertPairVector(long dataIndex, vector<pair<prf_type, prf_type>> ciphers, long beginIndex, long count);
    void insertVectorOfPairs(long dataIndex, vector<pair<prf_type, prf_type>> cipher);
    void AddVectorOfPairs(long dataIndex, vector<pair<prf_type, prf_type>> cipher);
    void setVectorOfPairs(long dataIndex, long index, vector<pair<prf_type, prf_type>> cipher);
    void setVectorOfEntries(long dataIndex, long index, vector<prf_type> ciphers);
    void insertVectorOfTriples(long dataIndex, vector<pair<pair<prf_type, prf_type>, prf_type> > cipher);
    void setEntry(long dataIndex, long index, prf_type cipher);
    vector<pair<prf_type, prf_type>> getAllPairs(long dataIndex);
    vector<pair<pair<prf_type, prf_type>, prf_type> > getAllTriples(long dataIndex);
    vector<prf_type> getAllData(long dataIndex);
    vector<prf_type> getEntriesPartially(long dataIndex, int beginIndex, int count);
    vector<pair<prf_type, prf_type>> getPairsPartially(long dataIndex, int beginIndex, int count);
    void clear(long index);
    pair<prf_type, prf_type> getPair(long dataIndex, long index);
    vector<pair<prf_type, prf_type>> getPairVector(long dataIndex, long begin, int count);
    void getTriple(long dataIndex, long index, prf_type& p1, prf_type& p2, prf_type& p3);
    void getTripleAndInt(long dataIndex, long index, prf_type& p1, prf_type& p2, prf_type& p3, unsigned int& p4);
    void getPairAndInt(long dataIndex, long index, prf_type& p1, prf_type& p2, unsigned int& p3);
    prf_type getEntry(long dataIndex, long index);
    vector<prf_type> getEntryVector(long dataIndex, long begin, long count);
    virtual ~TransientStorage();
    bool setup(bool overwrite, int index);
    char* readRawData(long dataIndex, long begin, long count);
    void writeRawData(long dataIndex, char* data, long count);
    void writeRawDataFrom(long dataIndex, long begin, char* data, long count);



};

#endif /* STORAGE_H */

