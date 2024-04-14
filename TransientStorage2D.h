#ifndef TransientStorage2D_H
#define TransientStorage2D_H

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

class TransientStorage2D {
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
    int D1, D2, D3;

public:
    long seekgCount = 0;
    int** counter;
    long KEY_VALUE_SIZE = (4 * AES_KEY_SIZE);
    TransientStorage2D(bool inMemory, long dataIndex, string fileAddressPrefix, bool profile, int D1, int D2, int D3);
    //    void insertPairList(long dataIndex, map<long, pair<prf_type,prf_type> > ciphers,int d1,int d2);
    void insertPair(long dataIndex, pair<prf_type, prf_type> cipher, int d1, int d2);
    //    void insertPairAndInt(long dataIndex, prf_type p1, prf_type p2, unsigned int p3,int d1,int d2);
    //    void insertIntAtTheEnd(long dataIndex, int pos, unsigned int p3,int d1,int d2);
    //    void setPair(long dataIndex,long index, pair<prf_type, prf_type> cipher,int d1,int d2);
    void insertTriple(long dataIndex, prf_type p1, prf_type p2, prf_type p3, int d1, int d2);
    //    void insertTripleAndInt(long dataIndex, prf_type p1,prf_type p2, prf_type p3,unsigned int p4,int d1,int d2);
    //    void insertEntry(long dataIndex, prf_type cipher,int d1,int d2);
    //    void insertEntryVector(long dataIndex, vector<prf_type> ciphers,long beginIndex, long count,int d1,int d2);
    //    void insertPairVector(long dataIndex, vector<pair<prf_type,prf_type>> ciphers,long beginIndex, long count,int d1,int d2);
    void insertVectorOfPairs(long dataIndex, vector<pair<prf_type, prf_type>> cipher, int d1, int d2);
    //    void AddVectorOfPairs(long dataIndex, vector<pair<prf_type,prf_type>> cipher,int d1,int d2);
    //    void setVectorOfPairs(long dataIndex,long index, vector<pair<prf_type,prf_type>> cipher,int d1,int d2);
    //    void setVectorOfEntries(long dataIndex,long index, vector<prf_type> ciphers,int d1,int d2);
    void insertVectorOfTriples(long dataIndex, vector<pair<pair<prf_type, prf_type>, prf_type> > cipher, int d1, int d2);
    //    void setEntry(long dataIndex,long index, prf_type cipher,int d1,int d2);
    vector<pair<prf_type, prf_type>> getAllPairs(long dataIndex, int d1, int d2);
    vector<pair<pair<prf_type, prf_type>, prf_type> > getAllTriples(long dataIndex, int d1, int d2);
    //    vector<prf_type> getAllData(long dataIndex,int d1,int d2);
    //    vector<prf_type> getEntriesPartially(long dataIndex,int beginIndex,int count,int d1,int d2);
    //    vector<pair<prf_type, prf_type>> getPairsPartially(long dataIndex,int beginIndex,int count,int d1,int d2);
    void clear(long index, int d1, int d2);
    pair<prf_type, prf_type> getPair(long dataIndex, long index, int d1, int d2);
    //    vector<pair<prf_type, prf_type>> getPairVector(long dataIndex,long begin,int count,int d1,int d2);
    void getTriple(long dataIndex, long index, prf_type& p1, prf_type& p2, prf_type& p3, int d1, int d2);
    //    void getTripleAndInt(long dataIndex,long index,prf_type& p1,prf_type& p2,prf_type& p3,unsigned int& p4,int d1,int d2);
    //    void getPairAndInt(long dataIndex,long index,prf_type& p1,prf_type& p2,unsigned int& p3,int d1,int d2);
    //    prf_type getEntry(long dataIndex,long index,int d1,int d2);
    //    vector<prf_type> getEntryVector(long dataIndex,long begin,long count,int d1,int d2);
    virtual ~TransientStorage2D();
    bool setup(bool overwrite, int index);
    //    char* readRawData(long dataIndex,long begin,long count,int d1,int d2);
    //    void writeRawData(long dataIndex,char* data,long count,int d1,int d2);
    //    void writeRawDataFrom(long dataIndex,long begin,char* data,long count,int d1,int d2);



};

#endif /* STORAGE_H */

