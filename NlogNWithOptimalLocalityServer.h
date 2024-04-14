#ifndef NLOGNWITHOPTIMALLOCALITYSERVER_H
#define NLOGNWITHOPTIMALLOCALITYSERVER_H

#include "NlogNWithOptimalLocalityStorage.h"
#include "Storage.h"

class NlogNWithOptimalLocalityServer {
public:
    NlogNWithOptimalLocalityStorage* storage;
    Storage* keywordCounters;
    void getAESRandomValue(unsigned char* keyword, long cnt, unsigned char* result);
    long numberOfBins, sizeOfEachBin;
    bool profile = false;

public:
    NlogNWithOptimalLocalityServer(long dataIndex, bool inMemory, bool overwrite, bool profile);
    void clear(long index);
    virtual ~NlogNWithOptimalLocalityServer();
    void storeCiphers(long dataIndex, long instance, vector<vector<prf_type> > ciphers, map<prf_type, prf_type> keywordCounters);
    void storeCiphers(long dataIndex, long instance, vector<vector<prf_type> > ciphers, bool firstRun);
    void storeKeywordCounters(long dataIndex, map<prf_type, prf_type> kwCounters);
    vector<prf_type> search(long dataIndex, long level, long instance, prf_type hashtoken, long keywordCnt, long attempt);
    vector<prf_type> getAllData(long dataIndex);
    vector<prf_type> getAllData(long dataIndex, long instance);
    long getCounter(long dataIndex, prf_type tokkw);

};

#endif /* NLOGNWITHOPTIMALLOCALITY_H */

