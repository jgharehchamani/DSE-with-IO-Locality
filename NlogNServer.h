#ifndef NLOGNSERVER_H
#define NLOGNSERVER_H

#include "NlogNStorage.h"
#include "Storage.h"

class NlogNServer {
public:
    NlogNStorage* storage;
    Storage* keywordCounters;
    void getAESRandomValue(unsigned char* keyword, long cnt, unsigned char* result);
    long numberOfBins, sizeOfEachBin;
    bool profile = false;
    bool storeKeywords = false;
    long getPos(long dataIndex, long posIndex, prf_type tokkw);

public:
    NlogNServer(long dataIndex, bool inMemory, bool overwrite, bool profile, string filePrefix, bool storeKWCounter = true);
    void clear(long index);
    virtual ~NlogNServer();
    void storeCiphers(long dataIndex, long instance, vector<vector<prf_type> > ciphers, map<prf_type, prf_type> keywordCounters);
    void storeCiphers(long dataIndex, long instance, vector<vector<prf_type> > ciphers, bool firstRun);
    void storeKeywordCounters(long dataIndex, map<prf_type, prf_type> kwCounters);
    vector<prf_type> search(long dataIndex, long instance, long pos);
    vector<prf_type> getAllData(long dataIndex);
    vector<prf_type> getAllData(long dataIndex, long instance);
    long getCounter(long dataIndex, prf_type tokkw);
    void endSetup();

};

#endif /* NLOGN_H */

