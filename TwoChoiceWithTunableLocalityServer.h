#ifndef TWOCHOICEWITHTUNABLELOCALITYSERVER_H
#define TWOCHOICEWITHTUNABLELOCALITYSERVER_H

#include "TwoChoiceWithTunableLocalityStorage.h"
#include "Storage.h"

class TwoChoiceWithTunableLocalityServer {
public:
    TwoChoiceWithTunableLocalityStorage* storage;
    Storage* keywordCounters;
    void getAESRandomValue(unsigned char* keyword, long cnt, unsigned char* result);
    long numberOfBins, sizeOfEachBin;
    bool profile = false;

public:
    long serverSearchTime = 0;
    TwoChoiceWithTunableLocalityServer(long dataIndex, bool inMemory, bool overwrite, bool profile);
    void clear(long index);
    virtual ~TwoChoiceWithTunableLocalityServer();
    void storeCiphers(long dataIndex, vector<vector<prf_type>> ciphers, map<prf_type, prf_type> keywordCounters);
    vector<prf_type> search(long dataIndex, prf_type tokkw, prf_type token, long & keywordCnt, long num);
    vector<prf_type> search(long dataIndex, prf_type hashtoken, long num);
    long getCounter(long dataIndex, prf_type tokkw);
    vector<prf_type> getAllData(long dataIndex);
    vector<prf_type> getStash(long dataIndex);
    void storeCiphers(long dataIndex, vector<vector<prf_type > > ciphers, bool firstrun);
    void storeKeywordCounters(long dataIndex, map<prf_type, prf_type> kwCounters);
    void printStashSizes();

};

#endif /* TWOCHOICEWITHTUNABLELOCALITYSERVER_H */

