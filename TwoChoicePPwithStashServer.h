#ifndef TWOCHOICESERVER_H
#define TWOCHOICESERVER_H

#include "TwoChoicePPwithStashStorage.h"
#include "Storage.h"

class TwoChoicePPwithStashServer {
public:
    TwoChoicePPwithStashStorage* storage;
    Storage* keywordCounters;
    void getAESRandomValue(unsigned char* keyword, long cnt, unsigned char* result);
    long numberOfBins, sizeOfEachBin;
    bool profile = false;

public:
    TwoChoicePPwithStashServer(long dataIndex, bool inMemory, bool overwrite, bool profile);
    void clear(long index);
    virtual ~TwoChoicePPwithStashServer();
    void storeCiphers(long dataIndex, vector<vector<prf_type> > ciphers, vector<prf_type> stashCiphers, map<prf_type, prf_type> keywordCounters);
    vector<prf_type> search(long dataIndex, prf_type tokkw, prf_type token, long & keywordCnt, long bin);
    vector<prf_type> getAllData(long dataIndex);
    vector<prf_type> getCuckooHT(long dataIndex);
    vector<prf_type> getStash(long dataIndex);
    pair<prf_type, vector<prf_type>> insertCuckooHT(long index, long tableNum, long cuckooID, long hash, prf_type keyw, vector<prf_type> fileids);
    vector<prf_type> cuckooSearch(long index, long tableNum, prf_type hashtoken1, prf_type hashtoken2);
    void insertCuckooStash(long index, long tableNum, vector<prf_type> ctCiphers);
    void storeKeywordAndStashCounters(long dataIndex, vector<prf_type> stashCiphers, map<prf_type, prf_type> kwCounter);
    void storeCiphers(long dataIndex, vector<vector<prf_type> > ciphers, bool firstRun);
};

#endif /* TWOCHOICESERVER_H */

