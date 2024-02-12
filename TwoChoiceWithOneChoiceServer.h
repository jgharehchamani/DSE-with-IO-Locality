#ifndef TWOCHOICEWITHONECHOICESERVER_H
#define TWOCHOICEWITHONECHOICESERVER_H

#include "TwoChoiceWithOneChoiceStorage.h"
#include "Storage.h"

class TwoChoiceWithOneChoiceServer {
public:
    TwoChoiceWithOneChoiceStorage* storage;
    Storage* keywordCounters;
    void getAESRandomValue(unsigned char* keyword, long cnt, unsigned char* result);
    long numberOfBins, sizeOfEachBin;
    bool profile = false;

public:
    long serverSearchTime = 0;
    TwoChoiceWithOneChoiceServer(long dataIndex, bool inMemory, bool overwrite, bool profile);
    void clear(long index);
    virtual ~TwoChoiceWithOneChoiceServer();
    void storeCiphers(long dataIndex, vector<vector<prf_type> > ciphers, map<prf_type, prf_type> keywordCounters);
    void storeKeywordCounters(long dataIndex, map<prf_type, prf_type> kwCounters);
    void storeCiphers(long dataIndex, vector<vector<prf_type> > ciphers, bool firstRun);
    //    vector<prf_type> search(long dataIndex, prf_type tokkw, prf_type token, long & keywordCnt, long num);
    vector<prf_type> search(long dataIndex, prf_type hashtoken, long keywordCnt, long max);
    vector<prf_type> getAllData(long dataIndex);
    vector<prf_type> getStash(long dataIndex);
    //vector<prf_type> newsearch(long dataIndex , prf_type hashtoken, long keywordCnt, long pos);
    void printStashSizes();
    long getCounter(long dataIndex, prf_type tokkw);
    void endSetup();

};

#endif /* TWOCHOICEWITHONECHOICESERVER_H */

