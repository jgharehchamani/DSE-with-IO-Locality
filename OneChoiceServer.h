#ifndef ONECHOICESERVER_H
#define ONECHOICESERVER_H

#include "OneChoiceStorage.h"
#include "Storage.h"

class OneChoiceServer {
public:
    OneChoiceStorage* storage;
    Storage* keywordCounters;
    int numberOfBins, sizeOfEachBin;
    bool profile = false;
    bool storeKWCounter = false;

public:
    long serverSearchTime = 0;
    OneChoiceServer(long dataIndex, bool inMemory, bool overwrite, bool profile, string filePrefix, bool storeKWCounter = true);
    void clear(long index);
    virtual ~OneChoiceServer();
    void storeKeywordCounters(long dataIndex, map<prf_type, prf_type> keywordCounters);
    void storeCiphers(long dataIndex, vector<vector<prf_type> > ciphers, map<prf_type, prf_type> keywordCounters);
    void storeCiphers(long dataIndex, vector<vector<prf_type> > ciphers, bool firstRun);
    void storeCiphers(long dataIndex, vector<vector<prf_type> > ciphers);
    //vector<prf_type> search(long dataIndex, prf_type token, long & keywordCnt);
    vector<prf_type> search(long dataIndex, prf_type token, long keywordCnt);
    vector<prf_type> getAllData(long dataIndex);
    long getCounter(long dataIndex, prf_type tokkw);
    void endSetup();

};

#endif /* ONECHOICESERVER_H */

