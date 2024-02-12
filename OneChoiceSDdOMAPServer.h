#ifndef OneChoiceSDdOMAPServer_H
#define OneChoiceSDdOMAPServer_H

#include "OneChoiceSDdOMAPStorage.h"
#include "StorageSDd.h"
#include "OMAP.h"

class OneChoiceSDdOMAPServer {
private:
    OneChoiceSDdOMAPStorage* storage;
    StorageSDd* keywordCounters;
    void getAESRandomValue(unsigned char* keyword, int cnt, unsigned char* result);
    int numberOfBins, sizeOfEachBin, dataIndex;
    bool profile = false;

public:
    OneChoiceSDdOMAPServer(int dataIndex, bool inMemory, bool overwrite, bool profile);
    virtual ~OneChoiceSDdOMAPServer();

    void destroy(int index, int instance);
    void storeKwCounters(int dataIndex, int instance, map<prf_type, prf_type> keywordCounters);
    void move(int index, int toInstance, int fromInstance, int size);
    void insertAll(int index, int instance, vector<prf_type>);
    void insertAll(int index, int instance, vector<vector<prf_type>>);
    int writeToNEW(int index, prf_type keyVal, int pos);
    int writeToKW(int index, prf_type keyVal, int pos);
    void resize(int index, int size, int filesize);

    int getCounter(int dataIndex, int instance, prf_type tokkw);
    vector<prf_type> getAllData(int dataIndex, int instance);
    vector<prf_type> getElements(int index, int instance, int start, int end);
    int putElements(int index, int instance, int start, int end, vector<prf_type> encNEW);
    vector< prf_type> getKW(int index, int count, int size);
    prf_type findCounter(int dataIndex, int instance, prf_type token);
    vector<prf_type> search(int dataIndex, int instance, prf_type token, int keywordCnt);

};

#endif /* OneChoiceSDdOMAPServer */

