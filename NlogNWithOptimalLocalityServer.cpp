#include "NlogNWithOptimalLocalityServer.h"
#include <string.h>

NlogNWithOptimalLocalityServer::NlogNWithOptimalLocalityServer(long dataIndex, bool inMemory, bool overwrite, bool profile) {
    this->profile = profile;
    storage = new NlogNWithOptimalLocalityStorage(inMemory, dataIndex, Utilities::rootAddress + "SDa", profile);
    storage->setup(overwrite);
    keywordCounters = new Storage(inMemory, dataIndex, Utilities::rootAddress + "keyword-", profile);
    keywordCounters->setup(overwrite);
}

NlogNWithOptimalLocalityServer::~NlogNWithOptimalLocalityServer() {
}

void NlogNWithOptimalLocalityServer::storeCiphers(long dataIndex, long instance, vector<vector<prf_type> > ciphers, map<prf_type, prf_type> kwCounters) {
    storage->insertAll(dataIndex, instance, ciphers, false, true);
    keywordCounters->insert(dataIndex, kwCounters);
}

void NlogNWithOptimalLocalityServer::storeCiphers(long dataIndex, long instance, vector<vector<prf_type> > ciphers, bool firstRun) {
    storage->insertAll(dataIndex, instance, ciphers, true, firstRun);
}

void NlogNWithOptimalLocalityServer::storeKeywordCounters(long dataIndex, map<prf_type, prf_type> kwCounters) {
    keywordCounters->insert(dataIndex, kwCounters);
}

vector<prf_type> NlogNWithOptimalLocalityServer::getAllData(long dataIndex, long instance) {
    //return storage->getAllData(dataIndex, instance);
}

vector<prf_type> NlogNWithOptimalLocalityServer::getAllData(long dataIndex) {
    return storage->getAllData(dataIndex);
}

void NlogNWithOptimalLocalityServer::clear(long index) {
    storage->clear(index);
    keywordCounters->clear(index);
}

long NlogNWithOptimalLocalityServer::getCounter(long dataIndex, prf_type tokkw) {
    prf_type curToken = tokkw;
    unsigned char cntstr[AES_KEY_SIZE];
    memset(cntstr, 0, AES_KEY_SIZE);
    *(long*) (&(cntstr[AES_KEY_SIZE - 5])) = -1;
    prf_type keywordMapKey = Utilities::generatePRF(cntstr, curToken.data());
    bool found = false;
    prf_type res = keywordCounters->find(dataIndex, keywordMapKey, found);
    int keywordCnt = 0;
    if (found) {
        prf_type plaintext;
        Utilities::decode(res, plaintext, curToken.data());
        keywordCnt = *(long*) (&(plaintext[0]));
    }
    return keywordCnt;
}

vector<prf_type> NlogNWithOptimalLocalityServer::search(long dataIndex, long level, long instance, prf_type hashtoken, long keywordCnt, long attempt) {
    keywordCounters->seekgCount = 0;
    storage->readBytes = 0;
    double keywordCounterTime = 0, serverSearchTime = 0;
    if (profile)
        Utilities::startTimer(35);

    if (profile) {
        keywordCounterTime = Utilities::stopTimer(35);
        //printf("keyword counter Search Time:%f number of SeekG:%d number of read bytes:%d\n", keywordCounterTime, keywordCounters->seekgCount, keywordCounters->KEY_VALUE_SIZE * keywordCounters->seekgCount);
        Utilities::startTimer(45);
    }
    vector<prf_type> result;
    result.resize(0);
    unsigned char cntstr[AES_KEY_SIZE];
    memset(cntstr, 0, AES_KEY_SIZE);
    *(long*) (&(cntstr[AES_KEY_SIZE - 5])) = -1;
    prf_type keywordMapKey = Utilities::generatePRF(cntstr, hashtoken.data());
    result = storage->find(dataIndex, level, instance, keywordMapKey, keywordCnt, attempt);
    if (profile) {
        serverSearchTime = Utilities::stopTimer(45);
        //printf("server Search Time:%f number of SeekG:%d number of read bytes:%d\n", serverSearchTime, storage->SeekG, storage->readBytes);
    }
    return result;
}
