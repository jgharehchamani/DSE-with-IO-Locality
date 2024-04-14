#include "NlogNServer.h"
#include <string.h>

NlogNServer::NlogNServer(long dataIndex, bool inMemory, bool overwrite, bool profile, string filePrefix, bool storeKWCounter) {
    this->profile = profile;
    storage = new NlogNStorage(inMemory, dataIndex, Utilities::rootAddress + filePrefix, profile);
    storage->setup(overwrite);
    if (storeKWCounter) {
        this->storeKeywords = storeKWCounter;
        keywordCounters = new Storage(inMemory, dataIndex, Utilities::rootAddress + filePrefix + "keyword-", profile);
        keywordCounters->setup(overwrite);
    }
}

NlogNServer::~NlogNServer() {
}

void NlogNServer::storeCiphers(long dataIndex, long instance, vector<vector<prf_type> > ciphers, map<prf_type, prf_type> kwCounters) {
    storage->insertAll(dataIndex, instance, ciphers, false, true);
    keywordCounters->insert(dataIndex, kwCounters);
}

void NlogNServer::storeCiphers(long dataIndex, long instance, vector<vector<prf_type> > ciphers, bool firstRun) {
    storage->insertAll(dataIndex, instance, ciphers, true, firstRun, true);
}

void NlogNServer::storeKeywordCounters(long dataIndex, map<prf_type, prf_type> kwCounters) {
    keywordCounters->insert(dataIndex, kwCounters, true);
}

vector<prf_type> NlogNServer::getAllData(long dataIndex, long instance) {
    return storage->getAllData(dataIndex, instance);
}

vector<prf_type> NlogNServer::getAllData(long dataIndex) {
    return storage->getAllData(dataIndex);
}

void NlogNServer::clear(long index) {
    storage->clear(index);
    keywordCounters->clear(index);
}

long NlogNServer::getCounter(long dataIndex, prf_type tokkw) {
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

long NlogNServer::getPos(long dataIndex, long posIndex, prf_type tokkw) {
    prf_type curToken = tokkw;
    unsigned char cntstr[AES_KEY_SIZE];
    memset(cntstr, 0, AES_KEY_SIZE);
    *(long*) (&(cntstr[AES_KEY_SIZE - 5])) = posIndex;
    prf_type keywordMapKey = Utilities::generatePRF(cntstr, curToken.data());
    bool found = false;
    prf_type res = keywordCounters->find(dataIndex, keywordMapKey, found);
    long pos = -1;
    if (found) {
        prf_type plaintext;
        Utilities::decode(res, plaintext, curToken.data());
        pos = *(long*) (&(plaintext[0]));
    }
    return pos;
}

vector<prf_type> NlogNServer::search(long dataIndex, long instance, long pos) {
    keywordCounters->seekgCount = 0;
    storage->readBytes = 0;
    double keywordCounterTime = 0, serverSearchTime = 0;
    if (profile)
        Utilities::startTimer(35);

    if (profile) {
        keywordCounterTime = Utilities::stopTimer(35);
        Utilities::startTimer(45);
    }
    vector<prf_type> result = storage->find(dataIndex, instance, pos);
    if (profile) {
        serverSearchTime = Utilities::stopTimer(45);
    }
    return result;
}

void NlogNServer::endSetup() {
    storage->loadCache();
    if (storeKeywords) {
        keywordCounters->loadCache();
    }
}
