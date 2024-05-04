#include "OneChoiceServer.h"
#include <string.h>

OneChoiceServer::OneChoiceServer(long dataIndex, bool inMemory, bool overwrite, bool profile, string filePrefix, bool storeKWCounter) {
    this->profile = profile;
    this->storeKWCounter = storeKWCounter;
    storage = new OneChoiceStorage(inMemory, dataIndex, Utilities::rootAddress + filePrefix, profile);
    storage->setup(overwrite);
    if (storeKWCounter) {
        this->storeKWCounter = storeKWCounter;
        keywordCounters = new Storage(inMemory, dataIndex, Utilities::rootAddress + filePrefix + "keyword-", profile);
        keywordCounters->setup(overwrite);
    }
}

OneChoiceServer::~OneChoiceServer() {
}

void OneChoiceServer::storeKeywordCounters(long dataIndex, map<prf_type, prf_type> kwCounters) {
    keywordCounters->insert(dataIndex, kwCounters, true);
}

void OneChoiceServer::storeCiphers(long dataIndex, vector<vector<prf_type> > ciphers) {
    storage->insertAll(dataIndex, ciphers, false, true);
}

void OneChoiceServer::storeCiphers(long dataIndex, vector<vector<prf_type> > ciphers, map<prf_type, prf_type> kwCounters) {
    storage->insertAll(dataIndex, ciphers);
    keywordCounters->insert(dataIndex, kwCounters);
}

void OneChoiceServer::storeCiphers(long dataIndex, vector<vector<prf_type> > ciphers, bool firstRun) {
    storage->insertAll(dataIndex, ciphers, true, firstRun, true);
}

long OneChoiceServer::getCounter(long dataIndex, prf_type tokkw) {
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

vector<prf_type> OneChoiceServer::search(long dataIndex, prf_type token, long keywordCnt) {
    serverSearchTime = 0;
    Utilities::startTimer(43);
    if (storeKWCounter) {
        keywordCounters->seekgCount = 0;
    }
    storage->readBytes = 0;
    double keywordCounterTime = 0;
    if (profile) {
        Utilities::startTimer(35);
    }
    prf_type curToken = token;
    unsigned char cntstr[AES_KEY_SIZE];
    memset(cntstr, 0, AES_KEY_SIZE);
    *(int*) (&(cntstr[AES_KEY_SIZE - 5])) = -1;
    prf_type keywordMapKey = Utilities::generatePRF(cntstr, curToken.data());
    bool found = false;
    prf_type res;
    if (profile && storeKWCounter) {
        keywordCounterTime = Utilities::stopTimer(35);
//        cout << "[[" << keywordCounterTime << "]]" << endl;
        //printf("keyword counter Search Time:%f number of SeekG:%d number of read bytes:%d\n", keywordCounterTime, keywordCounters->seekgCount, keywordCounters->KEY_VALUE_SIZE * keywordCounters->seekgCount);
    }
    serverSearchTime = Utilities::stopTimer(43);
    vector<prf_type> result;
    if (keywordCnt > 0)
        result = storage->find(dataIndex, keywordMapKey, keywordCnt);
    // if (profile) {
    //printf("server Search Time:%f number of SeekG:%d number of read bytes:%d\n", serverSearchTime, storage->SeekG, storage->readBytes);
    // }
    return result;
}

vector<prf_type > OneChoiceServer::getAllData(long dataIndex) {
    return storage->getAllDataFlat(dataIndex);
}

void OneChoiceServer::clear(long index) {
    storage->clear(index);
    if (storeKWCounter) {
        keywordCounters->clear(index);
    }
}

void OneChoiceServer::endSetup() {
    storage->loadCache();
    if (storeKWCounter) {
        keywordCounters->loadCache();
    }
}
