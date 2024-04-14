#include "NlogNWithTunableLocalityServer.h"
#include <string.h>

NlogNWithTunableLocalityServer::NlogNWithTunableLocalityServer(long dataIndex, bool inMemory, bool overwrite, bool profile) {
    this->profile = profile;
    storage = new NlogNWithTunableLocalityStorage(inMemory, dataIndex, Utilities::rootAddress + "SDa", profile);
    storage->setup(overwrite);
    keywordCounters = new Storage(inMemory, dataIndex, Utilities::rootAddress + "keyword-", profile);
    keywordCounters->setup(overwrite);
}

NlogNWithTunableLocalityServer::~NlogNWithTunableLocalityServer() {
}

void NlogNWithTunableLocalityServer::storeCiphers(long dataIndex, long instance, vector<vector<prf_type> > ciphers, map<prf_type, prf_type> kwCounters) {
    storage->insertAll(dataIndex, instance, ciphers, false, true);
    keywordCounters->insert(dataIndex, kwCounters);
}

void NlogNWithTunableLocalityServer::storeCiphers(long dataIndex, long instance, vector<vector<prf_type> > ciphers, bool firstRun) {
    storage->insertAll(dataIndex, instance, ciphers, true, firstRun);
}

void NlogNWithTunableLocalityServer::storeKeywordCounters(long dataIndex, map<prf_type, prf_type> kwCounters) {
    keywordCounters->insert(dataIndex, kwCounters);
}

vector<prf_type> NlogNWithTunableLocalityServer::getAllData(long dataIndex, long instance) {
    //return storage->getAllData(dataIndex, instance);
}

vector<prf_type> NlogNWithTunableLocalityServer::getAllData(long dataIndex) {
    return storage->getAllData(dataIndex);
}

void NlogNWithTunableLocalityServer::clear(long index) {
    storage->clear(index);
    keywordCounters->clear(index);
}

long NlogNWithTunableLocalityServer::getCounter(long dataIndex, prf_type tokkw) {
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

vector<prf_type> NlogNWithTunableLocalityServer::search(long dataIndex, long level, long instance, prf_type hashtoken, long keywordCnt, long attempt, long chunkNum) {
    Utilities::startTimer(189);
    keywordCounters->seekgCount = 0;
    storage->readBytes = 0;
    double keywordCounterTime = 0;
    vector<prf_type> result;
    result.resize(0);
    unsigned char cntstr[AES_KEY_SIZE];
    memset(cntstr, 0, AES_KEY_SIZE);
    *(long*) (&(cntstr[AES_KEY_SIZE - 5])) = -1;
    prf_type keywordMapKey = Utilities::generatePRF(cntstr, hashtoken.data());
    serverSearchTime = Utilities::stopTimer(189);
    result = storage->find(dataIndex, level, instance, keywordMapKey, keywordCnt, attempt, chunkNum);
    return result;
}
