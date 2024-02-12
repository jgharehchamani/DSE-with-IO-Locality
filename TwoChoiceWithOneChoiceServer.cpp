#include "TwoChoiceWithOneChoiceServer.h"
#include <string.h>

TwoChoiceWithOneChoiceServer::TwoChoiceWithOneChoiceServer(long dataIndex, bool inMemory, bool overwrite, bool profile) {
    this->profile = profile;
    storage = new TwoChoiceWithOneChoiceStorage(inMemory, dataIndex, Utilities::rootAddress + "SDa-", profile);
    storage->setup(overwrite);
    keywordCounters = new Storage(inMemory, dataIndex, Utilities::rootAddress + "keyword-", profile);
    keywordCounters->setup(overwrite);
}

TwoChoiceWithOneChoiceServer::~TwoChoiceWithOneChoiceServer() {
}

void TwoChoiceWithOneChoiceServer::storeCiphers(long dataIndex, vector<vector<prf_type> > ciphers, map<prf_type, prf_type> kwCounters) {
    storage->insertAll(dataIndex, ciphers, false, true);
    keywordCounters->insert(dataIndex, kwCounters);
}

void TwoChoiceWithOneChoiceServer::storeCiphers(long dataIndex, vector<vector<prf_type> > ciphers, bool firstRun) {
    storage->insertAll(dataIndex, ciphers, true, firstRun, true);
}

void TwoChoiceWithOneChoiceServer::storeKeywordCounters(long dataIndex, map<prf_type, prf_type> kwCounters) {
    keywordCounters->insert(dataIndex, kwCounters, true);
}

vector<prf_type> TwoChoiceWithOneChoiceServer::getAllData(long dataIndex) {
    return storage->getAllData(dataIndex);
}

/*
vector<prf_type> TwoChoiceWithOneChoiceServer::getStash(long dataIndex) {
    return storage->getStash(dataIndex);
}
 */
void TwoChoiceWithOneChoiceServer::clear(long index) {
    storage->clear(index);
    keywordCounters->clear(index);
}

long TwoChoiceWithOneChoiceServer::getCounter(long dataIndex, prf_type tokkw) {
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

vector<prf_type> TwoChoiceWithOneChoiceServer::search(long dataIndex, prf_type hashtoken, long keywordCnt, long max) {
    Utilities::startTimer(45);
    keywordCounters->seekgCount = 0;
    storage->readBytes = 0;
    double keywordCounterTime = 0;
    serverSearchTime = 0;
    vector<prf_type> result;
    result.resize(0);
    if (keywordCnt > max) {
        cout << "search in one choice instance, NOT HERE" << endl;
        return result;
    }
    unsigned char cntstr[AES_KEY_SIZE];
    memset(cntstr, 0, AES_KEY_SIZE);
    *(long*) (&(cntstr[AES_KEY_SIZE - 5])) = -1;
    prf_type keywordMapKey = Utilities::generatePRF(cntstr, hashtoken.data());
    serverSearchTime = Utilities::stopTimer(45);
    result = storage->find(dataIndex, keywordMapKey, keywordCnt);
    //cout <<"FIND TIME at TWO choice server:"<<sel<<endl;

    //if (profile) {
    //printf("server Search Time:%f number of SeekG:%d number of read bytes:%d\n", serverSearchTime, storage->SeekG, storage->readBytes);
    //}
    return result;
}

void TwoChoiceWithOneChoiceServer::endSetup() {
    keywordCounters->loadCache();
    storage->loadCache();

}
