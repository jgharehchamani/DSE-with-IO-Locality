#include "OneChoiceSDdOMAPServer.h"
#include <string>

OneChoiceSDdOMAPServer::OneChoiceSDdOMAPServer(int dataIndex, bool inMemory, bool overwrite, bool profile) {
    this->profile = profile;
    this->dataIndex = dataIndex;
    storage = new OneChoiceSDdOMAPStorage(inMemory, dataIndex, "/tmp/", profile);
    storage->setup(overwrite);
    keywordCounters = new StorageSDd(inMemory, dataIndex, "/tmp/keyword-", profile);
    keywordCounters->setup(overwrite);
}

OneChoiceSDdOMAPServer::~OneChoiceSDdOMAPServer() {
}

int OneChoiceSDdOMAPServer::getCounter(int dataIndex, int instance, prf_type tokkw) {
    prf_type curToken = tokkw;
    unsigned char cntstr[AES_KEY_SIZE];
    memset(cntstr, 0, AES_KEY_SIZE);
    *(int*) (&(cntstr[AES_KEY_SIZE - 5])) = -1;
    prf_type keywordMapKey = Utilities::generatePRF(cntstr, curToken.data());
    bool found = false;
    prf_type res = keywordCounters->find(dataIndex, instance, keywordMapKey, found);
    int keywordCnt = 0;
    if (found) {
        prf_type plaintext;
        Utilities::decode(res, plaintext, curToken.data());
        keywordCnt = *(int*) (&(plaintext[0]));
    }
    return keywordCnt;
}

void OneChoiceSDdOMAPServer::storeKwCounters(int dataIndex, int instance, map<prf_type, prf_type> kc) {
    keywordCounters->insert(dataIndex, instance, kc);
}

prf_type OneChoiceSDdOMAPServer::findCounter(int dataIndex, int instance, prf_type token) {
    bool found;
    prf_type res = keywordCounters->find(dataIndex, instance, token, found);
    return res;
}

vector<prf_type> OneChoiceSDdOMAPServer::search(int dataIndex, int instance, prf_type hashtoken, int keywordCnt) {
    keywordCounters->seekgCount = 0;
    storage->readBytes = 0;
    int keywordCounterTime = 0, serverSearchTime = 0;
    if (profile)
        Utilities::startTimer(35);
    if (profile) {
        keywordCounterTime = Utilities::stopTimer(35);
        printf("keyword counter Search Time:%f number of SeekG:%d number of read bytes:%d\n", keywordCounterTime, keywordCounters->seekgCount, keywordCounters->KEY_VALUE_SIZE * keywordCounters->seekgCount);
        Utilities::startTimer(45);
    }
    vector<prf_type> result;
    unsigned char cntstr[AES_KEY_SIZE];
    memset(cntstr, 0, AES_KEY_SIZE);
    *(int*) (&(cntstr[AES_KEY_SIZE - 5])) = -1;
    prf_type keywordMapKey = Utilities::generatePRF(cntstr, hashtoken.data());
    result = storage->find(dataIndex, instance, keywordMapKey, keywordCnt);
    if (profile) {
        serverSearchTime = Utilities::stopTimer(45);
        printf("server Search Time:%f number of SeekG:%d number of read bytes:%d\n", serverSearchTime, storage->SeekG, storage->readBytes);
    }
    return result;
}

vector<prf_type> OneChoiceSDdOMAPServer::getAllData(int dataIndex, int instance) {
    return storage->getAllData(dataIndex, instance);
}

void OneChoiceSDdOMAPServer::move(int index, int toInstance, int fromInstance, int size) {
    storage->move(index, toInstance, fromInstance, size);
    keywordCounters->move(index, toInstance, fromInstance);
    //map<prf_type,prf_type> wordCount;
    //wordCount = keywordCounters->getAllData(index, fromInstance);
    //keywordCounters->insert(index, toInstance, wordCount);
}

int OneChoiceSDdOMAPServer::writeToNEW(int index, prf_type keyVal, int pos) {
    int last = storage->writeToNEW(index, keyVal, pos);
    return last;
}

int OneChoiceSDdOMAPServer::writeToKW(int index, prf_type keyVal, int pos) {
    int last = storage->writeToKW(index, keyVal, pos);
    return last;
}

void OneChoiceSDdOMAPServer::destroy(int index, int instance) {
    storage->clear(index, instance);
    keywordCounters->clear(index, instance);
}

void OneChoiceSDdOMAPServer::resize(int index, int size, int filesize) {
    storage->truncate(index, size, filesize);
}

vector<prf_type> OneChoiceSDdOMAPServer::getElements(int index, int instance, int start, int end) {
    return storage->getElements(index, instance, start, end);
}

int OneChoiceSDdOMAPServer::putElements(int index, int instance, int start, int end, vector<prf_type> encNEW) {
    return storage->putElements(index, instance, start, end, encNEW);
}

vector< prf_type> OneChoiceSDdOMAPServer::getKW(int index, int start, int size) {
    return storage->getKW(index, start, size);
}

void OneChoiceSDdOMAPServer::insertAll(int index, int instance, vector<prf_type> sorted) {
    //storage->clear(index,instance);
    storage->insertAll(index, instance, sorted);
}

void OneChoiceSDdOMAPServer::insertAll(int index, int instance, vector<vector<prf_type>> sorted) {
    //storage->clear(index,instance);
    storage->insertAll(index, instance, sorted);
}

