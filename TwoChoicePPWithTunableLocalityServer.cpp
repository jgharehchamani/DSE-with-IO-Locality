#include "TwoChoicePPWithTunableLocalityServer.h"
#include <string.h>

TwoChoicePPWithTunableLocalityServer::TwoChoicePPWithTunableLocalityServer(long dataIndex, bool inMemory, bool overwrite, bool profile) {
    this->profile = profile;
    storage = new TwoChoicePPWithTunableLocalityStorage(inMemory, dataIndex, Utilities::rootAddress + "2CH-Locality-", profile);
    storage->setup(overwrite);
    keywordCounters = new Storage(inMemory, dataIndex, Utilities::rootAddress + "2CH-Locality-keyword-", profile);
    keywordCounters->setup(overwrite);
}

TwoChoicePPWithTunableLocalityServer::~TwoChoicePPWithTunableLocalityServer() {
}

void TwoChoicePPWithTunableLocalityServer::storeKeywordAndStashCounters(long dataIndex, vector<prf_type> stashCiphers, map<prf_type, prf_type> kwCounters) {
    keywordCounters->insert(dataIndex, kwCounters);
}

void TwoChoicePPWithTunableLocalityServer::storeKeywordCounters(long dataIndex, map<prf_type, prf_type> kwCounters) {
    keywordCounters->insert(dataIndex, kwCounters);
}

void TwoChoicePPWithTunableLocalityServer::storeCiphers(long dataIndex, vector<vector<prf_type> > ciphers, bool firstRun) {
    storage->insertAll(dataIndex, ciphers, true, firstRun);
}

void TwoChoicePPWithTunableLocalityServer::storeCiphers(long dataIndex, vector<vector<prf_type> > ciphers,
        map<prf_type, prf_type> keywordCounter) {
    storage->insertAll(dataIndex, ciphers);
    keywordCounters->insert(dataIndex, keywordCounter);
}

pair<prf_type, vector<prf_type>> TwoChoicePPWithTunableLocalityServer::insertCuckooHT(long index, long tableNum, long cuckooID,
        long hash, prf_type keyw, vector<prf_type> fileids) {
    return storage->insertCuckooHT(index, tableNum, cuckooID, hash, keyw, fileids);
}

vector<prf_type> TwoChoicePPWithTunableLocalityServer::search(long dataIndex, prf_type hashToken, long kwc) {
    vector<prf_type> result;
    result.resize(0);
    unsigned char cntstr[AES_KEY_SIZE];
    memset(cntstr, 0, AES_KEY_SIZE);
    *(long*) (&(cntstr[AES_KEY_SIZE - 5])) = -1;
    prf_type keywordMapKey = Utilities::generatePRF(cntstr, hashToken.data());
    result = storage->find(dataIndex, keywordMapKey, kwc);
    return result;
}

long TwoChoicePPWithTunableLocalityServer::getCounter(long dataIndex, prf_type tokkw) {
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

vector<prf_type> TwoChoicePPWithTunableLocalityServer::search(long dataIndex, prf_type tokkw, prf_type hashtoken,
        long& keywordCnt, long num) {
    keywordCounters->seekgCount = 0;
    storage->readBytes = 0;
    double keywordCounterTime = 0, serverSearchTime = 0;
    if (profile)
        Utilities::startTimer(35);

    prf_type curToken = tokkw;
    unsigned char cntstr[AES_KEY_SIZE];
    memset(cntstr, 0, AES_KEY_SIZE);
    *(long*) (&(cntstr[AES_KEY_SIZE - 5])) = -1;
    prf_type keywordMapKey = Utilities::generatePRF(cntstr, curToken.data());
    bool found = false;
    prf_type res = keywordCounters->find(dataIndex, keywordMapKey, found);
    if (profile) {
        keywordCounterTime = Utilities::stopTimer(35);
        printf("keyword counter Search Time:%f number of SeekG:%d number of read bytes:%d\n",
                keywordCounterTime, keywordCounters->seekgCount,
                keywordCounters->KEY_VALUE_SIZE * keywordCounters->seekgCount);
        Utilities::startTimer(45);
    }
    vector<prf_type> result;
    result.resize(0);
    if (found) {
        prf_type plalongext;
        Utilities::decode(res, plalongext, curToken.data());
        keywordCnt = *(long*) (&(plalongext[0]));
        cout << "keywordcnt at search:" << keywordCnt << endl;
        if (keywordCnt > num)
            return result;
        curToken = hashtoken;
        memset(cntstr, 0, AES_KEY_SIZE);
        *(long*) (&(cntstr[AES_KEY_SIZE - 5])) = -1;
        keywordMapKey = Utilities::generatePRF(cntstr, curToken.data());
        result = storage->find(dataIndex, keywordMapKey, keywordCnt);
        if (profile) {
            serverSearchTime = Utilities::stopTimer(45);
            printf("server Search Time:%f number of SeekG:%ld number of read bytes:%d\n",
                    serverSearchTime, storage->SeekG, storage->readBytes);
        }
    }
    return result;
}

vector<prf_type> TwoChoicePPWithTunableLocalityServer::getAllData(long dataIndex) {
    return storage->getAllData(dataIndex);
}

vector<prf_type> TwoChoicePPWithTunableLocalityServer::getCuckooHT(long dataIndex) {
    return storage->getCuckooHT(dataIndex);
}

void TwoChoicePPWithTunableLocalityServer::insertCuckooStash(long index, long tableNum, vector<prf_type> ctCiphers) {
    storage->insertCuckooStash(index, tableNum, ctCiphers);
}

vector<prf_type> TwoChoicePPWithTunableLocalityServer::cuckooSearch(long index, long tableNum,
        prf_type hashtoken1, prf_type hashtoken2) {
    vector<prf_type> results;
    unsigned char cntstr[AES_KEY_SIZE];
    long entryNum = pow(2, (index - tableNum));
    long h[2];

    memset(cntstr, 0, AES_KEY_SIZE);
    *(long*) (&(cntstr[AES_KEY_SIZE - 5])) = -1;
    prf_type mapKey1 = Utilities::generatePRF(cntstr, hashtoken1.data());
    unsigned char* hash1 = Utilities::sha256((char*) (mapKey1.data()), AES_KEY_SIZE);
    h[0] = (unsigned long) (*((long*) hash1)) % entryNum;

    memset(cntstr, 0, AES_KEY_SIZE);
    *(long*) (&(cntstr[AES_KEY_SIZE - 5])) = -1;
    prf_type mapKey2 = Utilities::generatePRF(cntstr, hashtoken2.data());
    unsigned char* hash2 = Utilities::sha256((char*) (mapKey2.data()), AES_KEY_SIZE);
    h[1] = (unsigned long) (*((long*) hash2)) % entryNum;

    results = storage->cuckooSearch(index, tableNum, h);
    return results;
}

void TwoChoicePPWithTunableLocalityServer::clear(long index) {
    storage->clear(index);
    keywordCounters->clear(index);
}
