#include "AmortizedBASServer.h"
#include <string.h>

AmortizedBASServer::AmortizedBASServer(int dataIndex, bool inMemory, bool overwrite, bool profile) {
    this->profile = profile;
    storage = new Storage(inMemory, dataIndex, Utilities::rootAddress, profile);
    storage->setup(overwrite);
}

AmortizedBASServer::~AmortizedBASServer() {
}

void AmortizedBASServer::storeCiphers(int dataIndex, map<prf_type, prf_type> ciphers) {
    storage->insert(dataIndex, ciphers, true);
}

vector<prf_type> AmortizedBASServer::search(int dataIndex, prf_type token) {
    vector<prf_type> results;
    storage->seekgCount = 0;
    bool exist = false;
    int cnt = 0;
    double serverSearchTime = 0;
    do {
//        if (cnt % 1000 == 0) {
//            cout << "searching for " << cnt << endl;
//        }
        prf_type curToken = token, mapKey;
        unsigned char cntstr[AES_KEY_SIZE];
        memset(cntstr, 0, AES_KEY_SIZE);
        *(int*) (&(cntstr[AES_KEY_SIZE - 5])) = cnt;
        mapKey = Utilities::generatePRF(cntstr, curToken.data());
        bool found = false;
        if (profile) {
            Utilities::startTimer(45);
        }
        prf_type res = storage->find(dataIndex, mapKey, found);
        if (profile) {
            serverSearchTime += Utilities::stopTimer(45);
        }
        if (found) {
            results.push_back(res);
            exist = true;
            cnt++;
        } else {
            exist = false;
        }
    } while (exist);
    return results;
}

vector<prf_type> AmortizedBASServer::getAllData(int dataIndex) {
    return storage->getAllData(dataIndex);
}

void AmortizedBASServer::clear(int index) {
    storage->clear(index);
}

void AmortizedBASServer::endSetup() {
    storage->loadCache();
}
