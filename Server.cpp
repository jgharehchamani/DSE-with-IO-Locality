#include "Server.h"
#include <iostream>
#include <sstream>
#include <cstring>
#include <vector>
#include "Utilities.h"

Server::Server(bool useHDD, bool deleteFiles) {
    this->useRocksDB = useHDD;
    this->deleteFiles = deleteFiles;
    this->useRocksDB = false;
}

Server::~Server() {
}

void Server::update(prf_type addr, prf_type val) {
    DictW[addr] = val;
}

vector<prf_type> Server::search(vector<prf_type> KList) {
    vector<prf_type> result;
    result.reserve(KList.size());
    prf_type notfound;
    memset(notfound.data(), 0, AES_KEY_SIZE);
    for (unsigned int i = 0; i < KList.size(); i++) {
        prf_type val;

        val = DictW[KList[i]];
        if (val != notfound) {
            result.emplace_back(val);
        }
    }
    return result;
}


