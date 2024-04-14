#include "DeAmortizedBASClient.h"
#include "AES.hpp"

DeAmortizedBASClient::~DeAmortizedBASClient() {
    delete server;
}

DeAmortizedBASClient::DeAmortizedBASClient(int numOfDataSets, bool inMemory, bool overwrite, bool profile) {
    server = new DeAmortizedBASServer(numOfDataSets, inMemory, overwrite, profile);
    for (int j = 0; j < 4; j++) {
        exist.push_back(vector<bool>());
        for (int i = 0; i < numOfDataSets; i++) {
            exist[j].push_back(false);
        }
    }
}

void DeAmortizedBASClient::setup(int instance, int index, unordered_map<string, vector<prf_type> > pairs, unsigned char* key) {
    server->clear(instance, index);
    exist[instance][index] = true;
    map<string, prf_type> K1;
    map<string, int> CNT;
    map<prf_type, prf_type> ciphers;
    for (auto pair : pairs) {
        if (CNT.count(pair.first) == 0) {
            K1[pair.first] = Utilities::encode(pair.first + "-1", key);
            CNT[pair.first] = 1;
        }
        for (int j = 0; j < pair.second.size(); j++) {
            prf_type mapKey, mapValue;
            unsigned char cntstr[AES_KEY_SIZE];
            memset(cntstr, 0, AES_KEY_SIZE);
            *(int*) (&(cntstr[AES_KEY_SIZE - 5])) = CNT[pair.first];
            mapKey = Utilities::generatePRF(cntstr, K1[pair.first].data());


            //        getAESRandomValue(K1[pair.first].data(), CNT[pair.first], mapKey.data());
            mapValue = Utilities::encode(pair.second[j].data(), key);
            ciphers[mapKey] = mapValue;
            CNT[pair.first]++;
        }
    }
    totalCommunication += ciphers.size() * sizeof (prf_type)*2;
    server->storeCiphers(instance, index, ciphers, true);
}

void DeAmortizedBASClient::setup(int instance, int index, vector<pair<string, prf_type> >pairs, unsigned char* key) {
    server->clear(instance, index);
    exist[instance][index] = true;
    map<string, prf_type> K1;
    map<string, int> CNT;
    map<prf_type, prf_type> ciphers;
    for (auto pair : pairs) {
        if (CNT.count(pair.first) == 0) {
            K1[pair.first] = Utilities::encode(pair.first + "-1", key);
            CNT[pair.first] = 1;
        }
        prf_type mapKey, mapValue;
        unsigned char cntstr[AES_KEY_SIZE];
        memset(cntstr, 0, AES_KEY_SIZE);
        *(int*) (&(cntstr[AES_KEY_SIZE - 5])) = CNT[pair.first];
        mapKey = Utilities::generatePRF(cntstr, K1[pair.first].data());


        //        getAESRandomValue(K1[pair.first].data(), CNT[pair.first], mapKey.data());
        mapValue = Utilities::encode(pair.second.data(), key);
        ciphers[mapKey] = mapValue;
        CNT[pair.first]++;
    }
    totalCommunication += ciphers.size() * sizeof (prf_type)*2;
    server->storeCiphers(instance, index, ciphers, true);
}

void DeAmortizedBASClient::add(int instance, int index, pair<string, prf_type> keyValue, int cnt, unsigned char* key) {
    prf_type K1 = Utilities::encode(keyValue.first + "-1", key);
    prf_type mapKey, mapValue;
    unsigned char cntstr[AES_KEY_SIZE];
    memset(cntstr, 0, AES_KEY_SIZE);
    *(int*) (&(cntstr[AES_KEY_SIZE - 5])) = cnt;
    mapKey = Utilities::generatePRF(cntstr, K1.data());
    //    getAESRandomValue(K1.data(), cnt, mapKey.data());
    mapValue = Utilities::encode(keyValue.second.data(), key);
    totalCommunication += sizeof (prf_type)*2;
    server->add(instance, index, pair<prf_type, prf_type>(mapKey, mapValue));
}

vector<prf_type> DeAmortizedBASClient::search(int instance, int index, string keyword, unsigned char* key) {
    vector<prf_type> finalRes;
    prf_type token = Utilities::encode(keyword + "-1", key);
    vector<prf_type> ciphers = server->search(instance, index, token);
    for (auto cipher : ciphers) {
        prf_type plaintext;
        Utilities::decode(cipher, plaintext, key);

        finalRes.push_back(plaintext);
    }
    totalCommunication += ciphers.size() * sizeof (prf_type) + sizeof (prf_type);
    return finalRes;
}

vector<prf_type> DeAmortizedBASClient::getAllData(int instance, int index, unsigned char* key) {
    vector<prf_type> finalRes;
    auto ciphers = server->getAllData(instance, index);
    for (auto cipher : ciphers) {
        prf_type plaintext;
        Utilities::decode(cipher, plaintext, key);
        finalRes.push_back(plaintext);
    }
    totalCommunication += sizeof (prf_type) * ciphers.size();
    return finalRes;
}

void DeAmortizedBASClient::destry(int instance, int index) {
    //    server->clear(instance, index);
    totalCommunication += sizeof (int);
    exist[instance][index] = false;
}

void DeAmortizedBASClient::destryAndClear(int instance, int index) {
    server->clear(instance, index);
    totalCommunication += sizeof (int);
    exist[instance][index] = false;
}

//void DeAmortizedBASClient::getAESRandomValue(unsigned char* keyword, int cnt, unsigned char* result) {
//    *(int*) (&keyword[AES_KEY_SIZE - 4]) = cnt;
//    AES::derive((unsigned char*) keyword, 0, AES_KEY_SIZE, result);
//}

void DeAmortizedBASClient::move(int fromInstance, int fromIndex, int toInstance, int toIndex) {
    server->move(fromInstance, fromIndex, toInstance, toIndex);
    totalCommunication += sizeof (int);
    //    long tail,s;
    //    vector<pair<pair<prf_type,prf_type>,pair<long,long> > > data = server->getAllDataForCopy(fromInstance, fromIndex,tail,s);
    //    server->storeCiphers(toInstance, toIndex, data,tail,s);
    if (size(toInstance, toIndex) > 0) {
        exist[toInstance][toIndex] = true;
    }

}

int DeAmortizedBASClient::size(int instance, int index) {
    return server->size(instance, index);
}

prf_type DeAmortizedBASClient::get(int instance, int index, int pos, unsigned char* key) {
    auto cipher = server->get(instance, index, pos);
    prf_type plaintext;
    Utilities::decode(cipher, plaintext, key);
    totalCommunication += sizeof (prf_type) + sizeof (int);
    return plaintext;
}

void DeAmortizedBASClient::endSetup(bool overwrite) {
    server->endSetup(overwrite);
}

void DeAmortizedBASClient::beginSetup() {
    server->beginSetup();
}

