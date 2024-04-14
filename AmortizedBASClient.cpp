#include "AmortizedBASClient.h"

AmortizedBASClient::~AmortizedBASClient() {
    delete server;
}

AmortizedBASClient::AmortizedBASClient(int numOfDataSets, bool inMemory, bool overwrite, bool profile) {
    this->profile = profile;
    server = new AmortizedBASServer(numOfDataSets, inMemory, overwrite, profile);
    for (int i = 0; i < numOfDataSets; i++) {
        exist.push_back(false);
    }
}

void AmortizedBASClient::setup2(int index, unordered_map<string, vector<tmp_prf_type> > pairs, unsigned char* key) {
    exist[index] = true;
    int batchSize = 100000;
    map<prf_type, prf_type> ciphers;
    for (auto pair : pairs) {

        prf_type K1 = Utilities::encode(pair.first, key);
        for (unsigned int i = 0; i < pair.second.size(); i++) {
            prf_type mapKey, mapValue;
            unsigned char cntstr[AES_KEY_SIZE];
            memset(cntstr, 0, AES_KEY_SIZE);
            *(int*) (&(cntstr[AES_KEY_SIZE - 5])) = i;
            mapKey = Utilities::generatePRF(cntstr, K1.data());

            int ind = *(int*) (&(pair.second[i].data()[TMP_AES_KEY_SIZE - 5]));
            byte op = *(byte*) (&(pair.second[i].data()[TMP_AES_KEY_SIZE - 6]));

            prf_type newvalue;
            std::fill(newvalue.begin(), newvalue.end(), 0);
            std::copy(pair.first.begin(), pair.first.end(), newvalue.begin());
            *(int*) (&(newvalue.data()[AES_KEY_SIZE - 5])) = ind;
            newvalue.data()[AES_KEY_SIZE - 6] = op;

            mapValue = Utilities::encode(newvalue.data(), key);
            ciphers[mapKey] = mapValue;
        }
        if (ciphers.size() > batchSize) {
            server->storeCiphers(index, ciphers);
            ciphers.clear();
        }
    }
    if (ciphers.size() > 0) {
        server->storeCiphers(index, ciphers);
    }
}

void AmortizedBASClient::setup(int index, unordered_map<string, vector<prf_type> > pairs, unsigned char* key) {
    exist[index] = true;
    map<prf_type, prf_type> ciphers;
    for (auto pair : pairs) {
        prf_type K1 = Utilities::encode(pair.first, key);
        for (unsigned int i = 0; i < pair.second.size(); i++) {
            prf_type mapKey, mapValue;
            unsigned char cntstr[AES_KEY_SIZE];
            memset(cntstr, 0, AES_KEY_SIZE);
            *(int*) (&(cntstr[AES_KEY_SIZE - 5])) = i;
            mapKey = Utilities::generatePRF(cntstr, K1.data());
            mapValue = Utilities::encode(pair.second[i].data(), key);
            ciphers[mapKey] = mapValue;
        }
    }
    totalCommunication += ciphers.size() * sizeof (prf_type)*2;
    server->storeCiphers(index, ciphers);
}

vector<prf_type> AmortizedBASClient::search(int index, string keyword, unsigned char* key) {
    double searchPreparation = 0, searchDecryption = 0;
    server->storage->cacheTime = 0;
    Utilities::startTimer(77);
    if (profile) {
        Utilities::startTimer(65);
    }
    vector<prf_type> finalRes;
    prf_type token = Utilities::encode(keyword, key);
    vector<prf_type> ciphers = server->search(index, token);
    if (profile) {
        searchPreparation = Utilities::stopTimer(65);
        printf("search preparation time:%f include server time\n", searchPreparation);
        Utilities::startTimer(65);
    }
    for (auto cipher : ciphers) {
        prf_type plaintext;
        Utilities::decode(cipher, plaintext, key);

        finalRes.push_back(plaintext);
    }
    printf("found %d items\n", finalRes.size());
    if (profile) {
        searchDecryption = Utilities::stopTimer(65);
        printf("search decryption time:%f for decrypting %d ciphers\n", searchDecryption, ciphers.size());
    }
    totalCommunication += ciphers.size() * sizeof (prf_type) + sizeof (prf_type);
    TotalCacheTime += server->storage->cacheTime;
    auto aa = Utilities::stopTimer(77);
    cout << "level time:" << aa << endl;
    cout << "level cache time:" << server->storage->cacheTime << endl;
    cout << "level pure time:" << aa - (server->storage->cacheTime) << endl;
    searchTime += aa; //Utilities::stopTimer(77);

    return finalRes;
}

vector<prf_type> AmortizedBASClient::getAllData(int index, unsigned char* key) {
    vector<prf_type> finalRes;
    auto ciphers = server->getAllData(index);
    for (auto cipher : ciphers) {
        prf_type plaintext;
        Utilities::decode(cipher, plaintext, key);
        finalRes.push_back(plaintext);
    }
    totalCommunication += ciphers.size() * sizeof (prf_type);
    return finalRes;
}

void AmortizedBASClient::destroy(int index) {
    server->clear(index);
    exist[index] = false;
    totalCommunication += sizeof (int);
}

void AmortizedBASClient::endSetup() {
    server->endSetup();
}
