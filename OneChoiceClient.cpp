#include "OneChoiceClient.h"

OneChoiceClient::~OneChoiceClient() {
    delete server;
}

OneChoiceClient::OneChoiceClient(long numOfDataSets, bool inMemory, bool overwrite, bool profile) {
    cout << "==================Running Vanilla One-Choice==================" << endl;
    this->profile = profile;
    server = new OneChoiceServer(numOfDataSets, inMemory, overwrite, profile, "OneChoice-");
    for (long i = 0; i < numOfDataSets; i++) {
        exist.push_back(false);
        long curNumberOfBins = i > 1 ? (long) ceil((float) pow(2, i) / (float) (log2(pow(2, i)) * log2(log2(pow(2, i))))) : 1;
        long curSizeOfEachBin = i > 1 ? 3 * (log2(pow(2, i)) * log2(log2(pow(2, i)))) : pow(2, i);
        numberOfBins.push_back(curNumberOfBins);
        sizeOfEachBin.push_back(curSizeOfEachBin);
    }
}

void OneChoiceClient::setup(long index, unordered_map<string, vector<prf_type> > pairs, unsigned char* key) {
    exist[index] = true;
    vector<vector<prf_type> > ciphers;
    for (long i = 0; i < numberOfBins[index]; i++) {
        ciphers.push_back(vector<prf_type>());
    }
    map<prf_type, prf_type> keywprdCntCiphers;
    for (auto pair : pairs) {
        prf_type K1 = Utilities::encode(pair.first, key);
        prf_type mapKey, mapValue;
        unsigned char cntstr[AES_KEY_SIZE];
        memset(cntstr, 0, AES_KEY_SIZE);
        *(long*) (&(cntstr[AES_KEY_SIZE - 5])) = -1;
        mapKey = Utilities::generatePRF(cntstr, K1.data());
        prf_type valueTmp;
        *(long*) (&(valueTmp[0])) = pair.second.size();
        mapValue = Utilities::encode(valueTmp.data(), K1.data());
        keywprdCntCiphers[mapKey] = mapValue;

        unsigned char* hash = Utilities::sha256((char*) mapKey.data(), AES_KEY_SIZE);
        long pos = (unsigned long) (*((long*) hash)) % numberOfBins[index];
        long cipherIndex = pos;
        for (unsigned long i = 0; i < pair.second.size(); i++) {
            prf_type mapValue;
            mapValue = Utilities::encode(pair.second[i].data(), key);
            ciphers[cipherIndex].push_back(mapValue);
            cipherIndex++;
            if (cipherIndex == numberOfBins[index]) {
                cipherIndex = 0;
            }
        }
    }
    prf_type dummy;
    memset(dummy.data(), 0, AES_KEY_SIZE);
    prf_type dummyV = Utilities::encode(dummy.data(), key);
    for (long i = 0; i < numberOfBins[index]; i++) {
        long curSize = ciphers[i].size();
        for (long j = curSize; j < sizeOfEachBin[index]; j++) {
            ciphers[i].push_back(dummyV);
        }
    }

    prf_type randomKey;
    for (long i = 0; i < AES_KEY_SIZE; i++) {
        randomKey[i] = rand();
    }
    for (long i = keywprdCntCiphers.size(); i < pow(2, index); i++) {
        unsigned char cntstr[AES_KEY_SIZE];
        memset(cntstr, 0, AES_KEY_SIZE);
        *(long*) (&(cntstr[AES_KEY_SIZE - 9])) = rand();
        prf_type mapKey = Utilities::generatePRF(cntstr, randomKey.data());
        *(long*) (&(cntstr[AES_KEY_SIZE - 5])) = rand();
        prf_type mapValue = Utilities::generatePRF(cntstr, randomKey.data());
        keywprdCntCiphers[mapKey] = mapValue;
    }
    //    totalCommunication += ciphers.size() * sizeof (prf_type)*2;
    server->storeCiphers(index, ciphers, keywprdCntCiphers);
}

void OneChoiceClient::setup2(long index, unordered_map<string, vector<tmp_prf_type> > pairs, unsigned char* key) {
    exist[index] = true;
    vector<vector<pair<pair<string, long>, tmp_prf_type> > > ciphers;
    for (long i = 0; i < numberOfBins[index]; i++) {
        ciphers.push_back(vector<pair<pair<string, long>, tmp_prf_type> >());
    }
    map<prf_type, prf_type> keywprdCntCiphers;
    for (auto pair : pairs) {
        //        printf("index:%d keyword:%s count:%d\n",index,pair.first.c_str(),pair.second.size());
        prf_type K1 = Utilities::encode(pair.first, key);
        prf_type mapKey, mapValue;
        unsigned char cntstr[AES_KEY_SIZE];
        memset(cntstr, 0, AES_KEY_SIZE);
        *(long*) (&(cntstr[AES_KEY_SIZE - 5])) = (long) - 1;
        mapKey = Utilities::generatePRF(cntstr, K1.data());
        prf_type valueTmp;
        *(long*) (&(valueTmp[0])) = (long) pair.second.size();
        //cout<<"["<<pair.first<<"]:"<<pair.second.size();
        mapValue = Utilities::encode(valueTmp.data(), K1.data());
        keywprdCntCiphers[mapKey] = mapValue;

        unsigned char* hash = Utilities::sha256((char*) mapKey.data(), AES_KEY_SIZE);
        long pos = (unsigned long) (*((long*) hash)) % numberOfBins[index];
        long cipherIndex = pos;
        for (unsigned long i = 0; i < pair.second.size(); i++) {
            std::pair<string, long> mapKey;
            tmp_prf_type mapValue;
            mapKey.first = pair.first;
            mapKey.second = i;
            mapValue = pair.second[i];
            auto p = std::pair< std::pair<string, long>, tmp_prf_type>(mapKey, mapValue);
            ciphers[cipherIndex].push_back(p);
            cipherIndex++;
            if (cipherIndex == numberOfBins[index]) {
                cipherIndex = 0;
            }
        }
    }
    tmp_prf_type dummy;
    memset(dummy.data(), 0, TMP_AES_KEY_SIZE);
    auto dummypair = pair<std::pair<string, long>, tmp_prf_type>(std::pair<string, long>("", -1), dummy);
    for (long i = 0; i < numberOfBins[index]; i++) {
        long curSize = ciphers[i].size();
        for (long j = curSize; j < sizeOfEachBin[index]; j++) {
            ciphers[i].push_back(dummypair);
        }
    }

    prf_type randomKey;
    for (long i = 0; i < AES_KEY_SIZE; i++) {
        randomKey[i] = rand();
    }
    for (long i = keywprdCntCiphers.size(); i < pow(2, index); i++) {
        unsigned char cntstr[AES_KEY_SIZE];
        memset(cntstr, 0, AES_KEY_SIZE);
        *(long*) (&(cntstr[AES_KEY_SIZE - 9])) = (long) rand();
        prf_type mapKey = Utilities::generatePRF(cntstr, randomKey.data());
        *(long*) (&(cntstr[AES_KEY_SIZE - 5])) = (long) rand();
        prf_type mapValue = Utilities::generatePRF(cntstr, randomKey.data());
        keywprdCntCiphers[mapKey] = mapValue;
    }
    server->storeKeywordCounters(index, keywprdCntCiphers);
    vector<vector<prf_type> > finalCiphers;
    for (long i = 0; i < ciphers.size(); i++) {
        finalCiphers.push_back(vector<prf_type>());
        finalCiphers[i] = convertTmpCiphersToFinalCipher(ciphers[i], key)[0];
    }
    server->storeCiphers(index, finalCiphers, true);
}

vector<prf_type> OneChoiceClient::search(long index, string keyword, unsigned char* key) {
    double searchPreparation = 0, searchDecryption = 0;
    server->storage->cacheTime = 0;
    server->keywordCounters->cacheTime = 0;
    if (profile) {
        Utilities::startTimer(65);
        Utilities::startTimer(77);
    }
    vector<prf_type> finalRes;

    Utilities::startTimer(10);
    prf_type token = Utilities::encode(keyword, key);
    long keywordCnt = server->getCounter(index, token);
    auto t = Utilities::stopTimer(10);
    cout << "index:" << index << " getCounter:" << keywordCnt << " time:" << t << endl;


    //if(keywordCnt > 0)
    {
        Utilities::startTimer(20);
        vector<prf_type> ciphers = server->search(index, token, keywordCnt);
        //vector<prf_type> ciphers = server->getAllData(index);
        totalCommunication += ciphers.size() * sizeof (prf_type);
        t = Utilities::stopTimer(20);
        cout << keywordCnt << " one choice time:" << t << endl;
        long cnt = 0;
        if (profile) {
            searchPreparation = Utilities::stopTimer(65);
            //printf("search preparation time:%f include server time\n", searchPreparation);
            Utilities::startTimer(65);
        }
        for (auto item : ciphers) {
            prf_type plaintext;
            Utilities::decode(item, plaintext, key);
            if (strcmp((char*) plaintext.data(), keyword.data()) == 0) {
                finalRes.push_back(plaintext);
            }
        }
        if (profile) {
            searchDecryption = Utilities::stopTimer(65);
            printf("search decryption time:%f for decrypting:%d ciphers\n", searchDecryption, ciphers.size());
        }
        TotalCacheTime += server->storage->cacheTime;
        TotalCacheTime += server->keywordCounters->cacheTime;
    }
    auto aa = Utilities::stopTimer(77);
    cout << "level time:" << aa << endl;
    cout << "level cache time:" << server->storage->cacheTime + server->keywordCounters->cacheTime << endl;
    cout << "level pure time:" << aa - (server->storage->cacheTime + server->keywordCounters->cacheTime) << endl;
    searchTime += Utilities::stopTimer(77);
    cout << finalRes.size() << "/" << keywordCnt << endl;
    return finalRes;
}

vector<prf_type> OneChoiceClient::getAllData(long index, unsigned char* key) {
    vector<prf_type> finalRes;
    auto ciphers = server->getAllData(index);
    prf_type dummy;
    memset(dummy.data(), 0, AES_KEY_SIZE);
    for (auto cipher : ciphers) {
        prf_type plaintext;
        Utilities::decode(cipher, plaintext, key);
        prf_type tmp = plaintext;
        tmp[AES_KEY_SIZE - 1] = 0;
        if (tmp != dummy) {
            finalRes.push_back(plaintext);
        }
    }
    totalCommunication += ciphers.size() * sizeof (prf_type);
    return finalRes;
}

void OneChoiceClient::destroy(long index) {
    server->clear(index);
    exist[index] = false;
    totalCommunication += sizeof (long);
}

vector<vector<prf_type> > OneChoiceClient::convertTmpCiphersToFinalCipher(vector<pair<std::pair<string, long>, tmp_prf_type> > ciphers, unsigned char* key) {
    vector<vector<prf_type> > results;
    results.push_back(vector<prf_type>());
    for (long i = 0; i < ciphers.size(); i++) {
        auto KV = ciphers[i];
        string keyword = KV.first.first;
        long cnt = KV.first.second;
        tmp_prf_type value = KV.second;
        int ind = *(int*) (&(value.data()[TMP_AES_KEY_SIZE - 5]));
        byte op = *(byte*) (&(value.data()[TMP_AES_KEY_SIZE - 6]));

        if (cnt == -1) {
            prf_type dummy;
            prf_type dummyV = Utilities::encode(dummy.data(), key);
            results[0].push_back(dummyV);
        } else {

            prf_type newvalue;
            std::fill(newvalue.begin(), newvalue.end(), 0);
            std::copy(keyword.begin(), keyword.end(), newvalue.begin());
            *(int*) (&(newvalue.data()[AES_KEY_SIZE - 5])) = ind;
            newvalue.data()[AES_KEY_SIZE - 6] = op;

            prf_type mapValue;
            mapValue = Utilities::encode(newvalue.data(), key);
            results[0].push_back(mapValue);
        }

    }
    return results;
}

void OneChoiceClient::endSetup() {
    server->endSetup();
}