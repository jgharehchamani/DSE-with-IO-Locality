#include "NlogNClient.h"
#include<vector>
#include<algorithm>

NlogNClient::~NlogNClient() {
    delete server;
}

NlogNClient::NlogNClient(long numOfDataSets, bool inMemory, bool overwrite, bool profile) {
    cout << "================= RUNNING SDa + NlogN )(long) ==================" << endl;
    this->profile = profile;
    server = new NlogNServer(numOfDataSets, inMemory, overwrite, profile, "");
    memset(nullKey.data(), 0, AES_KEY_SIZE);
    for (long i = 0; i < numOfDataSets; i++) {
        exist.push_back(false);
    }
}

void NlogNClient::setup2(long index, unordered_map<string, vector<tmp_prf_type> > pairs, unsigned char* key) {
    //    unordered_map<string, vector<prf_type> > newpairs;
    //    for (auto item : pairs) {
    //        vector<prf_type> data;
    //        for (int i = 0; i < item.second.size(); i++) {
    //            string keyword = item.first;
    //            tmp_prf_type value = item.second[i];
    //            int ind = *(int*) (&(value.data()[TMP_AES_KEY_SIZE - 5]));
    //            byte op = *(byte*) (&(value.data()[TMP_AES_KEY_SIZE - 6]));
    //
    //            prf_type newvalue;
    //            std::fill(newvalue.begin(), newvalue.end(), 0);
    //            std::copy(keyword.begin(), keyword.end(), newvalue.begin());
    //            *(int*) (&(newvalue.data()[AES_KEY_SIZE - 5])) = ind;
    //            newvalue.data()[AES_KEY_SIZE - 6] = op;
    //            data.push_back(newvalue);
    //        }
    //        newpairs[item.first] = data;
    //
    //    }
    //    setup(index, newpairs, key);

    exist[index] = true;
    vector<vector<vector<std::pair<string, tmp_prf_type> > > > buckets;
    vector<vector<pair<string, int> > > levelcounters;
    vector < vector < bool> > fullness;
    tmp_prf_type dummy;
    memset(dummy.data(), 0, TMP_AES_KEY_SIZE);
    int maxCapacity = pow(2, index)*2;
    int innerLevels = index + 1;
    for (int i = 0; i < innerLevels; i++) {
        buckets.push_back(vector<vector<std::pair<string, tmp_prf_type> > >());
        levelcounters.push_back(vector<pair<string, int> >());
        fullness.push_back(vector < bool>());
        for (int j = 0; j < (maxCapacity / ((int) pow(2, i))); j++) {
            buckets[i].push_back(vector<pair<string, tmp_prf_type >> ());
            fullness[i].push_back(false);
            levelcounters[i].push_back(pair<string, int>("", 0));
        }
    }

    map<prf_type, prf_type> keywordCntCiphers;

    for (auto item : pairs) {
        int curSize = item.second.size();
        int targetLevel = getCorrespondingLevel(index, curSize);
        int bucketSize = pow(2, targetLevel);
        int firstEmpty = 0;


        string keyword = item.first;

        if (keyword == "ZYXO$o*") {
            cout << "level:" << index << " size:" << curSize << endl;
        }

        prf_type K = Utilities::encode(item.first, key);
        unsigned char cntstr[AES_KEY_SIZE];
        memset(cntstr, 0, AES_KEY_SIZE);
        *(long*) (&(cntstr[AES_KEY_SIZE - 5])) = -1;
        prf_type mapKey = Utilities::generatePRF(cntstr, K.data());
        prf_type valueTmp;
        *(long*) (&(valueTmp[0])) = item.second.size();
        prf_type mapValue = Utilities::encode(valueTmp.data(), K.data());
        keywordCntCiphers[mapKey] = mapValue;


        while (fullness[targetLevel][firstEmpty]) {
            firstEmpty++;
        }
        if (firstEmpty >= pow(2, index)*2) {
            cout << "There is no extra space" << endl;
        }
        auto tmp = item.second;
        int counter = 0;

        while (counter < tmp.size()) {
            for (int i = 0; i < bucketSize; i++) {
                if (counter < tmp.size()) {
                    buckets[targetLevel][firstEmpty].push_back(pair<string, tmp_prf_type>(keyword, tmp[counter]));
                    counter++;
                } else {
                    buckets[targetLevel][firstEmpty].push_back(pair<string, tmp_prf_type>("", dummy));
                }
            }
            levelcounters[targetLevel][firstEmpty] = pair<string, int>(item.first, firstEmpty);
            fullness[targetLevel][firstEmpty] = true;
            firstEmpty++;
        }
    }
    map<string, vector<int> > keywordCounterMap;
    for (int i = 0; i < innerLevels; i++) {
        for (int j = 0; j < (maxCapacity / ((int) pow(2, i))); j++) {
            if (fullness[i][j] == false) {
                for (int k = 0; k < ((int) pow(2, i)); k++) {
                    buckets[i][j].push_back(pair<string, tmp_prf_type>("", dummy));
                }
            }
        }
        permuteLevel(buckets[i], levelcounters[i]);
        for (int j = 0; j < levelcounters[i].size(); j++) {
            if (levelcounters[i][j].first != "") {
                if (keywordCounterMap.count(levelcounters[i][j].first) == 0) {
                    keywordCounterMap[levelcounters[i][j].first] = vector<int>();
                }
                keywordCounterMap[levelcounters[i][j].first].push_back(j);

            }
        }
    }

    for (auto p : keywordCounterMap) {
        string keyword = p.first;
        prf_type K = Utilities::encode(keyword, key);
        for (int i = 0; i < p.second.size(); i++) {
            unsigned char cntstr[AES_KEY_SIZE];
            memset(cntstr, 0, AES_KEY_SIZE);
            *(long*) (&(cntstr[AES_KEY_SIZE - 5])) = i;
            prf_type mapKey = Utilities::generatePRF(cntstr, K.data());
            prf_type valueTmp;
            memset(valueTmp.data(), 0, AES_KEY_SIZE);
            *(long*) (&(valueTmp[0])) = p.second[i];
            prf_type mapValue = Utilities::encode(valueTmp.data(), K.data());
            keywordCntCiphers[mapKey] = mapValue;
        }
    }

    server->storeKeywordCounters(index, keywordCntCiphers);

    for (long instance = 0; instance < innerLevels; instance++) {
        vector<vector<prf_type> > finalCiphers = convertTmpCiphersToFinalCipher(buckets[instance], key);
        server->storeCiphers(index, instance, finalCiphers, true);
    }

    //    for (long instance = 0; instance < index + 1; instance++) {
    //        long numOfEntries = (float) pow(2, index) / (float) pow(2, instance);
    //        numOfEntries = 2 * numOfEntries;
    //        assert(ciphers[instance].size() == numOfEntries);
    //        for (long entry = 0; entry < ciphers[instance].size(); entry++) {
    //            assert(ciphers[instance][entry].size() == pow(2, instance));
    //            vector<vector<prf_type> > finalCiphers = convertTmpCiphersToFinalCipher(ciphers[instance][entry], key);
    //            server->storeCiphers(index, instance, finalCiphers, entry == 0);
    //        }
    //    }
}

void NlogNClient::setup(long index, unordered_map<string, vector<prf_type> > pairs, unsigned char* key) {
    exist[index] = true;
    vector<vector<vector<prf_type> > > buckets;
    vector<vector<pair<string, int> > > levelcounters;
    vector < vector < bool> > fullness;
    prf_type dummy;
    memset(dummy.data(), 0, AES_KEY_SIZE);
    int maxCapacity = pow(2, index)*2;
    int innerLevels = index + 1;
    for (int i = 0; i < innerLevels; i++) {
        buckets.push_back(vector<vector<prf_type> >());
        levelcounters.push_back(vector<pair<string, int> >());
        fullness.push_back(vector < bool>());
        for (int j = 0; j < (maxCapacity / ((int) pow(2, i))); j++) {
            buckets[i].push_back(vector<prf_type>());
            fullness[i].push_back(false);
            levelcounters[i].push_back(pair<string, int>("", 0));
        }
    }

    map<prf_type, prf_type> keywordCntCiphers;

    for (auto item : pairs) {
        int curSize = item.second.size();
        int targetLevel = getCorrespondingLevel(index, curSize);
        int bucketSize = pow(2, targetLevel);
        int firstEmpty = 0;


        string keyword = item.first;
        prf_type K = Utilities::encode(item.first, key);
        unsigned char cntstr[AES_KEY_SIZE];
        memset(cntstr, 0, AES_KEY_SIZE);
        *(long*) (&(cntstr[AES_KEY_SIZE - 5])) = -1;
        prf_type mapKey = Utilities::generatePRF(cntstr, K.data());
        prf_type valueTmp;
        *(long*) (&(valueTmp[0])) = item.second.size();
        prf_type mapValue = Utilities::encode(valueTmp.data(), K.data());
        keywordCntCiphers[mapKey] = mapValue;


        while (fullness[targetLevel][firstEmpty]) {
            firstEmpty++;
        }
        if (firstEmpty >= pow(2, index)*2) {
            cout << "There is no extra space" << endl;
        }
        auto tmp = item.second;
        int counter = 0;

        while (counter < tmp.size()) {
            for (int i = 0; i < bucketSize; i++) {
                if (counter < tmp.size()) {
                    byte op = *(byte*) (&(tmp[counter].data()[AES_KEY_SIZE - 6]));
                    int ind = *(int*) (&(tmp[counter].data()[AES_KEY_SIZE - 5]));

                    prf_type newvalue;
                    std::fill(newvalue.begin(), newvalue.end(), 0);
                    std::copy(keyword.begin(), keyword.end(), newvalue.begin());
                    *(int*) (&(newvalue.data()[AES_KEY_SIZE - 5])) = ind;
                    newvalue.data()[AES_KEY_SIZE - 6] = op;

                    prf_type mapValue;
                    mapValue = Utilities::encode(newvalue.data(), key);

                    buckets[targetLevel][firstEmpty].push_back(mapValue);
                    counter++;
                } else {
                    prf_type dummy;
                    memset(dummy.data(), 0, AES_KEY_SIZE);
                    prf_type dummyV = Utilities::encode(dummy.data(), key);
                    buckets[targetLevel][firstEmpty].push_back(dummyV);
                }
            }
            levelcounters[targetLevel][firstEmpty] = pair<string, int>(item.first, firstEmpty);
            fullness[targetLevel][firstEmpty] = true;
            firstEmpty++;
        }
    }
    map<string, vector<int> > keywordCounterMap;
    for (int i = 0; i < innerLevels; i++) {
        for (int j = 0; j < (maxCapacity / ((int) pow(2, i))); j++) {
            if (fullness[i][j] == false) {
                for (int k = 0; k < ((int) pow(2, i)); k++) {
                    prf_type dummy;
                    memset(dummy.data(), 0, AES_KEY_SIZE);
                    prf_type dummyV = Utilities::encode(dummy.data(), key);
                    buckets[i][j].push_back(dummyV);
                }
            }
        }
        permuteLevel(buckets[i], levelcounters[i]);
        for (int j = 0; j < levelcounters[i].size(); j++) {
            if (levelcounters[i][j].first != "") {
                if (keywordCounterMap.count(levelcounters[i][j].first) == 0) {
                    keywordCounterMap[levelcounters[i][j].first] = vector<int>();
                }
                keywordCounterMap[levelcounters[i][j].first].push_back(j);

            }
        }
    }

    for (auto p : keywordCounterMap) {
        string keyword = p.first;
        prf_type K = Utilities::encode(keyword, key);
        for (int i = 0; i < p.second.size(); i++) {
            unsigned char cntstr[AES_KEY_SIZE];
            memset(cntstr, 0, AES_KEY_SIZE);
            *(long*) (&(cntstr[AES_KEY_SIZE - 5])) = i;
            prf_type mapKey = Utilities::generatePRF(cntstr, K.data());
            prf_type valueTmp;
            memset(valueTmp.data(), 0, AES_KEY_SIZE);
            *(long*) (&(valueTmp[0])) = p.second[i];
            prf_type mapValue = Utilities::encode(valueTmp.data(), K.data());
            keywordCntCiphers[mapKey] = mapValue;
        }
    }

    server->storeKeywordCounters(index, keywordCntCiphers);
    for (long instance = 0; instance < innerLevels; instance++) {
        server->storeCiphers(index, instance, buckets[instance], true);
    }
}

void NlogNClient::permuteLevel(vector<vector<prf_type> >& buckets, vector<pair<string, int> >& counters) {
    std::vector<int> shuffleids;
    std::vector<int> shuffleids2;
    unsigned char key[AES_KEY_SIZE];

    for (int z = 0; z < buckets.size(); z++) {
        prf_type plain;
        memset(plain.data(), 0, AES_KEY_SIZE);
        memcpy(plain.data(), to_string(z).c_str(), 4);
        prf_type enc = Utilities::encode(plain.data(), key);
        int id = *((int*) enc.data());
        shuffleids.push_back(id);
        shuffleids2.push_back(id);
    }

    std::vector<std::pair < pair<string, int>, int> > zipped;
    std::vector<std::pair < vector<prf_type>, int> > zipped2;
    Utilities::zip(counters, shuffleids, zipped);
    Utilities::zip(buckets, shuffleids2, zipped2);

    std::sort(std::begin(zipped), std::end(zipped),
            [&](const auto& a, const auto& b) {
                return a.second > b.second;
            });

    std::sort(std::begin(zipped2), std::end(zipped2),
            [&](const auto& a, const auto& b) {
                return a.second > b.second;
            });

    Utilities::unzip(zipped, counters, shuffleids);
    Utilities::unzip(zipped2, buckets, shuffleids2);
}

void NlogNClient::permuteLevel(vector<vector<pair<string, tmp_prf_type> > >& buckets, vector<pair<string, int> >& counters) {
    std::vector<int> shuffleids;
    std::vector<int> shuffleids2;
    unsigned char key[AES_KEY_SIZE];

    for (int z = 0; z < buckets.size(); z++) {
        tmp_prf_type plain;
        memset(plain.data(), 0, TMP_AES_KEY_SIZE);
        memcpy(plain.data(), to_string(z).c_str(), 4);
        tmp_prf_type enc = Utilities::tmpencode(plain.data(), key);
        int id = *((int*) enc.data());
        shuffleids.push_back(id);
        shuffleids2.push_back(id);
    }

    std::vector<std::pair < pair<string, int>, int> > zipped;
    std::vector<std::pair < vector<pair<string, tmp_prf_type>>, int> > zipped2;
    Utilities::zip(counters, shuffleids, zipped);
    Utilities::zip(buckets, shuffleids2, zipped2);

    std::sort(std::begin(zipped), std::end(zipped),
            [&](const auto& a, const auto& b) {
                return a.second > b.second;
            });

    std::sort(std::begin(zipped2), std::end(zipped2),
            [&](const auto& a, const auto& b) {
                return a.second > b.second;
            });

    Utilities::unzip(zipped, counters, shuffleids);
    Utilities::unzip(zipped2, buckets, shuffleids2);
}

int NlogNClient::getCorrespondingLevel(int index, int size) {
    int maxCapacity = pow(2, index);
    int innerLevels = index + 1;
    int storeLevel = floor(log2(size));
    int res = storeLevel - (storeLevel % JUMP_SIZE);
    int maxLevelIndex = JUMP_SIZE * (MAX_LEVEL - 1);
    if (res > maxLevelIndex) {
        return maxLevelIndex;
    }
    return res;
}

vector<prf_type> NlogNClient::search(long index, string keyword, unsigned char* key) {
    Utilities::startTimer(77);
    server->keywordCounters->cacheTime = 0;
    server->storage->cacheTime = 0;
    server->keywordCounters->getCounterTime = 0;
    double searchPreparation = 0, searchDecryption = 0;

    prf_type token = Utilities::encode(keyword, key);
    Utilities::startTimer(131);
    long keywordCnt = server->getCounter(index, token);
    auto t3 = Utilities::stopTimer(131);
    cout << "index:" << index << " getCounter=" << keywordCnt << " time taken (for NlogN):" << t3 << endl;
    server->keywordCounters->getCounterTime = t3;
    vector<prf_type> finalRes;
    long attempt = 0;
    if (keywordCnt > 0) {
        vector<prf_type> ciphers;
        long instance = (long) getCorrespondingLevel(index, keywordCnt);
        long posIndex = 0;
        while (true) {
            long pos = server->getPos(index, posIndex, token);
            if (pos == -1) {
                break;
            }
            ciphers = server->search(index, instance, pos);
            for (auto item : ciphers) {
                prf_type plaintext;
                Utilities::decode(item, plaintext, key);
                if (strcmp((char*) plaintext.data(), keyword.data()) == 0) {
                    finalRes.push_back(plaintext);
                }
            }
            posIndex++;
        }
        //        if (finalRes.size() == 0 && (attempt < 2 * pow(2, (index - instance)))) {
        //            attempt++;
        //            goto SEARCH;
        //        }
    }
    auto aa = Utilities::stopTimer(77);
    searchTime += aa;
    cout << "level time:" << aa << endl;
    cout << "level cache time:" << server->storage->cacheTime + server->keywordCounters->cacheTime << endl;
    cout << "level pure time:" << aa - (server->storage->cacheTime + server->keywordCounters->cacheTime) << endl;


    TotalCacheTime += server->keywordCounters->cacheTime;
    TotalCacheTime += server->storage->cacheTime;
    //if(finalRes.size()>0)
    //	cout <<"found after attempts:"<<attempt+1<<endl;
    return finalRes;
}

vector<prf_type> NlogNClient::getAllData(long index, unsigned char* key) {
    vector<prf_type> finalRes = vector<prf_type>();
    auto ciphers = server->getAllData(index);

    for (auto cipher : ciphers) {
        prf_type plaintext;
        Utilities::decode(cipher, plaintext, key);
        finalRes.push_back(plaintext);
    }
    totalCommunication += (ciphers.size()) * sizeof (prf_type);
    return finalRes;
}

void NlogNClient::destroy(long index) {
    server->clear(index);
    exist[index] = false;
    totalCommunication += sizeof (long);
}

vector<vector<prf_type> > NlogNClient::convertTmpCiphersToFinalCipher(vector<vector<std::pair<string, tmp_prf_type> > > ciphers, unsigned char* key) {
    vector<vector<prf_type> > results;
    for (long i = 0; i < ciphers.size(); i++) {
        results.push_back(vector<prf_type>());
        for (long j = 0; j < ciphers[i].size(); j++) {
            auto KV = ciphers[i][j];
            string keyword = KV.first;
            tmp_prf_type value = KV.second;
            int ind = *(int*) (&(value.data()[TMP_AES_KEY_SIZE - 5]));
            byte op = *(byte*) (&(value.data()[TMP_AES_KEY_SIZE - 6]));

            if (keyword == "") {
                prf_type dummy;
                memset(dummy.data(), 0, AES_KEY_SIZE);
                prf_type dummyV = Utilities::encode(dummy.data(), key);
                results[i].push_back(dummyV);
            } else {

                prf_type newvalue;
                std::fill(newvalue.begin(), newvalue.end(), 0);
                std::copy(keyword.begin(), keyword.end(), newvalue.begin());
                *(int*) (&(newvalue.data()[AES_KEY_SIZE - 5])) = ind;
                newvalue.data()[AES_KEY_SIZE - 6] = op;

                prf_type mapValue;
                mapValue = Utilities::encode(newvalue.data(), key);
                results[i].push_back(mapValue);
            }
        }
    }
    return results;
}

void NlogNClient::endSetup() {
    server->endSetup();
}
