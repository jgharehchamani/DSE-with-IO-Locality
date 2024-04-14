#include "NlogNSDdGeneralClient.h"
#include<string.h>
#include<map>
#include<vector>
#include<algorithm>

using namespace::std;

NlogNSDdGeneralClient::~NlogNSDdGeneralClient() {
    for (int i = 0; i < 4; i++) {
        delete server[i];
    }
}

NlogNSDdGeneralClient::NlogNSDdGeneralClient(int N, bool inMemory, bool overwrite, bool profile) {
    this->profile = profile;
    int l = floor(log2(N)) + 1;
    memset(nullKey.data(), 0, AES_KEY_SIZE);
    this->numOfIndices = l;
    server = new NlogNServer*[4];
    for (int i = 0; i < 4; i++) {
        server[i] = new NlogNServer(numOfIndices, inMemory, overwrite, profile, "NlogN-" + to_string(i) + "-");
    }
    for (int j = 0; j < numOfIndices; j++) {
        int curNumberOfBins = j > 1 ?
                (int) ceil(((float) pow(2, j)) / (float) (log2(pow(2, j)) * log2(log2(pow(2, j))))) : 1;
        int curSizeOfEachBin = j > 1 ? 3 * (log2(pow(2, j))*(log2(log2(pow(2, j))))) : pow(2, j);
        numberOfBins.push_back(curNumberOfBins);
        sizeOfEachBin.push_back(curSizeOfEachBin);
        int is = curNumberOfBins*curSizeOfEachBin;
        indexSize.push_back(is);
        printf("Index:%d #of Bins:%d size of bin:%d is:%d\n", j, curNumberOfBins, curSizeOfEachBin, is);
    }
    exist.resize(3);
    setupFiles.resize(numOfIndices);

    memset(nullKey.data(), 0, AES_KEY_SIZE);

    for (int i = 0; i < numOfIndices; i++) {
        setupFiles[i].resize(4);
        exist[0].push_back(false);
        exist[1].push_back(false);
        exist[2].push_back(false);

        numNEW.push_back(1); //updateCount
        NEWsize.push_back(0);
        KWsize.push_back(0);
    }
}

vector<prf_type> NlogNSDdGeneralClient::search(int index, int instance, string keyword, unsigned char* key) {
    for (int i = 0; i < 3; i++) {
        server[i]->storage->cacheTime = 0;
        server[i]->keywordCounters->cacheTime = 0;
    }
    double searchPreparation = 0, searchDecryption = 0;
    prf_type token = Utilities::encode(keyword, key);
    Utilities::startTimer(131);
    long keywordCnt = server[instance]->getCounter(index, token);
    auto t3 = Utilities::stopTimer(131);
    cout << "index:" << index << " getCounter=" << keywordCnt << " time taken (for NlogN):" << t3 << endl;
    server[instance]->keywordCounters->getCounterTime = t3;
    vector<prf_type> finalRes;
    long attempt = 0;
    if (keywordCnt > 0) {
        vector<prf_type> ciphers;
        long innerinstance = (long) getCorrespondingLevel(index, keywordCnt);
        long posIndex = 0;
        while (true) {
            long pos = server[instance]->getPos(index, posIndex, token);
            if (pos == -1) {
                break;
            }
            ciphers = server[instance]->search(index, innerinstance, pos);
            cout << "index:" << index << " instance:" << instance << " size:" << ciphers.size() << endl;
            for (auto item : ciphers) {
                prf_type plaintext;
                Utilities::decode(item, plaintext, key);
                if (strcmp((char*) plaintext.data(), keyword.data()) == 0) {
                    finalRes.push_back(plaintext);
                }
            }
            posIndex++;
        }
    }
    double cachet = 0;
    for (int i = 0; i < 3; i++) {
        cachet += server[i]->storage->cacheTime;
        cachet += server[i]->keywordCounters->cacheTime;
    }
    TotalCacheTime += cachet;
    auto aa = Utilities::stopTimer(77);
    cout << "level time:" << aa << endl;
    cout << "level cache time:" << cachet << endl;
    cout << "level pure time:" << aa - cachet << endl;
    searchTime += aa;
    //    cout << finalRes.size() << "/" << keywordCount << endl;
    return finalRes;
}

void NlogNSDdGeneralClient::setup(long index, long instance, unordered_map<string, vector<prf_type> > pairs, unsigned char* key) {
    exist[instance][index] = true;
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
        if (keyword == "ZYXO$o*") {
            cout << "here" << endl;
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

        if ((int) (((levelcounters[i].size()) / 2) - keywordCntCiphers.size()) > 0) {
            for (int j = 0; j < ((levelcounters[i].size()) / 2) - keywordCntCiphers.size(); j++) {
                if (levelcounters[i][j].first != "") {
                    if (keywordCounterMap.count(levelcounters[i][j].first) == 0) {
                        keywordCounterMap[levelcounters[i][j].first] = vector<int>();
                    }
                    keywordCounterMap[levelcounters[i][j].first].push_back(j);

                }
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

    server[instance]->storeKeywordCounters(index, keywordCntCiphers);
    for (long p = 0; p < innerLevels; p++) {
        server[instance]->storeCiphers(index, p, buckets[p], true);
    }
    //    totalCommunication += ciphers.size() * sizeof (prf_type)*2;    
}

int NlogNSDdGeneralClient::getCorrespondingLevel(int index, int size) {
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

void NlogNSDdGeneralClient::permuteLevel(vector<vector<prf_type> >& buckets, vector<pair<string, int> >& counters) {
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

void NlogNSDdGeneralClient::permuteLevel(vector<vector<pair<string, tmp_prf_type> > >& buckets, vector<pair<string, int> >& counters) {
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

void NlogNSDdGeneralClient::setup2(long index, long instance, unordered_map<string, vector<tmp_prf_type> > pairs, unsigned char* key) {
    exist[instance][index] = true;
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
        prf_type K = Utilities::encode(item.first, key);
        unsigned char cntstr[AES_KEY_SIZE];
        memset(cntstr, 0, AES_KEY_SIZE);
        *(long*) (&(cntstr[AES_KEY_SIZE - 5])) = -1;
        prf_type mapKey = Utilities::generatePRF(cntstr, K.data());
        prf_type valueTmp;
        *(long*) (&(valueTmp[0])) = item.second.size();
        prf_type mapValue = Utilities::encode(valueTmp.data(), K.data());
        keywordCntCiphers[mapKey] = mapValue;


        //        if (item.first == "ZYXO$o*") {
        //            cout << item.second.size() << endl;
        //        }

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

    server[instance]->storeKeywordCounters(index, keywordCntCiphers);

    for (long p = 0; p < innerLevels; p++) {
        vector<vector<prf_type> > finalCiphers = convertTmpCiphersToFinalCipher(buckets[p], key);
        server[instance]->storeCiphers(index, p, finalCiphers, true);
    }
}

vector<vector<prf_type> > NlogNSDdGeneralClient::convertTmpCiphersToFinalCipher(vector<vector<std::pair<string, tmp_prf_type> > > ciphers, unsigned char* key) {
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

vector<prf_type> NlogNSDdGeneralClient::getAllData(long instance, long index, unsigned char* key) {
    vector<prf_type> finalRes = vector<prf_type>();
    auto ciphers = server[instance]->getAllData(index);

    for (auto cipher : ciphers) {
        prf_type plaintext;
        Utilities::decode(cipher, plaintext, key);
        finalRes.push_back(plaintext);
    }
    totalCommunication += (ciphers.size()) * sizeof (prf_type);
    return finalRes;
}

void NlogNSDdGeneralClient::destroy(long instance, long index) {
    server[instance]->clear(index);
    exist[instance][index] = false;
    totalCommunication += sizeof (long);
}

void NlogNSDdGeneralClient::endSetup() {
    for (int i = 0; i < 4; i++) {
        server[i]->endSetup();
    }
}
