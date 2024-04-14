#include "NlogNWithTunableLocalityClient.h"
#include<vector>
#include<algorithm>

NlogNWithTunableLocalityClient::~NlogNWithTunableLocalityClient() {
    delete server;
}

NlogNWithTunableLocalityClient::NlogNWithTunableLocalityClient(long numOfDataSets, bool inMemory, bool overwrite, bool profile) {
    cout << "==== RUNNING SDa + NlogNWithTUNABLELocality )(long)======[LOCALITY=" << NLOGN_LOCALITY << "] S=" << S << endl;
    this->profile = profile;
    server = new NlogNWithTunableLocalityServer(numOfDataSets, inMemory, overwrite, profile);
    memset(nullKey.data(), 0, AES_KEY_SIZE);
    for (long i = 0; i < numOfDataSets; i++) {
        exist.push_back(false);
    }
}

long NlogNWithTunableLocalityClient::countTotal(vector<long> fullness, long bin, long size) {
    long full = 0;
    for (long i = 0; i < size; i++)
        full = full + fullness[bin + i];
    return full;
}

bool NlogNWithTunableLocalityClient::cmpp(pair<string, vector<prf_type>> &a, pair<string, vector<prf_type>> &b) {
    return (a.second.size() > b.second.size());
}

bool NlogNWithTunableLocalityClient::cmpp2(pair<string, vector<tmp_prf_type>> &a, pair<string, vector<tmp_prf_type>> &b) {
    return (a.second.size() > b.second.size());
}

vector<pair<string, vector<prf_type> > > NlogNWithTunableLocalityClient::sort(unordered_map<string, vector<prf_type>> &M) {
    vector<pair<string, vector < prf_type > > > A;
    for (auto& it : M) {
        assert(it.first != "");
        A.push_back(it);
    }
    std::sort(A.begin(), A.end(), cmpp);
    return A;
}

vector<pair<string, vector<tmp_prf_type> > > NlogNWithTunableLocalityClient::sort2(unordered_map<string, vector<tmp_prf_type>> &M) {
    vector<pair<string, vector < tmp_prf_type > > > A;
    for (auto& it : M) {
        assert(it.first != "");
        A.push_back(it);
    }
    std::sort(A.begin(), A.end(), cmpp2);
    return A;
}

long findLevel(long index, long p, long size, long &actualLevel, long& dw) {
    long max2 = (long) ceil(log2(size));
    dw = pow(2, max2);
    if (index == 0 || dw <= NLOGN_LOCALITY) {
        actualLevel = 0;
        return 0;
    }
    long retLevel = index;
    actualLevel = S;
    for (long level = index - p; level >= (index - (S - 1) * p) && level >= 1; level = level - p) {
        if (NLOGN_LOCALITY * pow(2, level) < dw && dw <= NLOGN_LOCALITY * pow(2, retLevel)) {
            return retLevel;
        } else if (dw <= NLOGN_LOCALITY * pow(2, level)) {
            retLevel = level;
            actualLevel = actualLevel - 1;
        }
        //cout <<"findLevel:"<<level<<" retLevel:"<<retLevel<<endl;
    }
    return retLevel;
}

void NlogNWithTunableLocalityClient::setup2(long index, unordered_map<string, vector<tmp_prf_type> > pairs, unsigned char* key) {
    exist[index] = true;
    vector< vector < vector < pair < pair<string, long>, tmp_prf_type>>>> ciphers;
    ciphers.resize(S + 1);
    vector<vector<long>> full;
    full.resize(S + 1);
    long p = ceil((float) index / (float) S);
    if (p == 0)
        p = 1;
    for (long level = index, loop = S; level >= (index - (S - 1) * p) && level >= 1 && loop >= 1; level = level - p, loop--) {
        long levelSize = 2 * pow(2, index) + pow(2, level + 1);
        long numOfEntries = (float) levelSize / (float) pow(2, level);
        ciphers[loop].resize(numOfEntries);
        full[loop].resize(numOfEntries);
        assert(numOfEntries >= 4);
        for (long j = 0; j < numOfEntries; j++) {
            ciphers[loop][j].resize(0);
            full[loop][j] = 0;
        }
    }
    long levelZeroSize = 2 * pow(2, index) + 2;
    ciphers[0].resize(levelZeroSize);
    full[0].resize(levelZeroSize);
    for (long j = 0; j < levelZeroSize; j++) {
        ciphers[0][j].resize(0);
        full[0][j] = 0;
    }
    map<prf_type, prf_type> keywordCntCiphers;
    vector<pair<string, vector < tmp_prf_type>>> sorted = sort2(pairs);
    for (auto pair : pairs) {
        long pss = pair.second.size();
        long actualLevel, newSize;
        long level = findLevel(index, p, pss, actualLevel, newSize); // change this func
        long levelEntrySize = pow(2, level);
        long levelSize = 2 * pow(2, index) + pow(2, level + 1);
        long numOfEntries = (float) levelSize / (float) pow(2, level);

        assert(level <= index);
        assert(pss <= NLOGN_LOCALITY * pow(2, level));
        string temp = pair.first;
        prf_type K = Utilities::encode(temp, key);
        unsigned char cntstr[AES_KEY_SIZE];
        memset(cntstr, 0, AES_KEY_SIZE);
        *(long*) (&(cntstr[AES_KEY_SIZE - 5])) = -1;
        prf_type mapKey = Utilities::generatePRF(cntstr, K.data());
        unsigned char* hash = Utilities::sha256((char*) (mapKey.data()), AES_KEY_SIZE);
        long numOfChunks = ceil((float) newSize / (float) pow(2, level));
        long chunkSize = (newSize <= pow(2, level)) ? newSize : pow(2, level);
        long pos;
        long cnt = 0;
        long start = 0;
        //cout <<"numOfChunks:"<<numOfChunks<<" numOfEntries:"<<numOfEntries<<endl;
        for (long nc = 0; nc < numOfChunks; nc++) {
            pos = (((unsigned long) (*((long*) hash)) % numOfEntries) + nc + cnt) % numOfEntries;
            while (pow(2, level) - full[actualLevel][pos] < chunkSize) {
                assert(cnt < numOfEntries);
                cnt++;
                pos = (((unsigned long) (*((long*) hash)) % numOfEntries) + nc + cnt) % numOfEntries;
            }
            full[actualLevel][pos] = full[actualLevel][pos] + chunkSize;
            for (unsigned long i = nc * pow(2, level); i < nc * pow(2, level) + pow(2, level) && i < newSize; i++) {
                if (i < pss) {
                    std::pair<string, long> mapKey;
                    tmp_prf_type mapValue;
                    mapKey.first = pair.first;
                    mapKey.second = i;
                    mapValue = pair.second[i];
                    auto p = std::pair< std::pair<string, long>, tmp_prf_type>(mapKey, mapValue);
                    ciphers[actualLevel][pos].push_back(p);
                } else {
                    tmp_prf_type dummy;
                    memset(dummy.data(), 0, TMP_AES_KEY_SIZE);
                    auto dummypair = std::pair<std::pair<string, long>, tmp_prf_type>(std::pair<string, long>("", -1), dummy);
                    ciphers[actualLevel][pos].push_back(dummypair);
                }
            }
        }
        K = Utilities::encode(pair.first, key);
        memset(cntstr, 0, AES_KEY_SIZE);
        *(long*) (&(cntstr[AES_KEY_SIZE - 5])) = -1;
        mapKey = Utilities::generatePRF(cntstr, K.data());
        prf_type valueTmp, totalTmp;
        //*(long*) (&(valueTmp[0])) = newSize;
        *(long*) (&(valueTmp[0])) = pss;
        prf_type mapValue = Utilities::encode(valueTmp.data(), K.data());
        keywordCntCiphers[mapKey] = mapValue;
    }
    tmp_prf_type dummy;
    memset(dummy.data(), 0, TMP_AES_KEY_SIZE);
    auto dummypair = pair<std::pair<string, long>, tmp_prf_type>(std::pair<string, long>("", -1), dummy);
    for (long level = index, loop = S; level >= (index - (S - 1) * p) && level >= 1 && loop >= 1; level = level - p, loop--) {
        long levelSize = 2 * pow(2, index) + pow(2, level + 1);
        long numOfEntries = ((float) levelSize) / ((float) pow(2, level));
        for (long j = 0; j < numOfEntries; j++) {
            long curSize = ciphers[loop][j].size();
            //cout <<"level:"<<level<<" pos:"<<j<<"{"<<curSize<<"}/"<<pow(2,level)<<" p:"<<p<<endl;
            for (long k = curSize; k < pow(2, level); k++) {
                ciphers[loop][j].push_back(dummypair);
            }
            //cout <<"("<<ciphers[loop][j].size()<<"="<<pow(2, level)<<")"<<" pos:"<<j<<endl;
            assert(ciphers[loop][j].size() == pow(2, level));
        }
    }
    for (long j = 0; j < 2 * pow(2, index) + 2; j++) {
        long curSize = ciphers[0][j].size();
        for (long k = curSize; k < pow(2, 0); k++) {
            ciphers[0][j].push_back(dummypair);
        }
        //cout<<"index:"<<index<<" cursize:"<<curSize<<" then:"<<ciphers[0][j].size()<<endl;
        assert(ciphers[0][j].size() == pow(2, 0));
    }
    //cout<<"index:"<<index<<"<<ciphers[0].size():"<<ciphers[0].size()<<endl;
    assert(ciphers[0].size() == 2 * pow(2, index) + 2);
    prf_type randomKey;
    for (long i = 0; i < AES_KEY_SIZE; i++)
        randomKey[i] = rand();
    for (long i = keywordCntCiphers.size(); i < pow(2, index); i++) {
        unsigned char cntstr[AES_KEY_SIZE];
        memset(cntstr, 0, AES_KEY_SIZE);
        *(long*) (&(cntstr[AES_KEY_SIZE - 9])) = rand();
        prf_type mapKey = Utilities::generatePRF(cntstr, randomKey.data());
        *(long*) (&(cntstr[AES_KEY_SIZE - 5])) = rand();
        prf_type mapValue = Utilities::generatePRF(cntstr, randomKey.data());
        keywordCntCiphers[mapKey] = mapValue;
    }
    totalCommunication += ciphers.size() * sizeof (prf_type) * 2;
    server->storeKeywordCounters(index, keywordCntCiphers);
    assert(ciphers.size() == S + 1 || ciphers.size() == S);
    for (long instance = index, loop = S; instance >= (index - (S - 1) * p) && instance >= 1 && loop >= 1; instance = instance - p, loop--) {
        long numOfEntries = ((float) (2 * pow(2, index) + pow(2, instance + 1)) / ((float) pow(2, instance)));
        assert(ciphers[loop].size() == numOfEntries);
        for (long entry = 0; entry < ciphers[loop].size(); entry++) {
            vector<vector<prf_type> > finalCiphers = convertTmpCiphersToFinalCipher(ciphers[loop][entry], key);
            server->storeCiphers(index, loop, finalCiphers, entry == 0);
        }
    }
    //	cout<<"index:"<<index<<" ciphers[index][0].size():"
    //								   <<ciphers[index][0].size()<<"/"<< 2*pow(2, index) + pow(2, 0+1)<<endl;
    for (long entry = 0; entry < ciphers[0].size(); entry++) {
        assert(ciphers[0].size() == 2 * pow(2, index) + pow(2, 1));
        assert(ciphers[0][entry].size() == 1);
        vector<vector<prf_type> > finalCiphers = convertTmpCiphersToFinalCipher(ciphers[0][entry], key);
        server->storeCiphers(index, 0, finalCiphers, entry == 0);
    }
}

void NlogNWithTunableLocalityClient::setup(long index, unordered_map<string, vector<prf_type> > pairs, unsigned char* key) {
    exist[index] = true;
}

vector<prf_type> NlogNWithTunableLocalityClient::search(long index, string keyword, unsigned char* key) {
    server->keywordCounters->cacheTime = 0;
    server->storage->cacheTime = 0;
    server->keywordCounters->getCounterTime = 0;

    prf_type token = Utilities::encode(keyword, key);
    long keywordCnt = server->getCounter(index, token);
    cout << index << ":" << " time taken (for NlogN):[" << server->keywordCounters->getCounterTime << "]" << endl;
    searchTime += server->keywordCounters->getCounterTime;
    cout << index << ": keywordCount:" << keywordCnt << endl;
    vector<prf_type> finalRes;
    long attempt = 0;
    long storageSearchTime = 0;
    long decodeTime = 0;
    if (keywordCnt > 0) {
        prf_type hashtoken = Utilities::encode(keyword, key);
        long actualLevel, b;
        long p = ceil((float) index / (float) S);
        if (index == 0)
            p = 1;
        long level = findLevel(index, p, keywordCnt, actualLevel, b);
        keywordCnt = b;
        cout << index << ": padded list size :" << b << endl;
        long levelSize = 2 * pow(2, index) + pow(2, level + 1);
        long numOfEntries = (float) levelSize / (float) pow(2, level);
        long numOfChunks = ceil((float) keywordCnt / (float) pow(2, level));
        long chunkSize = (keywordCnt <= pow(2, level)) ? keywordCnt : pow(2, level);
        //cout <<"level:"<<level<<" (actualLevel:"<<actualLevel<<")"<<endl;
        long bytesRead = 0;
        cout << index << ": chunks -";
        for (long nc = 0; nc < numOfChunks; nc++) {
SEARCH:
            cout << "[" << attempt << "-" << nc << "]";
            vector<prf_type> ciphers;
            Utilities::startTimer(200);
            ciphers = server->search(index, level, actualLevel, hashtoken, keywordCnt, attempt, nc);
            storageSearchTime += server->serverSearchTime + server->storage->searchTime;
            //ciphers = server->getAllData(index);
            //assert(ciphers.size() == pow(2,level));
            totalCommunication += ciphers.size() * sizeof (prf_type); // how do I know where to write in the entry ??
            bytesRead += ciphers.size() * sizeof (prf_type);
            Utilities::startTimer(50);
            int cnt = 0;
            vector<prf_type> currentChunk;
            for (auto item : ciphers) {
                prf_type plaintext;
                Utilities::decode(item, plaintext, key);
                if (strcmp((char*) plaintext.data(), keyword.data()) == 0) {
                    currentChunk.push_back(plaintext);
                }
            }
            decodeTime += Utilities::stopTimer(50);
            if (currentChunk.size() == 0 && (attempt < numOfEntries)) {
                attempt++;
                goto SEARCH;
            } else {
                for (auto elem : currentChunk)
                    finalRes.push_back(elem);
            }
        }
        cout << endl << index << ": BYTES read:" << bytesRead << endl;
        cout << index << ": search Time:" << storageSearchTime << endl;
        cout << index << ": DECODE Time:" << decodeTime << endl;
    }
    searchTime += storageSearchTime;
    searchTime += decodeTime;

    TotalCacheTime += server->keywordCounters->cacheTime;
    TotalCacheTime += server->storage->cacheTime;
    cout << endl;

    return finalRes;
}

vector<prf_type> NlogNWithTunableLocalityClient::getAllData(long index, unsigned char* key) {
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

void NlogNWithTunableLocalityClient::destroy(long index) {
    server->clear(index);
    exist[index] = false;
    totalCommunication += sizeof (long);
}

vector<vector<prf_type> > NlogNWithTunableLocalityClient::convertTmpCiphersToFinalCipher(vector<pair<std::pair<string, long>, tmp_prf_type> > ciphers, unsigned char* key) {
    vector<vector<prf_type> > results;
    results.push_back(vector<prf_type>());
    for (long i = 0; i < ciphers.size(); i++) {
        //        printf("convert i:%d\n",i);
        auto KV = ciphers[i];
        string keyword = KV.first.first;
        long cnt = KV.first.second;
        tmp_prf_type value = KV.second;
        int ind = *(int*) (&(value.data()[TMP_AES_KEY_SIZE - 5]));
        byte op = *(byte*) (&(value.data()[TMP_AES_KEY_SIZE - 6]));

        if (cnt == -1) {
            prf_type dummy;
            memset(dummy.data(), 0, AES_KEY_SIZE);
            prf_type dummyV = Utilities::encode(dummy.data(), key);
            results[0].push_back(dummyV);
            //            printf("dummy %d %d %d\n",dummyV.data()[0],dummyV.data()[1],dummyV.data()[2]);
        } else {

            prf_type newvalue;
            std::fill(newvalue.begin(), newvalue.end(), 0);
            std::copy(keyword.begin(), keyword.end(), newvalue.begin());
            *(int*) (&(newvalue.data()[AES_KEY_SIZE - 5])) = ind;
            newvalue.data()[AES_KEY_SIZE - 6] = op;

            prf_type mapValue;
            mapValue = Utilities::encode(newvalue.data(), key);
            results[0].push_back(mapValue);
            //            printf("%s: %d %d %d\n",keyword.c_str(), mapValue.data()[0],mapValue.data()[1],mapValue.data()[2]);
        }

    }
    return results;
}
