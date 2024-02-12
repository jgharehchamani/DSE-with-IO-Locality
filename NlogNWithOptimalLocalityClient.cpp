#include "NlogNWithOptimalLocalityClient.h"
#include<vector>
#include<algorithm>

NlogNWithOptimalLocalityClient::~NlogNWithOptimalLocalityClient() {
    delete server;
}

NlogNWithOptimalLocalityClient::NlogNWithOptimalLocalityClient(long numOfDataSets, bool inMemory, bool overwrite, bool profile) {
    cout << "================= RUNNING SDa + NlogNWithOptimalLocality )(long) ==================" << endl;
    this->profile = profile;
    server = new NlogNWithOptimalLocalityServer(numOfDataSets, inMemory, overwrite, profile);
    memset(nullKey.data(), 0, AES_KEY_SIZE);
    for (long i = 0; i < numOfDataSets; i++) {
        exist.push_back(false);
    }
}

long NlogNWithOptimalLocalityClient::countTotal(vector<long> fullness, long bin, long size) {
    long full = 0;
    for (long i = 0; i < size; i++)
        full = full + fullness[bin + i];
    return full;
}

bool NlogNWithOptimalLocalityClient::cmpp(pair<string, vector<prf_type>> &a, pair<string, vector<prf_type>> &b) {
    return (a.second.size() > b.second.size());
}

bool NlogNWithOptimalLocalityClient::cmpp2(pair<string, vector<tmp_prf_type>> &a, pair<string, vector<tmp_prf_type>> &b) {
    return (a.second.size() > b.second.size());
}

vector<pair<string, vector<prf_type> > > NlogNWithOptimalLocalityClient::sort(unordered_map<string, vector<prf_type>> &M) {
    vector<pair<string, vector < prf_type > > > A;
    for (auto& it : M) {
        assert(it.first != "");
        A.push_back(it);
    }
    std::sort(A.begin(), A.end(), cmpp);
    return A;
}

vector<pair<string, vector<tmp_prf_type> > > NlogNWithOptimalLocalityClient::sort2(unordered_map<string, vector<tmp_prf_type>> &M) {
    vector<pair<string, vector < tmp_prf_type > > > A;
    for (auto& it : M) {
        assert(it.first != "");
        A.push_back(it);
    }
    std::sort(A.begin(), A.end(), cmpp2);
    return A;
}

long NlogNWithOptimalLocalityClient::findLevel(long index, long p, long size, long &actualLevel, long& dw) {
    long max2 = (long) ceil(log2(size));
    dw = pow(2, max2);
    long retLevel = index;
    actualLevel = S - 1;
    for (long level = index - p; level >= (index - (S - 1) * p) && level >= 0; level = level - p) {
        if (pow(2, level) < dw && dw <= pow(2, retLevel)) {
            return retLevel;
        } else //if(dw <= pow(2, level))
        {
            retLevel = level;
            actualLevel = actualLevel - 1;
        }
    }
    return retLevel;
}

void NlogNWithOptimalLocalityClient::setup2(long index, unordered_map<string, vector<tmp_prf_type> > pairs, unsigned char* key) {
    exist[index] = true;
    vector< vector < vector < pair < pair<string, long>, tmp_prf_type>>>> ciphers;
    ciphers.resize(S);
    vector<vector<long>> full;
    full.resize(S);
    long p = ceil((float) index / (float) S);
    if (p == 0)
        p = 1;
    for (long level = index, loop = S - 1; level >= (index - (S - 1) * p) && level >= 0 && loop >= 0; level = level - p, loop--) {

        long levelSize = 2 * pow(2, index) + pow(2, level + 1);
        long numOfEntries = (float) levelSize / (float) pow(2, level);
        ciphers[loop].resize(numOfEntries);
        full[loop].resize(numOfEntries);
        assert(numOfEntries >= 4);
        //cout<<index<<":: level:"<<level<<" ls:"<<levelSize<<" ne:"<<numOfEntries<<" loop:"<<loop<<" p:"<<p<<endl;
        for (long j = 0; j < numOfEntries; j++) {
            ciphers[loop][j].resize(0);
            full[loop][j] = 0;
        }
    }
    map<prf_type, prf_type> keywordCntCiphers;
    vector<pair<string, vector < tmp_prf_type>>> sorted = sort2(pairs);
    for (auto pair : pairs) {
        long pss = pair.second.size();
        long actualLevel, newSize; // = S-1;//(float) (index - level) / (float) p;
        long level = findLevel(index, p, pss, actualLevel, newSize);
        long levelEntrySize = pow(2, level);
        long levelSize = 2 * pow(2, index) + pow(2, level + 1);
        long numOfEntries = (float) levelSize / (float) pow(2, level);

        assert(level <= index);
        assert(pss <= pow(2, level));

        string temp = pair.first;
        prf_type K = Utilities::encode(temp, key);
        unsigned char cntstr[AES_KEY_SIZE];
        memset(cntstr, 0, AES_KEY_SIZE);
        *(long*) (&(cntstr[AES_KEY_SIZE - 5])) = -1;
        prf_type mapKey = Utilities::generatePRF(cntstr, K.data());
        unsigned char* hash = Utilities::sha256((char*) (mapKey.data()), AES_KEY_SIZE);
        long pos; // = (unsigned long) (*((long*) hash)) % numOfEntries;
        //cout <<"index"<<index<<" ->level:"<< level<<" actualLevel:"<<actualLevel<<" pss:"<<pss<<endl;
        long cnt = 0;
        do {
            pos = (((unsigned long) (*((long*) hash)) % numOfEntries) + cnt) % numOfEntries;
            //	cout<<"("<<cnt<<"/"<<numOfEntries<<") pos:"<<pos<<"=>"<<pss<<"-->"<<newSize<<endl;
            assert(cnt < numOfEntries);
            cnt++;
        } while (pow(2, level) - full[actualLevel][pos] < newSize);
        full[actualLevel][pos] = full[actualLevel][pos] + newSize;
        for (unsigned long i = 0; i < pss; i++) {
            std::pair<string, long> mapKey;
            tmp_prf_type mapValue;
            mapKey.first = pair.first;
            mapKey.second = i;
            mapValue = pair.second[i];
            auto p = std::pair< std::pair<string, long>, tmp_prf_type>(mapKey, mapValue);
            ciphers[actualLevel][pos].push_back(p);
        }
        for (long i = pss; i < newSize; i++) {
            tmp_prf_type dummy;
            memset(dummy.data(), 0, TMP_AES_KEY_SIZE);
            auto dummypair = std::pair<std::pair<string, long>, tmp_prf_type>(std::pair<string, long>("", -1), dummy);
            ciphers[actualLevel][pos].push_back(dummypair);
        }
        K = Utilities::encode(pair.first, key);
        memset(cntstr, 0, AES_KEY_SIZE);
        *(long*) (&(cntstr[AES_KEY_SIZE - 5])) = -1;
        mapKey = Utilities::generatePRF(cntstr, K.data());
        prf_type valueTmp, totalTmp;
        *(long*) (&(valueTmp[0])) = newSize;
        prf_type mapValue = Utilities::encode(valueTmp.data(), K.data());
        keywordCntCiphers[mapKey] = mapValue;
    }
    tmp_prf_type dummy;
    memset(dummy.data(), 0, TMP_AES_KEY_SIZE);
    auto dummypair = pair<std::pair<string, long>, tmp_prf_type>(std::pair<string, long>("", -1), dummy);
    for (long level = index, loop = S - 1; level >= (index - (S - 1) * p) && level >= 0 && loop >= 0; level = level - p, loop--)//filling up to max capacity
    {
        long levelSize = 2 * pow(2, index) + pow(2, level + 1);
        long numOfEntries = ((float) levelSize) / ((float) pow(2, level));
        for (long j = 0; j < numOfEntries; j++) {
            long curSize = ciphers[loop][j].size();
            //cout <<"level:"<<level<<"{"<<curSize<<"}/"<<pow(2,level)<<" p:"<<p<<endl;
            for (long k = curSize; k < pow(2, level); k++) {
                ciphers[loop][j].push_back(dummypair);
            }
            //cout <<"("<<ciphers[loop][j].size()<<"="<<pow(2, level)<<")"<<endl;
            assert(ciphers[loop][j].size() == pow(2, level));
        }
    }
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
    totalCommunication += ciphers.size() * sizeof (prf_type)*2;
    server->storeKeywordCounters(index, keywordCntCiphers);
    assert(ciphers.size() == S || ciphers.size() == S - 1);
    for (long instance = index, loop = S - 1; instance >= (index - (S - 1) * p) && instance >= 0 && loop >= 0; instance = instance - p, loop--) {
        long numOfEntries = ((float) (2 * pow(2, index) + pow(2, instance + 1)) / ((float) pow(2, instance)));
        assert(ciphers[loop].size() == numOfEntries);
        for (long entry = 0; entry < ciphers[loop].size(); entry++) {
            //cout <<"loop:"<<loop<<" "<<ciphers[loop][entry].size() <<"-"<< pow(2,instance)<<endl;
            //assert(ciphers[loop][entry].size() == pow(2,instance));
            vector<vector<prf_type> > finalCiphers = convertTmpCiphersToFinalCipher(ciphers[loop][entry], key);
            server->storeCiphers(index, loop, finalCiphers, entry == 0);
        }
    }
}

void NlogNWithOptimalLocalityClient::setup(long index, unordered_map<string, vector<prf_type> > pairs, unsigned char* key) {
    exist[index] = true;
}

vector<prf_type> NlogNWithOptimalLocalityClient::search(long index, string keyword, unsigned char* key) {
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
        prf_type hashtoken = Utilities::encode(keyword, key);
        long actualLevel, b;
        long p = ceil((float) index / (float) S);
        if (index == 0)
            p = 1;
        long level = findLevel(index, p, keywordCnt, actualLevel, b); //what is it ?? 
        long levelSize = 2 * pow(2, index) + pow(2, level + 1);
        long numOfEntries = (float) levelSize / (float) pow(2, level);
        cout << "level:" << level << " actual:" << actualLevel;
SEARCH:
        cout << "attempt:" << attempt << endl;
        vector<prf_type> ciphers;
        Utilities::startTimer(200);
        ciphers = server->search(index, level, actualLevel, hashtoken, keywordCnt, attempt);
        t3 = Utilities::stopTimer(200);
        totalCommunication += ciphers.size() * sizeof (prf_type); // how do I know where to write in the entry ??
        assert(ciphers.size() == pow(2, level));
        Utilities::startTimer(50);
        int cnt = 0;

        for (auto item : ciphers) {
            prf_type plaintext;
            Utilities::decode(item, plaintext, key);
            if (strcmp((char*) plaintext.data(), keyword.data()) == 0) {
                finalRes.push_back(plaintext);
            }
        }
        if (finalRes.size() == 0 && (attempt < levelSize)) {
            attempt++;
            goto SEARCH;
        }
    }
    t3 = Utilities::stopTimer(50);
    TotalCacheTime += server->keywordCounters->cacheTime;
    TotalCacheTime += server->storage->cacheTime;
    if (finalRes.size() > 0)
        cout << "found after attempts:" << attempt + 1 << endl;

    return finalRes;
}

vector<prf_type> NlogNWithOptimalLocalityClient::getAllData(long index, unsigned char* key) {
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

void NlogNWithOptimalLocalityClient::destroy(long index) {
    server->clear(index);
    exist[index] = false;
    totalCommunication += sizeof (long);
}

vector<vector<prf_type> > NlogNWithOptimalLocalityClient::convertTmpCiphersToFinalCipher(vector<pair<std::pair<string, long>, tmp_prf_type> > ciphers, unsigned char* key) {
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
