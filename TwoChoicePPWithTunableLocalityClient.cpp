#include "TwoChoicePPWithTunableLocalityClient.h"
#include<vector>
#include<algorithm>

TwoChoicePPWithTunableLocalityClient::~TwoChoicePPWithTunableLocalityClient() {
    delete server;
    delete oneChoiceServer;
}

TwoChoicePPWithTunableLocalityClient::TwoChoicePPWithTunableLocalityClient(long numOfDataSets, bool inMemory, bool overwrite, bool profile) {
    cout << "=============RUNNING SDa+TwoChoicePLUSPLUS version 2 (long) ====TUNABLE LOCALITY=" << LOCALITY << endl;
    this->profile = profile;
    server = new TwoChoicePPWithTunableLocalityServer(numOfDataSets, inMemory, overwrite, profile);
    oneChoiceServer = new OneChoiceServer(numOfDataSets, inMemory, overwrite, profile, "TwoChoicePPOneChoiceONE-");
    memset(nullKey.data(), 0, AES_KEY_SIZE);
    for (long i = 0; i < numOfDataSets; i++) {
        exist.push_back(false);
        long curNumberOfBins = i > 3 ? ((long) ceil((float) pow(2, i) / (log2(log2(log2(pow(2, i))))))) : 1;
        curNumberOfBins = pow(2, (long) ceil(log2(curNumberOfBins)));
        long curSizeOfEachBin = i > 3 ? SPACE_OVERHEAD * ((log2(log2(log2(pow(2, i)))))) : SPACE_OVERHEAD * pow(2, i);
        numberOfBins.push_back(curNumberOfBins);
        sizeOfEachBin.push_back(curSizeOfEachBin);
    }

    for (long j = 0; j < numOfDataSets; j++) {
        long curNumberOfBins = j > 1 ?
                (long) ceil(((float) pow(2, j)) / (float) (log2(pow(2, j)) * log2(log2(pow(2, j))))) : 1;
        long curSizeOfEachBin = j > 1 ? 3 * (log2(pow(2, j))*(log2(log2(pow(2, j))))) : pow(2, j);
        nB.push_back(curNumberOfBins);
        sEB.push_back(curSizeOfEachBin);
    }
}

long TwoChoicePPWithTunableLocalityClient::countTotal(vector<long> fullness, long bin, long size) {
    long full = 0;
    for (long i = 0; i < size; i++)
        full = full + fullness[bin + i];
    return full;
}

bool cmp1(pair<string, vector<prf_type>> &a, pair<string, vector<prf_type>> &b) {
    return (a.second.size() > b.second.size());
}

bool cmp2(pair<string, vector<tmp_prf_type>> &a, pair<string, vector<tmp_prf_type>> &b) {
    return (a.second.size() > b.second.size());
};

vector<pair<string, vector<tmp_prf_type>>> sort_1(unordered_map<string, vector<tmp_prf_type>> &M) {
    vector<pair<string, vector < tmp_prf_type>>> A;
    for (auto& it : M) {
        assert(it.first != "");
        A.push_back(it);
    }
    sort(A.begin(), A.end(), cmp2);
    return A;
}

vector<pair<string, vector<prf_type>>> sort1(unordered_map<string, vector<prf_type>> &M) {
    vector<pair<string, vector < prf_type>>> A;
    for (auto& it : M) {
        assert(it.first != "");
        A.push_back(it);
    }
    sort(A.begin(), A.end(), cmp1);
    return A;
}

long TwoChoicePPWithTunableLocalityClient::maxPossibleLen(long index) {
    long N = pow(2, index);
    if (N == 1) return 1;
    long l = (float) (log2(N) * log2(N) * log2(N));
    long max = ceil((float) N / (float) l);
    if (max > numberOfBins[index])
        max = numberOfBins[index];
    max = pow(2, (long) floor((float) log2(max)));
    return max;
}

void TwoChoicePPWithTunableLocalityClient::writeToCuckooStash(vector<prf_type> fileids, long cnt,
        long index, long tableNum, unsigned char* key) {
    long entrySize = pow(2, tableNum);
    vector<prf_type> ctCiphers;
    for (auto c : fileids) {
        prf_type value;
        value = Utilities::encode(c.data(), key);
        ctCiphers.push_back(value);
    }
    prf_type dummy;
    memset(dummy.data(), 0, AES_KEY_SIZE);
    prf_type dummyV = Utilities::encode(dummy.data(), key);
    if (fileids.size() < entrySize) {
        for (long i = fileids.size(); i < entrySize; i++)
            ctCiphers.push_back(dummyV);
    }
    server->insertCuckooStash(index, tableNum, ctCiphers);
}

void TwoChoicePPWithTunableLocalityClient::place(string keyword, vector<prf_type> fileids, long cuckooID,
        long cnt, long index, long tableNum, unsigned char* key) {
    if (cnt == (pow(2, index - tableNum)) + 1) //cycle occured
    {
        cout << "****Cuckoo overflow: write in cuckooStash:" << " index:" << index << " tableNum:" << tableNum << endl;
        writeToCuckooStash(fileids, cnt, index, tableNum, key);
        return;
    }
    long entrySize = pow(2, tableNum);
    long entryNum = pow(2, (index - tableNum));

    string temp = keyword;
    unsigned char cntstr[AES_KEY_SIZE];
    if (cuckooID == 0)
        temp = temp.append("0");
    else
        temp = temp.append("1");

    prf_type K = Utilities::encode(temp, key);
    memset(cntstr, 0, AES_KEY_SIZE);
    *(long*) (&(cntstr[AES_KEY_SIZE - 5])) = -1;
    prf_type mapKey = Utilities::generatePRF(cntstr, K.data());
    unsigned char* h = Utilities::sha256((char*) (mapKey.data()), AES_KEY_SIZE);
    long hash = (unsigned long) (*((long*) h)) % entryNum;

    prf_type encKeyw = Utilities::encode(keyword, key);
    pair<prf_type, vector < prf_type>> dis = server->insertCuckooHT(index, tableNum, cuckooID, hash,
            encKeyw, fileids);
    if (dis.first != nullKey) {
        string keyw = Utilities::decode(dis.first, key);
        place(keyw, dis.second, cnt + 1, ((cuckooID + 1) % 2), index, tableNum, key);
    }
}

void TwoChoicePPWithTunableLocalityClient::writeToCuckooHT(long index, long size, string keyword,
        vector<prf_type> fileids, unsigned char* key) {
    cout << "writeToCuckooht" << endl;
    assert(fileids.size() > 0);
    long tableNum = (long) ceil((float) log2(size));
    vector<prf_type> ctCiphers;
    for (long i = 0; i < fileids.size(); i++) {
        prf_type fid = Utilities::encode(fileids[i].data(), key);
        ctCiphers.push_back(fid);
    }
    ctCiphers.resize(size);
    if (fileids.size() < size) {
        prf_type dummy;
        memset(dummy.data(), 0, AES_KEY_SIZE);
        prf_type dummyV = Utilities::encode(dummy.data(), key);
        for (long i = fileids.size(); i < size; i++)
            ctCiphers.push_back(dummy);
    }
    place(keyword, ctCiphers, 0, 0, index, tableNum, key);
}

void TwoChoicePPWithTunableLocalityClient::writeToCuckooHT2(long index, long size, string keyword, vector<tmp_prf_type> fileids, unsigned char* key) {
    assert(fileids.size() > 0);
    long tableNum = (long) ceil((float) log2(size));

    vector<prf_type> ctCiphers;
    for (long i = 0; i < fileids.size(); i++) {
        tmp_prf_type value = fileids[i];
        long ind = *(long*) (&(value.data()[TMP_AES_KEY_SIZE - 5]));
        byte op = *(byte*) (&(value.data()[TMP_AES_KEY_SIZE - 6]));

        prf_type newvalue;
        std::fill(newvalue.begin(), newvalue.end(), 0);
        std::copy(keyword.begin(), keyword.end(), newvalue.begin());
        *(int*) (&(newvalue.data()[AES_KEY_SIZE - 5])) = ind;
        newvalue.data()[AES_KEY_SIZE - 6] = op;
        prf_type mapValue;
        mapValue = Utilities::encode(newvalue.data(), key);
        ctCiphers.push_back(mapValue);
    }
    //ctCiphers.resize(size);
    prf_type dummy;
    memset(dummy.data(), 0, AES_KEY_SIZE);
    prf_type dummyV = Utilities::encode(dummy.data(), key);
    if (fileids.size() < size) {
        for (long i = fileids.size(); i < size; i++) {
            ctCiphers.push_back(dummyV);
        }
    }
    place(keyword, ctCiphers, 0, 0, index, tableNum, key);
}

void TwoChoicePPWithTunableLocalityClient::setup2(long index, unordered_map<string, vector<tmp_prf_type> > pairs, unsigned char* key) {
    exist[index] = true;
    vector<vector<pair<pair<string, long>, tmp_prf_type> > > ciphers;
    for (long i = 0; i < numberOfBins[index]; i++) {
        ciphers.push_back(vector<pair<pair<string, long>, tmp_prf_type> >());
    }
    vector<vector<pair<pair<string, long>, tmp_prf_type> > > ciphersOne;
    for (long i = 0; i < nB[index]; i++) {
        ciphersOne.push_back(vector<pair<pair<string, long>, tmp_prf_type> >());
    }

    map<prf_type, prf_type> keywordCntCiphers;
    vector<long> fullness;
    for (long b = 0; b < numberOfBins[index]; b++) {
        fullness.push_back(0);
    }

    vector<pair<string, vector < tmp_prf_type> > > sorted = sort_1(pairs);
    long mpl = maxPossibleLen(index);

    for (auto pair : sorted) {
        long pss = pair.second.size();
        if (pss > LOCALITY * mpl) {
            assert(pair.first != "");
            prf_type K1 = Utilities::encode(pair.first, key);
            prf_type mapKey, mapValue;
            unsigned char cntstr[AES_KEY_SIZE];
            memset(cntstr, 0, AES_KEY_SIZE);
            *(long*) (&(cntstr[AES_KEY_SIZE - 5])) = -1;
            mapKey = Utilities::generatePRF(cntstr, K1.data());
            unsigned char* hash = Utilities::sha256((char*) mapKey.data(), AES_KEY_SIZE);
            long pos = ((unsigned long) (*((long*) hash))) % nB[index];
            long cipherIndex = pos;
            for (unsigned long i = LOCALITY * mpl; i < pair.second.size(); i++) {
                std::pair<string, long> mapKey;
                tmp_prf_type mapValue;
                mapKey.first = pair.first;
                mapKey.second = i;
                mapValue = pair.second[i];
                auto p = std::pair< std::pair<string, long>, tmp_prf_type>(mapKey, mapValue);
                ciphersOne[cipherIndex].push_back(p);
                fullness[cipherIndex] = fullness[cipherIndex] + 1;
                cipherIndex++;
                if (cipherIndex == nB[index]) {
                    cipherIndex = 0;
                }
            }
        }
        long times = ceil((float) pss / (float) mpl);
        if (times > LOCALITY)
            times = LOCALITY;
        for (long t = 0; t < times; t++) {
            long localpss = mpl;
            long newsize = mpl;
            if ((t + 1) * mpl < pss)
                localpss = mpl;
            else {
                localpss = pss - t*mpl;
                newsize = pow(2, (long) ceil(log2(localpss)));
            }
            if (newsize > mpl)
                newsize = mpl;
            string temp = pair.first;
            temp = temp.append("1");
            temp = temp.append(to_string(t));
            prf_type K1 = Utilities::encode(temp, key);
            unsigned char cntstr[AES_KEY_SIZE];
            memset(cntstr, 0, AES_KEY_SIZE);
            *(long*) (&(cntstr[AES_KEY_SIZE - 5])) = -1;
            prf_type mapKey1 = Utilities::generatePRF(cntstr, K1.data());
            unsigned char* hash1 = Utilities::sha256((char*) (mapKey1.data()), AES_KEY_SIZE);

            temp = pair.first;
            temp = temp.append("2");
            temp = temp.append(to_string(t));
            prf_type K2 = Utilities::encode(temp, key);
            memset(cntstr, 0, AES_KEY_SIZE);
            *(long*) (&(cntstr[AES_KEY_SIZE - 5])) = -1;
            prf_type mapKey2 = Utilities::generatePRF(cntstr, K2.data());
            unsigned char* hash2 = Utilities::sha256((char*) (mapKey2.data()), AES_KEY_SIZE);

            long superBins = ceil((float) numberOfBins[index] / newsize);
            long pos1 = (unsigned long) (*((long*) hash1)) % superBins;
            long pos2 = (unsigned long) (*((long*) hash2)) % superBins;

            long totalItems1 = countTotal(fullness, pos1*newsize, newsize);
            long totalItems2 = countTotal(fullness, pos2*newsize, newsize);
            long cipherIndex;
            if (totalItems1 > totalItems2) {
                cipherIndex = pos2 * newsize;
            } else {
                cipherIndex = pos1*newsize;
            }
            if (fullness[cipherIndex] < sizeOfEachBin[index]) {
                for (unsigned long i = t * mpl; i < t * mpl + localpss; i++) {
                    std::pair<string, long> mapKey;
                    tmp_prf_type mapValue;
                    mapKey.first = pair.first;
                    mapKey.second = i;
                    mapValue = pair.second[i];
                    auto p = std::pair< std::pair<string, long>, tmp_prf_type>(mapKey, mapValue);
                    ciphers[cipherIndex].push_back(p);
                    fullness[cipherIndex] = fullness[cipherIndex] + 1;
                    cipherIndex++;
                }
                tmp_prf_type dummy;
                memset(dummy.data(), 0, TMP_AES_KEY_SIZE);
                auto dummypair = std::pair<std::pair<string, long>, tmp_prf_type>(std::pair<string, long>("", -1), dummy);
                for (long i = localpss; i < newsize; i++) {
                    ciphers[cipherIndex].push_back(dummypair);
                    fullness[cipherIndex] = fullness[cipherIndex] + 1;
                    cipherIndex++;
                }
            } else {
                writeToCuckooHT2(index, newsize, pair.first, pair.second, key);
                cout << "writtenToCuckooHT2:" << index << endl;
            }
        }
        prf_type K = Utilities::encode(pair.first, key);
        unsigned char cntstr[AES_KEY_SIZE];
        memset(cntstr, 0, AES_KEY_SIZE);
        *(long*) (&(cntstr[AES_KEY_SIZE - 5])) = -1;
        prf_type mapKey = Utilities::generatePRF(cntstr, K.data());
        prf_type valueTmp, totalTmp;
        *(long*) (&(valueTmp[0])) = pair.second.size();
        prf_type mapValue = Utilities::encode(valueTmp.data(), K.data());
        keywordCntCiphers[mapKey] = mapValue;
    }
    tmp_prf_type dummy;
    memset(dummy.data(), 0, TMP_AES_KEY_SIZE);
    auto dummypair = pair<std::pair<string, long>, tmp_prf_type>(std::pair<string, long>("", -1), dummy);
    for (long i = 0; i < numberOfBins[index]; i++) //filling up each bin to maximum capacity
    {
        long curSize = ciphers[i].size();
        for (long j = curSize; j < sizeOfEachBin[index]; j++) {
            ciphers[i].push_back(dummypair);
        }
    }
    for (long i = 0; i < nB[index]; i++) //filling up each bin to maximum capacity
    {
        long curSize = ciphersOne[i].size();
        for (long j = curSize; j < sEB[index]; j++) {
            ciphersOne[i].push_back(dummypair);
        }
    }
    prf_type randomKey;
    for (long i = 0; i < AES_KEY_SIZE; i++) {
        randomKey[i] = rand();
    }

    for (long i = keywordCntCiphers.size(); i < pow(2, index); i++) {
        unsigned char cntstr[AES_KEY_SIZE];
        memset(cntstr, 0, AES_KEY_SIZE);
        *(long*) (&(cntstr[AES_KEY_SIZE - 9])) = rand();
        prf_type mapKey = Utilities::generatePRF(cntstr, randomKey.data());
        *(long*) (&(cntstr[AES_KEY_SIZE - 5])) = rand();
        prf_type mapValue = Utilities::generatePRF(cntstr, randomKey.data());
        keywordCntCiphers[mapKey] = mapValue;
    }
    totalCommunication += ciphers.size() * sizeof (prf_type)*2 + ciphersOne.size() * sizeof (prf_type);
    server->storeKeywordCounters(index, keywordCntCiphers);
    for (long i = 0; i < ciphers.size(); i++) {
        vector<vector<prf_type> > finalCiphers = convertTmpCiphersToFinalCipher(ciphers[i], key);
        server->storeCiphers(index, finalCiphers, i == 0);
    }
    for (long i = 0; i < ciphersOne.size(); i++) {
        vector<vector<prf_type> > finalCiphers = convertTmpCiphersToFinalCipher(ciphersOne[i], key);
        oneChoiceServer->storeCiphers(index, finalCiphers, i == 0);
    }
}

vector<vector<prf_type> > TwoChoicePPWithTunableLocalityClient::convertTmpCiphersToFinalCipher(vector<pair<std::pair<string, long>, tmp_prf_type> > ciphers, unsigned char* key) {
    vector<vector<prf_type> > results;
    results.push_back(vector<prf_type>());
    for (long i = 0; i < ciphers.size(); i++) {
        auto KV = ciphers[i];
        string keyword = KV.first.first;
        long cnt = KV.first.second;
        tmp_prf_type value = KV.second;
        long ind = *(long*) (&(value.data()[TMP_AES_KEY_SIZE - 5]));
        byte op = *(byte*) (&(value.data()[TMP_AES_KEY_SIZE - 6]));

        if (cnt == -1) {
            prf_type dummy;
            memset(dummy.data(), 0, AES_KEY_SIZE);
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

void TwoChoicePPWithTunableLocalityClient::setup(long index, unordered_map<string, vector<prf_type> > pairs, unsigned char* key) {
    exist[index] = true;
    vector<vector < prf_type>> ciphers;
    for (long i = 0; i < numberOfBins[index]; i++)
        ciphers.push_back(vector<prf_type>());
    vector<vector < prf_type>> ciphersOne;
    for (long i = 0; i < nB[index]; i++)
        ciphersOne.push_back(vector<prf_type>());

    map<prf_type, prf_type> keywordCntCiphers;
    vector<long> fullness;
    fullness.resize(numberOfBins[index]);
    for (long b = 0; b < numberOfBins[index]; b++) {
        fullness[b] = 0;
    }

    vector<pair<string, vector < prf_type>>> sorted = sort1(pairs);
    long mpl = maxPossibleLen(index);

    for (auto pair : sorted) {
        long pss = pair.second.size();
        if (pss > LOCALITY * mpl) {
            assert(pair.first != "");
            prf_type K1 = Utilities::encode(pair.first, key);
            prf_type mapKey, mapValue;
            unsigned char cntstr[AES_KEY_SIZE];
            memset(cntstr, 0, AES_KEY_SIZE);
            *(long*) (&(cntstr[AES_KEY_SIZE - 5])) = -1;
            mapKey = Utilities::generatePRF(cntstr, K1.data());
            unsigned char* hash = Utilities::sha256((char*) mapKey.data(), AES_KEY_SIZE);
            long pos = ((unsigned long) (*((long*) hash))) % nB[index];
            long cipherIndex = pos;
            for (unsigned long i = LOCALITY * mpl; i < pair.second.size(); i++) {
                prf_type mapKey, mapValue;
                mapValue = Utilities::encode(pair.second[i].data(), key);
                ciphersOne[cipherIndex].push_back(mapValue);
                cipherIndex++;
                if (cipherIndex == nB[index]) {
                    cipherIndex = 0;
                }
            }
        }
        long times = ceil((float) pss / (float) mpl);
        if (times > LOCALITY)
            times = LOCALITY;
        for (long t = 0; t < times; t++) {
            long localpss = mpl;
            long newsize = mpl;
            if ((t + 1) * mpl < pss)
                localpss = mpl;
            else {
                localpss = pss - t*mpl;
                newsize = pow(2, (long) ceil(log2(localpss)));
            }
            if (newsize > mpl)
                newsize = mpl;
            string temp = pair.first;
            temp = temp.append("1");
            temp = temp.append(to_string(t));
            prf_type K1 = Utilities::encode(temp, key);
            unsigned char cntstr[AES_KEY_SIZE];
            memset(cntstr, 0, AES_KEY_SIZE);
            *(long*) (&(cntstr[AES_KEY_SIZE - 5])) = -1;
            prf_type mapKey1 = Utilities::generatePRF(cntstr, K1.data());
            unsigned char* hash1 = Utilities::sha256((char*) (mapKey1.data()), AES_KEY_SIZE);

            temp = pair.first;
            temp = temp.append("2");
            temp = temp.append(to_string(t));
            prf_type K2 = Utilities::encode(temp, key);
            memset(cntstr, 0, AES_KEY_SIZE);
            *(long*) (&(cntstr[AES_KEY_SIZE - 5])) = -1;
            prf_type mapKey2 = Utilities::generatePRF(cntstr, K2.data());
            unsigned char* hash2 = Utilities::sha256((char*) (mapKey2.data()), AES_KEY_SIZE);

            long superBins = ceil((float) numberOfBins[index] / newsize);
            long pos1 = (unsigned long) (*((long*) hash1)) % superBins;
            long pos2 = (unsigned long) (*((long*) hash2)) % superBins;

            long totalItems1 = countTotal(fullness, pos1*newsize, newsize);
            long totalItems2 = countTotal(fullness, pos2*newsize, newsize);
            long cipherIndex;
            if (totalItems1 > totalItems2)
                cipherIndex = pos2 * newsize;
            else
                cipherIndex = pos1*newsize;
            if (fullness[cipherIndex] < sizeOfEachBin[index]) {
                for (unsigned long i = t * mpl; i < t * mpl + localpss; i++) {
                    prf_type mapValue = Utilities::encode(pair.second[i].data(), key);
                    assert(fullness[cipherIndex] < sizeOfEachBin[index]);
                    ciphers[cipherIndex].push_back(mapValue);
                    fullness[cipherIndex] = fullness[cipherIndex] + 1;
                    assert(cipherIndex < ciphers.size());
                    cipherIndex++;
                }
                for (long i = localpss; i < newsize; i++) {
                    prf_type dummy;
                    memset(dummy.data(), 0, AES_KEY_SIZE);
                    prf_type mapValue = Utilities::encode(dummy.data(), key);
                    ciphers[cipherIndex].push_back(mapValue);
                    fullness[cipherIndex] = fullness[cipherIndex] + 1;
                    cipherIndex++;
                }
            } else
                writeToCuckooHT(index, newsize, pair.first, pair.second, key);
        }
        prf_type K = Utilities::encode(pair.first, key);
        unsigned char cntstr[AES_KEY_SIZE];
        memset(cntstr, 0, AES_KEY_SIZE);
        *(long*) (&(cntstr[AES_KEY_SIZE - 5])) = -1;
        prf_type mapKey = Utilities::generatePRF(cntstr, K.data());
        prf_type valueTmp, totalTmp;
        *(long*) (&(valueTmp[0])) = pair.second.size();
        prf_type mapValue = Utilities::encode(valueTmp.data(), K.data());
        keywordCntCiphers[mapKey] = mapValue;
    }
    prf_type dummy;
    memset(dummy.data(), 0, AES_KEY_SIZE);
    prf_type dummyV = Utilities::encode(dummy.data(), key);
    for (long i = 0; i < numberOfBins[index]; i++) {
        long curSize = ciphers[i].size();
        for (long j = curSize; j < sizeOfEachBin[index]; j++)
            ciphers[i].push_back(dummyV);
    }
    for (long i = 0; i < nB[index]; i++) {
        long curSize = ciphersOne[i].size();
        for (long j = curSize; j < sEB[index]; j++) {
            ciphersOne[i].push_back(dummyV);
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
    totalCommunication += ciphers.size() * sizeof (prf_type)*2 + ciphersOne.size() * sizeof (prf_type);
    server->storeCiphers(index, ciphers, keywordCntCiphers);
    oneChoiceServer->storeCiphers(index, ciphersOne);
}

vector<prf_type> TwoChoicePPWithTunableLocalityClient::search(long index, string keyword, unsigned char* key) {
    double searchPreparation = 0, searchDecryption = 0;
    long flag = 0;
    if (profile)
        Utilities::startTimer(65);
    vector<prf_type> finalRes;
    prf_type hashtoken;
    prf_type token = Utilities::encode(keyword, key);
    long keywordCnt = server->getCounter(index, token);
    vector<prf_type> ciphers;
    ciphers.resize(0);
    vector<prf_type> oneChoiceCiphers;
    long mpl = maxPossibleLen(index);
    if (keywordCnt > mpl) {
        long remaining = keywordCnt - mpl;
        oneChoiceCiphers = oneChoiceServer->search(index, token, remaining);
        if (oneChoiceCiphers.size() > 0) {
            for (auto item : oneChoiceCiphers) {
                prf_type plaintext;
                Utilities::decode(item, plaintext, key);
                if (strcmp((char*) plaintext.data(), keyword.data()) == 0) {
                    finalRes.push_back(plaintext);
                }
            }
        }
        totalCommunication += oneChoiceCiphers.size() * sizeof (prf_type);
    }
    if (keywordCnt > 0) {
        //cout<<index <<" kw:["<<keywordCnt<<"]"<<endl;;
        if (finalRes.size() > 0)
            cout << index << ": retrieved from One choice:" << finalRes.size() << " mpl:" << mpl << "loc:" << LOCALITY << endl;
        long times = ceil((float) keywordCnt / (float) mpl);
        if (times > LOCALITY)
            times = LOCALITY;
        for (long t = 0; t < times; t++) {
            long localpss;
            long newsize = mpl;
            if ((t + 1) * mpl < keywordCnt)
                localpss = mpl;
            else {
                localpss = keywordCnt - t*mpl;
                newsize = pow(2, (long) ceil(log2(localpss)));
            }
            if (newsize > mpl)
                newsize = mpl;
            long flag = 0;
            for (long s = 1; s <= 2; s++) {
                string temp = keyword;
                prf_type hashtoken;
                if (s == 1) {
                    temp = temp.append("1");
                    temp = temp.append(to_string(t));
                    hashtoken = Utilities::encode(temp, key);
                } else if (s == 2) {
                    temp = temp.append("2");
                    temp = temp.append(to_string(t));
                    hashtoken = Utilities::encode(temp, key);
                }
                ciphers = server->search(index, hashtoken, newsize);
                //ciphers = server->getAllData(index);
                //vector<prf_type> localfinalRes;
                //localfinalRes.resize(0);
                //if(flag < localpss)
                //{
                flag = 0;
                for (auto item : ciphers) {
                    if (item != nullKey) {
                        prf_type plaintext;
                        Utilities::decode(item, plaintext, key);
                        if (strcmp((char*) plaintext.data(), keyword.data()) == 0) {
                            //localfinalRes.push_back(plaintext);
                            finalRes.push_back(plaintext);
                            flag++;
                        }
                    }
                }
                //	}
                //	if(localfinalRes.size()>=localpss)
                //	{
                //		for(auto a: localfinalRes)
                //		{
                //			finalRes.push_back(a);
                //		}
                //	}
                totalCommunication += ciphers.size() * sizeof (prf_type);
                //cout <<index<<":localfinal:"<<localfinalRes.size()<<" localpss:"<<localpss<<" ns:"<<newsize<<" ";
                //		cout<<" t:"<< t<<" s:"<<s<<" :"<<finalRes.size()-f1<<" cc:"<<ciphers.size()<<endl;

            }
        }
        //	cout <<"f1:"<<finalRes.size()<<endl;
        if (keywordCnt > 0) {
            long tableNum = (long) ceil(log2(keywordCnt));
            string newkeyword = keyword;
            newkeyword = newkeyword.append("0");
            prf_type hashtoken1 = Utilities::encode(newkeyword, key);
            newkeyword = keyword;
            newkeyword = newkeyword.append("1");
            prf_type hashtoken2 = Utilities::encode(newkeyword, key);
            vector<prf_type> cuckooCiphers;
            cuckooCiphers = server->cuckooSearch(index, tableNum, hashtoken1, hashtoken2); //search HT+cuckoostash
            //vector<prf_type> tempRes;
            if (cuckooCiphers.size() > 0) {
                cout << "cuckoo data size:" << cuckooCiphers.size() << endl;
                for (auto item : cuckooCiphers) {
                    prf_type plaintext;
                    Utilities::decode(item, plaintext, key);
                    if (strcmp((char*) plaintext.data(), keyword.data()) == 0) {
                        finalRes.push_back(plaintext);
                    }
                }
            }
            //vector<prf_type> cuckooCiphers1 = server->getCuckooHT(index); // also fetches the cuckoo stash
            /*vector<prf_type> tempRes1;
            if(cuckooCiphers1.size()>0)
            {
                    for (auto item : cuckooCiphers) 
                    {
                            prf_type plaintext;
                            Utilities::decode(item, plaintext, key);
                            if (strcmp((char*) plaintext.data(), keyword.data()) == 0) 
                            {
                                            tempRes1.push_back(plaintext);
                                            finalRes.push_back(plaintext);
                            }
                    }
            }
            cout <<"cuckoo data size:"<<tempRes.size()<<"|"<<tempRes1.size()<<endl;
             */
            totalCommunication += cuckooCiphers.size() * sizeof (prf_type);
        }
    }
    return finalRes;
}

vector<prf_type> TwoChoicePPWithTunableLocalityClient::getAllData(long index, unsigned char* key) {
    vector<prf_type> finalRes = vector<prf_type>();
    auto ciphers = server->getAllData(index);
    auto oneChoiceCiphers = oneChoiceServer->getAllData(index);
    vector<prf_type> cuckooCiphers = server->getCuckooHT(index); // also fetches the cuckoo stash
    for (auto cipher : ciphers) {
        //if(cipher!=nullKey)
        {
            prf_type plaintext;
            Utilities::decode(cipher, plaintext, key);
            finalRes.push_back(plaintext);
        }
    }
    for (auto cipher : oneChoiceCiphers) {
        //if(cipher!=nullKey)
        {
            prf_type plaintext;
            Utilities::decode(cipher, plaintext, key);
            finalRes.push_back(plaintext);
        }
    }
    if (cuckooCiphers.size() > 0) {
        //cout <<"getAllData:size of cuckoo ciphers:"<<cuckooCiphers.size()<<endl;
        for (auto b : cuckooCiphers) {
            //if(b!=nullKey)
            {
                prf_type plaintext;
                Utilities::decode(b, plaintext, key);
                finalRes.push_back(plaintext);
            }
        }
    }
    totalCommunication += (ciphers.size() + oneChoiceCiphers.size() + cuckooCiphers.size()) * sizeof (prf_type);
    return finalRes;
}

void TwoChoicePPWithTunableLocalityClient::destroy(long index) {
    server->clear(index);
    oneChoiceServer->clear(index);
    exist[index] = false;
    totalCommunication += sizeof (long);
}
