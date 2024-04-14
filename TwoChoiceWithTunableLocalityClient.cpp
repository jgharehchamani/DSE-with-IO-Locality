#include "TwoChoiceWithTunableLocalityClient.h"
#include<vector>
#include<algorithm>

TwoChoiceWithTunableLocalityClient::~TwoChoiceWithTunableLocalityClient() {
    delete server;
    delete oneChoiceServer;
}

TwoChoiceWithTunableLocalityClient::TwoChoiceWithTunableLocalityClient(long numOfDataSets, bool inMemory, bool overwrite, bool profile) {
    cout << "======RUNNING SDa+TwoChoice+(+OneChoice version 2)(long)==TUNABLE LOCALITY:" << LOCALITY << endl;
    this->profile = profile;
    server = new TwoChoiceWithTunableLocalityServer(numOfDataSets, inMemory, overwrite, profile);
    oneChoiceServer = new OneChoiceServer(numOfDataSets, inMemory, overwrite, profile, "OneChoice-", false);
    memset(nullKey.data(), 0, AES_KEY_SIZE);

    for (long i = 0; i < numOfDataSets; i++) {
        exist.push_back(false);
        long curNumberOfBins = i > 3 ? ((long) ceil((float) pow(2, i) / ((log2(log2(pow(2, i))))*(log2(log2(log2(pow(2, i)))))*(log2(log2(log2(pow(2, i)))))))) : 1;
        curNumberOfBins = pow(2, (long) ceil(log2(curNumberOfBins)));
        long curSizeOfEachBin = i > 3 ? SPACE_OVERHEAD * (log2(log2(pow(2, i))))*(log2(log2(log2(pow(2, i)))))*(log2(log2(log2(pow(2, i))))) : SPACE_OVERHEAD * pow(2, i);
        numberOfBins.push_back(curNumberOfBins);
        sizeOfEachBin.push_back(curSizeOfEachBin);
        //    printf("Level:%d number of Bins:%d size of bin:%d\n", i, curNumberOfBins, curSizeOfEachBin);
    }
    for (long i = 0; i < numOfDataSets; i++) {
        long curNumberOfBins = i > 1 ? (long) ceil((float) pow(2, i) / (float) (log2(pow(2, i)) * log2(log2(pow(2, i))))) : 1;
        long curSizeOfEachBin = i > 1 ? 3 * (log2(pow(2, i)) * log2(log2(pow(2, i)))) : pow(2, i);
        nB.push_back(curNumberOfBins);
        sEB.push_back(curSizeOfEachBin);
    }
}

long countTotal(vector<long> fullness, long bin, long size) {
    long full = 0;
    for (long i = 0; i < size; i++)
        full = full + fullness[bin + i];
    return full;
}

bool cmpp(pair<string, vector<prf_type>> &a, pair<string, vector<prf_type>> &b) {
    return (a.second.size() > b.second.size());
}

vector<pair<string, vector<prf_type>>> sort(unordered_map<string, vector<prf_type>> &M) {
    vector<pair<string, vector < prf_type>>> A;
    for (auto& it : M) {
        assert(it.first != "");
        A.push_back(it);
    }
    sort(A.begin(), A.end(), cmpp);
    return A;
}

long TwoChoiceWithTunableLocalityClient::maxPossibleLen(long index) {
    long N = pow(2, index);
    long bins = numberOfBins[index];
    long max;
    if (N < 4)
        max = 1;
    else {
        float p = (float) ((float) 1 / log2(log2(N)));
        float m = (float) (1 - p);
        max = (float) floor(pow(N, m));
    }
    long maxmax = pow(2, (long) ceil(log2(max)));
    long minmin = pow(2, (long) floor(log2(max)));
    if (maxmax <= bins)
        max = maxmax;
    else
        max = minmin;
    return max;
}

bool cmpp2(pair<string, vector<tmp_prf_type>> &a, pair<string, vector<tmp_prf_type>> &b) {
    return (a.second.size() > b.second.size());
}

vector<pair<string, vector<tmp_prf_type>>> sort2(unordered_map<string, vector<tmp_prf_type>> &M) {
    vector<pair<string, vector < tmp_prf_type>>> A;
    for (auto& it : M) {
        assert(it.first != "");
        A.push_back(it);
    }
    sort(A.begin(), A.end(), cmpp2);
    return A;
}

void TwoChoiceWithTunableLocalityClient::setup2(long index, unordered_map<string, vector<tmp_prf_type> > pairs, unsigned char* key) {
    //cout <<"setup2:"<< index<<endl;
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

    vector<pair<string, vector < tmp_prf_type> > > sorted = sort2(pairs);
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
                cout << "BIN OVERFLOW, NOT STORING THIS LIST" << endl;
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

vector<vector<prf_type> > TwoChoiceWithTunableLocalityClient::convertTmpCiphersToFinalCipher(vector<pair<std::pair<string, long>, tmp_prf_type> > ciphers, unsigned char* key) {
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

void TwoChoiceWithTunableLocalityClient::setup(long index, unordered_map<string, vector<prf_type> > pairs, unsigned char* key) {
    exist[index] = true;
    cout << "vanilla setup" << endl;
    //vector<vector<pair<prf_type, prf_type>>> ciphers;
    //vector<vector<pair<prf_type, prf_type>>> ciphersOne;
    vector<vector < prf_type>> ciphers;
    vector<vector < prf_type>> ciphersOne;
    for (long i = 0; i < numberOfBins[index]; i++)
        ciphers.push_back(vector<prf_type>());
    for (long i = 0; i < nB[index]; i++)
        ciphersOne.push_back(vector<prf_type>());

    map<prf_type, prf_type> keywordCntCiphers;
    vector<long> fullness;
    fullness.resize(0);
    for (long f = 0; f < numberOfBins[index]; f++) {
        fullness.push_back(0);
    }

    long mpl = maxPossibleLen(index);

    vector<pair<string, vector < prf_type>>> sorted = sort(pairs);
    for (auto pair : sorted) {
        long pss = pair.second.size();
        if (pss > LOCALITY * mpl) {
            //cout <<index<<":ONE CHOICE pss:"<<pss<<" mpl:"<<mpl<<" #bins:"<<numberOfBins[index]<<endl;
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
            int localpss = mpl;
            int newsize = mpl;
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
            //cout <<index<<"key:"<<pair.first<<" mpl:"<<mpl<<" localpss:"<<localpss<<" ns:"<<newsize<<" t:"<<t<<"ci:"<<cipherIndex<< "t:"<<t<<" #bin:"<<numberOfBins[index]<<endl;
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
            } else {
                cout << fullness[cipherIndex] << "/" << sizeOfEachBin[index] << " BIN OVERFLOW,index:" << index << endl;
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

vector<prf_type> TwoChoiceWithTunableLocalityClient::search(long index, string keyword, unsigned char* key) {
    //double searchPreparation = 0, searchDecryption = 0;
    server->storage->cacheTime = 0;
    server->keywordCounters->cacheTime = 0;
    oneChoiceServer->storage->cacheTime = 0;
    vector<prf_type> finalRes;
    prf_type hashtoken;
    prf_type token = Utilities::encode(keyword, key);
    long keywordCnt = server->getCounter(index, token);
    searchTime += server->keywordCounters->getCounterTime;
    cout << index << ": getCounter = " << keywordCnt << " time:[" << server->keywordCounters->getCounterTime << "]" << endl;

    vector<prf_type> ciphers;
    ciphers.resize(0);
    vector<prf_type> oneChoiceCiphers;
    long mpl = maxPossibleLen(index);
    cout << index << ": Threshold :" << mpl << endl;
    assert(mpl <= numberOfBins[index]);
    cout << index << ": keywordCount:" << keywordCnt << endl;

    if (keywordCnt > LOCALITY * mpl) {
        long newCounter = (keywordCnt - LOCALITY * mpl);
        oneChoiceCiphers = oneChoiceServer->search(index, token, newCounter);
        totalCommunication += oneChoiceCiphers.size() * sizeof (prf_type);
        searchTime += oneChoiceServer->storage->searchTime;
        searchTime += oneChoiceServer->serverSearchTime;
        cout << index << ": ONE Choice (Tunable) BYTES READ:{"
                << oneChoiceCiphers.size() * sizeof (prf_type) << "}" << endl;
        cout << index << ": ONEChoice time (Tunable):[" << oneChoiceServer->storage->searchTime +
                oneChoiceServer->serverSearchTime << "]           <---------" << endl;
        if (oneChoiceCiphers.size() > 0) {
            Utilities::startTimer(40);
            for (auto item : oneChoiceCiphers) {
                prf_type plaintext;
                Utilities::decode(item, plaintext, key);
                if (strcmp((char*) plaintext.data(), keyword.data()) == 0) {
                    finalRes.push_back(plaintext);
                }
            }
            auto t3 = Utilities::stopTimer(40);
            cout << "One Choice (with Tunable) cipher size:" << oneChoiceCiphers.size()
                    << " cipher decode time:[" << t3 << "]" << endl;
            cout << "newCounter=" << newCounter << endl;
            searchTime += t3;
        }
    }
    if (keywordCnt > 0) {
        long prepareHT = 0;
        long times = ceil((float) keywordCnt / (float) mpl);
        if (times > LOCALITY)
            times = LOCALITY;
        for (long t = 0; t < times; t++) {
            Utilities::startTimer(116);
            int localpss;
            int newsize = mpl;
            if ((t + 1) * mpl < keywordCnt)
                localpss = mpl;
            else {
                localpss = keywordCnt - t*mpl;
                newsize = pow(2, (long) ceil(log2(localpss)));
            }
            if (newsize > mpl)
                newsize = mpl;
            long flag = 0;
            prepareHT += Utilities::stopTimer(116);
            if (newsize > 0) {
                for (long s = 1; s <= 2; s++) {
                    Utilities::startTimer(117);
                    prf_type hashtoken, hashtoken1, hashtoken2;
                    if (s == 1) {
                        string temp1 = keyword;
                        temp1 = temp1.append("1");
                        temp1 = temp1.append(to_string(t));
                        hashtoken1 = Utilities::encode(temp1, key);
                        hashtoken = hashtoken1;
                    } else if (s == 2) {
                        string temp2 = keyword;
                        temp2 = temp2.append("2");
                        temp2 = temp2.append(to_string(t));
                        hashtoken2 = Utilities::encode(temp2, key);
                        hashtoken = hashtoken2;
                    }
                    prepareHT += Utilities::stopTimer(117);
                    ciphers = server->search(index, hashtoken, newsize);
                    totalCommunication += ciphers.size() * sizeof (prf_type);
                    cout << index << ": s:" << s << " L:" << t + 1 << " TUNABLE TWO Choice (with one) BYTES READ:{"
                            << ciphers.size() * sizeof (prf_type) << "}" << endl;
                    searchTime += server->storage->searchTime;
                    searchTime += server->serverSearchTime;
                    cout << index << ":s:" << s << " L:" << t + 1 << " TUNABLE TWO Choice search Time:[" << server->storage->searchTime
                            + server->serverSearchTime + prepareHT << "]         <<=========" << endl;
                    Utilities::startTimer(40);
                    if (flag == 0) {
                        for (auto item : ciphers) {
                            prf_type plaintext;
                            Utilities::decode(item, plaintext, key);
                            if (strcmp((char*) plaintext.data(), keyword.data()) == 0) {
                                finalRes.push_back(plaintext);
                                flag++;
                            }
                        }
                    }
                    if (hashtoken1.data() == hashtoken2.data())
                        break;
                    auto t3 = Utilities::stopTimer(40);
                    cout << index << ":s" << s << " Two Choice cipher size:" << ciphers.size() << " decode time:[" << t3 << "]" << endl;
                    assert(sizeOfEachBin[index] * newsize == ciphers.size());
                    searchTime += t3;
                }
            }
        }
    }
    TotalCacheTime += oneChoiceServer->storage->cacheTime;
    TotalCacheTime += server->keywordCounters->cacheTime;
    TotalCacheTime += server->storage->cacheTime;
    cout << endl;
    return finalRes;
}

vector<prf_type> TwoChoiceWithTunableLocalityClient::getAllData(long index, unsigned char* key) {
    vector<prf_type> finalRes = vector<prf_type>();
    auto ciphers = server->getAllData(index);
    auto oneChoiceCiphers = oneChoiceServer->getAllData(index);

    for (auto cipher : ciphers) {
        prf_type plaintext;
        Utilities::decode(cipher, plaintext, key);
        finalRes.push_back(plaintext);
    }
    for (auto cipher : oneChoiceCiphers) {
        prf_type plaintext;
        Utilities::decode(cipher, plaintext, key);
        finalRes.push_back(plaintext);
    }
    totalCommunication += (ciphers.size() + oneChoiceCiphers.size()) * sizeof (prf_type);
    return finalRes;
}

void TwoChoiceWithTunableLocalityClient::destroy(long index) {
    server->clear(index);
    oneChoiceServer->clear(index);
    exist[index] = false;
    totalCommunication += sizeof (long);
}
