#include "TwoChoiceWithOneChoiceClient.h"
#include<vector>
#include<algorithm>

TwoChoiceWithOneChoiceClient::~TwoChoiceWithOneChoiceClient() {
    delete twoChoiceServer;
    delete oneChoiceServer;
}

TwoChoiceWithOneChoiceClient::TwoChoiceWithOneChoiceClient(long numOfDataSets, bool inMemory, bool overwrite, bool profile) {
    cout << "================= RUNNING SDa+TwoChoice+(One choice when bins overflow)(long) ==================" << endl;
    this->profile = profile;
    twoChoiceServer = new TwoChoiceWithOneChoiceServer(numOfDataSets, inMemory, overwrite, profile);

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

long TwoChoiceWithOneChoiceClient::countTotal(vector<long> fullness, long bin, long size) {
    long full = 0;
    for (long i = 0; i < size; i++)
        full = full + fullness[bin + i];
    return full;
}

bool TwoChoiceWithOneChoiceClient::cmpp(pair<string, vector<prf_type>> &a, pair<string, vector<prf_type>> &b) {
    return (a.second.size() > b.second.size());
}

bool TwoChoiceWithOneChoiceClient::cmpp2(pair<string, vector<tmp_prf_type>> &a, pair<string, vector<tmp_prf_type>> &b) {
    return (a.second.size() > b.second.size());
}

vector<pair<string, vector<prf_type> > > TwoChoiceWithOneChoiceClient::sort(unordered_map<string, vector<prf_type>> &M) {
    vector<pair<string, vector < prf_type > > > A;
    for (auto& it : M) {
        assert(it.first != "");
        A.push_back(it);
    }
    std::sort(A.begin(), A.end(), cmpp);
    return A;
}

vector<pair<string, vector<tmp_prf_type> > > TwoChoiceWithOneChoiceClient::sort2(unordered_map<string, vector<tmp_prf_type>> &M) {
    vector<pair<string, vector < tmp_prf_type > > > A;
    for (auto& it : M) {
        assert(it.first != "");
        A.push_back(it);
    }
    std::sort(A.begin(), A.end(), cmpp2);
    return A;
}

long TwoChoiceWithOneChoiceClient::maxPossibleLen(long index) {
    long N = pow(2, index);
    long bins = numberOfBins[index];
    long max;
    if (N < 4)
        max = bins;
    else {
        float p = (float) ((float) 1 / (float) log2(log2(N)));
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

void TwoChoiceWithOneChoiceClient::writeToStash(long pss, long mpl, vector<prf_type> fileids,
        unsigned char* key, vector<prf_type> &stashCiphers) {
    for (unsigned long i = mpl; i < pss; i++) {
        prf_type value;
        value = Utilities::encode(fileids[i].data(), key);
        stashCiphers.push_back(value);
    }
}

void TwoChoiceWithOneChoiceClient::setup2(long index, unordered_map<string, vector<tmp_prf_type> > pairs, unsigned char* key) {
    exist[index] = true;
    vector<vector < pair < pair<string, long>, tmp_prf_type>>> ciphers;
    vector<vector < pair < pair<string, long>, tmp_prf_type>>> ciphersOne;
    for (long i = 0; i < numberOfBins[index]; i++)
        ciphers.push_back(vector<pair<pair<string, long>, tmp_prf_type> > ());
    for (long i = 0; i < nB[index]; i++)
        ciphersOne.push_back(vector<pair < pair<string, long>, tmp_prf_type >> ());

    map<prf_type, prf_type> keywordCntCiphers;
    vector<long> fullness;
    fullness.resize(0);
    for (long f = 0; f < numberOfBins[index]; f++) {
        fullness.push_back(0);
    }

    long mpl = maxPossibleLen(index);
    vector<pair<string, vector < tmp_prf_type>>> sorted = sort2(pairs);
    for (auto pair : sorted) {
        //        if (pair.first == "ZYXO$o*") {
        //            cout << "here" << endl;
        //        }
        long pss = pair.second.size();
        long newsize = pss;
        long flagOneChoice = 0;
        if (pss > mpl) {
            flagOneChoice = 1;
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
            for (unsigned long i = 0; i < pair.second.size(); i++) {
                std::pair<string, long> mapKey;
                tmp_prf_type mapValue;
                mapKey.first = pair.first;
                mapKey.second = i;
                mapValue = pair.second[i];
                auto p = std::pair< std::pair<string, long>, tmp_prf_type>(mapKey, mapValue);
                //prf_type mapValue = Utilities::encode(pair.second[i].data(), key);
                ciphersOne[cipherIndex].push_back(p);
                cipherIndex++;
                if (cipherIndex == nB[index]) {
                    cipherIndex = 0;
                }
            }
        } else {
            newsize = pow(2, (long) ceil(log2(pss)));
            if (newsize > mpl)
                newsize = mpl;

            string temp = pair.first;
            temp = temp.append("1");
            prf_type K1 = Utilities::encode(temp, key);
            unsigned char cntstr[AES_KEY_SIZE];
            memset(cntstr, 0, AES_KEY_SIZE);
            *(long*) (&(cntstr[AES_KEY_SIZE - 5])) = -1;
            prf_type mapKey1 = Utilities::generatePRF(cntstr, K1.data());
            unsigned char* hash1 = Utilities::sha256((char*) (mapKey1.data()), AES_KEY_SIZE);

            temp = pair.first;
            temp = temp.append("2");
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
                for (unsigned long i = 0; i < pss; i++) {
                    std::pair<string, long> mapKey;
                    tmp_prf_type mapValue;
                    mapKey.first = pair.first;
                    mapKey.second = i;
                    mapValue = pair.second[i];
                    auto p = std::pair< std::pair<string, long>, tmp_prf_type>(mapKey, mapValue);

                    //                    prf_type mapValue = Utilities::encode(pair.second[i].data(), key);
                    //                    assert(fullness[cipherIndex] < sizeOfEachBin[index]);
                    ciphers[cipherIndex].push_back(p);
                    fullness[cipherIndex] = fullness[cipherIndex] + 1;
                    assert(cipherIndex < ciphers.size());
                    cipherIndex++;
                    if (cipherIndex == ciphers.size()) {
                        cipherIndex = 0;
                    }
                }
                for (long i = pss; i < newsize; i++) {
                    tmp_prf_type dummy;
                    memset(dummy.data(), 0, TMP_AES_KEY_SIZE);
                    auto dummypair = std::pair<std::pair<string, long>, tmp_prf_type>(std::pair<string, long>("", -1), dummy);

                    //                    prf_type dummy;
                    //                    prf_type dummyV = Utilities::encode(dummy.data(), key);
                    ciphers[cipherIndex].push_back(dummypair);
                    fullness[cipherIndex] = fullness[cipherIndex] + 1;
                    cipherIndex++;
                    if (cipherIndex == ciphers.size()) {
                        cipherIndex = 0;
                    }
                }
            } else {
                sleep(2);
                cout << "BIN OVERFLOW, ABORT" << endl;
            }
        }
        prf_type K = Utilities::encode(pair.first, key);
        unsigned char cntstr[AES_KEY_SIZE];
        memset(cntstr, 0, AES_KEY_SIZE);
        *(long*) (&(cntstr[AES_KEY_SIZE - 5])) = -1;
        prf_type mapKey = Utilities::generatePRF(cntstr, K.data());
        prf_type valueTmp, totalTmp;
        if (flagOneChoice == 0)
            //*(long*) (&(valueTmp[0])) = newsize;
            *(long*) (&(valueTmp[0])) = pair.second.size();
        else if (flagOneChoice == 1)
            *(long*) (&(valueTmp[0])) = pair.second.size();
        prf_type mapValue = Utilities::encode(valueTmp.data(), K.data());
        keywordCntCiphers[mapKey] = mapValue;
    }
    //    prf_type dummy;
    tmp_prf_type dummy;
    memset(dummy.data(), 0, TMP_AES_KEY_SIZE);
    auto dummypair = pair<std::pair<string, long>, tmp_prf_type>(std::pair<string, long>("", -1), dummy);
    for (long i = 0; i < numberOfBins[index]; i++) //filling up each bin to maximum capacity
    {
        long curSize = ciphers[i].size();
        for (long j = curSize; j < sizeOfEachBin[index]; j++) {
            //            prf_type dummyV = Utilities::encode(dummy.data(), key);
            ciphers[i].push_back(dummypair);
        }
    }
    for (long i = 0; i < nB[index]; i++) {
        long curSize = ciphersOne[i].size();
        for (long j = curSize; j < sEB[index]; j++) {
            //            prf_type dummyV = Utilities::encode(dummy.data(), key);
            ciphersOne[i].push_back(dummypair);
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
    twoChoiceServer->storeKeywordCounters(index, keywordCntCiphers);
    vector<vector<prf_type> > finalCiphers1;
    for (long i = 0; i < ciphers.size(); i++) {
        finalCiphers1.push_back(vector<prf_type>());
        finalCiphers1[i] = convertTmpCiphersToFinalCipher(ciphers[i], key)[0];
        //        vector<vector<prf_type> > finalCiphers = convertTmpCiphersToFinalCipher(ciphers[i], key);
        //        twoChoiceServer->storeCiphers(index, finalCiphers, i == 0);
    }
    twoChoiceServer->storeCiphers(index, finalCiphers1, true);
    vector<vector<prf_type> > finalCiphers2;
    for (long i = 0; i < ciphersOne.size(); i++) {
        finalCiphers2.push_back(vector<prf_type>());
        finalCiphers2[i] = convertTmpCiphersToFinalCipher(ciphersOne[i], key)[0];
        //        vector<vector<prf_type> > finalCiphers = convertTmpCiphersToFinalCipher(ciphersOne[i], key);
        //        oneChoiceServer->storeCiphers(index, finalCiphers, i == 0);
    }
    oneChoiceServer->storeCiphers(index, finalCiphers2, true);
}

void TwoChoiceWithOneChoiceClient::setup(long index, unordered_map<string, vector<prf_type> > pairs, unsigned char* key) {
    exist[index] = true;
    vector<vector < prf_type>> ciphers;
    vector<vector < prf_type>> ciphersOne;
    for (long i = 0; i < numberOfBins[index]; i++)
        ciphers.push_back(vector<prf_type > ());
    for (long i = 0; i < nB[index]; i++)
        ciphersOne.push_back(vector<prf_type> ());

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
        long newsize = pss;
        long flagOneChoice = 0;
        if (pss > mpl) {
            flagOneChoice = 1;
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
            for (unsigned long i = 0; i < pair.second.size(); i++) {
                prf_type mapValue = Utilities::encode(pair.second[i].data(), key);
                ciphersOne[cipherIndex].push_back(mapValue);
                cipherIndex++;
                if (cipherIndex == nB[index]) {
                    cipherIndex = 0;
                }
            }
        } else {
            newsize = pow(2, (long) ceil(log2(pss)));
            if (newsize > mpl)
                newsize = mpl;

            string temp = pair.first;
            temp = temp.append("1");
            prf_type K1 = Utilities::encode(temp, key);
            unsigned char cntstr[AES_KEY_SIZE];
            memset(cntstr, 0, AES_KEY_SIZE);
            *(long*) (&(cntstr[AES_KEY_SIZE - 5])) = -1;
            prf_type mapKey1 = Utilities::generatePRF(cntstr, K1.data());
            unsigned char* hash1 = Utilities::sha256((char*) (mapKey1.data()), AES_KEY_SIZE);

            temp = pair.first;
            temp = temp.append("2");
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
                for (unsigned long i = 0; i < pss; i++) {
                    prf_type mapValue = Utilities::encode(pair.second[i].data(), key);
                    assert(fullness[cipherIndex] < sizeOfEachBin[index]);
                    ciphers[cipherIndex].push_back(mapValue);
                    fullness[cipherIndex] = fullness[cipherIndex] + 1;
                    cipherIndex++;
                    if (cipherIndex == ciphers.size()) {
                        cipherIndex = 0;
                    }
                    assert(cipherIndex < ciphers.size());

                }
                for (long i = pss; i < newsize; i++) {
                    prf_type dummy;
                    memset(dummy.data(), 0, AES_KEY_SIZE);
                    prf_type dummyV = Utilities::encode(dummy.data(), key);
                    ciphers[cipherIndex].push_back(dummyV);
                    fullness[cipherIndex] = fullness[cipherIndex] + 1;
                    cipherIndex++;
                    if (cipherIndex == ciphers.size()) {
                        cipherIndex = 0;
                    }
                }
            } else {
                sleep(2);
                cout << "BIN OVERFLOW, ABORT" << endl;
            }
        }
        prf_type K = Utilities::encode(pair.first, key);
        unsigned char cntstr[AES_KEY_SIZE];
        memset(cntstr, 0, AES_KEY_SIZE);
        *(long*) (&(cntstr[AES_KEY_SIZE - 5])) = -1;
        prf_type mapKey = Utilities::generatePRF(cntstr, K.data());
        prf_type valueTmp, totalTmp;
        if (flagOneChoice == 0)
            *(long*) (&(valueTmp[0])) = newsize;
        else if (flagOneChoice == 1)
            *(long*) (&(valueTmp[0])) = pair.second.size();
        prf_type mapValue = Utilities::encode(valueTmp.data(), K.data());
        keywordCntCiphers[mapKey] = mapValue;
    }
    prf_type dummy;
    memset(dummy.data(), 0, AES_KEY_SIZE);
    //    memset(dummy.data(), 0, AES_KEY_SIZE);
    //    auto dummypair = pair<prf_type, prf_type>(dummy, dummy);
    for (long i = 0; i < numberOfBins[index]; i++) //filling up each bin to maximum capacity
    {
        long curSize = ciphers[i].size();
        for (long j = curSize; j < sizeOfEachBin[index]; j++) {
            prf_type dummyV = Utilities::encode(dummy.data(), key);
            ciphers[i].push_back(dummyV);
        }
    }
    for (long i = 0; i < nB[index]; i++) {
        long curSize = ciphersOne[i].size();
        for (long j = curSize; j < sEB[index]; j++) {
            prf_type dummyV = Utilities::encode(dummy.data(), key);
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
    twoChoiceServer->storeCiphers(index, ciphers, keywordCntCiphers);
    oneChoiceServer->storeCiphers(index, ciphersOne);
}

vector<prf_type> TwoChoiceWithOneChoiceClient::search(long index, string keyword, unsigned char* key) {
    auto previousSearchTime = searchTime;
    oneChoiceServer->storage->cacheTime = 0;
    twoChoiceServer->keywordCounters->cacheTime = 0;
    twoChoiceServer->storage->cacheTime = 0;

    Utilities::startTimer(77);
    Utilities::startTimer(177);
    Utilities::startTimer(10);

    long flag = 0;
    prf_type token = Utilities::encode(keyword, key);
    vector<prf_type> finalRes;

    long keywordCnt = twoChoiceServer->getCounter(index, token);
    auto t = Utilities::stopTimer(10);
    cout << "index:" << index << " getCounter:" << keywordCnt << " time:" << t << endl;
    cout << index << ": getCounter (TWO+ONE Choice) Time:[" << twoChoiceServer->keywordCounters->getCounterTime << "]" << endl;
    searchTime += twoChoiceServer->keywordCounters->getCounterTime;

    auto h = Utilities::stopTimer(77);
    cout << "counter extraction:" << h << endl;

    int mpl = maxPossibleLen(index);
    cout << index << ": Threshold :" << mpl << endl;
    cout << index << ": keywordCount:" << keywordCnt << endl;
    vector<prf_type> ciphers;
    vector<prf_type> oneChoiceCiphers;
    cout << "number of results:" << keywordCnt << " mpl:" << mpl << endl;
    if (keywordCnt <= mpl && keywordCnt > 0) {
        keywordCnt = pow(2, (long) ceil(log2(keywordCnt)));
        Utilities::startTimer(17);
        for (long s = 1; s <= 2; s++) {
            Utilities::startTimer(99);
            ciphers.resize(0);
            string newkeyword = keyword;
            prf_type hashtoken, hashtoken1, hashtoken2;
            if (s == 1) {
                string temp1 = keyword;
                temp1 = temp1.append("1");
                hashtoken1 = Utilities::encode(temp1, key);
                hashtoken = hashtoken1;
                string temp2 = keyword;
                temp2 = temp2.append("2");
                hashtoken2 = Utilities::encode(temp2, key);
            } else if (s == 2) {
                string temp2 = keyword;
                temp2 = temp2.append("2");
                hashtoken2 = Utilities::encode(temp2, key);
                hashtoken = hashtoken2;
            }
            auto prepareHT = Utilities::stopTimer(99);
            searchTime += prepareHT;
            ciphers = twoChoiceServer->search(index, hashtoken, keywordCnt, mpl);
            totalCommunication += ciphers.size() * sizeof (prf_type);
            cout << index << ": s:" << s << " TWO Choice (with one) BYTES READ:{"
                    << ciphers.size() * sizeof (prf_type) << "}" << endl;
            searchTime += twoChoiceServer->storage->searchTime;
            searchTime += twoChoiceServer->serverSearchTime;
            cout << "twoChoiceServer->storage->searchTime:" << twoChoiceServer->storage->searchTime << " twoChoiceServer->serverSearchTime:" << twoChoiceServer->serverSearchTime << " prepareHT:" << prepareHT << endl;
            cout << index << ":s:" << s << " TWO Choice search Time:[" << twoChoiceServer->storage->searchTime +
                    twoChoiceServer->serverSearchTime + prepareHT << "]         <<===========" << endl;
            Utilities::startTimer(99);
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
            if (s == 1 && hashtoken1.data() == hashtoken2.data()) {
                cout << "BREAK" << endl << endl;
                break;
            }
            auto decodeTime = Utilities::stopTimer(99);
            cout << index << ": s:" << s << " TWO Choice(with one) cipher size:" << ciphers.size()
                    << " DECODE+ Time:[" << decodeTime << "]" << endl;
            searchTime += decodeTime;
        }
        auto t9 = Utilities::stopTimer(17);
        cout << "first part time:" << t9 << endl;
    } else if (keywordCnt > mpl) {
        Utilities::startTimer(17);

        oneChoiceCiphers = oneChoiceServer->search(index, token, keywordCnt);
        totalCommunication += oneChoiceCiphers.size() * sizeof (prf_type);
        cout << index << ": ONE Choice (with two) BYTES READ:{" << oneChoiceCiphers.size() * sizeof (prf_type) << "}" << endl;
        cout << index << ": ONE Choice (two with one) Time :[" << oneChoiceServer->storage->searchTime
                + oneChoiceServer->serverSearchTime << "]      <----------" << endl;
        searchTime += oneChoiceServer->storage->searchTime;
        searchTime += oneChoiceServer->serverSearchTime;
        if (oneChoiceCiphers.size() > 0) {
            Utilities::startTimer(100);
            for (auto item : oneChoiceCiphers) {
                prf_type plaintext;
                Utilities::decode(item, plaintext, key);
                if (strcmp((char*) plaintext.data(), keyword.data()) == 0) {
                    finalRes.push_back(plaintext);
                }
            }
            auto decodeTime = Utilities::stopTimer(100);
            cout << index << ": ONE choice(with two) DECODE Time:[" << decodeTime << "]" << endl;
            searchTime = searchTime + decodeTime;
        }
        auto t9 = Utilities::stopTimer(17);
        cout << "second part time:" << t9 << endl;
        //cout<<"THIS TIME SEARCH TIME:"<<searchTime-previousSearchTime<<endl;
    }
    TotalCacheTime += oneChoiceServer->storage->cacheTime;
    TotalCacheTime += twoChoiceServer->keywordCounters->cacheTime;
    TotalCacheTime += twoChoiceServer->storage->cacheTime;
    cout << endl;
    auto zz = Utilities::stopTimer(177);
    cout << "level time:" << zz << endl;
    cout << "level cache time:" << oneChoiceServer->storage->cacheTime + twoChoiceServer->keywordCounters->cacheTime + twoChoiceServer->storage->cacheTime << endl;
    cout << "level pure time:" << zz - (oneChoiceServer->storage->cacheTime + twoChoiceServer->keywordCounters->cacheTime + twoChoiceServer->storage->cacheTime) << endl;

    return finalRes;
}

//vector<prf_type> TwoChoiceWithOneChoiceClient::search(long index, string keyword, unsigned char* key) {
//    oneChoiceServer->storage->cacheTime = 0;
//    twoChoiceServer->keywordCounters->cacheTime = 0;
//    twoChoiceServer->storage->cacheTime = 0;
//    double searchPreparation = 0, searchDecryption = 0;
//    long flag = 0;
//    if (profile)
//        Utilities::startTimer(65);
//    vector<prf_type> finalRes;
//    long keywordCnt = 0;
//    prf_type hashtoken;
//    prf_type token = Utilities::encode(keyword, key);
//    vector<prf_type> ciphers;
//    ciphers.resize(0);
//    vector<prf_type> cuckooCiphers;
//    vector<prf_type> oneChoiceCiphers;
//    for (long s = 1; s <= 2; s++) {
//        string newkeyword = keyword;
//        if (s == 1) {
//            newkeyword = newkeyword.append("1");
//            hashtoken = Utilities::encode(newkeyword, key);
//        } else if (s == 2) {
//            newkeyword = keyword;
//            newkeyword = newkeyword.append("2");
//            hashtoken = Utilities::encode(newkeyword, key);
//        }
//        ciphers = twoChoiceServer->search(index, token, hashtoken, keywordCnt, numberOfBins[index]);
//        if (flag == 0) {
//            for (auto item : ciphers) {
//                prf_type plaintext;
//                Utilities::decode(item, plaintext, key);
//                if (strcmp((char*) plaintext.data(), keyword.data()) == 0) {
//                    finalRes.push_back(plaintext);
//                    flag++;
//                }
//            }
//        }
//        totalCommunication += ciphers.size() * sizeof (prf_type);
//    }
//    if (keywordCnt > maxPossibleLen(index)) {
//        oneChoiceCiphers = oneChoiceServer->search(index, token, keywordCnt);
//        cout << "Searching [" << keyword << "] in One choice bins of index:" << index << endl;
//        if (oneChoiceCiphers.size() > 0) {
//            for (auto item : oneChoiceCiphers) {
//                prf_type plaintext;
//                Utilities::decode(item, plaintext, key);
//                if (strcmp((char*) plaintext.data(), keyword.data()) == 0) {
//                    finalRes.push_back(plaintext);
//                }
//            }
//        }
//        totalCommunication += cuckooCiphers.size() * sizeof (prf_type);
//    }
//
//    long tableNum = (long) ceil(log2(keywordCnt));
//    if (keywordCnt > 0) {
//        string newkeyword = keyword;
//        newkeyword = newkeyword.append("0");
//        prf_type hashtoken1 = Utilities::encode(newkeyword, key);
//        newkeyword = keyword;
//        newkeyword = newkeyword.append("1");
//        prf_type hashtoken2 = Utilities::encode(newkeyword, key);
//        if (cuckooCiphers.size() > 0) {
//            for (auto item : cuckooCiphers) {
//                prf_type plaintext;
//                Utilities::decode(item, plaintext, key);
//                if (strcmp((char*) plaintext.data(), keyword.data()) == 0) {
//                    finalRes.push_back(plaintext);
//                }
//                cout << "cuckoo data:" << plaintext.data() << endl;
//            }
//        }
//        totalCommunication += cuckooCiphers.size() * sizeof (prf_type);
//    }
//    TotalCacheTime += oneChoiceServer->storage->cacheTime;
//    TotalCacheTime += twoChoiceServer->keywordCounters->cacheTime;
//    TotalCacheTime += twoChoiceServer->storage->cacheTime;
//    return finalRes;
//}

vector<prf_type> TwoChoiceWithOneChoiceClient::getAllData(long index, unsigned char* key) {
    vector<prf_type> finalRes = vector<prf_type>();
    auto ciphers = twoChoiceServer->getAllData(index);
    vector<prf_type > oneChoiceCiphers = oneChoiceServer->getAllData(index);
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
    for (auto cipher : oneChoiceCiphers) {
        prf_type plaintext;
        Utilities::decode(cipher, plaintext, key);
        prf_type tmp = plaintext;
        tmp[AES_KEY_SIZE - 1] = 0;
        if (tmp != dummy) {
            finalRes.push_back(plaintext);
        }
    }

    totalCommunication += (ciphers.size() + oneChoiceCiphers.size()) * sizeof (prf_type);
    return finalRes;
}

void TwoChoiceWithOneChoiceClient::destroy(long index) {
    twoChoiceServer->clear(index);
    oneChoiceServer->clear(index);
    exist[index] = false;
    totalCommunication += sizeof (long);
}

vector<vector<prf_type> > TwoChoiceWithOneChoiceClient::convertTmpCiphersToFinalCipher(vector<pair<std::pair<string, long>, tmp_prf_type> > ciphers, unsigned char* key) {
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

void TwoChoiceWithOneChoiceClient::endSetup() {
    twoChoiceServer->endSetup();
    oneChoiceServer->endSetup();
}
