#include "TwoChoicePPwithStashClient.h"
#include<vector>
#include<algorithm>

TwoChoicePPwithStashClient::~TwoChoicePPwithStashClient() {
    delete server;
}

TwoChoicePPwithStashClient::TwoChoicePPwithStashClient(long numOfDataSets, bool inMemory, bool overwrite, bool profile) {
    cout << "===================RUNNING SDa+TwoChoicePLUSPLUS with Stash==================" << endl;

    this->profile = profile;
    server = new TwoChoicePPwithStashServer(numOfDataSets, inMemory, overwrite, profile);
    memset(nullKey.data(), 0, AES_KEY_SIZE);
    for (long i = 0; i < numOfDataSets; i++) //why not <=
    {
        exist.push_back(false);
        long curNumberOfBins = i > 3 ? ((long) ceil((float) pow(2, i) / (log2(log2(log2(pow(2, i))))))) : 1;
        curNumberOfBins = pow(2, (long) ceil(log2(curNumberOfBins)));
        long curSizeOfEachBin = i > 3 ? SPACE_OVERHEAD * (log2(log2(log2(pow(2, i)))))
                : SPACE_OVERHEAD * pow(2, i);
        numberOfBins.push_back(curNumberOfBins);
        sizeOfEachBin.push_back(curSizeOfEachBin);
    }
}

long TwoChoicePPwithStashClient::countTotal(map<long, long> fullness, long bin, long size) {
    long full = 0;
    for (long i = 0; i < size; i++)
        full = full + fullness[bin + i];
    return full;
}

long TwoChoicePPwithStashClient::countTotal(vector<long> fullness, long bin, long size) {
    long full = 0;
    for (long i = 0; i < size; i++)
        full = full + fullness[bin + i];
    return full;
}

bool TwoChoicePPwithStashClient::cmpp(pair<string, vector<prf_type>> &a, pair<string, vector<prf_type>> &b) {
    //cout <<"cmp:["<<a.second.size()<< " "<<b.second.size()<<"]["<<(a.second.size() > b.second.size()) <<"]"<<endl;
    return (a.second.size() > b.second.size());
}

bool TwoChoicePPwithStashClient::cmpp2(pair<string, vector<tmp_prf_type>> &a, pair<string, vector<tmp_prf_type>> &b) {
    //cout <<"cmp:["<<a.second.size()<< " "<<b.second.size()<<"]["<<(a.second.size() > b.second.size()) <<"]"<<endl;
    return (a.second.size() > b.second.size());
}

vector<pair<string, vector<prf_type>>> TwoChoicePPwithStashClient::sort(unordered_map<string, vector<prf_type>> &M) {
    vector<pair<string, vector < prf_type>>> A;
    for (auto& it : M) {
        assert(it.first != "");
        A.push_back(it);
    }
    std::sort(A.begin(), A.end(), cmpp);
    return A;
}

vector<pair<string, vector<tmp_prf_type>>> TwoChoicePPwithStashClient::sort2(unordered_map<string, vector<tmp_prf_type>> &M) {
    vector<pair<string, vector < tmp_prf_type>>> A;
    for (auto& it : M) {
        assert(it.first != "");
        A.push_back(it);
    }
    std::sort(A.begin(), A.end(), cmpp2);
    return A;
}

//long maxPossibleLen(long N, long bins, long index) {
//    long max;
//    if (N < 4)
//        max = bins;
//    else {
//        float p = (float) ((float) 1 / log2(log2(N)));
//        float m = (float) (1 - p);
//        max = (float) floor(pow(N, m));
//    }
//    long maxmax = pow(2, (long) ceil(log2(max)));
//    long minmin = pow(2, (long) floor(log2(max)));
//    if (maxmax <= bins)
//        max = maxmax;
//    else
//        max = minmin;
//    return max;
//}

void TwoChoicePPwithStashClient::writeToStash2(string keyword, long pss, long mpl, vector<tmp_prf_type> fileids, unsigned char* key, vector<prf_type> &stashCiphers) {
    for (unsigned long i = mpl; i < pss; i++) {
        tmp_prf_type value = fileids[i];
        long ind = *(long*) (&(value.data()[TMP_AES_KEY_SIZE - 5]));
        byte op = *(byte*) (&(value.data()[TMP_AES_KEY_SIZE - 6]));

        prf_type newvalue;
        std::fill(newvalue.begin(), newvalue.end(), 0);
        std::copy(keyword.begin(), keyword.end(), newvalue.begin());
        *(long*) (&(newvalue.data()[AES_KEY_SIZE - 5])) = ind;
        newvalue.data()[AES_KEY_SIZE - 6] = op;

        prf_type mapValue;
        mapValue = Utilities::encode(newvalue.data(), key);

        stashCiphers.push_back(mapValue);
    }
}

void TwoChoicePPwithStashClient::writeToStash(long pss, long mpl, vector<prf_type> fileids, unsigned char* key, vector<prf_type> &stashCiphers) {
    for (unsigned long i = mpl; i < pss; i++) {
        prf_type value;
        value = Utilities::encode(fileids[i].data(), key);
        stashCiphers.push_back(value);
    }
}

void TwoChoicePPwithStashClient::writeToCuckooStash(vector<prf_type> fileids, long cnt,
        long index, long tableNum, unsigned char* key) {
    long entrySize = pow(2, tableNum);
    vector<prf_type> ctCiphers;
    for (auto c : fileids) {
        prf_type value;
        value = Utilities::encode(c.data(), key);
        ctCiphers.push_back(value);
    }
    if (fileids.size() < entrySize) {
        prf_type dummy;
        memset(dummy.data(), 0, AES_KEY_SIZE);
        for (long i = fileids.size(); i < entrySize; i++)
            ctCiphers.push_back(dummy);
    }
    server->insertCuckooStash(index, tableNum, ctCiphers);
}

void TwoChoicePPwithStashClient::place(string keyword, vector<prf_type> fileids, long cuckooID, long cnt, long index, long tableNum, unsigned char* key) {
    if (cnt == (pow(2, index - tableNum)) + 1) {// check this condition
        cout << "Cuckoo overflow: write in cuckooStash:" << " index:" << index << " tableNum:" << tableNum << endl;
        writeToCuckooStash(fileids, cnt, index, tableNum, key);
        return;
    }
    long entrySize = pow(2, tableNum);
    long entryNum = pow(2, (index - tableNum));

    string temp = keyword;
    unsigned char cntstr[AES_KEY_SIZE];
    if (cuckooID == 0) {
        temp = temp.append("0");
    } else {
        temp = temp.append("1");
    }

    prf_type K = Utilities::encode(temp, key);
    memset(cntstr, 0, AES_KEY_SIZE);
    *(long*) (&(cntstr[AES_KEY_SIZE - 5])) = -1;
    prf_type mapKey = Utilities::generatePRF(cntstr, K.data());
    unsigned char* h = Utilities::sha256((char*) (mapKey.data()), AES_KEY_SIZE);
    long hash = (unsigned long) (*((long*) h)) % entryNum;

    prf_type encKeyw = Utilities::encode(keyword, key);
    pair<prf_type, vector < prf_type>> dis = server->insertCuckooHT(index, tableNum, cuckooID, hash, encKeyw, fileids);
    if (dis.first != nullKey) {
        string keyw = Utilities::decode(dis.first, key);
        place(keyw, dis.second, cnt + 1, ((cuckooID + 1) % 2), index, tableNum, key);
    }
}

void TwoChoicePPwithStashClient::writeToCuckooHT(long index, long size, string keyword, vector<prf_type> fileids, unsigned char* key) {
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
        for (long i = fileids.size(); i < size; i++) {
            ctCiphers.push_back(dummy);
        }
    }
    place(keyword, ctCiphers, 0, 0, index, tableNum, key);
}

void TwoChoicePPwithStashClient::writeToCuckooHT2(long index, long size, string keyword, vector<tmp_prf_type> fileids, unsigned char* key) {
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
        *(long*) (&(newvalue.data()[AES_KEY_SIZE - 5])) = ind;
        newvalue.data()[AES_KEY_SIZE - 6] = op;

        prf_type mapValue;
        mapValue = Utilities::encode(newvalue.data(), key);

        ctCiphers.push_back(mapValue);
    }
    ctCiphers.resize(size);
    if (fileids.size() < size) {
        for (long i = fileids.size(); i < size; i++) {
            prf_type dummy;
            prf_type dummyV = Utilities::encode(dummy.data(), key);
            ;
            ctCiphers.push_back(dummyV);
        }
    }
    place(keyword, ctCiphers, 0, 0, index, tableNum, key);
}

void TwoChoicePPwithStashClient::setup2(long index, unordered_map<string, vector<tmp_prf_type> > pairs, unsigned char* key) {
    exist[index] = true;
    vector<vector<pair<pair<string, long>, tmp_prf_type> > > ciphers;
    for (long i = 0; i < numberOfBins[index]; i++) {
        ciphers.push_back(vector<pair<pair<string, long>, tmp_prf_type> >());
    }
    //    vector<vector<prf_type> > ciphers;
    //    for (long i = 0; i < numberOfBins[index]; i++) {
    //        ciphers.push_back(vector<prf_type>());
    //    }

    vector<prf_type> stashCiphers; //for horizontal overflow
    map<prf_type, prf_type> keywordCntCiphers;
    vector<long> fullness2;
    for (long b = 0; b < numberOfBins[index]; b++) {
        fullness2.push_back(0);
    }
    map<long, long> fullness;
    for (long b = 0; b < numberOfBins[index]; b++) {
        fullness[b] = 0;
    }

    vector<pair<string, vector < tmp_prf_type> > > sorted = sort2(pairs);
    long mpl = maxPossibleLen(index);
    //    long mpl = maxPossibleLen((pow(2, index)), numberOfBins[index], index);
    //    mpl = numberOfBins[index]; // for now

    for (auto pair : sorted) {
        //                printf("keyword:%s in index:%d size:%d\n", pair.first.c_str(), index, pair.second.size());
        long pss = pair.second.size();
        long newsize = pow(2, (long) ceil(log2(pss)));
        if (pss > mpl) {
            writeToStash2(pair.first, pss, mpl, pair.second, key, stashCiphers);
            pss = mpl;
            newsize = mpl;
        }
        if (newsize > mpl) {
            newsize = mpl;
        }
        //        printf("keyword:%s storage bound:%d newSize:%d keyword size:%d\n",pair.first.c_str(),pss,newsize,pair.second.size());

        prf_type K = Utilities::encode(pair.first, key);
        unsigned char cntstr[AES_KEY_SIZE];
        memset(cntstr, 0, AES_KEY_SIZE);
        *(long*) (&(cntstr[AES_KEY_SIZE - 5])) = -1;
        prf_type mapKey = Utilities::generatePRF(cntstr, K.data());
        prf_type valueTmp, totalTmp;
        *(long*) (&(valueTmp[0])) = newsize;
        //*(long*) (&(valueTmp[0])) = pair.second.size(); 
        prf_type mapValue = Utilities::encode(valueTmp.data(), K.data());
        keywordCntCiphers[mapKey] = mapValue;

        string temp = pair.first;
        temp = temp.append("1");
        prf_type K1 = Utilities::encode(temp, key);
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

        //        long totalItems1 = countTotal(fullness, pos1*newsize, newsize);
        long totalItems1 = countTotal(fullness2, pos1*newsize, newsize);
        long totalItems2 = countTotal(fullness2, pos2*newsize, newsize);
        //        long totalItems2 = countTotal(fullness, pos2*newsize, newsize);
        long cipherIndex;
        if (totalItems1 > totalItems2) {
            cipherIndex = pos2 * newsize;
        } else {
            cipherIndex = pos1*newsize;
        }
        if (fullness2[cipherIndex] < sizeOfEachBin[index]) {
            for (unsigned long i = 0; i < pss; i++) {
                std::pair<string, long> mapKey;
                tmp_prf_type mapValue;
                mapKey.first = pair.first;
                mapKey.second = i;
                mapValue = pair.second[i];
                auto p = std::pair< std::pair<string, long>, tmp_prf_type>(mapKey, mapValue);
                ciphers[cipherIndex].push_back(p);




                //                tmp_prf_type value = pair.second[i];
                //                long ind = *(long*) (&(value.data()[TMP_AES_KEY_SIZE - 5]));
                //                byte op = *(byte*) (&(value.data()[TMP_AES_KEY_SIZE - 6]));
                //
                //                prf_type newvalue;
                //                std::fill(newvalue.begin(), newvalue.end(), 0);
                //                std::copy(pair.first.begin(), pair.first.end(), newvalue.begin());
                //                *(long*) (&(newvalue.data()[AES_KEY_SIZE - 5])) = ind;
                //                newvalue.data()[AES_KEY_SIZE - 6] = op;
                //
                //                prf_type mapValue;
                //                mapValue = Utilities::encode(newvalue.data(), key);

                //                ciphers[cipherIndex].push_back(mapValue);
                //                if (fullness.find(cipherIndex) == fullness.end()) {
                //                    fullness[cipherIndex] = 1;
                //                } else {
                fullness2[cipherIndex] = fullness2[cipherIndex] + 1;
                //                }
                cipherIndex++;
            }
            tmp_prf_type dummy;
            memset(dummy.data(), 0, TMP_AES_KEY_SIZE);
            auto dummypair = std::pair<std::pair<string, long>, tmp_prf_type>(std::pair<string, long>("", -1), dummy);
            for (long i = pss; i < newsize; i++) {
                //                prf_type dummy;
                //                prf_type dummyV = Utilities::encode(dummy.data(), key);
                //                memset(dummy.data(), 0, AES_KEY_SIZE);
                //                auto dummypair = std::pair<prf_type, prf_type>(dummy, dummy);
                ciphers[cipherIndex].push_back(dummypair);
                fullness2[cipherIndex] = fullness2[cipherIndex] + 1;
                cipherIndex++;
            }
        } else {
            writeToCuckooHT2(index, newsize, pair.first, pair.second, key);
        }
    }
    tmp_prf_type dummy;
    memset(dummy.data(), 0, TMP_AES_KEY_SIZE);
    auto dummypair = pair<std::pair<string, long>, tmp_prf_type>(std::pair<string, long>("", -1), dummy);
    for (long i = 0; i < numberOfBins[index]; i++) //filling up each bin to maximum capacity
    {
        long curSize = ciphers[i].size();
        for (long j = curSize; j < sizeOfEachBin[index]; j++) {
            //            prf_type dummy;
            //    memset(dummy.data(), 0, AES_KEY_SIZE);
            //            prf_type dummyV = Utilities::encode(dummy.data(), key);
            ciphers[i].push_back(dummypair);
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
    totalCommunication += ciphers.size() * sizeof (prf_type)*2 + stashCiphers.size() * sizeof (prf_type);
    printf("stash cipher size of level:%d is %d\n", index, stashCiphers.size());
    server->storeKeywordAndStashCounters(index, stashCiphers, keywordCntCiphers);
    for (long i = 0; i < ciphers.size(); i++) {
        vector<vector<prf_type> > finalCiphers = convertTmpCiphersToFinalCipher(ciphers[i], key);
        server->storeCiphers(index, finalCiphers, i == 0);
    }

    //    server->storeCiphers(index, ciphers, stashCiphers, keywordCntCiphers);
}

void TwoChoicePPwithStashClient::setup(long index, unordered_map<string, vector<prf_type> > pairs, unsigned char* key) {
    exist[index] = true;
    vector<vector<prf_type> > ciphers;
    for (long i = 0; i < numberOfBins[index]; i++) {
        ciphers.push_back(vector<prf_type>());
    }

    vector<prf_type> stashCiphers; //for horizontal overflow
    map<prf_type, prf_type> keywordCntCiphers;
    map<long, long> fullness;

    vector<pair<string, vector < prf_type> > > sorted = sort(pairs);
    long mpl = maxPossibleLen(index);
    //    long mpl = maxPossibleLen((pow(2, index)), numberOfBins[index], index);
    //    mpl = numberOfBins[index]; // for now

    for (auto pair : sorted) {
        long pss = pair.second.size();
        long newsize = pow(2, (long) ceil(log2(pss)));
        if (pss > mpl) {
            writeToStash(pss, mpl, pair.second, key, stashCiphers);
            pss = mpl;
            newsize = mpl;
        }
        if (newsize > mpl)
            newsize = mpl;

        prf_type K = Utilities::encode(pair.first, key);
        unsigned char cntstr[AES_KEY_SIZE];
        memset(cntstr, 0, AES_KEY_SIZE);
        *(long*) (&(cntstr[AES_KEY_SIZE - 5])) = -1;
        prf_type mapKey = Utilities::generatePRF(cntstr, K.data());
        prf_type valueTmp, totalTmp;
        *(long*) (&(valueTmp[0])) = newsize;
        //*(long*) (&(valueTmp[0])) = pair.second.size(); 
        prf_type mapValue = Utilities::encode(valueTmp.data(), K.data());
        keywordCntCiphers[mapKey] = mapValue;

        string temp = pair.first;
        temp = temp.append("1");
        prf_type K1 = Utilities::encode(temp, key);
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
        if (totalItems1 > totalItems2) {
            cipherIndex = pos2 * newsize;
        } else {
            cipherIndex = pos1*newsize;
        }
        if (fullness[cipherIndex] < sizeOfEachBin[index]) {
            for (unsigned long i = 0; i < pss; i++) {
                //				unsigned char cntstr[AES_KEY_SIZE];
                //				memset(cntstr, 0, AES_KEY_SIZE);
                //				*(long*) (&(cntstr[AES_KEY_SIZE - 5])) = i;
                //				prf_type mapKey = Utilities::generatePRF(cntstr, K.data());
                prf_type mapValue = Utilities::encode(pair.second[i].data(), key);
                //				auto p = std::pair<prf_type, prf_type>(mapKey, mapValue);
                ciphers[cipherIndex].push_back(mapValue);
                if (fullness.find(cipherIndex) == fullness.end()) {
                    fullness[cipherIndex] = 1;
                } else {
                    fullness[cipherIndex] = fullness[cipherIndex] + 1;
                }
                cipherIndex++;
            }
            for (long i = pss; i < newsize; i++) {
                prf_type dummy;
                prf_type dummyV = Utilities::encode(dummy.data(), key);
                //                memset(dummy.data(), 0, AES_KEY_SIZE);
                //                auto dummypair = std::pair<prf_type, prf_type>(dummy, dummy);
                ciphers[cipherIndex].push_back(dummyV);
                fullness[cipherIndex] = fullness[cipherIndex] + 1;
                cipherIndex++;
            }
        } else {
            writeToCuckooHT(index, newsize, pair.first, pair.second, key);
        }
    }
    for (long i = 0; i < numberOfBins[index]; i++) //filling up each bin to maximum capacity
    {
        long curSize = ciphers[i].size();
        for (long j = curSize; j < sizeOfEachBin[index]; j++) {
            prf_type dummy;
            //    memset(dummy.data(), 0, AES_KEY_SIZE);
            prf_type dummyV = Utilities::encode(dummy.data(), key);
            ciphers[i].push_back(dummyV);
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
    totalCommunication += ciphers.size() * sizeof (prf_type)*2 + stashCiphers.size() * sizeof (prf_type);
    server->storeCiphers(index, ciphers, stashCiphers, keywordCntCiphers);
}

vector<prf_type> TwoChoicePPwithStashClient::search(long index, string keyword, unsigned char* key) {
    double searchPreparation = 0, searchDecryption = 0;
    server->storage->cacheTime = 0;
    server->keywordCounters->cacheTime = 0;
    long flag = 0;
    if (profile)
        Utilities::startTimer(65);
    vector<prf_type> finalRes;
    long keywordCnt = 0;
    prf_type hashtoken;
    prf_type token = Utilities::encode(keyword, key);
    vector<prf_type> ciphers;
    vector<prf_type> cuckooCiphers;
    vector<prf_type> stashCiphers;
    for (long s = 1; s <= 2; s++) {
        string newkeyword = keyword;
        if (s == 1) {
            newkeyword = newkeyword.append("1");
            hashtoken = Utilities::encode(newkeyword, key);
        } else if (s == 2) {
            newkeyword = keyword;
            newkeyword = newkeyword.append("2");
            hashtoken = Utilities::encode(newkeyword, key);
        }
        ciphers = server->search(index, token, hashtoken, keywordCnt, numberOfBins[index]);
        stashCiphers = server->getStash(index);
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
        if (flag != 0)//found in one superBin will imply NOT found in the other
        {
            for (auto item : stashCiphers) {
                prf_type plaintext;
                Utilities::decode(item, plaintext, key);
                if (strcmp((char*) plaintext.data(), keyword.data()) == 0) {
                    finalRes.push_back(plaintext);
                    flag++;
                }
            }
        }
        totalCommunication += ciphers.size() * sizeof (prf_type);
    }
    long tableNum = (long) ceil(log2(keywordCnt));

    if (keywordCnt > 0) {
        string newkeyword = keyword;
        newkeyword = newkeyword.append("0");
        prf_type hashtoken1 = Utilities::encode(newkeyword, key);
        newkeyword = keyword;
        newkeyword = newkeyword.append("1");
        prf_type hashtoken2 = Utilities::encode(newkeyword, key);
        cuckooCiphers = server->cuckooSearch(index, tableNum, hashtoken1, hashtoken2); // also searche suckoo stash
        if (cuckooCiphers.size() > 0) {
            for (auto item : cuckooCiphers) {
                prf_type plaintext;
                Utilities::decode(item, plaintext, key);
                if (strcmp((char*) plaintext.data(), keyword.data()) == 0) {
                    finalRes.push_back(plaintext);
                }
                cout << "cuckoo data:" << plaintext.data() << endl;
            }
        }
        totalCommunication += cuckooCiphers.size() * sizeof (prf_type);
    }
    TotalCacheTime += server->storage->cacheTime;
    TotalCacheTime += server->keywordCounters->cacheTime;
    return finalRes;
}

vector<prf_type> TwoChoicePPwithStashClient::getAllData(long index, unsigned char* key) {
    vector<prf_type> finalRes = vector<prf_type>();
    auto ciphers = server->getAllData(index);
    vector<prf_type> stashCiphers = server->getStash(index);
    vector<prf_type> cuckooCiphers = server->getCuckooHT(index); // also fetches the cuckoo stash

    for (auto cipher : ciphers) {
        prf_type plaintext;
        Utilities::decode(cipher, plaintext, key);
        finalRes.push_back(plaintext);
    }
    if (stashCiphers.size() > 0) {
        //cout <<"size of stash ciphers:"<<stashCiphers.size()<<endl;
        for (auto b : stashCiphers) {
            prf_type plaintext;
            Utilities::decode(b, plaintext, key);
            //cout <<"{"<<plaintext.data()<<"}"<<endl;
            finalRes.push_back(plaintext);
        }
    }
    if (cuckooCiphers.size() > 0) {
        cout << "getAllData:size of cuckoo ciphers:" << cuckooCiphers.size() << endl;
        for (auto b : cuckooCiphers) {
            prf_type plaintext;
            Utilities::decode(b, plaintext, key);
            finalRes.push_back(plaintext);
        }
    }
    totalCommunication += (ciphers.size() + stashCiphers.size() + cuckooCiphers.size()) * sizeof (prf_type);
    return finalRes;
}

void TwoChoicePPwithStashClient::destroy(long index) {
    server->clear(index);
    exist[index] = false;
    totalCommunication += sizeof (long);
}

vector<vector<prf_type> > TwoChoicePPwithStashClient::convertTmpCiphersToFinalCipher(vector<pair<std::pair<string, long>, tmp_prf_type> > ciphers, unsigned char* key) {
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

long TwoChoicePPwithStashClient::maxPossibleLen(long index) {
    long N = pow(2, index);
    if (N == 1) return 1;
    long l = (float) (log2(N) * log2(N) * log2(N));
    long max = ceil((float) N / (float) l);
    if (max > numberOfBins[index]) {
        max = numberOfBins[index];
    }
    return max;
}
