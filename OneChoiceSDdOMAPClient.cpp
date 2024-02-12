#include "OneChoiceSDdOMAPClient.h"
#include<string.h>
#include<map>
#include<vector>
#include<algorithm>

using namespace::std;

OneChoiceSDdOMAPClient::~OneChoiceSDdOMAPClient() {
    for (int i = 0; i < 4; i++) {
        delete server[i];
    }
}

OneChoiceSDdOMAPClient::OneChoiceSDdOMAPClient(int N, bool inMemory, bool overwrite, bool profile) {
    this->profile = profile;
    int l = floor(log2(N)) + 1;
    memset(nullKey.data(), 0, AES_KEY_SIZE);
    this->numOfIndices = l;
    server = new OneChoiceServer*[4];
    for (int i = 0; i < 4; i++) {
        //        server[i] = new OneChoiceServer(numOfIndices, inMemory, overwrite, profile);
        server[i] = new OneChoiceServer(numOfIndices, inMemory, overwrite, profile, "OneChoice-" + to_string(i) + "-");
    }
    bitonic = new Bitonic();
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

    for (int i = 0; i < numOfIndices; i++) {
        setupFiles[i].resize(4);
        exist[0].push_back(false);
        exist[1].push_back(false);
        exist[2].push_back(false);

        numNEW.push_back(1); //updateCount
        NEWsize.push_back(0);
        KWsize.push_back(0);
    }
    //    for (int i = 0; i <= numOfIndices; i++) {
    //        bytes<Key> key{0};
    //        OMAP* omap = new OMAP(max((int) pow(2, i + 2), 8), key);
    //        omaps.push_back(omap);
    //    }
    //    exist[0][3] = true;
}

//vector<prf_type> OneChoiceSDdOMAPClient::searchSetup(int index, int instance, string keyword, unsigned char* key) {
//    vector<prf_type> finalRes;
//    for (auto item : setupFiles[index][instance]) {
//        if (strcmp((char*) item.data(), keyword.data()) == 0) {
//            finalRes.push_back(item);
//        }
//    }
//    return finalRes;
//}

vector<prf_type> OneChoiceSDdOMAPClient::search(int index, int instance, string keyword, unsigned char* key) {
    double searchPreparation = 0, searchDecryption = 0;
    for (int i = 0; i < 3; i++) {
        server[i]->storage->cacheTime = 0;
        server[i]->keywordCounters->cacheTime = 0;
    }
    Utilities::startTimer(77);
    vector<prf_type> finalRes;
    prf_type K = Utilities::encode(keyword, key);
    Utilities::startTimer(65);
    int keywordCount = server[instance]->getCounter(index, K);
    auto t = Utilities::stopTimer(65);
    cout << "index:" << index << " getCounter:" << keywordCount << " time:" << t << endl;
    if (keywordCount > 0) {
        //cout <<"index:"<<index<<" instance:"<<instance<<" counter:"<<keywordCount<<endl;
        vector<prf_type> ciphers = server[instance]->search(index, K, keywordCount);
        //        ciphers = server[instance]->getAllData(index);
        totalCommunication += ciphers.size() * sizeof (prf_type);
        for (auto item : ciphers) {
            prf_type plaintext = item;
            Utilities::decode(item, plaintext, key);
            if (strcmp((char*) plaintext.data(), keyword.data()) == 0) {
                finalRes.push_back(plaintext);
            }
        }
        /*
        cout <<"finalResSize:"<<finalRes.size()<<endl;
        if(finalRes.size()<keywordCount)
        {
                ciphers = server->getAllData(index, instance);
                for (auto item : ciphers) 
                {
                    prf_type plaintext = item;
                    Utilities::decode(item, plaintext, key);
                        string w((char*) plaintext.data());
                        if(w!="")
                                cout<<(char*) plaintext.data() <<"=="<<keyword.data()<<endl;
                        if (strcmp((char*) plaintext.data(), keyword.data()) == 0) 
                        {
                        finalRes.push_back(plaintext);
                        }
                }
        }*/
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
    cout << finalRes.size() << "/" << keywordCount << endl;
    return finalRes;
}

//void OneChoiceSDdOMAPClient::endSetup(int index, int instance, unsigned char* key, bool setup) {
//    map<string, int> keywordCounters;
//    vector<vector < prf_type>> ciphers;
//    ciphers.resize(numberOfBins[index]);
//    for (int k = 0; k < setupFiles[index][instance].size(); k++) {
//        prf_type plaintext = setupFiles[index][instance][k];
//        string w((char*) plaintext.data());
//        if (keywordCounters.count(w) > 0)
//            keywordCounters[w] = keywordCounters[w] + 1;
//        else
//            keywordCounters[w] = 1;
//        int bin = hashKey(w, keywordCounters[w] - 1, index, key);
//        *(int*) (&(plaintext.data()[AES_KEY_SIZE - 11])) = bin;
//        prf_type encKeyVal;
//        encKeyVal = Utilities::encode(plaintext.data(), key);
//        ciphers[bin].push_back(encKeyVal);
//    }
//    prf_type dummy;
//    memset(dummy.data(), 0, AES_KEY_SIZE);
//    prf_type dummyKeyVal = Utilities::encode(dummy.data(), key);
//    for (int k = 0; k < numberOfBins[index]; k++) {
//        for (int el = ciphers[k].size(); el < sizeOfEachBin[index]; el++) {
//            ciphers[k].push_back(dummyKeyVal);
//        }
//    }
//
//    server->insertAll(index, instance, ciphers);
//    cout << "insertion done:" << index << "-" << instance << endl;
//
//    map<prf_type, prf_type> kcc;
//    for (auto m : keywordCounters) {
//        prf_type K = Utilities::encode(m.first, key);
//        unsigned char cntstr[AES_KEY_SIZE];
//        memset(cntstr, 0, AES_KEY_SIZE);
//        *(int*) (&(cntstr[AES_KEY_SIZE - 5])) = -1;
//        prf_type mapKey = Utilities::generatePRF(cntstr, K.data());
//        prf_type valueTmp;
//        *(int*) (&(valueTmp[0])) = m.second;
//        prf_type mapValue = Utilities::encode(valueTmp.data(), K.data());
//        kcc[mapKey] = mapValue;
//    }
//    cout << "keywC map creation done:" << index << "-" << instance << endl;
//    server->storeKwCounters(index, instance, kcc);
//}

//void OneChoiceSDdOMAPClient::move(int index, int toInstance, int fromInstance, bool setup) {
//    if (!setup) {
//        server->move(index, toInstance, fromInstance, indexSize[index]);
//        exist[index][toInstance] = true;
//        exist[index][fromInstance] = false;
//        if (fromInstance == 3) {
//            numNEW[index] = numNEW[index] + 1;
//            NEWsize[index] = 0;
//            KWsize[index] = 0;
//
//            delete omaps[index];
//            bytes<Key> key{0};
//            OMAP* omap = new OMAP(max((int) pow(2, index + 2), 8), key);
//            omaps[index] = omap;
//        }
//    } else {
//        exist[index][toInstance] = true;
//        exist[index][fromInstance] = false;
//        setupFiles[index][toInstance].clear();
//        setupFiles[index][toInstance].resize(0);
//        assert(setupFiles[index][toInstance].size() == 0);
//        for (int el = 0; el < setupFiles[index][fromInstance].size(); el++) {
//            setupFiles[index][toInstance].push_back(setupFiles[index][fromInstance][el]);
//            string w((char*) setupFiles[index][fromInstance][el].data());
//        }
//        assert(setupFiles[index][toInstance].size() == setupFiles[index][fromInstance].size());
//        setupFiles[index][fromInstance].resize(0);
//        assert(setupFiles[index][fromInstance].size() == 0);
//    }
//}
//
//void OneChoiceSDdOMAPClient::appendTokwCounter(int index, prf_type keyVal, unsigned char* key, bool setup) {
//    if (!setup) {
//        exist[index][3] = true;
//        prf_type encKeyVal;
//        encKeyVal = Utilities::encode(keyVal.data(), key);
//        int last = server->writeToKW(index, encKeyVal, KWsize[index]); //write at end
//        KWsize[index] = KWsize[index] + 1;
//        //assert(last == KWsize[index]*AES_KEY_SIZE);
//    }
//}
//
//void OneChoiceSDdOMAPClient::append(int index, prf_type keyVal, unsigned char* key, bool setup) {
//    if (!setup) {
//        exist[index][3] = true;
//        prf_type encKeyVal;
//        encKeyVal = Utilities::encode(keyVal.data(), key);
//        int last = server->writeToNEW(index, encKeyVal, NEWsize[index]); //write at end
//        NEWsize[index] = NEWsize[index] + 1;
//        assert(last == NEWsize[index] * AES_KEY_SIZE);
//    }
//    if (setup) {
//        exist[index][3] = true;
//        setupFiles[index][3].push_back(keyVal);
//        string w((char*) keyVal.data());
//        assert(w != "");
//    }
//}
//
//void OneChoiceSDdOMAPClient::destroy(int index, int instance, bool setup) {
//    if (!setup) {
//        server->destroy(index, instance);
//        exist[index][instance] = false;
//        if (instance == 3) {
//            NEWsize[index] = 0;
//            KWsize[index] = 0;
//        }
//    } else {
//        setupFiles[index][instance].clear();
//        setupFiles[index][instance].resize(0);
//        exist[index][instance] = false;
//    }
//}
//
//void OneChoiceSDdOMAPClient::resize(int index, int size, bool setup) {
//    if (!setup) {
//        server->resize(index, size, NEWsize[index]);
//        NEWsize[index] = size;
//    }
//    /*else
//    {
//            setupFiles[index][3].resize(size);
//            NEWsize[index]=size;
//    }*/
//}
//
//void OneChoiceSDdOMAPClient::getBin(int index, int instance, int count, int numOfBins,
//        unsigned char* key, unsigned char* keynew, bool setup) {
//    int start = count * sizeOfEachBin[index - 1];
//    int readSize = numOfBins * sizeOfEachBin[index - 1];
//    if (!setup) {
//        assert(start + readSize <= indexSize[index - 1]);
//        vector<prf_type> ciphers = server->getElements(index - 1, instance, start, readSize);
//        int upCnt = numNEW[index];
//        for (prf_type c : ciphers) {
//            prf_type plaintext;
//            Utilities::decode(c, plaintext, key);
//            string w((char*) plaintext.data());
//            int cnt = 0;
//            if (w != "") {
//                cnt = stoi(omaps[index]->incrementCnt(getBid(w, upCnt)));
//            }
//            //else do dummy omap access
//            int newbin = hashKey(w, cnt, index, keynew);
//            *(int*) (&(plaintext.data()[AES_KEY_SIZE - 11])) = newbin;
//            append(index, plaintext, keynew, setup);
//            if (w != "") {
//                string ob = omaps[index]->incrementCnt(getBid(to_string(newbin), upCnt));
//            }
//            //else do dummy omap access
//        }
//    } else {
//        for (int el = start; el < start + readSize; el++) {
//            if (el < pow(2, index - 1)) {
//                setupFiles[index][3].push_back(setupFiles[index - 1][instance][el]);
//                string w((char*) setupFiles[index - 1][instance][el].data());
//                assert(w != "");
//            }
//        }
//    }
//}
//
//void OneChoiceSDdOMAPClient::kwCount(int index, int count, int numOfBins, unsigned char* key, bool setup) {
//    if (!setup) {
//        int upCnt = numNEW[index];
//        int start = 2 * count * sizeOfEachBin[index - 1];
//        vector<prf_type> some = server->getElements(index, 3, start, numOfBins * sizeOfEachBin[index - 1]);
//        assert(NEWsize[index] == 2 * indexSize[index - 1]);
//        assert(start + numOfBins * sizeOfEachBin[index - 1] <= 2 * indexSize[index - 1]);
//        assert(count < numberOfBins[index - 1]);
//        assert(some.size() == numOfBins * sizeOfEachBin[index - 1]);
//
//        for (auto c : some) {
//            prf_type plaintext;
//            Utilities::decode(c, plaintext, key);
//            string w((char*) plaintext.data());
//            int cntw = 0;
//            if (w != "") {
//                //string s = omaps[index]->find(getBid(w, upCnt));
//                //cout <<s<<"/["<<w<<"]"<<upCnt<<endl;
//                cntw = stoi(omaps[index]->find(getBid(w, upCnt)));
//                assert(cntw != 0);
//            } else {
//                cntw = 0;
//                //dummy access to OMAP
//            }
//            prf_type keyVal;
//            memset(keyVal.data(), 0, AES_KEY_SIZE);
//            std::copy(w.begin(), w.end(), keyVal.begin());
//            *(int*) (&(keyVal.data()[AES_KEY_SIZE - 5])) = cntw;
//            *(int*) (&(keyVal.data()[AES_KEY_SIZE - 11])) = PRP(w, index, key);
//            appendTokwCounter(index, keyVal, key, setup);
//        }
//        assert(KWsize[index] <= 2 * indexSize[index - 1]);
//    }
//}
//
//void OneChoiceSDdOMAPClient::addDummy(int index, int count, int numOfBins, unsigned char* key, bool setup) {
//    if (!setup) {
//        assert(NEWsize[index] >= 2 * indexSize[index - 1]);
//        assert(NEWsize[index] <= 2 * indexSize[index - 1] + indexSize[index]);
//        int upCnt = numNEW[index];
//
//        for (int bin = count; bin < count + numOfBins; bin++) {
//            assert(bin < numberOfBins[index]);
//            int cbin;
//            string cb = omaps[index]->find(getBid(to_string(bin), upCnt));
//            if (cb == "")
//                cbin = 0;
//            else
//                cbin = stoi(cb);
//            assert(cbin <= sizeOfEachBin[index]);
//            prf_type realDummy;
//            memset(realDummy.data(), 0, AES_KEY_SIZE);
//            *(int*) (&(realDummy.data()[AES_KEY_SIZE - 11])) = bin; //bin
//            for (int k = cbin; k < sizeOfEachBin[index]; k++) {
//                append(index, realDummy, key, setup);
//                //string ob = omaps[index]->incrementCnt(getBid(to_string(bin), upCnt));
//            }
//            omaps[index]->insert((getBid(to_string(bin), upCnt)), to_string(sizeOfEachBin[index]));
//            prf_type dummy;
//            memset(dummy.data(), 0, AES_KEY_SIZE);
//            *(int*) (&(dummy.data()[AES_KEY_SIZE - 11])) = INF; //bin
//            for (int k = 0; k < cbin; k++) {
//                append(index, dummy, key, setup);
//            }
//            //dummy omap access here
//        }
//        if ((count == numberOfBins[index] - 1) || index <= 3) {
//            int newSize = pow(2, ceil((float) log2(NEWsize[index])));
//            pad(index, newSize, key, setup);
//        }
//    }
//}
//
//void OneChoiceSDdOMAPClient::pad(int index, int newSize, unsigned char* key, bool setup) {
//    if (!setup) {
//        assert(NEWsize[index] == indexSize[index] + 2 * indexSize[index - 1]);
//        prf_type dummy;
//        memset(dummy.data(), 0, AES_KEY_SIZE);
//        *(int*) (&(dummy.data()[AES_KEY_SIZE - 11])) = INF; //bin
//        int size = NEWsize[index];
//        for (int k = 0; k < newSize - size; k++) {
//            append(index, dummy, key, setup);
//            //**dummy omap access here
//        }
//        int kwsize = KWsize[index];
//        memset(dummy.data(), 0, AES_KEY_SIZE);
//        *(int*) (&(dummy.data()[AES_KEY_SIZE - 5])) = 0; //cntw
//        *(int*) (&(dummy.data()[AES_KEY_SIZE - 11])) = 0; //prp
//        for (int k = 0; k < newSize - kwsize; k++) {
//            appendTokwCounter(index, dummy, key, setup);
//        }
//        assert(NEWsize[index] == KWsize[index]);
//    }
//}
//
//void OneChoiceSDdOMAPClient::updateHashTable(int index, unsigned char* key, bool setup) {
//    if (!setup) {
//        assert(KWsize[index] < 8 * indexSize[index]);
//        assert(KWsize[index] == NEWsize[index]);
//        vector<prf_type> all = server->getKW(index, 0, KWsize[index]); // for first pow(2, index) items
//        map <prf_type, prf_type> kcc;
//        for (auto c : all) {
//            prf_type plaintext;
//            Utilities::decode(c, plaintext, key);
//            string w((char*) plaintext.data());
//            int cntw = *(int*) (&(plaintext.data()[AES_KEY_SIZE - 5]));
//            prf_type K = Utilities::encode(w, key);
//            unsigned char cntstr[AES_KEY_SIZE];
//            memset(cntstr, 0, AES_KEY_SIZE);
//            *(int*) (&(cntstr[AES_KEY_SIZE - 5])) = -1;
//            prf_type mapKey = Utilities::generatePRF(cntstr, K.data());
//            prf_type valueTmp;
//            *(int*) (&(valueTmp[0])) = cntw;
//            prf_type mapValue = Utilities::encode(valueTmp.data(), K.data());
//            if (kcc.find(mapKey) == kcc.end()) {
//                kcc[mapKey] = mapValue;
//            }
//        }
//        server->storeKwCounters(index, 3, kcc);
//    }
//}
//
//Bid OneChoiceSDdOMAPClient::getBid(string input, int cnt) {
//    std::array< uint8_t, ID_SIZE> value;
//    std::fill(value.begin(), value.end(), 0);
//    std::copy(input.begin(), input.end(), value.begin());
//    *(int*) (&value[ID_SIZE - 4]) = cnt;
//    Bid res(value);
//    return res;
//}
//
//int OneChoiceSDdOMAPClient::hashKey(string w, int cnt, int index, unsigned char* key) {
//    if (w == "")
//        return INF;
//    prf_type K = Utilities::encode(w, key);
//    unsigned char cntstr[AES_KEY_SIZE];
//    memset(cntstr, 0, AES_KEY_SIZE);
//    *(int*) (&(cntstr[AES_KEY_SIZE - 5])) = -1;
//    prf_type mapKey = Utilities::generatePRF(cntstr, K.data());
//    unsigned char* hash = Utilities::sha256((char*) mapKey.data(), AES_KEY_SIZE);
//    int bin = ((((unsigned int) (*((int*) hash))) + cnt) % numberOfBins[index]);
//    return bin;
//}
//
//int OneChoiceSDdOMAPClient::PRP(string w, int index, unsigned char* key) {
//    if (w == "")
//        return 0;
//    prf_type K = Utilities::encode(w, key);
//    unsigned char cntstr[AES_KEY_SIZE];
//    memset(cntstr, 0, AES_KEY_SIZE);
//    *(int*) (&(cntstr[AES_KEY_SIZE - 5])) = -1;
//    prf_type mapKey = Utilities::generatePRF(cntstr, K.data());
//    unsigned char* hash = Utilities::sha256((char*) mapKey.data(), AES_KEY_SIZE);
//    int prp = ((unsigned int) (*((int*) hash))) + 1;
//    return prp;
//}
//
//bool issortedSDd(vector<prf_type> A) {
//    for (int a = 0; a < A.size() - 1; a++) {
//        int bina = *(int*) (&(A[a].data()[AES_KEY_SIZE - 11]));
//        int binb = *(int*) (&(A[a + 1].data()[AES_KEY_SIZE - 11]));
//        if (bina > binb) {
//            return false;
//        }
//    }
//    return true;
//}
//
//bool issortedSDdC(vector<prf_type> A) {
//    for (int a = 0; a < A.size() - 1; a++) {
//        int prpa = *(int*) (&(A[a].data()[AES_KEY_SIZE - 11]));
//        int prpb = *(int*) (&(A[a + 1].data()[AES_KEY_SIZE - 11]));
//        if (prpa < prpb)
//            return false;
//    }
//    return true;
//}
//
//bool cmppSDd(prf_type &a, prf_type &b) {
//    int bina = *(int*) (&(a.data()[AES_KEY_SIZE - 11]));
//    int binb = *(int*) (&(b.data()[AES_KEY_SIZE - 11]));
//    return (bina < binb);
//}
//
//bool cmppSDd2(prf_type &a, prf_type &b) {
//    int prpa = *(int*) (&(a.data()[AES_KEY_SIZE - 11]));
//    int prpb = *(int*) (&(b.data()[AES_KEY_SIZE - 11]));
//    return (prpa > prpb);
//}
//
///*
//bool OneChoiceSDdOMAPClient::sorted(int index, unsigned char* key)
//{
//        vector<prf_type> els = server->getElements(index, 3, 0, indexSize[index]);
//        vector<prf_type> decoded;
//        for(auto n :els)
//        {
//                prf_type plain;
//                Utilities::decode(n, plain, key);
//                decoded.push_back(plain);
//        }
//        bool one = issortedSDd(decoded);
//        vector<prf_type> els2 = server->getKW(index, 0, KWsize[index]);
//        vector<prf_type> decoded2;
//        for(auto n :els2)
//        {
//                prf_type plain;
//                Utilities::decode(n, plain, key);
//                decoded2.push_back(plain);
//        }
//
//        bool two = issortedSDdC(decoded2);
//        return (one&two);
//}
// */
//
//void OneChoiceSDdOMAPClient::deAmortBitSortC(int step, int count, int size, int index, unsigned char* key, bool setup) {
//    if (!setup) {
//        vector<int> curMem = bitonic->getSeq(step, count, size);
//        std::sort(curMem.begin(), curMem.end(), [](int a, int b) {
//            return a < b;
//        });
//        vector<int> ncm = bitonic->remDup(curMem);
//        vector<prf_type> encNEW = server->getElements(index, 4, ncm[0], ncm.size());
//        //assert(encNEW.size() == ncm.size());
//        vector<prf_type> decodedNEW;
//        for (int n = 0; n < encNEW.size(); n++) {
//            prf_type dec;
//            Utilities::decode(encNEW[n], dec, key);
//            decodedNEW.push_back(dec);
//        }
//        sort(decodedNEW.begin(), decodedNEW.end(), cmppSDd2);
//        //assert(issortedSDdC(decodedNEW));
//        encNEW.clear();
//        for (auto n : decodedNEW) {
//            prf_type enc;
//            enc = Utilities::encode(n.data(), key);
//            encNEW.push_back(enc);
//        }
//        int pos = server->putElements(index, 4, ncm[0], ncm.size(), encNEW);
//        //cout <<"pos:"<<pos<<"("<<encNEW.size()<<")"<<endl;
//    }
//}
//
//void OneChoiceSDdOMAPClient::deAmortBitSort(int step, int count, int size, int index, unsigned char* key, bool setup) {
//    if (!setup) {
//        vector<int> curMem = bitonic->getSeq(step, count, size);
//        std::sort(curMem.begin(), curMem.end(), [](int a, int b) {
//            return a < b;
//        });
//        vector<int> ncm = bitonic->remDup(curMem);
//        vector<prf_type> encNEW = server->getElements(index, 3, ncm[0], ncm.size()); //divide the elems into two groups
//        vector<prf_type> decodedNEW;
//        for (auto n : encNEW) {
//            prf_type dec;
//            Utilities::decode(n, dec, key);
//            decodedNEW.push_back(dec);
//        }
//        sort(decodedNEW.begin(), decodedNEW.end(), cmppSDd);
//        //assert(issortedSDd(decodedNEW));
//        encNEW.clear();
//        for (auto n : decodedNEW) {
//            prf_type enc;
//            enc = Utilities::encode(n.data(), key);
//            encNEW.push_back(enc);
//        }
//        int pos = server->putElements(index, 3, ncm[0], ncm.size(), encNEW);
//        //cout <<"pos:"<<pos<<"("<<encNEW.size()<<")"<<endl;
//    }
//}
//
//int OneChoiceSDdOMAPClient::getNEWsize(int index) {
//    return NEWsize[index];
//}
//

void OneChoiceSDdOMAPClient::setup(long index, long instance, unordered_map<string, vector<prf_type> > pairs, unsigned char* key) {
    exist[instance][index] = true;
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
    server[instance]->storeCiphers(index, ciphers, keywprdCntCiphers);
}

void OneChoiceSDdOMAPClient::setup2(long index, long instance, unordered_map<string, vector<tmp_prf_type> > pairs, unsigned char* key) {
    exist[instance][index] = true;
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
    server[instance]->storeKeywordCounters(index, keywprdCntCiphers);
    for (long i = 0; i < ciphers.size(); i++) {
        vector<vector<prf_type> > finalCiphers = convertTmpCiphersToFinalCipher(ciphers[i], key);
        server[instance]->storeCiphers(index, finalCiphers, i == 0);
    }
}

vector<vector<prf_type> > OneChoiceSDdOMAPClient::convertTmpCiphersToFinalCipher(vector<pair<std::pair<string, long>, tmp_prf_type> > ciphers, unsigned char* key) {
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