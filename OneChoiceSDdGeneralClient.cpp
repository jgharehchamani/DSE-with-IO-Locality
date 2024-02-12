#include "OneChoiceSDdGeneralClient.h"
#include<string.h>
#include<map>
#include<vector>
#include<algorithm>

using namespace::std;

OneChoiceSDdGeneralClient::~OneChoiceSDdGeneralClient() {
    delete server;
}

OneChoiceSDdGeneralClient::OneChoiceSDdGeneralClient(int N, bool inMemory, bool overwrite, bool profile) {
    this->profile = profile;
    int l = floor(log2(N)) + 1;
    memset(nullKey.data(), 0, AES_KEY_SIZE);
    this->numOfIndices = l;
    prf_type newvalue;
    std::fill(newvalue.begin(), newvalue.end(), 0);
    //    *(byte*) (&(newvalue.data()[0])) = 1;
    prf_type initialDummy = Utilities::encode(newvalue.data(), EncKey);

    server = new OneChoiceSDdGeneralServer(numOfIndices, inMemory, overwrite, profile, initialDummy, this);
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
    exist.resize(4);
    setupFiles.resize(numOfIndices);

    for (int i = 0; i < numOfIndices; i++) {
        setupFiles[i].resize(4);
        exist[0].push_back(false);
        exist[1].push_back(false);
        exist[2].push_back(false);
        exist[3].push_back(false);

        numNEW.push_back(1); //updateCount
        NEWsize.push_back(0);
        KWsize.push_back(0);
    }
    //#########################################################
    //   For UPDATE should be Uncommented
    //#########################################################
        transData.setup(numOfIndices, numberOfBins);

    //#########################################################
}

vector<prf_type> OneChoiceSDdGeneralClient::search(int index, int instance, string keyword, unsigned char* key) {
    double searchPreparation = 0, searchDecryption = 0;
    for (int i = 0; i < 3; i++) {
        server->storage[i]->cacheTime = 0;
        server->keywordCounters[i]->cacheTime = 0;
    }
    Utilities::startTimer(77);
    vector<prf_type> finalRes;
    prf_type K = Utilities::encode(keyword, key);
    Utilities::startTimer(65);
    int keywordCount = server->getCounter(instance, index, K);
    auto t = Utilities::stopTimer(65);
    cout << "index:" << index << " getCounter:" << keywordCount << " time:" << t << endl;
    if (keywordCount > 0) {
        //cout <<"index:"<<index<<" instance:"<<instance<<" counter:"<<keywordCount<<endl;
        vector<prf_type> ciphers = server->search(instance, index, K, keywordCount);
        //        ciphers = server[instance]->getAllData(index);
        totalCommunication += ciphers.size() * sizeof (prf_type);
        for (auto item : ciphers) {
            prf_type plaintext = item;
            Utilities::decode(item, plaintext, key);
            if (strcmp((char*) plaintext.data(), keyword.data()) == 0) {
                finalRes.push_back(plaintext);
            }
        }
    }
    double cachet = 0;
    for (int i = 0; i < 3; i++) {
        cachet += server->storage[i]->cacheTime;
        cachet += server->keywordCounters[i]->cacheTime;
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

void OneChoiceSDdGeneralClient::setup(long index, long instance, unordered_map<string, vector<prf_type> > pairs, unsigned char* key) {
    exist[instance][index] = true;
    vector<vector<prf_type> >* ciphers = new vector<vector<prf_type> >();
    for (long i = 0; i < numberOfBins[index]; i++) {
        (*ciphers).push_back(vector<prf_type>());
    }
    unordered_map<prf_type, prf_type, PRFHasher>* keywprdCntCiphers = new unordered_map<prf_type, prf_type, PRFHasher>();
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
        (*keywprdCntCiphers)[mapKey] = mapValue;

        unsigned char* hash = Utilities::sha256((char*) mapKey.data(), AES_KEY_SIZE);
        long pos = (unsigned long) (*((long*) hash)) % numberOfBins[index];
        long cipherIndex = pos;
        for (unsigned long i = 0; i < pair.second.size(); i++) {
            prf_type mapValue;
            mapValue = Utilities::encode(pair.second[i].data(), key);
            (*ciphers)[cipherIndex].push_back(mapValue);
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
            (*ciphers)[i].push_back(dummyV);
        }
    }

    prf_type randomKey;
    for (long i = 0; i < AES_KEY_SIZE; i++) {
        randomKey[i] = rand();
    }
    for (long i = (*keywprdCntCiphers).size(); i < pow(2, index); i++) {
        unsigned char cntstr[AES_KEY_SIZE];
        memset(cntstr, 0, AES_KEY_SIZE);
        *(long*) (&(cntstr[AES_KEY_SIZE - 9])) = rand();
        prf_type mapKey = Utilities::generatePRF(cntstr, randomKey.data());
        *(long*) (&(cntstr[AES_KEY_SIZE - 5])) = rand();
        prf_type mapValue = Utilities::generatePRF(cntstr, randomKey.data());
        (*keywprdCntCiphers)[mapKey] = mapValue;
    }
    //    totalCommunication += ciphers.size() * sizeof (prf_type)*2;
    server->storeCiphers(instance, index, ciphers, keywprdCntCiphers);
}

void OneChoiceSDdGeneralClient::setup2(long index, long instance, unordered_map<string, vector<tmp_prf_type> > pairs, unsigned char* key) {
    exist[instance][index] = true;
    vector<vector<pair<pair<string, long>, tmp_prf_type> > > ciphers;
    for (long i = 0; i < numberOfBins[index]; i++) {
        ciphers.push_back(vector<pair<pair<string, long>, tmp_prf_type> >());
    }
    unordered_map<prf_type, prf_type, PRFHasher>* keywprdCntCiphers = new unordered_map<prf_type, prf_type, PRFHasher>();
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
        (*keywprdCntCiphers)[mapKey] = mapValue;

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
    for (long i = (*keywprdCntCiphers).size(); i < pow(2, index); i++) {
        unsigned char cntstr[AES_KEY_SIZE];
        memset(cntstr, 0, AES_KEY_SIZE);
        *(long*) (&(cntstr[AES_KEY_SIZE - 9])) = (long) rand();
        prf_type mapKey = Utilities::generatePRF(cntstr, randomKey.data());
        *(long*) (&(cntstr[AES_KEY_SIZE - 5])) = (long) rand();
        prf_type mapValue = Utilities::generatePRF(cntstr, randomKey.data());
        (*keywprdCntCiphers)[mapKey] = mapValue;
    }
    server->storeKeywordCounters(instance, index, keywprdCntCiphers);
    for (long i = 0; i < ciphers.size(); i++) {
        vector<prf_type> finalCiphers = convertTmpCiphersToFinalCipher(ciphers[i], key);
        server->storeCiphers(instance, index, finalCiphers, i == 0);
    }

    //    vector<vector<prf_type> > finalCiphers;
    //    for (long i = 0; i < ciphers.size(); i++) {
    //        finalCiphers.push_back(vector<prf_type>());
    //        finalCiphers[i] = convertTmpCiphersToFinalCipher(ciphers[i], key);        
    //    }
    //    server->storeCiphers(instance, index, finalCiphers, true);
}

vector<prf_type> OneChoiceSDdGeneralClient::convertTmpCiphersToFinalCipher(vector<pair<std::pair<string, long>, tmp_prf_type> > ciphers, unsigned char* key) {
    vector<prf_type> results;
    for (long i = 0; i < ciphers.size(); i++) {
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
            results.push_back(dummyV);
        } else {

            prf_type newvalue;
            std::fill(newvalue.begin(), newvalue.end(), 0);
            std::copy(keyword.begin(), keyword.end(), newvalue.begin());
            *(int*) (&(newvalue.data()[AES_KEY_SIZE - 5])) = ind;
            newvalue.data()[AES_KEY_SIZE - 6] = op;

            prf_type mapValue;
            mapValue = Utilities::encode(newvalue.data(), key);
            results.push_back(mapValue);
        }

    }
    return results;
}

void OneChoiceSDdGeneralClient::destry(int instance, int index) {
    //    server->clear(instance, index);
    totalCommunication += sizeof (int);
    exist[instance][index] = false;
}

void OneChoiceSDdGeneralClient::destryAndClear(int instance, int index) {
    server->clear(instance, index);
    totalCommunication += sizeof (int);
    exist[instance][index] = false;
}

void OneChoiceSDdGeneralClient::move(int fromInstance, int fromIndex, int toInstance, int toIndex) {
    server->move(fromInstance, fromIndex, toInstance, toIndex);
    exist[toInstance][toIndex] = true;
}

int OneChoiceSDdGeneralClient::getTotalNumberOfSteps(int oldestAndOldIndex) {
    return server->getTotalNumberOfSteps(oldestAndOldIndex);
}

void OneChoiceSDdGeneralClient::permuteBucket(vector<Entry >& bucket, int beginStep, int count, int index, UpdateData& updateData) {

    if (beginStep == 0) {
        //        updateData.clearLabeledEntries();
        updateData.labeledEntries.clear();
        //        int bucketSize = updateData.getArrayAsSize(bucket_index1, bucket_index2);
        int bucketSize = bucket.size();
        for (int i = 0; i < bucketSize; i++) {
            std::array<uint8_t, TMP_AES_KEY_SIZE> plain;
            memset(plain.data(), 0, TMP_AES_KEY_SIZE);
            *(int*) (&(plain[0])) = rand();
            prf_type enc = Utilities::encode(plain.data(), EncKey);
            unsigned int label = (unsigned int) (*((unsigned int*) enc.data())) % 65536;
            //            Entry bucketi = updateData.getArrayAsEntry(bucket_index1, bucket_index2, i);
            //            updateData.pushBackLabeledEntries(pair<Entry, int>(bucketi, label));
            //              updateData.putIntInArrayAsPlace(bucket_index1, bucket_index2, i,label);
            updateData.labeledEntries.push_back(pair<Entry, int>(bucket[i], label));
        }
        //        updateData.transferArrayAsToLabeledEntries(bucket_index1, bucket_index2,bucketSize);
    }
    int stepCounter = 0;
    if (beginStep == 0) {
        //        updateData.clearArray2();
        updateData.leftArray2.clear();
        updateData.rightArray2.clear();
        updateData.indexOfSubArrayOne.clear();
        updateData.indexOfSubArrayTwo.clear();
        updateData.indexOfMergedArray.clear();
    }

    //    mergeSort(0, updateData.getLabeledEntriesSize() - 1, beginStep, count, index, updateData);
    mergeSort(&updateData.labeledEntries, 0, updateData.labeledEntries.size() - 1, beginStep, count, index, updateData);

}

//--------------------------------
//Client

void OneChoiceSDdGeneralClient::mergeSplit(vector<Entry > A0, vector<Entry > A1, unsigned int bitIndex, vector<Entry >& A0prime, vector<Entry >& A1prime, bool permute, int n, int beginStep, int count, int bucketSizeZ, int index, UpdateData& updateData) {

    //void OneChoiceSDdGeneralClient::mergeSplit(int A0_index1, int A0_index2, int A1_index1, int A1_index2, unsigned int bitIndex, int A0prime_index1, int A0prime_index2, int A1prime_index1, int A1prime_index2, bool permute, int n, int beginStep, int count, int bucketSizeZ, int index, UpdateData& updateData) {
    int currentStep = 0;
    int curSteps = 0;

    // n steps
    //    int A0Size = updateData.getArrayAsSize(A0_index1, A0_index2);
    int A0Size = A0.size();
    curSteps = A0Size;
    //    cout << "A0:" << endl;
    if (beginStep >= currentStep && beginStep < currentStep + curSteps) {
        int forwardStep = beginStep - currentStep;
        for (int i = forwardStep; i < A0Size && count > 0; i++) {
            prf_type el;
            //            Entry A0i = updateData.getArrayAsEntry(A0_index1, A0_index2, i);
            Entry A0i = A0[i];
            //            el = A0i.element;
            Utilities::decode(A0i.element, el, EncKey);
            if (*(long*) el.data() != 0 || *(byte*) (&(el.data()[AES_KEY_SIZE - 4])) == 1) {
                //                cout << *((int*) (&(el.data()[1]))) << " ";
                prf_type plaintext;
                //                plaintext = A0i.key;
                Utilities::decode(A0i.key, plaintext, EncKey);
                int label = *((int*) (&(plaintext.data()[1])));
                int targetBit = (label >> (bitIndex));
                A0i.element = Utilities::encode(el.data(), EncKey);
                A0i.key = Utilities::encode(plaintext.data(), EncKey);

                if ((1 & targetBit) == 1) {
                    //                    updateData.insertEntryInArrayAs(A1prime_index1, A1prime_index2, A0i);
                    A1prime.push_back(A0i);
                } else {
                    //                    updateData.insertEntryInArrayAs(A0prime_index1, A0prime_index2, A0i);
                    A0prime.push_back(A0i);
                }
            }
            count--;
        }

        beginStep = count > 0 ? (currentStep + curSteps) : beginStep;
    }
    //    cout << endl;
    currentStep += curSteps;


    //    int A1Size = updateData.getArrayAsSize(A1_index1, A1_index2);
    int A1Size = A1.size();
    curSteps = A1Size;
    //    cout << "A1:" << endl;
    if (beginStep >= currentStep && beginStep < currentStep + curSteps) {
        int forwardStep = beginStep - currentStep;
        for (int i = forwardStep; i < A1Size && count > 0; i++) {
            prf_type el;
            //            Entry A1i = updateData.getArrayAsEntry(A1_index1, A1_index2, i);
            Entry A1i = A1[i];
            //            el=A1i.element;
            Utilities::decode(A1i.element, el, EncKey);
            if (*(long*) el.data() != 0 || *(byte*) (&(el.data()[AES_KEY_SIZE - 4])) == 1) {
                //                cout << *((int*) (&(el.data()[1]))) << " ";
                prf_type plaintext;
                //                plaintext = A1i.key;
                Utilities::decode(A1i.key, plaintext, EncKey);
                int label = *((int*) (&(plaintext.data()[1])));
                int targetBit = (label >> (bitIndex));
                A1i.element = Utilities::encode(el.data(), EncKey);
                A1i.key = Utilities::encode(plaintext.data(), EncKey);
                if ((1 & targetBit) == 1) {
                    //                    updateData.insertEntryInArrayAs(A1prime_index1, A1prime_index2, A1i);
                    A1prime.push_back(A1i);
                } else {
                    //                    updateData.insertEntryInArrayAs(A0prime_index1, A0prime_index2, A1i);
                    A0prime.push_back(A1i);
                }
            }
            count--;
        }
        beginStep = count > 0 ? (currentStep + curSteps) : beginStep;
    }
    //    cout << endl;
    currentStep += curSteps;

    //    int A0primeSize = updateData.getArrayAsSize(A0prime_index1, A0prime_index2);
    //    int A1primeSize = updateData.getArrayAsSize(A1prime_index1, A1prime_index2);
    int A0primeSize = A0prime.size();
    int A1primeSize = A1prime.size();
    if (permute) {
        curSteps = A0primeSize * log2(A0primeSize);
        if (A0primeSize > 0 && beginStep >= currentStep && beginStep < currentStep + curSteps) {
            int relativeBegin = beginStep - currentStep;
            int relativeCount = (count + relativeBegin) >= curSteps ? (curSteps - relativeBegin) : count;
            if (count > 0) {
                //                permuteBucket(A0prime, relativeBegin, relativeCount, index, updateData);
            }
        }
        curSteps = bucketSizeZ * log2(bucketSizeZ);
        count = (count + beginStep) > currentStep + curSteps ? count + beginStep - (currentStep + curSteps) : 0;
        beginStep = count > 0 ? (currentStep + curSteps) : beginStep;

        currentStep += curSteps;

        curSteps = A1primeSize * log2(A1primeSize);
        if (A1primeSize > 0 && beginStep >= currentStep && beginStep < currentStep + curSteps) {
            int relativeBegin = beginStep - currentStep;
            int relativeCount = (count + relativeBegin) >= curSteps ? (curSteps - relativeBegin) : count;
            if (count > 0) {
                //                permuteBucket(A1prime, relativeBegin, relativeCount, index, updateData);
            }
        }
        curSteps = bucketSizeZ * log2(bucketSizeZ);
        count = (count + beginStep) > currentStep + curSteps ? count + beginStep - (currentStep + curSteps) : 0;
        beginStep = count > 0 ? (currentStep + curSteps) : beginStep;

        currentStep += curSteps;
    }


    int size = A0Size;

    curSteps = A0Size - A0primeSize;
    if (beginStep >= currentStep && beginStep < currentStep + size) {
        //        int forwardStep = beginStep - currentStep;
        for (int i = A0primeSize; i < size && count > 0; i++) {
            Entry dummyEntry;
            prf_type dummyElement, dummyKey;
            std::fill(dummyElement.begin(), dummyElement.end(), 0);
            //            *(byte*) (&(dummyElement.data()[0])) = 1;            
            //            prf_type encElement = dummyElement;
            prf_type encElement = Utilities::encode(dummyElement.data(), EncKey);

            std::fill(dummyKey.begin(), dummyKey.end(), 0);
            //            prf_type encKey = dummyElement;
            prf_type encKey = Utilities::encode(dummyElement.data(), EncKey);

            dummyEntry.element = encElement;
            dummyEntry.key = encKey;
            //            updateData.insertEntryInArrayAs(A0prime_index1, A0prime_index2, dummyEntry);
            A0prime.push_back(dummyEntry);

            count--;
        }
        beginStep = count > 0 ? (currentStep + size) : beginStep;
    }
    currentStep += size;

    curSteps = A1Size - A1primeSize;
    if (beginStep >= currentStep && beginStep < currentStep + size) {
        //        int forwardStep = beginStep - currentStep;
        for (int i = A1primeSize; i < size && count > 0; i++) {
            Entry dummyEntry;
            prf_type dummyElement, dummyKey;
            std::fill(dummyElement.begin(), dummyElement.end(), 0);
            //            *(byte*) (&(dummyElement.data()[0])) = 1;
            //            prf_type encElement = dummyElement;
            prf_type encElement = Utilities::encode(dummyElement.data(), EncKey);

            std::fill(dummyKey.begin(), dummyKey.end(), 0);
            //            prf_type encKey = dummyElement;
            prf_type encKey = Utilities::encode(dummyElement.data(), EncKey);

            dummyEntry.element = encElement;
            dummyEntry.key = encKey;
            //            updateData.insertEntryInArrayAs(A1prime_index1, A1prime_index2, dummyEntry);
            A1prime.push_back(dummyEntry);

            count--;
        }
        beginStep = count > 0 ? (currentStep + size) : beginStep;
    }
    currentStep += size;
    //    cout << "A0prime.size" << A0prime.size() << endl;
}

vector<prf_type> OneChoiceSDdGeneralClient::getRandomKeys(int n, int bucketNumberB, int begin, int count, int index) {
    vector<prf_type> keys;
    for (int i = begin; i < n && count > 0; i++) {
        std::array<uint8_t, TMP_AES_KEY_SIZE> plain;
        memset(plain.data(), 0, TMP_AES_KEY_SIZE);
        *(int*) (&(plain[0])) = i;
        prf_type enc = Utilities::encode(plain.data(), EncKey);
        unsigned int bucketId = (unsigned int) (*((unsigned int*) enc.data())) % bucketNumberB;

        prf_type newvalue;
        std::fill(newvalue.begin(), newvalue.end(), 0);
        *(int*) (&(newvalue.data()[1])) = bucketId;
        prf_type mapValue = Utilities::encode(newvalue.data(), EncKey);
        keys.push_back(mapValue);
        count--;
    }
    return keys;
}

void OneChoiceSDdGeneralClient::removeDummies(int level, int bucketSizeZ, int beginStep, int count, int index, UpdateData& updateData) {
    int i = 0, j = 0;
    int forwardStep = beginStep;
    i = forwardStep / bucketSizeZ;
    j = forwardStep % bucketSizeZ;
    for (; i < updateData.bucketNumberB && count > 0; i++) {
        vector<Entry> buk = updateData.getArrayAsBucket(level, i);
        vector<prf_type> out;
        for (; j < updateData.bucketSizeZ && count > 0; j++) {
            prf_type el;
            //            Entry arrayAsij = updateData.getArrayAsEntry(level, i, j);
            Entry arrayAsij = buk[j];
            //            el = arrayAsij.element;
            Utilities::decode(arrayAsij.element, el, EncKey);
            if (*(long*) el.data() != 0 || *(byte*) (&(el.data()[AES_KEY_SIZE - 4])) == 1) {
                //                updateData.insertInPermutedArrayWithNoDummyEntry(arrayAsij.element);
                out.push_back(arrayAsij.element);
            }
            count--;
        }
        updateData.insertVectorInPermutedArrayWithNoDummyEntry(out);
        j = 0;
    }
}

prf_type OneChoiceSDdGeneralClient::decryptEntity(prf_type input) {
    prf_type el;
    Utilities::decode(input, el, EncKey);
    return el;
}

pair<prf_type, prf_type> OneChoiceSDdGeneralClient::decryptEntity2(pair<prf_type, prf_type> input) {
    prf_type el1, el2;
    Utilities::decode(input.first, el1, NEWKEY);
    Utilities::decode(input.second, el2, NEWKEY);
    return pair<prf_type, prf_type>(el1, el2);
}

prf_type OneChoiceSDdGeneralClient::decryptEntity2(prf_type input) {
    prf_type el1, el2;
    Utilities::decode(input, el1, NEWKEY);
    return el1;
}

prf_type OneChoiceSDdGeneralClient::encryptEntity(prf_type input) {
    prf_type el = Utilities::encode(input.data(), EncKey);
    return el;
}

pair<prf_type, prf_type> OneChoiceSDdGeneralClient::encryptEntity2(pair<prf_type, prf_type> input) {
    prf_type el1 = Utilities::encode(input.first.data(), NEWKEY);
    prf_type el2 = Utilities::encode(input.second.data(), NEWKEY);
    return pair<prf_type, prf_type>(el1, el2);
}

bool OneChoiceSDdGeneralClient::compare(prf_type lhs, prf_type rhs) {
    prf_type lefte = *((prf_type*) & lhs);
    prf_type righte = *((prf_type*) & rhs);
    prf_type left, right;
    Utilities::decode(lefte, left, EncKey);
    Utilities::decode(righte, right, EncKey);

    if (*((int*) (&(left.data()[1]))) <= *((int*) (&(right.data()[1])))) {
        return true;
    } else {
        return false;
    }

}

bool OneChoiceSDdGeneralClient::keywordCompare(prf_type lhs, prf_type rhs) {

    //bool OneChoiceSDdGeneralClient::keywordCompare(prf_type left, prf_type right) {
    prf_type lefte = *((prf_type*) & lhs);
    prf_type righte = *((prf_type*) & rhs);
    prf_type left, right;
    Utilities::decode(lefte, left, EncKey);
    Utilities::decode(righte, right, EncKey);
    string lkeyword((char*) left.data());
    string rkeyword((char*) right.data());

    if ((*(long*) right.data() == 0 && *(byte*) (&(right.data()[AES_KEY_SIZE - 4])) == 1) ||
            lkeyword <= rkeyword && (*(long*) right.data() != 0 && *(byte*) (&(right.data()[AES_KEY_SIZE - 4])) != 1 && (*(long*) left.data() != 0 && *(byte*) (&(left.data()[AES_KEY_SIZE - 4])) != 1))) {
        return true;
    } else {
        return false;
    }

}

bool OneChoiceSDdGeneralClient::compare(pair<Entry, unsigned int> lhs, pair<Entry, unsigned int> rhs) {
    unsigned int left = ((pair<Entry, unsigned int>*) & lhs)->second;
    unsigned int right = ((pair<Entry, unsigned int>*) & rhs)->second;
    if (left <= right) {
        return true;
    } else {
        return false;
    }
}

void OneChoiceSDdGeneralClient::mergeSort(vector<pair<Entry, unsigned int> >* array, int const begin, int const end, int beginStep, int& count, int index, UpdateData& updateData) {
    int curr_size = 1; // For current size of subarrays to be merged
    int left_start = 0; // For picking starting index of left subarray
    int n = end;
    int forwardStep = beginStep;
    int outterForward = (int) pow(2, (int) (forwardStep / (n + 1)));
    int innerForward = ((forwardStep % (n + 1)) / (outterForward * 2))*(2 * outterForward);
    curr_size = outterForward;
    left_start = innerForward;

    for (; curr_size <= n && count > 0; curr_size = 2 * curr_size) {
        for (; left_start < n && count > 0; left_start += 2 * curr_size) {
            int mid = min(left_start + curr_size - 1, n);
            int right_end = min(left_start + 2 * curr_size - 1, n);
            merge(array, left_start, mid, right_end, count, index, n * curr_size + left_start, updateData);
        }
        left_start = 0;
    }
}

void OneChoiceSDdGeneralClient::merge(vector<pair<Entry, unsigned int> >* array, int const left, int const mid, int const right, int& count, int index, int innerMapCounter, UpdateData& updateData) {
    auto const subArrayOne = mid - left + 1;
    auto const subArrayTwo = right - mid;
    const int beginStepCounter = innerMapCounter;

    if (updateData.indexOfMergedArray.count(beginStepCounter) == 0) {
        updateData.leftArray2.clear();
        updateData.rightArray2.clear();
        for (auto i = 0; i < subArrayOne; i++) {
            updateData.leftArray2.push_back((*array)[left + i]);
        }
        for (auto j = 0; j < subArrayTwo; j++) {
            updateData.rightArray2.push_back((*array)[mid + 1 + j]);
        }
        updateData.indexOfSubArrayOne[beginStepCounter] = 0;
        updateData.indexOfSubArrayTwo[beginStepCounter] = 0;
        updateData.indexOfMergedArray[beginStepCounter] = left;
    }


    while (updateData.indexOfSubArrayOne[beginStepCounter] < subArrayOne && updateData.indexOfSubArrayTwo[beginStepCounter] < subArrayTwo && count > 0) {
        if (compare(updateData.leftArray2[updateData.indexOfSubArrayOne[beginStepCounter]], updateData.rightArray2[updateData.indexOfSubArrayTwo[beginStepCounter]])) {
            (*array)[updateData.indexOfMergedArray[beginStepCounter]] = updateData.leftArray2[updateData.indexOfSubArrayOne[beginStepCounter]];
            updateData.indexOfSubArrayOne[beginStepCounter]++;
        } else {
            (*array)[updateData.indexOfMergedArray[beginStepCounter]] = updateData.rightArray2[updateData.indexOfSubArrayTwo[beginStepCounter]];
            updateData.indexOfSubArrayTwo[beginStepCounter]++;
        }
        updateData.indexOfMergedArray[beginStepCounter]++;
        count--;
    }
    while (updateData.indexOfSubArrayOne[beginStepCounter] < subArrayOne && count > 0) {
        (*array)[updateData.indexOfMergedArray[beginStepCounter]] = updateData.leftArray2[updateData.indexOfSubArrayOne[beginStepCounter]];
        updateData.indexOfSubArrayOne[beginStepCounter]++;
        updateData.indexOfMergedArray[beginStepCounter]++;
        count--;
    }
    while (updateData.indexOfSubArrayTwo[beginStepCounter] < subArrayTwo && count > 0) {
        (*array)[updateData.indexOfMergedArray[beginStepCounter]] = updateData.rightArray2[updateData.indexOfSubArrayTwo[beginStepCounter]];
        updateData.indexOfSubArrayTwo[beginStepCounter]++;
        updateData.indexOfMergedArray[beginStepCounter]++;
        count--;
    }
}

void OneChoiceSDdGeneralClient::obliviousMerge(unsigned char* oldestKey, unsigned char* olderKey, unsigned char* newKey, int oldestAndOldIndex, int beginStep, int maxSteps) {
    memcpy(A0KEY, oldestKey, TMP_AES_KEY_SIZE);
    memcpy(A1KEY, olderKey, TMP_AES_KEY_SIZE);
    memcpy(NEWKEY, newKey, TMP_AES_KEY_SIZE);
    int totalNumberOfSteps = server->getTotalNumberOfSteps(oldestAndOldIndex);
    int step = (int) ceil((float) totalNumberOfSteps / (float) maxSteps);

    server->obliviousMerge(oldestAndOldIndex, (beginStep - 1) * step, step);
    //    server->obliviousMerge(oldestAndOldIndex, 0, totalNumberOfSteps);
}

vector<prf_type> OneChoiceSDdGeneralClient::updateKeys(vector<prf_type> input, bool isA0) {
    unsigned char tmpKey[TMP_AES_KEY_SIZE];
    vector<prf_type> result;
    if (isA0) {
        memcpy(tmpKey, A0KEY, TMP_AES_KEY_SIZE);
    } else {
        memcpy(tmpKey, A1KEY, TMP_AES_KEY_SIZE);
    }
    for (int i = 0; i < input.size(); i++) {
        prf_type plaintext, newCipher;
        Utilities::decode(input[i], plaintext, tmpKey);
        if (*(long*) plaintext.data() == 0) {
            memset(plaintext.data(), 0, AES_KEY_SIZE);
            *(byte*) (&(plaintext[AES_KEY_SIZE - 4])) = (byte) 1;
        }
        newCipher = Utilities::encode(plaintext.data(), EncKey);
        result.push_back(newCipher);
    }
    return result;
}

void OneChoiceSDdGeneralClient::phase0(int srcIndex) {
    transData.clearBIN(srcIndex);
    transData.resetBIN(srcIndex, numberOfBins[srcIndex]);
    transData.clearCNT(srcIndex);
}

pair<prf_type, prf_type> OneChoiceSDdGeneralClient::assignToNewBin(prf_type entry, int newIndex) {
    int oldIndex = newIndex - 1;
    pair<prf_type, prf_type> res;
    prf_type plaintext;
    Utilities::decode(entry, plaintext, EncKey);
    if (*(long*) plaintext.data() != 0) {
        string keyword((char*) plaintext.data());

        prf_type K1 = Utilities::encode(keyword, NEWKEY);
        prf_type mapKey;
        unsigned char cntstr[AES_KEY_SIZE];
        memset(cntstr, 0, AES_KEY_SIZE);
        *(long*) (&(cntstr[AES_KEY_SIZE - 5])) = (long) - 1;
        mapKey = Utilities::generatePRF(cntstr, K1.data());

        int id = *(int*) (&(plaintext.data()[AES_KEY_SIZE - 5]));
        int op = ((byte) plaintext.data()[AES_KEY_SIZE - 6]);

        prf_type newvalue;
        std::fill(newvalue.begin(), newvalue.end(), 0);
        std::copy(keyword.begin(), keyword.end(), newvalue.begin());
        *(int*) (&(newvalue.data()[AES_KEY_SIZE - 5])) = id;
        newvalue.data()[AES_KEY_SIZE - 6] = op;

        prf_type mapValue;
        mapValue = Utilities::encode(newvalue.data(), NEWKEY);

        if (transData.CNTkeyExist(oldIndex, keyword) == false) {
            transData.insertCNT(oldIndex, keyword, 0);
        }

        unsigned char* hash = Utilities::sha256((char*) mapKey.data(), AES_KEY_SIZE);
        long pos = (unsigned long) (*((long*) hash)) % numberOfBins[newIndex];

        prf_type newPos;
        memset(newPos.data(), 0, AES_KEY_SIZE);
        *(int*) (&(newPos[0])) = (pos + transData.getCNT(oldIndex, keyword)) % numberOfBins[newIndex];

        //        cout << "Keyword:" << keyword << " pos:" << (pos + CNT[oldIndex][keyword]) % numberOfBins[newIndex] << endl;
        int binID = (pos + transData.getCNT(oldIndex, keyword)) % numberOfBins[newIndex];
        int newV = 0;
        if (transData.BINKeyExist(oldIndex, binID)) {
            newV = transData.getBIN(oldIndex, binID) + 1;
            transData.replaceBIN(oldIndex, binID, newV);
        } else {
            transData.insertBIN(oldIndex, binID, newV);
        }


        newV = transData.getCNT(oldIndex, keyword) + 1;
        transData.replaceCNT(oldIndex, keyword, newV);

        res.first = mapValue;
        res.second = Utilities::encode(newPos.data(), NEWKEY);


    } else {
        prf_type dummy;
        memset(dummy.data(), 0, AES_KEY_SIZE);
        *(byte*) (&(dummy.data()[AES_KEY_SIZE - 4])) = 1;
        prf_type dummyV = Utilities::encode(dummy.data(), NEWKEY);

        res.first = dummyV;

        prf_type newPos;
        memset(newPos.data(), 0, AES_KEY_SIZE);
        *(int*) (&(newPos[0])) = 999999999;

        res.second = Utilities::encode(newPos.data(), NEWKEY);

    }


    return res;

}

pair<prf_type, prf_type> OneChoiceSDdGeneralClient::createBuf2Entry(prf_type entry, int newIndex) {
    pair<prf_type, prf_type> buf2Entry;
    int oldIndex = newIndex - 1;
    pair<prf_type, prf_type> res;
    prf_type plaintext;
    Utilities::decode(entry, plaintext, EncKey);
    string keyword((char*) plaintext.data());
    if (*(long*) plaintext.data() != 0 && transData.CNTkeyExist(oldIndex, keyword)) {

        prf_type mapKey;

        std::fill(mapKey.begin(), mapKey.end(), 0);
        std::copy(keyword.begin(), keyword.end(), mapKey.begin());
        *(int*) (&(mapKey.data()[AES_KEY_SIZE - 5])) = (int) transData.getCNT(oldIndex, keyword);
        mapKey = Utilities::encode(mapKey.data(), NEWKEY);


        prf_type randData;
        memset(randData.data(), 0, AES_KEY_SIZE);
        *(int*) (&(randData[0])) = (rand() % 1000) + 1;


        buf2Entry.first = mapKey;
        buf2Entry.second = Utilities::encode(randData.data(), NEWKEY);
        transData.eraseCNT(oldIndex, keyword);
    } else {



        prf_type randomKey;
        unsigned char cntstr[AES_KEY_SIZE];
        memset(cntstr, 0, AES_KEY_SIZE);
        *(byte*) (&(cntstr[AES_KEY_SIZE - 4])) = 1;
        prf_type mapKey = Utilities::encode(cntstr, NEWKEY);

        prf_type randData;
        memset(randData.data(), 0, AES_KEY_SIZE);
        *(int*) (&(randData[0])) = 0;


        buf2Entry.first = mapKey;
        buf2Entry.second = Utilities::encode(randData.data(), NEWKEY);
    }


    return buf2Entry;

}

vector<pair<prf_type, prf_type> > OneChoiceSDdGeneralClient::getExtraDummies(int newIndex, int binNumber, int beginStep, int& count) {
    int oldIndex = newIndex - 1;
    vector<pair<prf_type, prf_type> > result;
    int bi = sizeOfEachBin[newIndex];
    int value = 0;
    if (transData.BINKeyExist(oldIndex, binNumber)) {
        value = transData.getBIN(oldIndex, binNumber);
    }
    if (beginStep < (bi - value)) {
        for (int j = beginStep; j < (bi - value) && count > 0; j++) {
            pair<prf_type, prf_type> curItem;
            prf_type dummy;
            memset(dummy.data(), 0, AES_KEY_SIZE);
            *(byte*) (&(dummy.data()[AES_KEY_SIZE - 4])) = 1;
            prf_type dummyV = Utilities::encode(dummy.data(), NEWKEY);

            curItem.first = dummyV;

            prf_type newPos;
            memset(newPos.data(), 0, AES_KEY_SIZE);
            *(int*) (&(newPos[0])) = binNumber;

            curItem.second = Utilities::encode(newPos.data(), NEWKEY);
            result.push_back(curItem);
            count--;
        }
        beginStep = (bi - value);
    }
    for (int j = (beginStep - (bi - value)); j < value && count > 0; j++) {
        pair<prf_type, prf_type> curItem;
        prf_type dummy;
        memset(dummy.data(), 0, AES_KEY_SIZE);
        *(byte*) (&(dummy.data()[AES_KEY_SIZE - 4])) = 1;
        prf_type dummyV = Utilities::encode(dummy.data(), NEWKEY);

        curItem.first = dummyV;

        prf_type newPos;
        memset(newPos.data(), 0, AES_KEY_SIZE);
        *(int*) (&(newPos[0])) = 999999999;

        curItem.second = Utilities::encode(newPos.data(), NEWKEY);
        result.push_back(curItem);
        count--;

    }

    return result;
}

void OneChoiceSDdGeneralClient::mergeSplit(vector<Entry2 > A0, vector<Entry2 > A1, unsigned int bitIndex, vector<Entry2 >& A0prime, vector<Entry2 >& A1prime, bool permute, int n, int beginStep, int count, int bucketSizeZ, int index, UpdateData& updateData) {

    //void OneChoiceSDdGeneralClient::mergeSplit2(int A0_index1, int A0_index2, int A1_index1, int A1_index2, unsigned int bitIndex, int A0prime_index1, int A0prime_index2, int A1prime_index1, int A1prime_index2, bool permute, int n, int beginStep, int count, int bucketSizeZ, int index, UpdateData& updateData) {
    int currentStep = 0;
    int curSteps = 0;

    // n steps
    //    int A0Size = updateData.getArrayAs2Size(A0_index1, A0_index2);
    int A0Size = A0.size();
    curSteps = A0Size;
    //    cout << "A0:" << endl;
    if (beginStep >= currentStep && beginStep < currentStep + curSteps) {
        int forwardStep = beginStep - currentStep;
        for (int i = forwardStep; i < A0Size && count > 0; i++) {
            prf_type el;
            //            Entry2 A0i = updateData.getArrayAs2Entry(A0_index1, A0_index2, i);
            Entry2 A0i = A0[i];
            //            el = A0i.element.first;
            Utilities::decode(A0i.element.first, el, NEWKEY);
            if (*(long*) el.data() != 0 || *(byte*) (&(el.data()[AES_KEY_SIZE - 4])) == 1) {
                //                cout << *((int*) (&(el.data()[1]))) << " ";
                prf_type plaintext, tmp;
                //                plaintext = A0i.key;
                //                tmp = A0i.element.second;
                Utilities::decode(A0i.key, plaintext, NEWKEY);
                Utilities::decode(A0i.element.second, tmp, NEWKEY);
                int label = *((int*) (&(plaintext.data()[1])));
                int targetBit = (label >> (bitIndex));
                A0i.element.first = Utilities::encode(el.data(), NEWKEY);
                A0i.element.second = Utilities::encode(tmp.data(), NEWKEY);
                A0i.key = Utilities::encode(plaintext.data(), NEWKEY);

                if ((1 & targetBit) == 1) {
                    //                    updateData.insertEntryInArrayAs2(A1prime_index1, A1prime_index2, A0i);
                    A1prime.push_back(A0i);
                } else {
                    //                    updateData.insertEntryInArrayAs2(A0prime_index1, A0prime_index2, A0i);
                    A0prime.push_back(A0i);
                }
            }
            count--;
        }

        beginStep = count > 0 ? (currentStep + curSteps) : beginStep;
    }
    //    cout << endl;
    currentStep += curSteps;


    //    int A1Size = updateData.getArrayAs2Size(A1_index1, A1_index2);
    int A1Size = A1.size();
    curSteps = A1Size;
    //    cout << "A1:" << endl;
    if (beginStep >= currentStep && beginStep < currentStep + curSteps) {
        int forwardStep = beginStep - currentStep;
        for (int i = forwardStep; i < A1Size && count > 0; i++) {
            prf_type el;
            //            Entry2 A1i = updateData.getArrayAs2Entry(A1_index1, A1_index2, i);
            Entry2 A1i = A1[i];
            //            el = A1i.element.first;
            Utilities::decode(A1i.element.first, el, NEWKEY);
            if (*(long*) el.data() != 0 || *(byte*) (&(el.data()[AES_KEY_SIZE - 4])) == 1) {
                //                cout << *((int*) (&(el.data()[1]))) << " ";
                prf_type plaintext, tmp;
                //                plaintext = A1i.key;
                //                tmp = A1i.element.second;
                Utilities::decode(A1i.key, plaintext, NEWKEY);
                Utilities::decode(A1i.element.second, tmp, NEWKEY);
                int label = *((int*) (&(plaintext.data()[1])));
                int targetBit = (label >> (bitIndex));
                A1i.element.first = Utilities::encode(el.data(), NEWKEY);
                A1i.element.second = Utilities::encode(tmp.data(), NEWKEY);
                A1i.key = Utilities::encode(plaintext.data(), NEWKEY);
                if ((1 & targetBit) == 1) {
                    //                    updateData.insertEntryInArrayAs2(A1prime_index1, A1prime_index2, A1i);
                    A1prime.push_back(A1i);
                } else {
                    //                    updateData.insertEntryInArrayAs2(A0prime_index1, A0prime_index2, A1i);
                    A0prime.push_back(A1i);
                }
            }
            count--;
        }
        beginStep = count > 0 ? (currentStep + curSteps) : beginStep;
    }
    //    cout << endl;
    currentStep += curSteps;

    //    int A0primeSize = updateData.getArrayAs2Size(A0prime_index1, A0prime_index2);
    //    int A1primeSize = updateData.getArrayAs2Size(A1prime_index1, A1prime_index2);
    int A0primeSize = A0prime.size();
    int A1primeSize = A1prime.size();

    if (permute) {
        curSteps = A0primeSize * log2(A0primeSize);
        if (A0primeSize > 0 && beginStep >= currentStep && beginStep < currentStep + curSteps) {
            int relativeBegin = beginStep - currentStep;
            int relativeCount = (count + relativeBegin) >= curSteps ? (curSteps - relativeBegin) : count;
            if (count > 0) {
                //                permuteBucket(A0prime, relativeBegin, relativeCount, index, updateData);
            }
        }
        curSteps = bucketSizeZ * log2(bucketSizeZ);
        count = (count + beginStep) > currentStep + curSteps ? count + beginStep - (currentStep + curSteps) : 0;
        beginStep = count > 0 ? (currentStep + curSteps) : beginStep;

        currentStep += curSteps;

        curSteps = A1primeSize * log2(A1primeSize);
        if (A1primeSize > 0 && beginStep >= currentStep && beginStep < currentStep + curSteps) {
            int relativeBegin = beginStep - currentStep;
            int relativeCount = (count + relativeBegin) >= curSteps ? (curSteps - relativeBegin) : count;
            if (count > 0) {
                //                permuteBucket(A1prime, relativeBegin, relativeCount, index, updateData);
            }
        }
        curSteps = bucketSizeZ * log2(bucketSizeZ);
        count = (count + beginStep) > currentStep + curSteps ? count + beginStep - (currentStep + curSteps) : 0;
        beginStep = count > 0 ? (currentStep + curSteps) : beginStep;

        currentStep += curSteps;
    }


    int size = A0Size;

    curSteps = A0Size - A0primeSize;
    if (beginStep >= currentStep && beginStep < currentStep + size) {
        //        int forwardStep = beginStep - currentStep;
        for (int i = A0primeSize; i < size && count > 0; i++) {
            Entry2 dummyEntry;
            prf_type dummyElement, dummyKey;
            std::fill(dummyElement.begin(), dummyElement.end(), 0);
            //                        *(byte*) (&(dummyElement.data()[0])) = 1;
            //            prf_type encElement = dummyElement;
            prf_type encElement = Utilities::encode(dummyElement.data(), NEWKEY);
            //            prf_type encElement2 = dummyElement;
            prf_type encElement2 = Utilities::encode(dummyElement.data(), NEWKEY);

            std::fill(dummyKey.begin(), dummyKey.end(), 0);
            //            prf_type encKey = dummyElement;
            prf_type encKey = Utilities::encode(dummyElement.data(), NEWKEY);

            dummyEntry.element.first = encElement;
            dummyEntry.element.second = encElement2;
            dummyEntry.key = encKey;
            //            updateData.insertEntryInArrayAs2(A0prime_index1, A0prime_index2, dummyEntry);
            A0prime.push_back(dummyEntry);

            count--;
        }
        beginStep = count > 0 ? (currentStep + size) : beginStep;
    }
    currentStep += size;

    curSteps = A1Size - A1primeSize;
    if (beginStep >= currentStep && beginStep < currentStep + size) {
        //        int forwardStep = beginStep - currentStep;
        for (int i = A1primeSize; i < size && count > 0; i++) {
            Entry2 dummyEntry;
            prf_type dummyElement, dummyKey;
            std::fill(dummyElement.begin(), dummyElement.end(), 0);
            //            *(byte*) (&(dummyElement.data()[0])) = 1;
            //            prf_type encElement = dummyElement;
            prf_type encElement = Utilities::encode(dummyElement.data(), NEWKEY);
            //            prf_type encElement2 = dummyElement;
            prf_type encElement2 = Utilities::encode(dummyElement.data(), NEWKEY);

            std::fill(dummyKey.begin(), dummyKey.end(), 0);
            //            prf_type encKey = dummyElement;
            prf_type encKey = Utilities::encode(dummyElement.data(), NEWKEY);

            dummyEntry.element.first = encElement;
            dummyEntry.element.second = encElement2;
            dummyEntry.key = encKey;
            //            updateData.insertEntryInArrayAs2(A1prime_index1, A1prime_index2, dummyEntry);
            A1prime.push_back(dummyEntry);

            count--;
        }
        beginStep = count > 0 ? (currentStep + size) : beginStep;
    }
    currentStep += size;
    //    cout << "A0prime.size" << A0prime.size() << endl;
}

void OneChoiceSDdGeneralClient::permuteBucket(vector<Entry2 >& bucket, int beginStep, int count, int index, UpdateData& updateData) {

    //    int bucketSize = updateData.getArrayAs2Size(bucket_index1, bucket_index2);
    int bucketSize = bucket.size();
    if (beginStep == 0) {
        updateData.labeledEntries2.clear();
        //        updateData.clearLabeledEntries2();
        for (int i = 0; i < bucketSize; i++) {
            std::array<uint8_t, TMP_AES_KEY_SIZE> plain;
            memset(plain.data(), 0, TMP_AES_KEY_SIZE);
            *(int*) (&(plain[0])) = rand();
            prf_type enc = Utilities::encode(plain.data(), NEWKEY);
            unsigned int label = (unsigned int) (*((unsigned int*) enc.data())) % 65536;
            //            updateData.putIntInArrayAs2Place(bucket_index1, bucket_index2, i,label);
            //            Entry2 bucketi = updateData.getArrayAs2Entry(bucket_index1, bucket_index2, i);
            //            updateData.pushBackLabeledEntries2(pair<Entry2, int>(bucketi, label));
            updateData.labeledEntries2.push_back(pair<Entry2, int>(bucket[i], label));
        }
        //        updateData.transferArrayAs2ToLabeledEntries2(bucket_index1, bucket_index2,bucketSize);
    }
    int stepCounter = 0;
    if (beginStep == 0) {
        //        updateData.clearArray4();
        updateData.leftArray4.clear();
        updateData.rightArray4.clear();
        updateData.indexOfSubArrayOne.clear();
        updateData.indexOfSubArrayTwo.clear();
        updateData.indexOfMergedArray.clear();
    }
    mergeSort(&updateData.labeledEntries2, 0, updateData.labeledEntries2.size() - 1, beginStep, count, index, updateData);
}

void OneChoiceSDdGeneralClient::mergeSort(vector<pair<Entry2, unsigned int> >* array, int const begin, int const end, int beginStep, int& count, int index, UpdateData& updateData) {
    int curr_size = 1; // For current size of subarrays to be merged
    int left_start = 0; // For picking starting index of left subarray
    int n = end;
    int forwardStep = beginStep;
    int outterForward = (int) pow(2, (int) (forwardStep / (n + 1)));
    int innerForward = ((forwardStep % (n + 1)) / (outterForward * 2))*(2 * outterForward);
    curr_size = outterForward;
    left_start = innerForward;

    for (; curr_size <= n && count > 0; curr_size = 2 * curr_size) {
        for (; left_start < n && count > 0; left_start += 2 * curr_size) {
            int mid = min(left_start + curr_size - 1, n);
            int right_end = min(left_start + 2 * curr_size - 1, n);
            merge(array, left_start, mid, right_end, count, index, n * curr_size + left_start, updateData);
        }
        left_start = 0;
    }
}

void OneChoiceSDdGeneralClient::merge(vector<pair<Entry2, unsigned int> >* array, int const left, int const mid, int const right, int& count, int index, int innerMapCounter, UpdateData& updateData) {
    auto const subArrayOne = mid - left + 1;
    auto const subArrayTwo = right - mid;
    const int beginStepCounter = innerMapCounter;

    if (updateData.indexOfMergedArray.count(beginStepCounter) == 0) {
        updateData.leftArray4.clear();
        updateData.rightArray4.clear();
        for (auto i = 0; i < subArrayOne; i++) {
            updateData.leftArray4.push_back((*array)[left + i]);
        }
        for (auto j = 0; j < subArrayTwo; j++) {
            updateData.rightArray4.push_back((*array)[mid + 1 + j]);
        }
        updateData.indexOfSubArrayOne[beginStepCounter] = 0;
        updateData.indexOfSubArrayTwo[beginStepCounter] = 0;
        updateData.indexOfMergedArray[beginStepCounter] = left;
    }


    while (updateData.indexOfSubArrayOne[beginStepCounter] < subArrayOne && updateData.indexOfSubArrayTwo[beginStepCounter] < subArrayTwo && count > 0) {
        if (compare(updateData.leftArray4[updateData.indexOfSubArrayOne[beginStepCounter]], updateData.rightArray4[updateData.indexOfSubArrayTwo[beginStepCounter]])) {
            (*array)[updateData.indexOfMergedArray[beginStepCounter]] = updateData.leftArray4[updateData.indexOfSubArrayOne[beginStepCounter]];
            updateData.indexOfSubArrayOne[beginStepCounter]++;
        } else {
            (*array)[updateData.indexOfMergedArray[beginStepCounter]] = updateData.rightArray4[updateData.indexOfSubArrayTwo[beginStepCounter]];
            updateData.indexOfSubArrayTwo[beginStepCounter]++;
        }
        updateData.indexOfMergedArray[beginStepCounter]++;
        count--;
    }
    while (updateData.indexOfSubArrayOne[beginStepCounter] < subArrayOne && count > 0) {
        (*array)[updateData.indexOfMergedArray[beginStepCounter]] = updateData.leftArray4[updateData.indexOfSubArrayOne[beginStepCounter]];
        updateData.indexOfSubArrayOne[beginStepCounter]++;
        updateData.indexOfMergedArray[beginStepCounter]++;
        count--;
    }
    while (updateData.indexOfSubArrayTwo[beginStepCounter] < subArrayTwo && count > 0) {
        (*array)[updateData.indexOfMergedArray[beginStepCounter]] = updateData.rightArray4[updateData.indexOfSubArrayTwo[beginStepCounter]];
        updateData.indexOfSubArrayTwo[beginStepCounter]++;
        updateData.indexOfMergedArray[beginStepCounter]++;
        count--;
    }
}

bool OneChoiceSDdGeneralClient::compare(pair<Entry2, unsigned int> lhs, pair<Entry2, unsigned int> rhs) {
    unsigned int left = ((pair<Entry2, unsigned int>*) & lhs)->second;
    unsigned int right = ((pair<Entry2, unsigned int>*) & rhs)->second;
    if (left <= right) {
        return true;
    } else {
        return false;
    }
}

void OneChoiceSDdGeneralClient::removeDummies2(int level, int bucketSizeZ, int beginStep, int count, int index, UpdateData& updateData) {
    int i = 0, j = 0;
    int forwardStep = beginStep;
    i = forwardStep / bucketSizeZ;
    j = forwardStep % bucketSizeZ;
    for (; i < updateData.bucketNumberB && count > 0; i++) {
        vector<Entry2> buk = updateData.getArrayAs2Bucket(level, i);
        vector<pair<prf_type, prf_type> > out;
        for (; j < updateData.bucketSizeZ && count > 0; j++) {
            prf_type el;
            //            Entry2 arrayAsij = updateData.getArrayAs2Entry(level, i, j);
            Entry2 arrayAsij = buk[j];
            //            el = arrayAsij.element.first;
            Utilities::decode(arrayAsij.element.first, el, NEWKEY);
            if (*(long*) el.data() != 0 || *(byte*) (&(el.data()[AES_KEY_SIZE - 4])) == 1) {
                //                updateData.insertInPermutedArrayWithNoDummy2Entry(arrayAsij.element);
                out.push_back(arrayAsij.element);
            }
            count--;
        }
        updateData.insertVectorInPermutedArrayWithNoDummy2Entry(out);
        j = 0;
    }
}

bool OneChoiceSDdGeneralClient::binCompare(pair<prf_type, prf_type> lhs, pair<prf_type, prf_type> rhs) {
    //    prf_type left = lhs.second, right = rhs.second;
    prf_type left, right;
    prf_type lp, rp;
    Utilities::decode(lhs.second, left, NEWKEY);
    Utilities::decode(rhs.second, right, NEWKEY);
    Utilities::decode(lhs.first, lp, NEWKEY);
    //    prf_type lp = lhs.first;
    int lval = *(int*) (&(left[0]));
    int rval = *(int*) (&(right[0]));

    if (lval < rval || (lval == rval && (*(long*) lp.data() != 0)) || rval == 999999999) {
        return true;
    } else {
        return false;
    }

}

bool OneChoiceSDdGeneralClient::buf2Compare(pair<prf_type, prf_type> lhs, pair<prf_type, prf_type> rhs) {
    //    prf_type left = lhs.second, right = rhs.second;
    prf_type left, right;
    Utilities::decode(lhs.second, left, NEWKEY);
    Utilities::decode(rhs.second, right, NEWKEY);
    int lval = *(int*) (&(left.data()[0]));
    int rval = *(int*) (&(right.data()[0]));

    if (lval >= rval) {
        return true;
    } else {
        return false;
    }

}

prf_type OneChoiceSDdGeneralClient::makeReadyForStore(prf_type encryptedValue) {
    prf_type tmp;
    Utilities::decode(encryptedValue, tmp, NEWKEY);
    if (*(long*) tmp.data() == 0) {
        memset(tmp.data(), 0, AES_KEY_SIZE);
    } else {
        string test((char*) tmp.data());
    }
    prf_type res = Utilities::encode(tmp.data(), NEWKEY);
    return res;
}

pair<prf_type, prf_type> OneChoiceSDdGeneralClient::getInitialDummy2() {
    prf_type newvalue;
    std::fill(newvalue.begin(), newvalue.end(), 0);
    //    *(byte*) (&(newvalue.data()[0])) = 1;
    prf_type t1 = Utilities::encode(newvalue.data(), NEWKEY);
    prf_type t2 = Utilities::encode(newvalue.data(), NEWKEY);
    return pair<prf_type, prf_type>(t1, t2);
}

vector<prf_type> OneChoiceSDdGeneralClient::getRandomKeys2(int n, int bucketNumberB, int begin, int count, int index) {
    vector<prf_type> keys;
    for (int i = begin; i < n && count > 0; i++) {
        std::array<uint8_t, TMP_AES_KEY_SIZE> plain;
        memset(plain.data(), 0, TMP_AES_KEY_SIZE);
        *(int*) (&(plain[0])) = i;
        prf_type enc = Utilities::encode(plain.data(), NEWKEY);
        unsigned int bucketId = (unsigned int) (*((unsigned int*) enc.data())) % bucketNumberB;

        prf_type newvalue;
        std::fill(newvalue.begin(), newvalue.end(), 0);
        *(int*) (&(newvalue.data()[1])) = bucketId;
        prf_type mapValue = Utilities::encode(newvalue.data(), NEWKEY);
        keys.push_back(mapValue);
        count--;
    }
    return keys;
}

pair<prf_type, prf_type> OneChoiceSDdGeneralClient::prepareKWCounter(pair<prf_type, prf_type> entry) {
    prf_type myTest;
    Utilities::decode(entry.second, myTest, NEWKEY);
    prf_type plaintext;
    Utilities::decode(entry.first, plaintext, NEWKEY);
    unsigned char cntstr[AES_KEY_SIZE];
    memset(cntstr, 0, AES_KEY_SIZE);
    *(long*) (&(cntstr[AES_KEY_SIZE - 5])) = (long) - 1;

    string keyword((char*) plaintext.data());

    prf_type K1 = Utilities::encode(keyword, NEWKEY);
    prf_type mapKey;
    mapKey = Utilities::generatePRF(cntstr, K1.data());
    prf_type valueTmp;
    memset(valueTmp.data(), 0, AES_KEY_SIZE);
    *(long*) (&(valueTmp[0])) = (long) *(int*) (&(plaintext.data()[AES_KEY_SIZE - 5]));
    prf_type mapValue = Utilities::encode(valueTmp.data(), K1.data());


    pair<prf_type, prf_type> res;
    res.first = mapKey;
    res.second = mapValue;
    return res;
}

void OneChoiceSDdGeneralClient::endSetup(bool overwrite) {
    server->endSetup(overwrite);
    if (overwrite) {
        transData.endSetup();
    }
}

void OneChoiceSDdGeneralClient::beginSetup() {
    server->beginSetup();
    transData.useDisk = false;
}