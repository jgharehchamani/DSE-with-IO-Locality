#include "OneChoiceSDdGeneralServer.h"
#include <string.h>
#include <vector>
#include "OneChoiceSDdGeneralClient.h"

OneChoiceSDdGeneralServer::OneChoiceSDdGeneralServer(long dataIndex, bool inMemory, bool overwrite, bool profile, prf_type initialDummy, OneChoiceSDdGeneralClient* client, bool storeKWCounter) {
    this->profile = profile;
    this->storeKWCounter = storeKWCounter;
    this->initialDummy = initialDummy;
    this->initialDummy2.first = initialDummy;
    this->initialDummy2.second = initialDummy;
    this->client = client;
    this->dataIndex = dataIndex;
    storage = new OneChoiceStorage*[4];
    keywordCounters = new Storage*[4];
    for (int i = 0; i < 4; i++) {
        storage[i] = new OneChoiceStorage(inMemory, dataIndex, Utilities::rootAddress + "OneChoice-" + to_string(i) + "-", profile);
        storage[i]->setup(overwrite);
        if (storeKWCounter) {
            keywordCounters[i] = new Storage(inMemory, dataIndex, Utilities::rootAddress + "OneChoice-" + to_string(i) + "-" + "keyword-", profile);
            keywordCounters[i]->setup(overwrite);
        }
    }
    for (int j = 0; j < 4; j++) {
        data.push_back(vector< vector<vector<prf_type> >* >());
        for (int i = 0; i < dataIndex; i++) {
            auto item = new vector<vector<prf_type> >();
            data[j].push_back(item);
        }
    }
    for (int j = 0; j < 4; j++) {
        keywordData.push_back(vector<EachSet2*>());
        for (int i = 0; i < dataIndex; i++) {
            EachSet2* curData = new EachSet2();
            keywordData[j].push_back(curData);
        }
    }
    for (int j = 0; j < dataIndex; j++) {
        int curNumberOfBins = j > 1 ?
                (int) ceil(((float) pow(2, j)) / (float) (log2(pow(2, j)) * log2(log2(pow(2, j))))) : 1;
        int curSizeOfEachBin = j > 1 ? 3 * (log2(pow(2, j))*(log2(log2(pow(2, j))))) : pow(2, j);
        numberOfBins.push_back(curNumberOfBins);
        sizeOfEachBin.push_back(curSizeOfEachBin);
        //        printf("Index:%d #of Bins:%d size of bin:%d is:%d\n", j, curNumberOfBins, curSizeOfEachBin, is);
        //#########################################################
        //   For UPDATE should be Uncommented
        //#########################################################
                int n = (numberOfBins[j] * sizeOfEachBin[j])*2;
                UpdateData curData(n, j, dataIndex);
                updateData.push_back(curData);
        
                updateData[j].bucketNumberB = (int) ceil(2 * n / updateData[j].bucketSizeZ);
                int power = 1;
                while (power < updateData[j].bucketNumberB) {
                    power *= 2;
                }
                updateData[j].bucketNumberB = power == 1 ? 2 : power;
                updateData[j].numberOfLevels = (int) (log2(updateData[j].bucketNumberB)) + 1;
                updateData[j].initialPerBucketCount = ceil((double) n / (double) updateData[j].bucketNumberB);
                updateData[j].totalNumberOfSteps = updateData[j].getTotalNumberOfSteps(updateData[j].numberOfDataEntries);
                updateData[j].fixedTotalNumberOfSteps = updateData[j].getTotalNumberOfSteps(updateData[j].numberOfDataEntries);
        //#########################################################
    }
    //#########################################################
    //   For UPDATE should be Uncommented
    //#########################################################
        for (int j = 0; j < dataIndex; j++) {
            updateData[j].setup(numberOfBins[dataIndex - 1]);
        }
        transData.setup(dataIndex);
    //#########################################################
}

OneChoiceSDdGeneralServer::~OneChoiceSDdGeneralServer() {
}

void OneChoiceSDdGeneralServer::storeKeywordCounters(long instance, long dataIndex, unordered_map<prf_type, prf_type, PRFHasher>* kwCounters) {
    if (hdd) {
        keywordCounters[instance]->insert(dataIndex, *kwCounters, true);
    } else {
        delete keywordData[instance][dataIndex]->setData;
        keywordData[instance][dataIndex]->setData = kwCounters;
    }
}

void OneChoiceSDdGeneralServer::storeCiphers(long instance, long dataIndex, vector<vector<prf_type> >* ciphers) {
    if (hdd) {
        storage[instance]->insertAll(dataIndex, (*ciphers), false, true);
    } else {
        delete data[instance][dataIndex];
        data[instance][dataIndex] = &(*ciphers);
    }
}

void OneChoiceSDdGeneralServer::storeCiphers(long instance, long dataIndex) {
    if (hdd) {
        vector < vector<prf_type> > data;
        for (int i = 0; i < numberOfBins[dataIndex]; i++) {
            vector<prf_type> column = updateData[dataIndex - 1].getCiphertexts(i);
            data.push_back(column);
        }
        storage[instance]->insertAll(dataIndex, data, false, true);
    } else {
        delete data[instance][dataIndex];
        data[instance][dataIndex] = updateData[dataIndex - 1].getAllCiphertexts();
    }
}

void OneChoiceSDdGeneralServer::storeCiphers(long instance, long dataIndex, vector<vector<prf_type> >* ciphers, unordered_map<prf_type, prf_type, PRFHasher>* kwCounters) {
    if (hdd) {
        storage[instance]->insertAll(dataIndex, (*ciphers));
        keywordCounters[instance]->insert(dataIndex, *kwCounters);
    } else {
        delete data[instance][dataIndex];
        data[instance][dataIndex] = ciphers;
        keywordData[instance][dataIndex]->setData = kwCounters;
    }
}

void OneChoiceSDdGeneralServer::storeCiphers(long instance, long dataIndex, vector<prf_type> ciphers, bool firstRun) {
    if (hdd) {
        storage[instance]->insertAll(dataIndex, ciphers, true, firstRun, true);
    } else {
        if (firstRun) {
            delete data[instance][dataIndex];
            data[instance][dataIndex] = new vector<vector<prf_type> >();
        }
        (*(data[instance][dataIndex])).push_back(ciphers);
    }
}

//void OneChoiceSDdGeneralServer::storeCiphers(long instance, long dataIndex, vector<vector<prf_type> > ciphers, bool firstRun) {
//    if (hdd) {
//        storage[instance]->insertAll(dataIndex, ciphers, true, firstRun,true);
//    } else {
//        cout<<"extra: Not implemented yet"<<endl;
//    }
//}

long OneChoiceSDdGeneralServer::getCounter(long instance, long dataIndex, prf_type tokkw) {
    if (hdd) {
        prf_type curToken = tokkw;
        unsigned char cntstr[AES_KEY_SIZE];
        memset(cntstr, 0, AES_KEY_SIZE);
        *(long*) (&(cntstr[AES_KEY_SIZE - 5])) = -1;
        prf_type keywordMapKey = Utilities::generatePRF(cntstr, curToken.data());
        bool found = false;
        prf_type res = keywordCounters[instance]->find(dataIndex, keywordMapKey, found);
        int keywordCnt = 0;
        if (found) {
            prf_type plaintext;
            Utilities::decode(res, plaintext, curToken.data());
            keywordCnt = *(long*) (&(plaintext[0]));
        }
        return keywordCnt;
    } else {
        prf_type curToken = tokkw;
        unsigned char cntstr[AES_KEY_SIZE];
        memset(cntstr, 0, AES_KEY_SIZE);
        *(long*) (&(cntstr[AES_KEY_SIZE - 5])) = -1;
        prf_type keywordMapKey = Utilities::generatePRF(cntstr, curToken.data());
        bool found = false;
        prf_type res;
        if (keywordData[instance][dataIndex]->setData->count(keywordMapKey) != 0) {
            res = (*(keywordData[instance][dataIndex]->setData))[keywordMapKey];
            found = true;
        }
        int keywordCnt = 0;
        if (found) {
            prf_type plaintext;
            Utilities::decode(res, plaintext, curToken.data());
            keywordCnt = *(long*) (&(plaintext[0]));
        }
        return keywordCnt;
    }
}

vector<prf_type> OneChoiceSDdGeneralServer::search(long instance, long dataIndex, prf_type token, long keywordCnt) {
    serverSearchTime = 0;
    Utilities::startTimer(43);
    if (storeKWCounter) {
        keywordCounters[instance]->seekgCount = 0;
    }
    storage[instance]->readBytes = 0;
    double keywordCounterTime = 0;
    if (profile) {
        Utilities::startTimer(35);
    }
    prf_type curToken = token;
    unsigned char cntstr[AES_KEY_SIZE];
    memset(cntstr, 0, AES_KEY_SIZE);
    *(int*) (&(cntstr[AES_KEY_SIZE - 5])) = -1;
    prf_type keywordMapKey = Utilities::generatePRF(cntstr, curToken.data());
    bool found = false;
    prf_type res;
    if (profile && storeKWCounter) {
        keywordCounterTime = Utilities::stopTimer(35);
        cout << "[[" << keywordCounterTime << "]]" << endl;
        //printf("keyword counter Search Time:%f number of SeekG:%d number of read bytes:%d\n", keywordCounterTime, keywordCounters->seekgCount, keywordCounters->KEY_VALUE_SIZE * keywordCounters->seekgCount);
    }
    serverSearchTime = Utilities::stopTimer(43);
    vector<prf_type> result;
    if (keywordCnt > 0) {
        if (hdd) {
            result = storage[instance]->find(dataIndex, keywordMapKey, keywordCnt);
        } else {
            //            result = 
        }
    }
    return result;
}

vector<prf_type> OneChoiceSDdGeneralServer::getAllDataFlat(long instance, long dataIndex) {
    if (hdd) {
        return storage[instance]->getAllDataFlat(dataIndex);
    } else {
        vector<prf_type > res;
        for (int i = 0; i < (*(data[instance][dataIndex])).size(); i++) {
            res.insert(res.end(), (*(data[instance][dataIndex]))[i].begin(), (*(data[instance][dataIndex]))[i].end());
        }
        return res;
    }
}

vector<vector<prf_type> >* OneChoiceSDdGeneralServer::getAllData(long instance, long dataIndex) {
    if (hdd) {
        return storage[instance]->getAllData(dataIndex);
    } else {
        return data[instance][dataIndex];
    }
}

unordered_map<prf_type, prf_type, PRFHasher>* OneChoiceSDdGeneralServer::getAllKWCounters(long instance, long dataIndex) {
    if (hdd) {
        return keywordCounters[instance]->getAllDataPairs(dataIndex);
    } else {
        return keywordData[instance][dataIndex]->setData;
    }
}

void OneChoiceSDdGeneralServer::resetup(long instance, long index) {
    if (hdd) {
        storage[instance]->clear(index);
        if (storeKWCounter) {
            keywordCounters[instance]->clear(index);
        }
    } else {
        data[instance][index] = new vector<vector<prf_type> >();
        keywordData[instance][index]->setData = new unordered_map<prf_type, prf_type, PRFHasher>();
    }
}

void OneChoiceSDdGeneralServer::clear(long instance, long index) {
    if (hdd) {
        storage[instance]->clear(index);
        if (storeKWCounter) {
            keywordCounters[instance]->clear(index);
        }
    } else {
        data[instance][index]->clear();
        keywordData[instance][index]->setData->clear();
    }
}

void OneChoiceSDdGeneralServer::move(int fromInstance, int fromIndex, int toInstance, int toIndex) {
    if (hdd) {
        string inputFileName = storage[fromInstance]->getName(fromIndex);
        storage[fromInstance]->closeHandle(fromIndex);
        storage[toInstance]->rename(toIndex, inputFileName);
        storage[fromInstance]->resetup(fromIndex);

        inputFileName = keywordCounters[fromInstance]->getName(fromIndex);
        keywordCounters[fromInstance]->closeHandle(fromIndex);
        keywordCounters[toInstance]->rename(toIndex, inputFileName);
        keywordCounters[fromInstance]->resetup(fromIndex);
    } else {
        delete data[toInstance][toIndex];
        data[toInstance][toIndex] = data[fromInstance][fromIndex];
        delete keywordData[toInstance][toIndex]->setData;
        keywordData[toInstance][toIndex]->setData = keywordData[fromInstance][fromIndex]->setData;
        data[fromInstance][fromIndex] = new vector<vector<prf_type> >();
        keywordData[fromInstance][fromIndex]->setData = new unordered_map<prf_type, prf_type, PRFHasher>();
    }
}

bool OneChoiceSDdGeneralServer::obliviousBucketSort(int beginStep, int count, int index, int inputSize, bool (OneChoiceSDdGeneralClient::*cmpFunc)(prf_type, prf_type)) {
    int currentStep = 0;
    int curSteps = 0;
    int n = inputSize;

    if (Utilities::DEBUG_MODE) {
        cout << "level:" << index << " phase:1" << " begin first oblivious sort" << endl;
    }
    //1 step
    curSteps = 1;
    if (beginStep >= currentStep && beginStep < currentStep + curSteps) {
        count = (count + beginStep) > currentStep + curSteps ? count + beginStep - (currentStep + curSteps) : 0;
        beginStep = count > 0 ? (currentStep + curSteps) : beginStep;
    }
    currentStep += curSteps;

    //numberOfLevels*bucketNumberB
    curSteps = updateData[index].numberOfLevels * updateData[index].bucketNumberB;
    if (beginStep >= currentStep && beginStep < currentStep + curSteps) {
        int i = 0, j = 0;
        int forwardStep = beginStep - currentStep;
        i = forwardStep / updateData[index].bucketNumberB;
        j = forwardStep % updateData[index].bucketNumberB;
        for (; i < updateData[index].numberOfLevels && count > 0; i++) {
            if (j == 0) {
                updateData[index].insertInArrayAs(vector< vector<Entry > >());
            }
            for (; j < updateData[index].bucketNumberB && count > 0; j++) {
                updateData[index].insertVectorInArrayAs(i, vector<Entry >());
                count--;
            }
            j = 0;
        }

        //        count = (count + beginStep) > currentStep + curSteps ? count + beginStep - (currentStep + curSteps) : 0;
        beginStep = count > 0 ? (currentStep + curSteps) : beginStep;
    }
    currentStep += curSteps;

    //2n steps (label creation and encryption)
    curSteps = 2 * n;
    if (beginStep >= currentStep && beginStep < currentStep + curSteps) {
        int relativeBegin = beginStep - currentStep;
        int relativeCount = count + relativeBegin >= curSteps ? curSteps - relativeBegin : count;

        vector<prf_type> tmp = client->getRandomKeys(n, updateData[index].bucketNumberB, relativeBegin, relativeCount, index);
        for (int i = 0; i < tmp.size(); i++) {
            updateData[index].insertInRandomLabels(tmp[i]);
        }

        count = (count + beginStep) > currentStep + curSteps ? count + beginStep - (currentStep + curSteps) : 0;
        beginStep = count > 0 ? (currentStep + curSteps) : beginStep;
    }
    currentStep += curSteps;

    if (Utilities::DEBUG_MODE) {
        cout << "level:" << index << " phase:1" << " after create randoms first oblivious sort" << endl;
    }

    //n steps   
    curSteps = n;
    if (beginStep >= currentStep && beginStep < currentStep + curSteps) {
        int i = 0;
        int forwardStep = beginStep - currentStep;
        i = forwardStep;
        for (; i < n && count > 0; i++) {
            auto inp = pair<prf_type, prf_type>(updateData[index].getInputArrayElement(i), updateData[index].getrandomLabelsElement(i));
            updateData[index].insertInInputAssignedBuckets(inp);
            count--;
        }

        //        count = (count + beginStep) > currentStep + curSteps ? count + beginStep - (currentStep + curSteps) : 0;
        beginStep = count > 0 ? (currentStep + curSteps) : beginStep;
    }
    currentStep += curSteps;

    if (Utilities::DEBUG_MODE) {
        cout << "level:" << index << " phase:1" << " after insert in inputAssignedBuckets first oblivious sort" << endl;
    }
    //bucketNumberB * bucketSizeZ steps
    curSteps = updateData[index].bucketNumberB * updateData[index].bucketSizeZ;
    if (beginStep >= currentStep && beginStep < currentStep + curSteps) {
        int globalBucketKey = 0;
        int tmpCnt = 0;
        int i = 0;
        int forwardStep = beginStep - currentStep;
        if (forwardStep < n) {
            i = forwardStep;
            tmpCnt = forwardStep % updateData[index].initialPerBucketCount;
            globalBucketKey = forwardStep / updateData[index].initialPerBucketCount;
            for (; i < n && count > 0; i++) {
                if (tmpCnt == updateData[index].initialPerBucketCount) {
                    globalBucketKey++;
                    globalBucketKey = globalBucketKey % updateData[index].bucketNumberB;
                    tmpCnt = 0;
                }
                Entry entry;
                pair<prf_type, prf_type> iab = updateData[index].getInputAssignedBuckets(i);
                entry.element = iab.first;
                entry.key = iab.second;
                updateData[index].insertEntryInArrayAs(0, globalBucketKey, entry);
                tmpCnt++;
                count--;
            }
            forwardStep = 0;
        } else {
            forwardStep -= n;
        }
        for (int j = 0; j < updateData[index].bucketNumberB && count > 0; j++) {
            for (int k = updateData[index].getArrayAsSize(0, j); k < updateData[index].bucketSizeZ && count > 0; k++) {
                Entry dummyEntry;
                dummyEntry.element = initialDummy;
                dummyEntry.key = initialDummy;
                updateData[index].insertEntryInArrayAs(0, j, dummyEntry);
                count--;
            }
        }

        beginStep = count > 0 ? (currentStep + curSteps) : beginStep;
    }
    currentStep += curSteps;

    if (Utilities::DEBUG_MODE) {
        cout << "level:" << index << " phase:1" << " after create ArrayAs first oblivious sort" << endl;
    }


    //(numberOfLevels * bucketNumberB / 2 * merge_split cost) + bucketNumberB * ZlogZ  permutation
    //merge split cost:
    //  2*Z decryption + 2*Z encryption 
    curSteps = (((updateData[index].numberOfLevels - 1) * (updateData[index].bucketNumberB / 2) * (2 * updateData[index].bucketSizeZ * 2)) + updateData[index].bucketNumberB * updateData[index].bucketSizeZ * log2(updateData[index].bucketSizeZ));
    if (beginStep >= currentStep && beginStep < currentStep + curSteps) {
        int i = 0, j = 0, innerStep = 0;
        int forwardStep = beginStep - currentStep;
        //        if (forwardStep == 0) {
        //            decryptPermutedArrayWithNoDummyEntry(n + 1, index);
        //        }
        if (forwardStep > (((updateData[index].numberOfLevels - 2) * (updateData[index].bucketNumberB / 2) * (2 * updateData[index].bucketSizeZ * 2)))) {
            i = updateData[index].numberOfLevels - 2;
            int passedSteps = (((updateData[index].numberOfLevels - 2) * (updateData[index].bucketNumberB / 2) * (2 * updateData[index].bucketSizeZ * 2)));
            j = (forwardStep - passedSteps) / (2 * updateData[index].bucketSizeZ * 2 + updateData[index].bucketSizeZ * log2(updateData[index].bucketSizeZ) * 2);
            innerStep = (forwardStep - passedSteps) % (int) (2 * updateData[index].bucketSizeZ * 2 + updateData[index].bucketSizeZ * log2(updateData[index].bucketSizeZ) * 2);
        } else {
            i = forwardStep / ((updateData[index].bucketNumberB / 2) * 2 * updateData[index].bucketSizeZ * 2);
            j = (forwardStep / (2 * updateData[index].bucketSizeZ * 2)) % (updateData[index].bucketNumberB / 2);
            innerStep = forwardStep % (2 * updateData[index].bucketSizeZ * 2);
        }


        for (; i < updateData[index].numberOfLevels - 1 && count > 0; i++) {
            for (; j < (updateData[index].bucketNumberB / 2) && count > 0; j++) {
                int jprime = floor(j / pow(2, i)) * pow(2, i);
                bool permuteNeeded = (i == (updateData[index].numberOfLevels - 2));
                int innerCount = 0;
                if (innerStep != 0) {
                    if (permuteNeeded) {
                        innerCount = count < ((2 * updateData[index].bucketSizeZ * 2 + updateData[index].bucketSizeZ * log2(updateData[index].bucketSizeZ) * 2) - innerStep) ? count : ((2 * updateData[index].bucketSizeZ * 2 + updateData[index].bucketSizeZ * log2(updateData[index].bucketSizeZ) * 2) - innerStep);
                    } else {
                        innerCount = count < ((2 * updateData[index].bucketSizeZ * 2) - innerStep) ? count : ((2 * updateData[index].bucketSizeZ * 2) - innerStep);
                    }
                    vector<Entry> inp1 = updateData[index].getArrayAsBucket(i, j + jprime);
                    vector<Entry> inp2 = updateData[index].getArrayAsBucket(i, j + jprime + pow(2, i));
                    vector<Entry> out1 = updateData[index].getArrayAsBucket(i + 1, 2 * j);
                    vector<Entry> out2 = updateData[index].getArrayAsBucket(i + 1, 2 * j + 1);
                    client->mergeSplit(inp1, inp2, i, out1, out2, permuteNeeded, n, innerStep, innerCount, updateData[index].bucketSizeZ, index, updateData[index]);
                    updateData[index].setArrayAsBucket(i + 1, 2 * j, out1);
                    updateData[index].setArrayAsBucket(i + 1, 2 * j + 1, out2);
                    //                    client->mergeSplit(i, j + jprime, i, j + jprime + pow(2, i), i, i + 1, 2 * j, i + 1, 2 * j + 1, permuteNeeded, n, innerStep, innerCount, updateData[index].bucketSizeZ, index, updateData[index]);
                    innerStep = 0;
                } else {
                    if (permuteNeeded) {
                        innerCount = count < (2 * updateData[index].bucketSizeZ * 2 + updateData[index].bucketSizeZ * log2(updateData[index].bucketSizeZ) * 2) ? count : (2 * updateData[index].bucketSizeZ * 2 + updateData[index].bucketSizeZ * log2(updateData[index].bucketSizeZ) * 2);
                    } else {
                        innerCount = count < (2 * updateData[index].bucketSizeZ * 2) ? count : (2 * updateData[index].bucketSizeZ * 2);
                    }
                    vector<Entry> inp1 = updateData[index].getArrayAsBucket(i, j + jprime);
                    vector<Entry> inp2 = updateData[index].getArrayAsBucket(i, j + jprime + pow(2, i));
                    vector<Entry> out1 = updateData[index].getArrayAsBucket(i + 1, 2 * j);
                    vector<Entry> out2 = updateData[index].getArrayAsBucket(i + 1, 2 * j + 1);
                    client->mergeSplit(inp1, inp2, i, out1, out2, permuteNeeded, n, 0, innerCount, updateData[index].bucketSizeZ, index, updateData[index]);
                    updateData[index].setArrayAsBucket(i + 1, 2 * j, out1);
                    updateData[index].setArrayAsBucket(i + 1, 2 * j + 1, out2);
                    //                    client->mergeSplit(i, j + jprime, i, j + jprime + pow(2, i), i, i + 1, 2 * j, i + 1, 2 * j + 1, permuteNeeded, n, 0, innerCount, updateData[index].bucketSizeZ, index, updateData[index]);
                }
                count = count - innerCount;
            }
            j = 0;
        }
        beginStep = count > 0 ? (currentStep + curSteps) : beginStep;
    }
    currentStep += curSteps;

    if (Utilities::DEBUG_MODE) {
        cout << "level:" << index << " phase:1" << " after merge split first oblivious sort" << endl;
    }

    //bucketNumberB * bucketSizeZ steps
    curSteps = updateData[index].bucketNumberB * updateData[index].bucketSizeZ;
    if (beginStep >= currentStep && beginStep < currentStep + curSteps) {
        int relativeBegin = beginStep - currentStep;
        int relativeCount = count + relativeBegin >= curSteps ? curSteps - relativeBegin : count;
        //        auto tmp = client->removeDummies(updateData[index].getArrayAsLevel(updateData[index].numberOfLevels - 1), updateData[index].bucketSizeZ, relativeBegin, relativeCount, index);
        //        for (int i = 0; i < tmp.size(); i++) {
        //            updateData[index].insertInPermutedArrayWithNoDummyEntry(tmp[i]);
        //        }
        client->removeDummies(updateData[index].numberOfLevels - 1, updateData[index].bucketSizeZ, relativeBegin, relativeCount, index, updateData[index]);

        count = (count + beginStep) > currentStep + curSteps ? count + beginStep - (currentStep + curSteps) : 0;
        beginStep = count > 0 ? (currentStep + curSteps) : beginStep;
    }
    currentStep += curSteps;

    if (Utilities::DEBUG_MODE) {
        cout << "level:" << index << " phase:1" << " after remove dummies first oblivious sort" << endl;
    }

    bool completed = false;
    //n log n steps
    curSteps = n * ceil(log2(n));
    if (beginStep >= currentStep && beginStep < currentStep + curSteps) {
        int relativeBegin = beginStep - currentStep;
        int relativeCount = count + relativeBegin >= curSteps ? curSteps - relativeBegin : count;

        int stepCounter = 0;
        if (relativeBegin == 0) {
            updateData[index].clearBeforeMergeSort();
            //            updateData[index].leftArray.clear();
            //            updateData[index].rightArray.clear();
            updateData[index].indexOfSubArrayOne.clear();
            updateData[index].indexOfSubArrayTwo.clear();
            updateData[index].indexOfMergedArray.clear();
        }
        mergeSort(0, n - 1, relativeBegin, relativeCount, index, cmpFunc);
        completed = (count + beginStep) >= currentStep + curSteps ? true : false;
        //        if (completed) {
        //            encryptPermutedArrayWithNoDummyEntry(n, index);
        //        }
        updateData[index].flushPermutedArrayWithNoDummyEntry();
        count = (count + beginStep) > currentStep + curSteps ? count + beginStep - (currentStep + curSteps) : 0;
        beginStep = count > 0 ? (currentStep + curSteps) : beginStep;
    }
    currentStep += curSteps;

    if (Utilities::DEBUG_MODE) {
        cout << "level:" << index << " phase:1" << " after merge sort first oblivious sort" << endl;
    }

    return completed;
}

void OneChoiceSDdGeneralServer::merge(int const left, int const mid, int const right, int& count, int index, int innerMapCounter, bool (OneChoiceSDdGeneralClient::*cmpFunc)(prf_type, prf_type)) {
    auto const subArrayOne = mid - left + 1;
    auto const subArrayTwo = right - mid;
    const int beginStepCounter = innerMapCounter;


    if (updateData[index].indexOfMergedArray.count(beginStepCounter) == 0) {
        //        updateData[index].flushPermutedArrayWithNoDummyEntry();
        updateData[index].clearLeftArray();
        updateData[index].clearRightArray();
        //        updateData[index].transferPermutedArrayWithNoDummyEntrytoLeftArray(left, subArrayOne);
        for (auto i = 0; i < subArrayOne; i++) {
            prf_type inp = updateData[index].getPermutedArrayWithNoDummyEntry(left + i);
            updateData[index].insertInLeftArray(i, inp);
        }
        //        updateData[index].transferPermutedArrayWithNoDummyEntrytoRightArray(mid + 1, subArrayTwo);
        for (auto j = 0; j < subArrayTwo; j++) {
            prf_type inp = updateData[index].getPermutedArrayWithNoDummyEntry(mid + 1 + j);
            updateData[index].insertInRightArray(j, inp);
        }
        updateData[index].indexOfSubArrayOne[beginStepCounter] = 0;
        updateData[index].indexOfSubArrayTwo[beginStepCounter] = 0;
        updateData[index].indexOfMergedArray[beginStepCounter] = left;
    }

    while (updateData[index].indexOfSubArrayOne[beginStepCounter] < subArrayOne && updateData[index].indexOfSubArrayTwo[beginStepCounter] < subArrayTwo && count > 0) {
        if ((client->*cmpFunc)(updateData[index].getLeftArrayEntry(updateData[index].indexOfSubArrayOne[beginStepCounter]), updateData[index].getRightArrayEntry(updateData[index].indexOfSubArrayTwo[beginStepCounter]))) {
            prf_type inp = updateData[index].getLeftArrayEntry(updateData[index].indexOfSubArrayOne[beginStepCounter]);
            updateData[index].setPermutedArrayWithNoDummyEntry(updateData[index].indexOfMergedArray[beginStepCounter], inp);
            updateData[index].indexOfSubArrayOne[beginStepCounter]++;
        } else {
            prf_type inp = updateData[index].getRightArrayEntry(updateData[index].indexOfSubArrayTwo[beginStepCounter]);
            updateData[index].setPermutedArrayWithNoDummyEntry(updateData[index].indexOfMergedArray[beginStepCounter], inp);
            updateData[index].indexOfSubArrayTwo[beginStepCounter]++;
        }
        updateData[index].indexOfMergedArray[beginStepCounter]++;
        count--;
    }
    //    if (updateData[index].indexOfSubArrayOne[beginStepCounter] < subArrayOne && count > 0) {
    //        int curCount = min(count, subArrayOne - updateData[index].indexOfSubArrayOne[beginStepCounter]);
    //        updateData[index].transferLeftArraytoPermutedArrayWithNoDummyEntry(updateData[index].indexOfSubArrayOne[beginStepCounter], updateData[index].indexOfMergedArray[beginStepCounter], curCount);
    //        updateData[index].indexOfSubArrayOne[beginStepCounter] += curCount;
    //        updateData[index].indexOfMergedArray[beginStepCounter] += curCount;
    //        count -= curCount;
    //    }
    while (updateData[index].indexOfSubArrayOne[beginStepCounter] < subArrayOne && count > 0) {
        prf_type inp = updateData[index].getLeftArrayEntry(updateData[index].indexOfSubArrayOne[beginStepCounter]);
        updateData[index].setPermutedArrayWithNoDummyEntry(updateData[index].indexOfMergedArray[beginStepCounter], inp);
        updateData[index].indexOfSubArrayOne[beginStepCounter]++;
        updateData[index].indexOfMergedArray[beginStepCounter]++;
        count--;
    }
    //    if (updateData[index].indexOfSubArrayTwo[beginStepCounter] < subArrayTwo && count > 0) {
    //        int curCount = min(count, subArrayTwo - updateData[index].indexOfSubArrayTwo[beginStepCounter]);
    //        updateData[index].transferRightArraytoPermutedArrayWithNoDummyEntry(updateData[index].indexOfSubArrayTwo[beginStepCounter], updateData[index].indexOfMergedArray[beginStepCounter], curCount);
    //        updateData[index].indexOfSubArrayTwo[beginStepCounter] += curCount;
    //        updateData[index].indexOfMergedArray[beginStepCounter] += curCount;
    //        count -= curCount;
    //    }
    while (updateData[index].indexOfSubArrayTwo[beginStepCounter] < subArrayTwo && count > 0) {
        prf_type inp = updateData[index].getRightArrayEntry(updateData[index].indexOfSubArrayTwo[beginStepCounter]);
        updateData[index].setPermutedArrayWithNoDummyEntry(updateData[index].indexOfMergedArray[beginStepCounter], inp);
        updateData[index].indexOfSubArrayTwo[beginStepCounter]++;
        updateData[index].indexOfMergedArray[beginStepCounter]++;
        count--;
    }
}

void OneChoiceSDdGeneralServer::decryptPermutedArrayWithNoDummyEntry(int size, int index) {
    //    for (int i = 0; i < size; i++) {
    //        prf_type res = client->decryptEntity(updateData[index].getPermutedArrayWithNoDummyEntry(i));
    //        updateData[index].setPermutedArrayWithNoDummyEntry(i, res);
    //    }
    for (int i = 0; i < updateData[index].bucketNumberB; i++) {
        vector<Entry> inp1 = updateData[index].getArrayAsBucket(0, i);
        vector<Entry> out1;
        for (int j = 0; j < inp1.size(); j++) {
            Entry o;
            o.element = client->decryptEntity(inp1[j].element);
            o.key = client->decryptEntity(inp1[j].key);
            out1.push_back(o);
        }
        updateData[index].setArrayAsBucket(0, i, out1);
    }
}

void OneChoiceSDdGeneralServer::encryptPermutedArrayWithNoDummyEntry(int size, int index) {
    for (int i = 0; i < updateData[index].getPermutedArrayWithNoDummySize(); i++) {
        prf_type res = client->encryptEntity(updateData[index].getPermutedArrayWithNoDummyEntry(i));
        updateData[index].setPermutedArrayWithNoDummyEntry(i, res);
    }
}

void OneChoiceSDdGeneralServer::mergeSort(int const begin, int const end, int beginStep, int& count, int index, bool (OneChoiceSDdGeneralClient::*cmpFunc)(prf_type, prf_type)) {
    int curr_size = 1; // For current size of subarrays to be merged
    int left_start = 0; // For picking starting index of left subarray
    int n = end;
    int forwardStep = beginStep;
    int outterForward = (int) pow(2, (int) (forwardStep / (n + 1)));
    int innerForward = ((forwardStep % (n + 1)) / (outterForward * 2))*(2 * outterForward);
    curr_size = outterForward;
    left_start = innerForward;

    //    if (beginStep == 0) {
    //        decryptPermutedArrayWithNoDummyEntry(n + 1, index);
    //    }

    for (; curr_size <= n && count > 0; curr_size = 2 * curr_size) {
        for (; left_start < n && count > 0; left_start += 2 * curr_size) {
            int mid = min(left_start + curr_size - 1, n);
            int right_end = min(left_start + 2 * curr_size - 1, n);
            if (Utilities::DEBUG_MODE) {
                cout << "merge sort:" << index << " left_start:" << left_start << " right_end:" << right_end << endl;
            }
            merge(left_start, mid, right_end, count, index, n * curr_size + left_start, cmpFunc);
        }
        left_start = 0;
    }
}

void OneChoiceSDdGeneralServer::obliviousMerge(int oldestAndOldIndex, int beginStep, int count) {
    if (Utilities::DEBUG_MODE) {
        Utilities::startTimer(555);
    }
    int curSteps = 0, currentStep = 0;
    if (beginStep == 0) {
        phase0(oldestAndOldIndex);
        count--;
    }

    curSteps = numberOfBins[oldestAndOldIndex] * sizeOfEachBin[oldestAndOldIndex]*4 + 2 * updateData[oldestAndOldIndex].fixedNumberOfDataEntries +
            updateData[oldestAndOldIndex].fixedTotalNumberOfSteps;
    if (beginStep >= currentStep && beginStep < currentStep + curSteps) {
        int relativeBegin = beginStep - currentStep;
        int relativeCount = count + relativeBegin >= curSteps ? curSteps - relativeBegin : count;
        phase1(oldestAndOldIndex, relativeBegin, relativeCount);

        count = (count + beginStep) > currentStep + curSteps ? count + beginStep - (currentStep + curSteps) : 0;
        beginStep = count > 0 ? (currentStep + curSteps) : beginStep;
    }
    currentStep += curSteps;

    curSteps = numberOfBins[oldestAndOldIndex + 1] * sizeOfEachBin[oldestAndOldIndex + 1];
    if (beginStep >= currentStep && beginStep < currentStep + curSteps) {
        int relativeBegin = beginStep - currentStep;
        int relativeCount = count + relativeBegin >= curSteps ? curSteps - relativeBegin : count;
        phase2(oldestAndOldIndex, relativeBegin, relativeCount);

        count = (count + beginStep) > currentStep + curSteps ? count + beginStep - (currentStep + curSteps) : 0;
        beginStep = count > 0 ? (currentStep + curSteps) : beginStep;
    }
    currentStep += curSteps;

    curSteps = updateData[oldestAndOldIndex].getTotalNumberOfSteps(updateData[oldestAndOldIndex].fixedNumberOfDataEntries + numberOfBins[oldestAndOldIndex + 1] * sizeOfEachBin[oldestAndOldIndex + 1])+
            + numberOfBins[oldestAndOldIndex + 1] * sizeOfEachBin[oldestAndOldIndex + 1] +
            1 + updateData[oldestAndOldIndex].fixedTotalNumberOfSteps +
            + (int) pow(2, oldestAndOldIndex + 1) +
            numberOfBins[oldestAndOldIndex + 1] * sizeOfEachBin[oldestAndOldIndex + 1] + (int) pow(2, oldestAndOldIndex + 1);
    if (beginStep >= currentStep && beginStep < currentStep + curSteps) {
        int relativeBegin = beginStep - currentStep;
        int relativeCount = count + relativeBegin >= curSteps ? curSteps - relativeBegin : count;
        phase3(oldestAndOldIndex, relativeBegin, relativeCount);

        count = (count + beginStep) > currentStep + curSteps ? count + beginStep - (currentStep + curSteps) : 0;
        beginStep = count > 0 ? (currentStep + curSteps) : beginStep;
    }
    currentStep += curSteps;
    if (Utilities::DEBUG_MODE) {
        auto fetchtime = Utilities::stopTimer(555);
        cout << "level:" << oldestAndOldIndex << " total level time:" << fetchtime << endl;
    }
}

void OneChoiceSDdGeneralServer::phase0(int srcIndex) {
    transData.clear(srcIndex);
    client->phase0(srcIndex);
    updateData[srcIndex].clear();
}

void OneChoiceSDdGeneralServer::phase1(int srcIndex, int beginStep, int& count) {
    int curSteps = 0, currentStep = 0;
    int newIndex = srcIndex + 1;
    if (Utilities::DEBUG_MODE) {
        cout << "level:" << srcIndex << " begin phase1" << endl;
    }
    curSteps = numberOfBins[srcIndex] * sizeOfEachBin[srcIndex] * 4;
    if (beginStep >= currentStep && beginStep < currentStep + curSteps) {
        if (beginStep + count >= currentStep + curSteps) {
            if (Utilities::DEBUG_MODE) {
                Utilities::startTimer(1366);
            }
            vector<prf_type> list1 = getAllDataFlat(0, srcIndex);
            vector<prf_type> list2 = getAllDataFlat(1, srcIndex);
            if (Utilities::DEBUG_MODE) {
                auto fetchtime = Utilities::stopTimer(1366);
                cout << "level:" << srcIndex << " fetch time:" << fetchtime << endl;
            }
            list1 = client->updateKeys(list1, true);
            list2 = client->updateKeys(list2, false);

            //            for (int i = 0; i < list1.size(); i++) {
            //                transData.pushBackBuf1(srcIndex, list1[i]);
            //            }
            int i;
            for (i = 0; i < list1.size() / updateData[srcIndex].bucketSizeZ; i++) {
                transData.pushBackBuf1Vector(srcIndex, list1, i * updateData[srcIndex].bucketSizeZ, updateData[srcIndex].bucketSizeZ);
            }
            transData.pushBackBuf1Vector(srcIndex, list1, i * updateData[srcIndex].bucketSizeZ, list1.size() % updateData[srcIndex].bucketSizeZ);

            //            for (int i = 0; i < list2.size(); i++) {
            //                transData.pushBackBuf1(srcIndex, list2[i]);
            //            }
            for (i = 0; i < list2.size() / updateData[srcIndex].bucketSizeZ; i++) {
                transData.pushBackBuf1Vector(srcIndex, list2, i * updateData[srcIndex].bucketSizeZ, updateData[srcIndex].bucketSizeZ);
            }
            transData.pushBackBuf1Vector(srcIndex, list2, i * updateData[srcIndex].bucketSizeZ, list2.size() % updateData[srcIndex].bucketSizeZ);

        } else {
            //            cout << "hello" << endl;
        }
        count = (count + beginStep) > currentStep + curSteps ? count + beginStep - (currentStep + curSteps) : 0;
        beginStep = count > 0 ? (currentStep + curSteps) : beginStep;
    }
    currentStep += curSteps;

    if (Utilities::DEBUG_MODE) {
        cout << "level:" << srcIndex << " After fetching lists" << endl;
    }

    curSteps = updateData[srcIndex].fixedTotalNumberOfSteps;
    if (beginStep >= currentStep && beginStep < currentStep + curSteps) {
        int relativeBegin = beginStep - currentStep;
        int relativeCount = count + relativeBegin >= curSteps ? curSteps - relativeBegin : count;

        updateData[srcIndex].numberOfDataEntries = transData.getBuf1Size(srcIndex);
        updateData[srcIndex].bucketNumberB = (int) ceil(2 * updateData[srcIndex].numberOfDataEntries / updateData[srcIndex].bucketSizeZ);
        int power = 1;
        while (power < updateData[srcIndex].bucketNumberB) {
            power *= 2;
        }
        updateData[srcIndex].bucketNumberB = power == 1 ? 2 : power;
        updateData[srcIndex].numberOfLevels = (int) (log2(updateData[srcIndex].bucketNumberB)) + 1;
        updateData[srcIndex].initialPerBucketCount = ceil((double) updateData[srcIndex].numberOfDataEntries / (double) updateData[srcIndex].bucketNumberB);
        updateData[srcIndex].totalNumberOfSteps = updateData[srcIndex].getTotalNumberOfSteps(updateData[srcIndex].numberOfDataEntries);

        //        vector<prf_type> inputs = transData.getBUF1(srcIndex);
        int buf1size = transData.getBuf1Size(srcIndex);
        if (relativeBegin == 0) {

            //            for (int i = 0; i < buf1size; i++) {
            //                updateData[srcIndex].insertAthTheEndOfInputArray(transData.getBUF1(srcIndex, i));
            //            }
            int i;
            for (i = 0; i < buf1size / updateData[srcIndex].bucketSizeZ; i++) {
                updateData[srcIndex].transferFromBuf1ToEndIfInputArray(transData.getBUF1Vector(srcIndex, i * updateData[srcIndex].bucketSizeZ, updateData[srcIndex].bucketSizeZ));
            }
            updateData[srcIndex].transferFromBuf1ToEndIfInputArray(transData.getBUF1Vector(srcIndex, i * updateData[srcIndex].bucketSizeZ, buf1size % updateData[srcIndex].bucketSizeZ));


            updateData[srcIndex].clearPermutedArrayWithNoDummyEntry();
        }

        bool completed = obliviousBucketSort(relativeBegin, relativeCount, srcIndex, buf1size, &OneChoiceSDdGeneralClient::keywordCompare);
        if (completed) {
            int permutedSize = updateData[srcIndex].getPermutedArrayWithNoDummySize();


            int i;
            for (i = 0; i < permutedSize / updateData[srcIndex].bucketSizeZ; i++) {
                updateData[srcIndex].transferFromPermutedArrayWithNoDummyEntryToSortedKeywords(updateData[srcIndex].getPermutedArrayWithNoDummyEntryPartially(i * updateData[srcIndex].bucketSizeZ, updateData[srcIndex].bucketSizeZ));
            }
            updateData[srcIndex].transferFromPermutedArrayWithNoDummyEntryToSortedKeywords(updateData[srcIndex].getPermutedArrayWithNoDummyEntryPartially(i * updateData[srcIndex].bucketSizeZ, permutedSize % updateData[srcIndex].bucketSizeZ));


            //            for (int i = 0; i < permutedSize; i++) {
            //                updateData[srcIndex].insertSortedKeywords(updateData[srcIndex].getPermutedArrayWithNoDummyEntry(i));
            //            }
        }

        count = (count + beginStep) > currentStep + curSteps ? count + beginStep - (currentStep + curSteps) : 0;
        beginStep = count > 0 ? (currentStep + curSteps) : beginStep;
    }
    currentStep += curSteps;

    if (Utilities::DEBUG_MODE) {
        cout << "level:" << srcIndex << " after first oblivious bucket sort" << endl;
    }

    curSteps = updateData[srcIndex].fixedNumberOfDataEntries;
    if (beginStep >= currentStep && beginStep < currentStep + curSteps) {
        int i = 0;
        int forwardStep = beginStep - currentStep;
        i = forwardStep;

        //        for (; i < updateData[srcIndex].getSortedKeywordsSize() && count > 0; i++) {
        //            prf_type sortedEntry = updateData[srcIndex].getSortedKeywords(i);
        //            auto out = client->assignToNewBin(sortedEntry, newIndex);
        //            transData.pushBackBinAssignedEntries(srcIndex, out);
        //            count--;
        //        }

        for (; i < updateData[srcIndex].getSortedKeywordsSize() && count > 0;) {
            int mycurStep = min(min(count, updateData[srcIndex].getSortedKeywordsSize() - i), updateData[srcIndex].bucketSizeZ);
            vector<prf_type> sortedEntryVector = updateData[srcIndex].getSortedKeywordsVector(i, mycurStep);
            vector<pair<prf_type, prf_type>> outVector;
            for (int j = 0; j < mycurStep; j++) {
                pair<prf_type, prf_type> out = client->assignToNewBin(sortedEntryVector[j], newIndex);
                outVector.push_back(out);
                i++;
            }
            transData.pushBackVectorBinAssignedEntries(srcIndex, outVector);
            count -= mycurStep;
        }
        beginStep = count > 0 ? (currentStep + curSteps) : beginStep;
    }
    currentStep += curSteps;

    if (Utilities::DEBUG_MODE) {
        cout << "level:" << srcIndex << " after put in binAssignedEntries" << endl;
    }

    curSteps = updateData[srcIndex].fixedNumberOfDataEntries;
    if (beginStep >= currentStep && beginStep < currentStep + curSteps) {
        int i = 0;
        int forwardStep = beginStep - currentStep;
        i = forwardStep;

        //        for (; i < updateData[srcIndex].getSortedKeywordsSize() && count > 0; i++) {
        //            pair<prf_type, prf_type> buf2Entry = client->createBuf2Entry(updateData[srcIndex].getSortedKeywords(i), newIndex);
        //                    transData.pushBackBuf2(srcIndex, buf2Entry);
        //            count--;
        //        }
        for (; i < updateData[srcIndex].getSortedKeywordsSize() && count > 0;) {
            int mycurStep = min(min(count, updateData[srcIndex].getSortedKeywordsSize() - i), updateData[srcIndex].bucketSizeZ);
            vector<prf_type> sortedEntryVector = updateData[srcIndex].getSortedKeywordsVector(i, mycurStep);
            vector<pair<prf_type, prf_type>> outVector;
            for (int j = 0; j < mycurStep; j++) {
                pair<prf_type, prf_type> buf2Entry = client->createBuf2Entry(sortedEntryVector[j], newIndex);
                outVector.push_back(buf2Entry);
                i++;
            }
            transData.pushBackVectorBuf2(srcIndex, outVector);
            count -= mycurStep;
        }


        beginStep = count > 0 ? (currentStep + curSteps) : beginStep;
    }
    currentStep += curSteps;
    if (Utilities::DEBUG_MODE) {
        cout << "level:" << srcIndex << " end of phase1" << endl;
    }

}

void OneChoiceSDdGeneralServer::phase2(int srcIndex, int beginStep, int& count) {
    if (Utilities::DEBUG_MODE) {
        cout << "level:" << srcIndex << " begin phase2" << endl;
    }
    int newIndex = srcIndex + 1;
    int i = beginStep / sizeOfEachBin[srcIndex + 1];
    int forward = beginStep % sizeOfEachBin[srcIndex + 1];

    for (; i < numberOfBins[srcIndex + 1] && count > 0; i++) {
        vector<pair<prf_type, prf_type> > newDummies = client->getExtraDummies(newIndex, i, forward, count);
        transData.pushBackVectorBinAssignedEntries(srcIndex, newDummies);
        //        for (int j = 0; j < newDummies.size(); j++) {
        //            transData.pushBackBinAssignedEntries(srcIndex, newDummies[j]);
        //        }
        forward = 0;
    }
    if (Utilities::DEBUG_MODE) {
        cout << "level:" << srcIndex << " end of phase2" << endl;
    }
}

void OneChoiceSDdGeneralServer::phase3(int srcIndex, int beginStep, int& count) {
    int curSteps = 0, currentStep = 0;
    int newIndex = srcIndex + 1;

    if (Utilities::DEBUG_MODE) {
        cout << "level:" << srcIndex << " begin phase3" << endl;
    }

    initialDummy2 = client->getInitialDummy2();

    curSteps = updateData[srcIndex].getTotalNumberOfSteps(updateData[srcIndex].fixedNumberOfDataEntries + numberOfBins[srcIndex + 1] * sizeOfEachBin[srcIndex + 1]);
    if (beginStep >= currentStep && beginStep < currentStep + curSteps) {

        int relativeBegin = beginStep - currentStep;
        int relativeCount = count + relativeBegin >= curSteps ? curSteps - relativeBegin : count;
        //        int test = updateData[srcIndex].getTotalNumberOfSteps(transData.getBinAssignedEntries[srcIndex].size());

        if (relativeBegin == 0) {
            updateData[srcIndex].DestroyArray2DataStructure();
        }
        updateData[srcIndex].numberOfDataEntries = transData.getBinAssignedEntriesSize(srcIndex);
        updateData[srcIndex].bucketNumberB = (int) ceil(2 * updateData[srcIndex].numberOfDataEntries / updateData[srcIndex].bucketSizeZ);
        int power = 1;
        while (power < updateData[srcIndex].bucketNumberB) {
            power *= 2;
        }
        updateData[srcIndex].bucketNumberB = power == 1 ? 2 : power;
        updateData[srcIndex].numberOfLevels = (int) (log2(updateData[srcIndex].bucketNumberB)) + 1;
        updateData[srcIndex].initialPerBucketCount = ceil((double) updateData[srcIndex].numberOfDataEntries / (double) updateData[srcIndex].bucketNumberB);
        updateData[srcIndex].totalNumberOfSteps = updateData[srcIndex].getTotalNumberOfSteps(updateData[srcIndex].numberOfDataEntries);

        int binsize = transData.getBinAssignedEntriesSize(srcIndex);
        if (relativeBegin == 0) {
            updateData[srcIndex].UpdateArray2DataStructure();
            //            updateData[srcIndex].clearInputArray2();
            for (int i = 0; i < binsize;) {
                int mycurStep = min(binsize, updateData[srcIndex].bucketSizeZ);
                vector<pair<prf_type, prf_type>> inp = transData.getBinAssignedEntriesVector(srcIndex, i, mycurStep);
                updateData[srcIndex].insertVectorAthTheEndOfInputArray2(inp);
                i += mycurStep;

                //                auto inp = transData.getBinAssignedEntries(srcIndex, i);
                //                updateData[srcIndex].insertAthTheEndOfInputArray2(inp);
            }
            updateData[srcIndex].clearPermutedArrayWithNoDummyEntry2();
        }

        bool completed = obliviousBucketSort2(relativeBegin, relativeCount, srcIndex, binsize, &OneChoiceSDdGeneralClient::binCompare);

        if (completed) {
            int permutedSize = updateData[srcIndex].getPermutedArrayWithNoDummy2Size();
            for (int i = 0; i < permutedSize;) {
                int mycurStep = min(permutedSize, updateData[srcIndex].bucketSizeZ);
                vector<pair<prf_type, prf_type>> inp = updateData[srcIndex].getPermutedArrayWithNoDummyEntry2Partially(i, mycurStep);
                updateData[srcIndex].insertVectorSortedBUF1(inp);
                i += mycurStep;

                //                pair<prf_type, prf_type> inp = updateData[srcIndex].getPermutedArrayWithNoDummyEntry2(i);
                //                updateData[srcIndex].insertSortedBUF1(inp);
            }
        }

        count = (count + beginStep) > currentStep + curSteps ? count + beginStep - (currentStep + curSteps) : 0;
        beginStep = count > 0 ? (currentStep + curSteps) : beginStep;
    }
    currentStep += curSteps;

    if (Utilities::DEBUG_MODE) {
        cout << "level:" << srcIndex << " After second oblivious bucket sort" << endl;
    }

    curSteps = numberOfBins[srcIndex + 1] * sizeOfEachBin[srcIndex + 1];
    if (beginStep >= currentStep && beginStep < currentStep + curSteps) {
        int i = 0, j = 0;
        int forwardStep = beginStep - currentStep;
        i = forwardStep / sizeOfEachBin[newIndex];
        j = forwardStep % sizeOfEachBin[newIndex];

        if (forwardStep == 0) {
            updateData[srcIndex].clearCiphertexts();
            for (int p = 0; p < numberOfBins[newIndex]; p++) {
                updateData[srcIndex].pushBackVectorInCiphertexts(vector<prf_type>());
            }
        }


        for (; i < numberOfBins[newIndex] && count > 0; i++) {
            for (; j < sizeOfEachBin[newIndex] && count > 0;) {
                int mycurStep = min(min(count, updateData[srcIndex].bucketSizeZ), sizeOfEachBin[newIndex] - j);
                vector<pair<prf_type, prf_type>> sorted = updateData[srcIndex].getSortedBUF1Vector(i * sizeOfEachBin[newIndex], mycurStep);
                vector<prf_type> outVals;

                for (int k = 0; k < mycurStep; k++) {
                    prf_type inp = sorted[k].first;
                    prf_type out = client->makeReadyForStore(inp);
                    outVals.push_back(out);
                }

                updateData[srcIndex].insertVectorCiphertext(i, outVals);
                count -= mycurStep;
                j += mycurStep;
            }

            //                                    for (; j < sizeOfEachBin[newIndex] && count > 0; j++) {
            //                                        prf_type inp = updateData[srcIndex].getSortedBUF1(i * sizeOfEachBin[newIndex] + j).first;
            //                                        prf_type out = client->makeReadyForStore(inp);
            //                                        updateData[srcIndex].insertCiphertext(i, out);
            //                                        count--;
            //                                    }
            j = 0;
        }

        beginStep = count > 0 ? (currentStep + curSteps) : beginStep;
    }
    currentStep += curSteps;

    if (Utilities::DEBUG_MODE) {
        cout << "level:" << srcIndex << " After preparing ciphertexts" << endl;
    }

    curSteps = 1;
    if (beginStep >= currentStep && beginStep < currentStep + curSteps) {
        updateData[srcIndex].clearForThirdSort();
        updateData[srcIndex].indexOfSubArrayOne.clear();
        updateData[srcIndex].indexOfSubArrayTwo.clear();
        updateData[srcIndex].indexOfMergedArray.clear();
        count--;
        beginStep = count > 0 ? (currentStep + curSteps) : beginStep;
    }
    currentStep += curSteps;

    curSteps = updateData[srcIndex].fixedTotalNumberOfSteps;
    if (beginStep >= currentStep && beginStep < currentStep + curSteps) {
        int relativeBegin = beginStep - currentStep;
        int relativeCount = count + relativeBegin >= curSteps ? curSteps - relativeBegin : count;
        //        int test = updateData[srcIndex].getTotalNumberOfSteps(transData.getBUF2Size(srcIndex));

        if (relativeBegin == 0) {
            updateData[srcIndex].DestroyArray2DataStructure();
        }

        updateData[srcIndex].numberOfDataEntries = transData.getBUF2Size(srcIndex);
        updateData[srcIndex].bucketNumberB = (int) ceil(2 * updateData[srcIndex].numberOfDataEntries / updateData[srcIndex].bucketSizeZ);
        int power = 1;
        while (power < updateData[srcIndex].bucketNumberB) {
            power *= 2;
        }
        updateData[srcIndex].bucketNumberB = power == 1 ? 2 : power;
        updateData[srcIndex].numberOfLevels = (int) (log2(updateData[srcIndex].bucketNumberB)) + 1;
        updateData[srcIndex].initialPerBucketCount = ceil((double) updateData[srcIndex].numberOfDataEntries / (double) updateData[srcIndex].bucketNumberB);
        updateData[srcIndex].totalNumberOfSteps = updateData[srcIndex].getTotalNumberOfSteps(updateData[srcIndex].numberOfDataEntries);

        int buf2size = transData.getBUF2Size(srcIndex);
        if (relativeBegin == 0) {
            updateData[srcIndex].UpdateArray2DataStructure();
            //            updateData[srcIndex].clearInputArray2();
            for (int i = 0; i < buf2size; i++) {
                updateData[srcIndex].insertAthTheEndOfInputArray2(transData.getBUF2(srcIndex, i));
            }
            updateData[srcIndex].clearPermutedArrayWithNoDummyEntry2();
        }

        bool completed = obliviousBucketSort2(relativeBegin, relativeCount, srcIndex, buf2size, &OneChoiceSDdGeneralClient::buf2Compare);

        if (completed) {
            int permutedSize = updateData[srcIndex].getPermutedArrayWithNoDummy2Size();


            int i;
            for (i = 0; i < permutedSize / updateData[srcIndex].bucketSizeZ; i++) {
                updateData[srcIndex].transferFromPermutedArrayWithNoDummyEntry2ToSortedBUF2(updateData[srcIndex].getPermutedArrayWithNoDummyEntry2Partially(i * updateData[srcIndex].bucketSizeZ, updateData[srcIndex].bucketSizeZ));
            }
            updateData[srcIndex].transferFromPermutedArrayWithNoDummyEntry2ToSortedBUF2(updateData[srcIndex].getPermutedArrayWithNoDummyEntry2Partially(i * updateData[srcIndex].bucketSizeZ, permutedSize % updateData[srcIndex].bucketSizeZ));



            //            for (int i = 0; i < permutedSize; i++) {
            //                updateData[srcIndex].insertSortedBUF2(updateData[srcIndex].getPermutedArrayWithNoDummyEntry2(i));
            //            }
        }

        count = (count + beginStep) > currentStep + curSteps ? count + beginStep - (currentStep + curSteps) : 0;
        beginStep = count > 0 ? (currentStep + curSteps) : beginStep;
    }
    currentStep += curSteps;
    if (Utilities::DEBUG_MODE) {
        cout << "level:" << srcIndex << " After third oblivious bucket sort" << endl;
    }


    curSteps = (int) pow(2, srcIndex + 1);
    if (beginStep >= currentStep && beginStep < currentStep + curSteps) {
        int i = 0;
        int forwardStep = beginStep - currentStep;
        i = forwardStep;


        int correctCount = min((int) updateData[srcIndex].getSortedBUF2Size(), (int) pow(2, newIndex));
        for (; i < correctCount && count > 0;) {
            int mycurStep = min(min(count, updateData[srcIndex].bucketSizeZ), correctCount);
            vector<pair<prf_type, prf_type>> tmpKW = updateData[srcIndex].getSortedBUF2Vector(i, mycurStep);

            for (int j = 0; j < mycurStep; j++) {
                pair<prf_type, prf_type> ready = client->prepareKWCounter(tmpKW[j]);
                updateData[srcIndex].setKwCounters(ready.first, ready.second);
            }
            count -= mycurStep;
            i += mycurStep;

            //            pair<prf_type, prf_type> ready = client->prepareKWCounter(updateData[srcIndex].getSortedBUF2(i));
            //            updateData[srcIndex].setKwCounters(ready.first, ready.second);
            //            count--;
        }
        if (count > 0 && (int) pow(2, newIndex) > (int) updateData[srcIndex].getSortedBUF2Size()) {
            count -= min(((int) pow(2, newIndex) - (int) updateData[srcIndex].getSortedBUF2Size()), count);
        }
        beginStep = count > 0 ? (currentStep + curSteps) : beginStep;
    }
    currentStep += curSteps;

    if (Utilities::DEBUG_MODE) {
        cout << "level:" << srcIndex << " After preparing keword list" << endl;
    }

    curSteps = numberOfBins[srcIndex + 1] * sizeOfEachBin[srcIndex + 1] + (int) pow(2, srcIndex + 1);
    if (beginStep >= currentStep && beginStep < currentStep + curSteps) {
        if (beginStep + count >= currentStep + curSteps) {
            if (Utilities::DEBUG_MODE) {
                Utilities::startTimer(1366);
            }
            storeCiphers(3, newIndex);
            storeKeywordCounters(3, newIndex, updateData[srcIndex].getKwCounters());
            if (Utilities::DEBUG_MODE) {
                auto fetchtime = Utilities::stopTimer(1366);
                cout << "level:" << srcIndex << " store time:" << fetchtime << endl;
            }
        } else {
            //            cout << "hello" << endl;
        }
        count = (count + beginStep) > currentStep + curSteps ? count + beginStep - (currentStep + curSteps) : 0;
        beginStep = count > 0 ? (currentStep + curSteps) : beginStep;
    }
    currentStep += curSteps;
    if (Utilities::DEBUG_MODE) {
        cout << "level:" << srcIndex << " end of phase 3" << endl;
    }
}

int OneChoiceSDdGeneralServer::getTotalNumberOfSteps(int oldestAndOldIndex) {
    int totalSteps = 0;
    //phase0
    totalSteps++;
    //phase1
    totalSteps = totalSteps + numberOfBins[oldestAndOldIndex] * sizeOfEachBin[oldestAndOldIndex]*4 + 2 * updateData[oldestAndOldIndex].fixedNumberOfDataEntries + updateData[oldestAndOldIndex].fixedTotalNumberOfSteps;
    //phase2
    totalSteps = totalSteps + numberOfBins[oldestAndOldIndex + 1] * sizeOfEachBin[oldestAndOldIndex + 1];
    //phase3
    totalSteps = totalSteps + updateData[oldestAndOldIndex].getTotalNumberOfSteps(updateData[oldestAndOldIndex].fixedNumberOfDataEntries + numberOfBins[oldestAndOldIndex + 1] * sizeOfEachBin[oldestAndOldIndex + 1]) + numberOfBins[oldestAndOldIndex + 1] * sizeOfEachBin[oldestAndOldIndex + 1] +
            1 + updateData[oldestAndOldIndex].fixedTotalNumberOfSteps + (int) pow(2, oldestAndOldIndex + 1) +
            numberOfBins[oldestAndOldIndex + 1] * sizeOfEachBin[oldestAndOldIndex + 1] + (int) pow(2, oldestAndOldIndex + 1);

    return totalSteps;
}

bool OneChoiceSDdGeneralServer::obliviousBucketSort2(int beginStep, int count, int index, int inputSize, bool (OneChoiceSDdGeneralClient::*cmpFunc)(pair<prf_type, prf_type>, pair<prf_type, prf_type>)) {
    int currentStep = 0;
    int curSteps = 0;

    if (Utilities::DEBUG_MODE) {
        cout << "level:" << index << " begin second oblivious bucket sort" << endl;
    }

    int n = inputSize;

    //1 step
    curSteps = 1;
    if (beginStep >= currentStep && beginStep < currentStep + curSteps) {
        //        updateData[index].insertInInputArray2(input);

        count = (count + beginStep) > currentStep + curSteps ? count + beginStep - (currentStep + curSteps) : 0;
        beginStep = count > 0 ? (currentStep + curSteps) : beginStep;
    }
    currentStep += curSteps;

    //numberOfLevels*bucketNumberB
    curSteps = updateData[index].numberOfLevels * updateData[index].bucketNumberB;
    if (beginStep >= currentStep && beginStep < currentStep + curSteps) {
        int i = 0, j = 0;
        int forwardStep = beginStep - currentStep;
        i = forwardStep / updateData[index].bucketNumberB;
        j = forwardStep % updateData[index].bucketNumberB;
        for (; i < updateData[index].numberOfLevels && count > 0; i++) {
            if (j == 0) {
                updateData[index].insertInArrayAs2(vector< vector<Entry2 > >());
            }
            for (; j < updateData[index].bucketNumberB && count > 0; j++) {
                updateData[index].insertVectorInArrayAs2(i, vector<Entry2 >());
                //                updateData[index].arrayAs2[i].push_back(vector<Entry2 >());
                count--;
            }
            j = 0;
        }

        //        count = (count + beginStep) > currentStep + curSteps ? count + beginStep - (currentStep + curSteps) : 0;
        beginStep = count > 0 ? (currentStep + curSteps) : beginStep;
    }
    currentStep += curSteps;

    if (Utilities::DEBUG_MODE) {
        cout << "level:" << index << "phase:3 After empty vectors in ArrayAs2" << endl;
    }

    //2n steps (label creation and encryption)
    curSteps = 2 * n;
    if (beginStep >= currentStep && beginStep < currentStep + curSteps) {
        int relativeBegin = beginStep - currentStep;
        int relativeCount = count + relativeBegin >= curSteps ? curSteps - relativeBegin : count;

        vector<prf_type> tmp = client->getRandomKeys2(n, updateData[index].bucketNumberB, relativeBegin, relativeCount, index);
        for (int i = 0; i < tmp.size(); i++) {
            updateData[index].insertInRandomLabels2(tmp[i]);
        }

        count = (count + beginStep) > currentStep + curSteps ? count + beginStep - (currentStep + curSteps) : 0;
        beginStep = count > 0 ? (currentStep + curSteps) : beginStep;
    }
    currentStep += curSteps;

    if (Utilities::DEBUG_MODE) {
        cout << "level:" << index << " phase:3 After create random keys" << endl;
    }

    //n steps   
    curSteps = n;
    if (beginStep >= currentStep && beginStep < currentStep + curSteps) {
        int i = 0;
        int forwardStep = beginStep - currentStep;
        i = forwardStep;
        for (; i < n && count > 0; i++) {
            pair<pair<prf_type, prf_type>, prf_type> inp = pair<pair<prf_type, prf_type>, prf_type>(updateData[index].getInputArray2Element(i), updateData[index].getrandomLabels2Element(i));
            updateData[index].insertInInputAssignedBuckets2(inp);
            count--;
        }

        //        count = (count + beginStep) > currentStep + curSteps ? count + beginStep - (currentStep + curSteps) : 0;
        beginStep = count > 0 ? (currentStep + curSteps) : beginStep;
    }
    currentStep += curSteps;

    if (Utilities::DEBUG_MODE) {
        cout << "level:" << index << " phase:3 After insert in InputAssignedBucket" << endl;
    }

    //bucketNumberB * bucketSizeZ steps
    curSteps = updateData[index].bucketNumberB * updateData[index].bucketSizeZ;
    if (beginStep >= currentStep && beginStep < currentStep + curSteps) {
        int globalBucketKey = 0;
        int tmpCnt = 0;
        int i = 0;
        int forwardStep = beginStep - currentStep;
        if (forwardStep < n) {
            i = forwardStep;
            tmpCnt = forwardStep % updateData[index].initialPerBucketCount;
            globalBucketKey = forwardStep / updateData[index].initialPerBucketCount;
            for (; i < n && count > 0; i++) {
                if (tmpCnt == updateData[index].initialPerBucketCount) {
                    globalBucketKey++;
                    globalBucketKey = globalBucketKey % updateData[index].bucketNumberB;
                    tmpCnt = 0;
                }
                Entry2 entry;
                pair<pair<prf_type, prf_type>, prf_type> iab = updateData[index].getInputAssignedBuckets2(i);
                entry.element = iab.first;
                entry.key = iab.second;
                updateData[index].insertEntryInArrayAs2(0, globalBucketKey, entry);
                tmpCnt++;
                count--;
            }
            forwardStep = 0;
        } else {
            forwardStep -= n;
        }
        //        int bypassCounter = 0;
        for (int j = 0; j < updateData[index].bucketNumberB && count > 0; j++) {
            //            cout << "bucket:" << j << " size:" << arrayAs[0][j].size() << endl;
            for (int k = updateData[index].getArrayAs2Size(0, j); k < updateData[index].bucketSizeZ && count > 0; k++) {
                Entry2 dummyEntry;
                dummyEntry.element = initialDummy2;
                dummyEntry.key = initialDummy2.first;
                updateData[index].insertEntryInArrayAs2(0, j, dummyEntry);
                count--;
            }
        }

        beginStep = count > 0 ? (currentStep + curSteps) : beginStep;
    }
    currentStep += curSteps;

    if (Utilities::DEBUG_MODE) {
        cout << "level:" << index << " phase:3 After insert in ArrayAs2" << endl;
    }


    //(numberOfLevels * bucketNumberB / 2 * merge_split cost) + bucketNumberB * ZlogZ  permutation
    //merge split cost:
    //  2*Z decryption + 2*Z encryption 
    curSteps = (((updateData[index].numberOfLevels - 1) * (updateData[index].bucketNumberB / 2) * (2 * updateData[index].bucketSizeZ * 2)) + updateData[index].bucketNumberB * updateData[index].bucketSizeZ * log2(updateData[index].bucketSizeZ));
    if (beginStep >= currentStep && beginStep < currentStep + curSteps) {
        int i = 0, j = 0, innerStep = 0;
        int forwardStep = beginStep - currentStep;
        //                if (forwardStep == 0) {
        //            decryptPermutedArrayWithNoDummyEntry2(n + 1, index);
        //        }
        if (forwardStep > (((updateData[index].numberOfLevels - 2) * (updateData[index].bucketNumberB / 2) * (2 * updateData[index].bucketSizeZ * 2)))) {
            i = updateData[index].numberOfLevels - 2;
            int passedSteps = (((updateData[index].numberOfLevels - 2) * (updateData[index].bucketNumberB / 2) * (2 * updateData[index].bucketSizeZ * 2)));
            j = (forwardStep - passedSteps) / (2 * updateData[index].bucketSizeZ * 2 + updateData[index].bucketSizeZ * log2(updateData[index].bucketSizeZ) * 2);
            innerStep = (forwardStep - passedSteps) % (int) (2 * updateData[index].bucketSizeZ * 2 + updateData[index].bucketSizeZ * log2(updateData[index].bucketSizeZ) * 2);
        } else {
            i = forwardStep / ((updateData[index].bucketNumberB / 2) * 2 * updateData[index].bucketSizeZ * 2);
            j = (forwardStep / (2 * updateData[index].bucketSizeZ * 2)) % (updateData[index].bucketNumberB / 2);
            innerStep = forwardStep % (2 * updateData[index].bucketSizeZ * 2);
        }


        for (; i < updateData[index].numberOfLevels - 1 && count > 0; i++) {
            for (; j < (updateData[index].bucketNumberB / 2) && count > 0; j++) {
                int jprime = floor(j / pow(2, i)) * pow(2, i);
                bool permuteNeeded = (i == (updateData[index].numberOfLevels - 2));
                int innerCount = 0;
                if (innerStep != 0) {
                    if (permuteNeeded) {
                        innerCount = count < ((2 * updateData[index].bucketSizeZ * 2 + updateData[index].bucketSizeZ * log2(updateData[index].bucketSizeZ) * 2) - innerStep) ? count : ((2 * updateData[index].bucketSizeZ * 2 + updateData[index].bucketSizeZ * log2(updateData[index].bucketSizeZ) * 2) - innerStep);
                    } else {
                        innerCount = count < ((2 * updateData[index].bucketSizeZ * 2) - innerStep) ? count : ((2 * updateData[index].bucketSizeZ * 2) - innerStep);
                    }
                    vector<Entry2> inp1 = updateData[index].getArrayAs2Bucket(i, j + jprime);
                    vector<Entry2> inp2 = updateData[index].getArrayAs2Bucket(i, j + jprime + pow(2, i));
                    vector<Entry2> out1 = updateData[index].getArrayAs2Bucket(i + 1, 2 * j);
                    vector<Entry2> out2 = updateData[index].getArrayAs2Bucket(i + 1, 2 * j + 1);
                    client->mergeSplit(inp1, inp2, i, out1, out2, permuteNeeded, n, innerStep, innerCount, updateData[index].bucketSizeZ, index, updateData[index]);
                    updateData[index].setArrayAs2Bucket(i + 1, 2 * j, out1);
                    updateData[index].setArrayAs2Bucket(i + 1, 2 * j + 1, out2);
                    //                    client->mergeSplit2(i, j + jprime, i, j + jprime + pow(2, i), i, i + 1, 2 * j, i + 1, 2 * j + 1, permuteNeeded, n, innerStep, innerCount, updateData[index].bucketSizeZ, index, updateData[index]);
                    innerStep = 0;
                } else {
                    if (permuteNeeded) {
                        innerCount = count < (2 * updateData[index].bucketSizeZ * 2 + updateData[index].bucketSizeZ * log2(updateData[index].bucketSizeZ) * 2) ? count : (2 * updateData[index].bucketSizeZ * 2 + updateData[index].bucketSizeZ * log2(updateData[index].bucketSizeZ) * 2);
                    } else {
                        innerCount = count < (2 * updateData[index].bucketSizeZ * 2) ? count : (2 * updateData[index].bucketSizeZ * 2);
                    }
                    vector<Entry2> inp1 = updateData[index].getArrayAs2Bucket(i, j + jprime);
                    vector<Entry2> inp2 = updateData[index].getArrayAs2Bucket(i, j + jprime + pow(2, i));
                    vector<Entry2> out1 = updateData[index].getArrayAs2Bucket(i + 1, 2 * j);
                    vector<Entry2> out2 = updateData[index].getArrayAs2Bucket(i + 1, 2 * j + 1);
                    client->mergeSplit(inp1, inp2, i, out1, out2, permuteNeeded, n, 0, innerCount, updateData[index].bucketSizeZ, index, updateData[index]);
                    updateData[index].setArrayAs2Bucket(i + 1, 2 * j, out1);
                    updateData[index].setArrayAs2Bucket(i + 1, 2 * j + 1, out2);
                    //                    client->mergeSplit2(i, j + jprime, i, j + jprime + pow(2, i), i, i + 1, 2 * j, i + 1, 2 * j + 1, permuteNeeded, n, 0, innerCount, updateData[index].bucketSizeZ, index, updateData[index]);
                }
                count = count - innerCount;
            }
            j = 0;
        }
        beginStep = count > 0 ? (currentStep + curSteps) : beginStep;
    }
    currentStep += curSteps;

    if (Utilities::DEBUG_MODE) {
        cout << "level:" << index << " phase:3 After merge split" << endl;
    }

    //bucketNumberB * bucketSizeZ steps
    curSteps = updateData[index].bucketNumberB * updateData[index].bucketSizeZ;
    if (beginStep >= currentStep && beginStep < currentStep + curSteps) {
        int relativeBegin = beginStep - currentStep;
        int relativeCount = count + relativeBegin >= curSteps ? curSteps - relativeBegin : count;
        client->removeDummies2(updateData[index].numberOfLevels - 1, updateData[index].bucketSizeZ, relativeBegin, relativeCount, index, updateData[index]);
        //        auto tmp = client->removeDummies(updateData[index].getArrayAs2Level(updateData[index].numberOfLevels - 1), updateData[index].bucketSizeZ, relativeBegin, relativeCount, index);
        //        for (int i = 0; i < tmp.size(); i++) {
        //            updateData[index].insertInPermutedArrayWithNoDummy2Entry(tmp[i]);
        //        }

        count = (count + beginStep) > currentStep + curSteps ? count + beginStep - (currentStep + curSteps) : 0;
        beginStep = count > 0 ? (currentStep + curSteps) : beginStep;
    }
    currentStep += curSteps;

    if (Utilities::DEBUG_MODE) {
        cout << "level:" << index << " phase:3 After remove dummies" << endl;
    }

    bool completed = false;
    //n log n steps
    curSteps = n * ceil(log2(n));
    if (beginStep >= currentStep && beginStep < currentStep + curSteps) {
        int relativeBegin = beginStep - currentStep;
        int relativeCount = count + relativeBegin >= curSteps ? curSteps - relativeBegin : count;

        int stepCounter = 0;
        if (relativeBegin == 0) {
            updateData[index].clearBeforeMergeSort2();
            //            updateData[index].leftArray3.clear();
            //            updateData[index].rightArray3.clear();
            updateData[index].indexOfSubArrayOne.clear();
            updateData[index].indexOfSubArrayTwo.clear();
            updateData[index].indexOfMergedArray.clear();
        }
        mergeSort2(0, n - 1, relativeBegin, relativeCount, index, cmpFunc);
        completed = (count + beginStep) >= currentStep + curSteps ? true : false;
        //        if (completed) {
        //            encryptPermutedArrayWithNoDummyEntry2(n, index);
        //        }
        updateData[index].flushPermutedArrayWithNoDummyEntry2();

        count = (count + beginStep) > currentStep + curSteps ? count + beginStep - (currentStep + curSteps) : 0;
        beginStep = count > 0 ? (currentStep + curSteps) : beginStep;
    }
    currentStep += curSteps;

    if (Utilities::DEBUG_MODE) {
        cout << "level:" << index << " phase:3 end of oblivious bucket sort" << endl;
    }

    return completed;

}

void OneChoiceSDdGeneralServer::decryptPermutedArrayWithNoDummyEntry2(int size, int index) {
    //    for (int i = 0; i < size; i++) {
    //        pair<prf_type, prf_type> res = client->decryptEntity2(updateData[index].getPermutedArrayWithNoDummyEntry2(i));
    //        updateData[index].setPermutedArrayWithNoDummyEntry2(i, res);
    //    }
    for (int j = 0; j < updateData[index].bucketNumberB; j++) {
        vector<Entry2> inp1 = updateData[index].getArrayAs2Bucket(0, j);
        vector<Entry2> out1;
        for (int k = 0; k < inp1.size(); k++) {
            Entry2 o;
            o.element = client->decryptEntity2(inp1[k].element);
            o.key = client->decryptEntity2(inp1[k].key);
            out1.push_back(o);
        }
        updateData[index].setArrayAs2Bucket(0, j, out1);
    }
}

void OneChoiceSDdGeneralServer::encryptPermutedArrayWithNoDummyEntry2(int size, int index) {
    for (int i = 0; i < size; i++) {
        pair<prf_type, prf_type> res = client->encryptEntity2(updateData[index].getPermutedArrayWithNoDummyEntry2(i));
        updateData[index].setPermutedArrayWithNoDummyEntry2(i, res);
    }
}

void OneChoiceSDdGeneralServer::mergeSort2(int const begin, int const end, int beginStep, int& count, int index, bool (OneChoiceSDdGeneralClient::*cmpFunc)(pair<prf_type, prf_type>, pair<prf_type, prf_type>)) {
    int curr_size = 1; // For current size of subarrays to be merged
    int left_start = 0; // For picking starting index of left subarray
    int n = end;
    int forwardStep = beginStep;
    int outterForward = (int) pow(2, (int) (forwardStep / (n + 1)));
    int innerForward = ((forwardStep % (n + 1)) / (outterForward * 2))*(2 * outterForward);
    curr_size = outterForward;
    left_start = innerForward;

    //    if (beginStep == 0) {
    //        decryptPermutedArrayWithNoDummyEntry2(n + 1, index);
    //    }

    for (; curr_size <= n && count > 0; curr_size = 2 * curr_size) {
        for (; left_start < n && count > 0; left_start += 2 * curr_size) {
            int mid = min(left_start + curr_size - 1, n);
            int right_end = min(left_start + 2 * curr_size - 1, n);
            if (Utilities::DEBUG_MODE) {
                cout << "merge sort:" << index << " left_start:" << left_start << " right_end:" << right_end << endl;
            }
            merge2(left_start, mid, right_end, count, index, n * curr_size + left_start, cmpFunc);
        }
        left_start = 0;
    }
}

void OneChoiceSDdGeneralServer::merge2(int const left, int const mid, int const right, int& count, int index, int innerMapCounter, bool (OneChoiceSDdGeneralClient::*cmpFunc)(pair<prf_type, prf_type>, pair<prf_type, prf_type>)) {
    auto const subArrayOne = mid - left + 1;
    auto const subArrayTwo = right - mid;
    const int beginStepCounter = innerMapCounter;


    if (updateData[index].indexOfMergedArray.count(beginStepCounter) == 0) {
        //        updateData[index].flushPermutedArrayWithNoDummyEntry2();
        updateData[index].clearLeftArray3();
        updateData[index].clearRightArray3();

        //        updateData[index].transferPermutedArrayWithNoDummyEntry2toLeftArray3(left, subArrayOne);
        for (auto i = 0; i < subArrayOne; i++) {
            pair<prf_type, prf_type> inp = updateData[index].getPermutedArrayWithNoDummyEntry2(left + i);
            updateData[index].insertInLeftArray3(i, inp);
        }
        //        updateData[index].transferPermutedArrayWithNoDummyEntry2toRightArray3(mid + 1, subArrayTwo);
        for (auto j = 0; j < subArrayTwo; j++) {
            pair<prf_type, prf_type> inp = updateData[index].getPermutedArrayWithNoDummyEntry2(mid + 1 + j);
            updateData[index].insertInRightArray3(j, inp);
        }
        updateData[index].indexOfSubArrayOne[beginStepCounter] = 0;
        updateData[index].indexOfSubArrayTwo[beginStepCounter] = 0;
        updateData[index].indexOfMergedArray[beginStepCounter] = left;
    }


    while (updateData[index].indexOfSubArrayOne[beginStepCounter] < subArrayOne && updateData[index].indexOfSubArrayTwo[beginStepCounter] < subArrayTwo && count > 0) {
        if ((client->*cmpFunc)(updateData[index].getLeftArrayEntry3(updateData[index].indexOfSubArrayOne[beginStepCounter]), updateData[index].getRightArrayEntry3(updateData[index].indexOfSubArrayTwo[beginStepCounter]))) {
            pair<prf_type, prf_type> inp = updateData[index].getLeftArrayEntry3(updateData[index].indexOfSubArrayOne[beginStepCounter]);
            updateData[index].setPermutedArrayWithNoDummyEntry2(updateData[index].indexOfMergedArray[beginStepCounter], inp);
            updateData[index].indexOfSubArrayOne[beginStepCounter]++;
        } else {
            pair<prf_type, prf_type> inp = updateData[index].getRightArrayEntry3(updateData[index].indexOfSubArrayTwo[beginStepCounter]);
            updateData[index].setPermutedArrayWithNoDummyEntry2(updateData[index].indexOfMergedArray[beginStepCounter], inp);
            updateData[index].indexOfSubArrayTwo[beginStepCounter]++;
        }
        updateData[index].indexOfMergedArray[beginStepCounter]++;
        count--;
    }



    //    if (updateData[index].indexOfSubArrayOne[beginStepCounter] < subArrayOne && count > 0) {
    //        int curCount = min(count, subArrayOne - updateData[index].indexOfSubArrayOne[beginStepCounter]);
    //        updateData[index].transferLeftArray3toPermutedArrayWithNoDummyEntry2(updateData[index].indexOfSubArrayOne[beginStepCounter], updateData[index].indexOfMergedArray[beginStepCounter], curCount);
    //        updateData[index].indexOfSubArrayOne[beginStepCounter] += curCount;
    //        updateData[index].indexOfMergedArray[beginStepCounter] += curCount;
    //        count -= curCount;
    //    }
    while (updateData[index].indexOfSubArrayOne[beginStepCounter] < subArrayOne && count > 0) {
        pair<prf_type, prf_type> inp = updateData[index].getLeftArrayEntry3(updateData[index].indexOfSubArrayOne[beginStepCounter]);
        updateData[index].setPermutedArrayWithNoDummyEntry2(updateData[index].indexOfMergedArray[beginStepCounter], inp);
        updateData[index].indexOfSubArrayOne[beginStepCounter]++;
        updateData[index].indexOfMergedArray[beginStepCounter]++;
        count--;
    }
    //    if (updateData[index].indexOfSubArrayTwo[beginStepCounter] < subArrayTwo && count > 0) {
    //        int curCount = min(count, subArrayTwo - updateData[index].indexOfSubArrayTwo[beginStepCounter]);
    //        updateData[index].transferRightArray3toPermutedArrayWithNoDummyEntry2(updateData[index].indexOfSubArrayTwo[beginStepCounter], updateData[index].indexOfMergedArray[beginStepCounter], curCount);
    //        updateData[index].indexOfSubArrayTwo[beginStepCounter] += curCount;
    //        updateData[index].indexOfMergedArray[beginStepCounter] += curCount;
    //        count -= curCount;
    //    }

    while (updateData[index].indexOfSubArrayTwo[beginStepCounter] < subArrayTwo && count > 0) {
        pair<prf_type, prf_type> inp = updateData[index].getRightArrayEntry3(updateData[index].indexOfSubArrayTwo[beginStepCounter]);
        updateData[index].setPermutedArrayWithNoDummyEntry2(updateData[index].indexOfMergedArray[beginStepCounter], inp);
        updateData[index].indexOfSubArrayTwo[beginStepCounter]++;
        updateData[index].indexOfMergedArray[beginStepCounter]++;
        count--;
    }
}

void OneChoiceSDdGeneralServer::beginSetup() {
    storage[0]->setupMode = true;
    storage[1]->setupMode = true;
    storage[2]->setupMode = true;
    storage[3]->setupMode = true;
    bool HDD = false;
    hdd = HDD;
    transData.useDisk = HDD;
    for (int i = 0; i < updateData.size(); i++) {
        updateData[i].useDisk = HDD;
    }
}

void OneChoiceSDdGeneralServer::endSetup(bool overwrite) {
    if (overwrite) {
        for (int j = 0; j < 4; j++) {
            for (int i = 0; i < keywordData[j].size(); i++) {
                cout << "inserting keyword instance:" << j << "/4 index:" << i << "/" << data[j].size() << endl;
                //            map<prf_type, prf_type> ciphers;
                //            ciphers.insert(keywordData[j][i]->setData.begin(), keywordData[j][i]->setData.end());
                keywordCounters[j]->insert(i, *keywordData[j][i]->setData, true, true);
            }
        }
        for (int j = 0; j < 4; j++) {
            for (int i = 0; i < data[j].size(); i++) {
                cout << "inserting instance:" << j << "/4 index:" << i << "/" << data[j].size() << endl;
                //                vector<vector<prf_type> >* ciphers = new vector<vector<prf_type> >();
                //                (*ciphers).insert((*ciphers).end(), (*data[j][i]).begin(), (*data[j][i]).end());
                //                storage[j]->insertAll(i, (*ciphers), false, true);
                storage[j]->insertAll(i, (*data[j][i]), false, true, true);
            }
        }
    }
    storage[0]->setupMode = false;
    storage[1]->setupMode = false;
    storage[2]->setupMode = false;
    storage[3]->setupMode = false;
    keywordCounters[0]->setupMode = false;
    keywordCounters[1]->setupMode = false;
    keywordCounters[2]->setupMode = false;
    keywordCounters[3]->setupMode = false;
    bool HDD = true;
    hdd = HDD;
    transData.useDisk = HDD;
    for (int i = 0; i < updateData.size(); i++) {
        updateData[i].useDisk = HDD;
    }

    //#########################################################
    //   For UPDATE should be Uncommented
    //#########################################################
        cout << "TransData Setup begin" << endl;
        transData.endSetup();
        cout << "TransData Setup done" << endl;
        for (int j = 0; j < dataIndex; j++) {
            cout << j << "/" << dataIndex << endl;
            updateData[j].endSetup();
        }
    //#########################################################
    storage[0]->loadCache();
    storage[1]->loadCache();
    storage[2]->loadCache();
    storage[3]->loadCache();
    keywordCounters[0]->loadCache();
    keywordCounters[1]->loadCache();
    keywordCounters[2]->loadCache();
    keywordCounters[3]->loadCache();
}