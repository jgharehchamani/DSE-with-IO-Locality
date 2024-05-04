#ifndef OneChoiceSDdGeneralServer_H
#define OneChoiceSDdGeneralServer_H

#include <vector>

#include "OneChoiceStorage.h"
#include "Storage.h"
#include "TransientStorage.h"
#include "TransientStorage2D.h"

class OneChoiceSDdGeneralClient;

class Entry {
public:
    prf_type element;
    prf_type key;

    void operator=(const Entry& C) {
        element = C.element;
        key = C.key;
    }
};

class Entry2 {
public:
    pair<prf_type, prf_type> element;
    prf_type key;

    void operator=(const Entry2& C) {
        this->element = C.element;
        this->key = C.key;
    }
};

class UpdateData {
public:
    int maxBinSize;
    double tempCacheTime = 0;

    vector<prf_type> leftArray;
    vector<pair<prf_type, prf_type> > leftArray3;
    vector<pair<Entry, unsigned int> > leftArray2;
    vector<pair<Entry2, unsigned int> > leftArray4;
    vector<prf_type> rightArray;
    vector<pair<prf_type, prf_type>> rightArray3;
    vector<pair<Entry, unsigned int> > rightArray2;
    vector<pair<Entry2, unsigned int> > rightArray4;
    vector<pair<Entry, unsigned int> > labeledEntries;
    vector<pair<Entry2, unsigned int> > labeledEntries2;
    vector<prf_type> inputArray;
    vector<pair<prf_type, prf_type> > inputArray2;
    vector< vector< vector<Entry > > > arrayAs;
    vector< vector< vector<Entry2 > > > arrayAs2;
    vector<prf_type> randomLabels;
    vector<prf_type> randomLabels2;
    vector<pair<prf_type, prf_type> > inputAssignedBuckets;
    vector<pair<pair<prf_type, prf_type>, prf_type> > inputAssignedBuckets2;
    vector<prf_type> permutedArrayWithNoDummy;
    vector<pair<prf_type, prf_type>> permutedArrayWithNoDummy2;
    vector<prf_type> sortedKeywords;
    vector<pair<prf_type, prf_type>> sortedBUF1;
    vector<pair<prf_type, prf_type>> sortedBUF2;

    vector<vector<prf_type> >* ciphertexts;
    TransientStorage* leftArraydisk;
    TransientStorage* leftArray3disk;
    TransientStorage* rightArraydisk;
    TransientStorage* rightArray3disk;
    TransientStorage* inputArraydisk;
    TransientStorage* inputArray2disk;
    TransientStorage2D* arrayAsdisk;
    TransientStorage2D* arrayAs2disk;
    TransientStorage* randomLabelsdisk;
    TransientStorage* randomLabels2disk;
    TransientStorage* inputAssignedBucketsdisk;
    TransientStorage* inputAssignedBuckets2disk;
    TransientStorage* permutedArrayWithNoDummydisk;
    TransientStorage* permutedArrayWithNoDummy2disk;
    TransientStorage* sortedKeywordsdisk;
    TransientStorage** ciphertextsdisk;
    TransientStorage* sortedBUF1disk;
    TransientStorage* sortedBUF2disk;

    unordered_map<prf_type, prf_type, PRFHasher>* kwCounters;
    Storage* kwCountersdisk;
public:
    int initialNumberOfLevels, initialNumberOfBuckets;

    map<int, int> indexOfSubArrayOne;
    map<int, int> indexOfSubArrayTwo;
    map<int, int> indexOfMergedArray;

    void setup(int maxOfBinSize) {
        this->maxBinSize = maxOfBinSize;
        ciphertexts = new vector<vector<prf_type> >();
        kwCounters = new unordered_map<prf_type, prf_type, PRFHasher>();
        kwCountersdisk = new Storage(false, numOfIndices, Utilities::rootAddress + "kwServerTransient-" + to_string(curIndex), false);
        kwCountersdisk->setup(true, numOfIndices - 1);
        ciphertextsdisk = new TransientStorage*[maxOfBinSize];
        //        cout << "max bin size:" << maxOfBinSize << endl;
        this->initialNumberOfLevels = numberOfLevels;
        this->initialNumberOfBuckets = bucketNumberB;
        arrayAsdisk = new TransientStorage2D(false, numOfIndices, Utilities::rootAddress + "ArrayAsServerTransient2D-" + to_string(curIndex) + "-", false, numberOfLevels, bucketNumberB, bucketSizeZ);
        arrayAsdisk->setup(true, numOfIndices - 1);
        arrayAs2disk = new TransientStorage2D(false, numOfIndices, Utilities::rootAddress + "ArrayAs2ServerTransient2D-" + to_string(curIndex) + "-", false, numberOfLevels, bucketNumberB, bucketSizeZ);
        arrayAs2disk->setup(true, numOfIndices - 1);

        for (int i = 0; i < maxOfBinSize; i++) {
            ciphertextsdisk[i] = new TransientStorage(false, numOfIndices, Utilities::rootAddress + "CiphertextServerTransient-" + to_string(curIndex) + "-" + to_string(i), false);
            ciphertextsdisk[i]->setup(true, numOfIndices - 1);
        }

        leftArraydisk = new TransientStorage(false, numOfIndices, Utilities::rootAddress + "leftArraydiskServerTransient-" + to_string(curIndex), false);
        leftArray3disk = new TransientStorage(false, numOfIndices, Utilities::rootAddress + "leftArray3diskServerTransient-" + to_string(curIndex), false);
        rightArraydisk = new TransientStorage(false, numOfIndices, Utilities::rootAddress + "rightArraydiskServerTransient-" + to_string(curIndex), false);
        rightArray3disk = new TransientStorage(false, numOfIndices, Utilities::rootAddress + "rightArray3diskServerTransient-" + to_string(curIndex), false);
        inputArraydisk = new TransientStorage(false, numOfIndices, Utilities::rootAddress + "inputArraydiskServerTransient-" + to_string(curIndex), false);
        inputArray2disk = new TransientStorage(false, numOfIndices, Utilities::rootAddress + "inputArray2diskServerTransient-" + to_string(curIndex), false);
        randomLabelsdisk = new TransientStorage(false, numOfIndices, Utilities::rootAddress + "randomLabelsdiskServerTransient-" + to_string(curIndex), false);
        randomLabels2disk = new TransientStorage(false, numOfIndices, Utilities::rootAddress + "randomLabels2diskServerTransient-" + to_string(curIndex), false);
        inputAssignedBucketsdisk = new TransientStorage(false, numOfIndices, Utilities::rootAddress + "inputAssignedBucketsdiskServerTransient-" + to_string(curIndex), false);
        inputAssignedBuckets2disk = new TransientStorage(false, numOfIndices, Utilities::rootAddress + "inputAssignedBuckets2diskServerTransient-" + to_string(curIndex), false);
        permutedArrayWithNoDummydisk = new TransientStorage(false, numOfIndices, Utilities::rootAddress + "permutedArrayWithNoDummydiskServerTransient-" + to_string(curIndex), false);
        permutedArrayWithNoDummy2disk = new TransientStorage(false, numOfIndices, Utilities::rootAddress + "permutedArrayWithNoDummy2diskServerTransient-" + to_string(curIndex), false);
        sortedKeywordsdisk = new TransientStorage(false, numOfIndices, Utilities::rootAddress + "sortedKeywordsdiskServerTransient-" + to_string(curIndex), false);
        sortedBUF1disk = new TransientStorage(false, numOfIndices, Utilities::rootAddress + "sortedBUF1diskServerTransient-" + to_string(curIndex), false);
        sortedBUF2disk = new TransientStorage(false, numOfIndices, Utilities::rootAddress + "sortedBUF2diskServerTransient-" + to_string(curIndex), false);

        leftArraydisk->setup(true, numOfIndices - 1);
        leftArray3disk->setup(true, numOfIndices - 1);
        rightArraydisk->setup(true, numOfIndices - 1);
        rightArray3disk->setup(true, numOfIndices - 1);
        inputArraydisk->setup(true, numOfIndices - 1);
        inputArray2disk->setup(true, numOfIndices - 1);
        randomLabelsdisk->setup(true, numOfIndices - 1);
        randomLabels2disk->setup(true, numOfIndices - 1);
        inputAssignedBucketsdisk->setup(true, numOfIndices - 1);
        inputAssignedBuckets2disk->setup(true, numOfIndices - 1);
        permutedArrayWithNoDummydisk->setup(true, numOfIndices - 1);
        permutedArrayWithNoDummy2disk->setup(true, numOfIndices - 1);
        sortedKeywordsdisk->setup(true, numOfIndices - 1);
        sortedBUF1disk->setup(true, numOfIndices - 1);
        sortedBUF2disk->setup(true, numOfIndices - 1);
    }

    void endSetup() {
        useDisk = true;
//        cout << "inserting leftArray" << endl;
        for (int j = 0; j < leftArray.size(); j++) {
            leftArraydisk->insertEntry(numOfIndices - 1, leftArray[j]);
        }
//        cout << "inserting leftArray3" << endl;
        for (int j = 0; j < leftArray3.size(); j++) {
            leftArray3disk->insertPair(numOfIndices - 1, leftArray3[j]);
        }
//        cout << "inserting rightArray" << endl;
        for (int j = 0; j < rightArray.size(); j++) {
            rightArraydisk->insertEntry(numOfIndices - 1, rightArray[j]);
        }

//        cout << "inserting rightArray3" << endl;
        for (int j = 0; j < rightArray3.size(); j++) {
            rightArray3disk->insertPair(numOfIndices - 1, rightArray3[j]);
        }

//        cout << "inserting inputArray" << endl;
        for (int j = 0; j < inputArray.size(); j++) {
            inputArraydisk->insertEntry(numOfIndices - 1, inputArray[j]);
        }
//        cout << "inserting inputArray2" << endl;
        for (int j = 0; j < inputArray2.size(); j++) {
            inputArray2disk->insertPair(numOfIndices - 1, inputArray2[j]);
        }
//        cout << "inserting randomLabels" << endl;
        for (int j = 0; j < randomLabels.size(); j++) {
            randomLabelsdisk->insertEntry(numOfIndices - 1, randomLabels[j]);
        }
//        cout << "inserting randomLabels2" << endl;
        for (int j = 0; j < randomLabels2.size(); j++) {
            randomLabels2disk->insertEntry(numOfIndices - 1, randomLabels2[j]);
        }
//        cout << "inserting inputAssignedBuckets" << endl;
        for (int j = 0; j < inputAssignedBuckets.size(); j++) {
            inputAssignedBucketsdisk->insertPair(numOfIndices - 1, inputAssignedBuckets[j]);
        }
//        cout << "inserting inputAssignedBuckets2" << endl;
        for (int j = 0; j < inputAssignedBuckets2.size(); j++) {
            inputAssignedBuckets2disk->insertTriple(numOfIndices - 1, inputAssignedBuckets2[j].first.first, inputAssignedBuckets2[j].first.second, inputAssignedBuckets2[j].second);
        }
//        cout << "inserting permutedArrayWithNoDummy" << endl;
        for (int j = 0; j < permutedArrayWithNoDummy.size(); j++) {
            permutedArrayWithNoDummydisk->insertEntry(numOfIndices - 1, permutedArrayWithNoDummy[j]);
        }
//        cout << "inserting permutedArrayWithNoDummy2" << endl;
        for (int j = 0; j < permutedArrayWithNoDummy2.size(); j++) {
            permutedArrayWithNoDummy2disk->insertPair(numOfIndices - 1, permutedArrayWithNoDummy2[j]);
        }
//        cout << "inserting sortedKeywords" << endl;
        for (int j = 0; j < sortedKeywords.size(); j++) {
            sortedKeywordsdisk->insertEntry(numOfIndices - 1, sortedKeywords[j]);
        }
//        cout << "inserting sortedBUF1" << endl;
        for (int j = 0; j < sortedBUF1.size(); j++) {
            sortedBUF1disk->insertPair(numOfIndices - 1, sortedBUF1[j]);
        }
//        cout << "inserting sortedBUF2" << endl;
        for (int j = 0; j < sortedBUF2.size(); j++) {
            sortedBUF2disk->insertPair(numOfIndices - 1, sortedBUF2[j]);
        }
//        cout << "inserting kwCountersdisk" << endl;
        for (auto item : (*kwCounters)) {
            kwCountersdisk->insert(item.first, item.second);
        }

//        cout << "inserting arrayAs" << endl;
        for (int i = 0; i < arrayAs.size(); i++) {
            for (int j = 0; j < arrayAs[i].size(); j++) {
                for (int k = 0; k < arrayAs[i][j].size(); k++) {
                    arrayAsdisk->insertPair(numOfIndices - 1, pair<prf_type, prf_type>(arrayAs[i][j][k].element, arrayAs[i][j][k].key), i, j);
                }
            }
        }

//        cout << "inserting arrayAs2" << endl;
        for (int i = 0; i < arrayAs2.size(); i++) {
            for (int j = 0; j < arrayAs2[i].size(); j++) {
                for (int k = 0; k < arrayAs2[i][j].size(); k++) {
                    arrayAs2disk->insertTriple(numOfIndices - 1, arrayAs2[i][j][k].element.first, arrayAs2[i][j][k].element.second, arrayAs2[i][j][k].key, i, j);
                }
            }
        }

//        cout << "inserting ciphertexts" << endl;
        for (int i = 0; i < (*ciphertexts).size(); i++) {
            for (int j = 0; j < (*ciphertexts)[i].size(); j++) {
                ciphertextsdisk[i]->insertEntry(numOfIndices - 1, (*ciphertexts)[i][j]);
            }
        }

    }

    vector<Entry> getArrayAsBucket(int level, int bucketNumber) {
        if (useDisk) {
            vector<Entry> res;
            auto list = arrayAsdisk->getAllPairs(numOfIndices - 1, level, bucketNumber);
            for (auto item : list) {
                Entry en;
                en.element = item.first;
                en.key = item.second;
                res.push_back(en);
            }
            return res;
        } else {
            return arrayAs[level][bucketNumber];
        }
    }

    vector<Entry2> getArrayAs2Bucket(int level, int bucketNumber) {
        if (useDisk) {
            vector<Entry2> res;
            vector<pair<pair<prf_type, prf_type>, prf_type> > list = arrayAs2disk->getAllTriples(numOfIndices - 1, level, bucketNumber);
            for (auto item : list) {
                Entry2 en;
                en.element.first = item.first.first;
                en.element.second = item.first.second;
                en.key = item.second;
                res.push_back(en);
            }
            return res;
        } else {
            return arrayAs2[level][bucketNumber];
        }
    }

    void setArrayAsBucket(int level, int bucketNumber, vector<Entry> inputs) {
        if (useDisk) {
            vector<pair<prf_type, prf_type>> list;
            for (auto item : inputs) {
                list.push_back(pair<prf_type, prf_type>(item.element, item.key));
            }
            arrayAsdisk->insertVectorOfPairs(numOfIndices - 1, list, level, bucketNumber);
        } else {
            arrayAs[level][bucketNumber] = inputs;
        }
    }

    void setArrayAs2Bucket(int level, int bucketNumber, vector<Entry2> inputs) {
        if (useDisk) {
            vector<pair < pair<prf_type, prf_type>, prf_type>> list;
            for (auto item : inputs) {
                pair<prf_type, prf_type> tmp(item.element.first, item.element.second);
                list.push_back(pair<pair<prf_type, prf_type>, prf_type>(tmp, item.key));
            }
            arrayAs2disk->insertVectorOfTriples(numOfIndices - 1, list, level, bucketNumber);
        } else {
            arrayAs2[level][bucketNumber] = inputs;
        }
    }

    void DestroyArray2DataStructure() {
        tempCacheTime += arrayAs2disk->cacheTime;
        delete arrayAs2disk;

    }

    void UpdateArray2DataStructure() {
        arrayAs2disk = new TransientStorage2D(false, numOfIndices, Utilities::rootAddress + "ArrayAs2ServerTransient2D-" + to_string(curIndex) + "-", false, numberOfLevels, bucketNumberB, bucketSizeZ);
        arrayAs2disk->setup(true, numOfIndices - 1);
        arrayAs2disk->cacheTime = 0;
    }

    vector<prf_type> getLeftArrayPartially(int index, int count) {
        if (useDisk) {
            return leftArraydisk->getEntriesPartially(numOfIndices - 1, index, count);
        } else {
            vector<prf_type> res;
            for (int i = 0; i < count; i++) {
                res.push_back(leftArray[index + i]);
            }
            return res;
        }
    }

    vector<pair<prf_type, prf_type>> getLeftArray3Partially(int index, int count) {
        if (useDisk) {
            return leftArray3disk->getPairsPartially(numOfIndices - 1, index, count);
        } else {
            vector<pair<prf_type, prf_type>> res;
            for (int i = 0; i < count; i++) {
                res.push_back(leftArray3[index + i]);
            }
            return res;
        }
    }

    vector<prf_type> getRightArrayPartially(int index, int count) {
        if (useDisk) {
            return rightArraydisk->getEntriesPartially(numOfIndices - 1, index, count);
        } else {
            vector<prf_type> res;
            for (int i = 0; i < count; i++) {
                res.push_back(rightArray[index + i]);
            }
            return res;
        }
    }

    vector<pair<prf_type, prf_type>> getRightArray3Partially(int index, int count) {
        if (useDisk) {
            return rightArray3disk->getPairsPartially(numOfIndices - 1, index, count);
        } else {
            vector<pair<prf_type, prf_type>> res;
            for (int i = 0; i < count; i++) {
                res.push_back(rightArray3[index + i]);
            }
            return res;
        }
    }

    vector<prf_type> getPermutedArrayWithNoDummyEntryPartially(int index, int count) {
        if (useDisk) {
            return permutedArrayWithNoDummydisk->getEntriesPartially(numOfIndices - 1, index, count);
        } else {
            vector<prf_type> res;
            for (int i = 0; i < count; i++) {
                res.push_back(permutedArrayWithNoDummy[index + i]);
            }
            return res;
        }
    }

    vector<pair<prf_type, prf_type>> getPermutedArrayWithNoDummyEntry2Partially(int index, int count) {
        if (useDisk) {
            return permutedArrayWithNoDummy2disk->getPairsPartially(numOfIndices - 1, index, count);
        } else {
            vector<pair<prf_type, prf_type>> res;
            for (int i = 0; i < count; i++) {
                res.push_back(permutedArrayWithNoDummy2[index + i]);
            }
            return res;
        }
    }

    void storePermutedArrayWithNoDummyEntryPartially(int beginIndex, int count, vector<prf_type> inputs) {
        if (useDisk) {
            permutedArrayWithNoDummydisk->setVectorOfEntries(numOfIndices - 1, beginIndex, inputs);
        } else {
            for (int i = 0; i < count; i++) {
                permutedArrayWithNoDummy[beginIndex + i] = inputs[i];
            }
        }
    }

    void storePermutedArrayWithNoDummyEntry2Partially(int beginIndex, int count, vector<pair<prf_type, prf_type>> inputs) {
        if (useDisk) {
            permutedArrayWithNoDummy2disk->setVectorOfPairs(numOfIndices - 1, beginIndex, inputs);
        } else {
            for (int i = 0; i < count; i++) {
                permutedArrayWithNoDummy2[beginIndex + i] = inputs[i];
            }
        }
    }

    void clearInputArray2() {
        if (useDisk) {
            inputArray2disk->clear(numOfIndices - 1);
        } else {
            inputArray2.clear();
        }
    }

    void insertAthTheEndOfInputArray(prf_type input) {
        if (useDisk) {
            inputArraydisk->insertEntry(numOfIndices - 1, input);
        } else {
            inputArray.push_back(input);
        }
    }

    void transferFromBuf1ToEndIfInputArray(vector<prf_type> inputs) {
        if (useDisk) {
            inputArraydisk->insertEntryVector(numOfIndices - 1, inputs, 0, inputs.size());
        } else {
            inputArray.insert(inputArray.end(), inputs.begin(), inputs.end());
        }
    }

    void insertAthTheEndOfInputArray2(pair<prf_type, prf_type> input) {
        if (useDisk) {
            inputArray2disk->insertPair(numOfIndices - 1, input);
        } else {
            inputArray2.push_back(input);
        }
    }

    void insertVectorAthTheEndOfInputArray2(vector<pair<prf_type, prf_type>> input) {
        if (useDisk) {
            inputArray2disk->insertPairVector(numOfIndices - 1, input, 0, input.size());
        } else {
            for (int i = 0; i < input.size(); i++) {
                inputArray2.push_back(input[i]);
            }
        }
    }

    void insertInArrayAs(vector< vector<Entry > > input) {
        if (!useDisk) {
            arrayAs.push_back(input);
        }
    }

    void insertInArrayAs2(vector< vector<Entry2 > > input) {
        if (!useDisk) {
            arrayAs2.push_back(input);
        }
    }

    void insertVectorInArrayAs(int i, vector<Entry> input) {
        if (!useDisk) {
            arrayAs[i].push_back(input);
        }
    }

    void insertVectorInArrayAs2(int i, vector<Entry2> input) {
        if (!useDisk) {
            arrayAs2[i].push_back(input);
        }
    }

    void insertEntryInArrayAs(int i, int j, Entry input) {
        if (useDisk) {
            arrayAsdisk->insertPair(numOfIndices - 1, pair<prf_type, prf_type>(input.element, input.key), i, j);
        } else {
            arrayAs[i][j].push_back(input);
        }
    }

    void insertEntryInArrayAs2(int i, int j, Entry2 input) {
        if (useDisk) {
            arrayAs2disk->insertTriple(numOfIndices - 1, input.element.first, input.element.second, input.key, i, j);
        } else {
            arrayAs2[i][j].push_back(input);
        }
    }

    void insertInRandomLabels(prf_type tmp) {
        if (useDisk) {
            randomLabelsdisk->insertEntry(numOfIndices - 1, tmp);
        } else {
            randomLabels.push_back(tmp);
        }
    }

    void insertInRandomLabels2(prf_type tmp) {
        if (useDisk) {
            randomLabels2disk->insertEntry(numOfIndices - 1, tmp);
        } else {
            randomLabels2.push_back(tmp);
        }
    }

    void insertInInputAssignedBuckets(pair<prf_type, prf_type> input) {
        if (useDisk) {
            inputAssignedBucketsdisk->insertPair(numOfIndices - 1, input);
        } else {
            inputAssignedBuckets.push_back(input);
        }
    }

    void insertInInputAssignedBuckets2(pair<pair<prf_type, prf_type>, prf_type> input) {
        if (useDisk) {
            inputAssignedBuckets2disk->insertTriple(numOfIndices - 1, input.first.first, input.first.second, input.second);
        } else {
            inputAssignedBuckets2.push_back(input);
        }
    }

    pair<prf_type, prf_type> getInputAssignedBuckets(int i) {
        if (useDisk) {
            return inputAssignedBucketsdisk->getPair(numOfIndices - 1, i);
        } else {
            return inputAssignedBuckets[i];
        }
    }

    pair<pair<prf_type, prf_type>, prf_type> getInputAssignedBuckets2(int i) {
        if (useDisk) {
            prf_type p1, p2, p3;
            inputAssignedBuckets2disk->getTriple(numOfIndices - 1, i, p1, p2, p3);
            pair<prf_type, prf_type> inp1(p1, p2);
            return pair<pair<prf_type, prf_type>, prf_type>(inp1, p3);
        } else {
            return inputAssignedBuckets2[i];
        }
    }

    int getArrayAsSize(int level, int bucket) {
        if (useDisk) {
            return arrayAsdisk->counter[level][bucket];
        } else {
            return arrayAs[level][bucket].size();
        }
    }

    int getArrayAs2Size(int level, int bucket) {
        if (useDisk) {
            return arrayAs2disk->counter[level][bucket];
        } else {
            return arrayAs2[level][bucket].size();
        }
    }

    prf_type getInputArrayElement(int i) {
        if (useDisk) {
            return inputArraydisk->getEntry(numOfIndices - 1, i);
        } else {
            return inputArray[i];
        }
    }

    pair<prf_type, prf_type> getInputArray2Element(int i) {
        if (useDisk) {
            return inputArray2disk->getPair(numOfIndices - 1, i);
        } else {
            return inputArray2[i];
        }
    }

    prf_type getrandomLabelsElement(int i) {
        if (useDisk) {
            return randomLabelsdisk->getEntry(numOfIndices - 1, i);
        } else {
            return randomLabels[i];
        }
    }

    prf_type getrandomLabels2Element(int i) {
        if (useDisk) {
            return randomLabels2disk->getEntry(numOfIndices - 1, i);
        } else {
            return randomLabels2[i];
        }
    }

    Entry getArrayAsEntry(int level, int bucket, int pos) {
        if (useDisk) {
            auto pr = arrayAsdisk->getPair(numOfIndices - 1, pos, level, bucket);
            Entry en;
            en.element = pr.first;
            en.key = pr.second;
            return en;
        } else {
            return arrayAs[level][bucket][pos];
        }
    }

    Entry2 getArrayAs2Entry(int level, int bucket, int pos) {
        if (useDisk) {
            prf_type p1, p2, p3;
            arrayAs2disk->getTriple(numOfIndices - 1, pos, p1, p2, p3, level, bucket);
            Entry2 en;
            en.element = pair<prf_type, prf_type>(p1, p2);
            en.key = p3;
            return en;
        } else {
            return arrayAs2[level][bucket][pos];
        }
    }

    void setKwCounters(prf_type key, prf_type value) {
        if (useDisk) {
            kwCountersdisk->insert(key, value);
        } else {
            (*kwCounters)[key] = value;
        }
    }

    unordered_map<prf_type, prf_type, PRFHasher>* getKwCounters() {
        if (useDisk) {
            return kwCountersdisk->getAllDataPairs(numOfIndices - 1);
        } else {
            return kwCounters;
        }
    }

    vector<prf_type> getCiphertexts(int index) {
        if (useDisk) {
            return ciphertextsdisk[index]->getAllData(numOfIndices - 1);
        } else {
            return (*ciphertexts)[index];
        }
    }

    vector< vector<prf_type> >* getAllCiphertexts() {
        return ciphertexts;
    }

    void clearBeforeMergeSort() {
        if (useDisk) {
            leftArraydisk->clear(numOfIndices - 1);
            rightArraydisk->clear(numOfIndices - 1);
        } else {
            leftArray.clear();
            rightArray.clear();
        }
        indexOfSubArrayOne.clear();
        indexOfSubArrayTwo.clear();
        indexOfMergedArray.clear();
    }

    void clearBeforeMergeSort2() {
        if (useDisk) {
            leftArray3disk->clear(numOfIndices - 1);
            rightArray3disk->clear(numOfIndices - 1);
        } else {
            leftArray3.clear();
            rightArray3.clear();
        }
        indexOfSubArrayOne.clear();
        indexOfSubArrayTwo.clear();
        indexOfMergedArray.clear();
    }

    int getPermutedArrayWithNoDummySize() {
        if (useDisk) {
            return permutedArrayWithNoDummydisk->counter;
        } else {
            return permutedArrayWithNoDummy.size();
        }
    }

    int getPermutedArrayWithNoDummy2Size() {
        if (useDisk) {
            return permutedArrayWithNoDummy2disk->counter;
        } else {
            return permutedArrayWithNoDummy2.size();
        }
    }

    prf_type getPermutedArrayWithNoDummyEntry(int index) {
        if (useDisk) {
            if (index >= localPermutedArrayWithNoDummyEntryBase && localPermutedArrayWithNoDummyEntryBase + bucketSizeZ > index && localPermutedArrayWithNoDummyEntryBase != -1) {
                return localPermutedArrayWithNoDummyEntry[index - localPermutedArrayWithNoDummyEntryBase];
            } else {
                if (localPermutedArrayWithNoDummyEntryBase != -1) {
                    permutedArrayWithNoDummydisk->setVectorOfEntries(numOfIndices - 1, localPermutedArrayWithNoDummyEntryBase, localPermutedArrayWithNoDummyEntry);
                }
                localPermutedArrayWithNoDummyEntryBase = index;
                localPermutedArrayWithNoDummyEntry = getPermutedArrayWithNoDummyEntryPartially(index, bucketSizeZ);
                return localPermutedArrayWithNoDummyEntry[index - localPermutedArrayWithNoDummyEntryBase];
            }
        } else {
            return permutedArrayWithNoDummy[index];
        }
    }

    pair<prf_type, prf_type> getPermutedArrayWithNoDummyEntry2(int index) {
        if (useDisk) {
            if (index >= localPermutedArrayWithNoDummyEntry2Base && localPermutedArrayWithNoDummyEntry2Base + bucketSizeZ > index && localPermutedArrayWithNoDummyEntry2Base != -1) {
                return localPermutedArrayWithNoDummyEntry2[index - localPermutedArrayWithNoDummyEntry2Base];
            } else {
                if (localPermutedArrayWithNoDummyEntry2Base != -1) {
                    permutedArrayWithNoDummy2disk->setVectorOfPairs(numOfIndices - 1, localPermutedArrayWithNoDummyEntry2Base, localPermutedArrayWithNoDummyEntry2);
                }
                localPermutedArrayWithNoDummyEntry2Base = index;
                localPermutedArrayWithNoDummyEntry2 = getPermutedArrayWithNoDummyEntry2Partially(index, bucketSizeZ);
                return localPermutedArrayWithNoDummyEntry2[index - localPermutedArrayWithNoDummyEntry2Base];
            }
        } else {
            return permutedArrayWithNoDummy2[index];
        }
    }

    void insertInPermutedArrayWithNoDummyEntry(prf_type inp) {
        if (useDisk) {
            permutedArrayWithNoDummydisk->insertEntry(numOfIndices - 1, inp);
        } else {
            permutedArrayWithNoDummy.push_back(inp);
        }
    }

    void insertVectorInPermutedArrayWithNoDummyEntry(vector<prf_type> inp) {
        if (useDisk) {
            permutedArrayWithNoDummydisk->insertEntryVector(numOfIndices - 1, inp, 0, inp.size());
        } else {
            for (int i = 0; i < inp.size(); i++) {
                permutedArrayWithNoDummy.push_back(inp[i]);
            }
        }
    }

    void insertInPermutedArrayWithNoDummy2Entry(pair<prf_type, prf_type> inp) {
        if (useDisk) {
            permutedArrayWithNoDummy2disk->insertPair(numOfIndices - 1, inp);
        } else {
            permutedArrayWithNoDummy2.push_back(inp);
        }
    }

    void insertVectorInPermutedArrayWithNoDummy2Entry(vector<pair<prf_type, prf_type>> inp) {
        if (useDisk) {
            permutedArrayWithNoDummy2disk->insertPairVector(numOfIndices - 1, inp, 0, inp.size());
        } else {
            for (int i = 0; i < inp.size(); i++) {
                permutedArrayWithNoDummy2.push_back(inp[i]);
            }
        }
    }

    void setPermutedArrayWithNoDummyEntry(int index, prf_type inp) {
        if (useDisk) {
            if (index >= localPermutedArrayWithNoDummyEntryBase && localPermutedArrayWithNoDummyEntryBase + bucketSizeZ > index && localPermutedArrayWithNoDummyEntryBase != -1) {
                localPermutedArrayWithNoDummyEntry[index - localPermutedArrayWithNoDummyEntryBase] = inp;
            } else {
                if (localPermutedArrayWithNoDummyEntryBase != -1) {
                    permutedArrayWithNoDummydisk->setVectorOfEntries(numOfIndices - 1, localPermutedArrayWithNoDummyEntryBase, localPermutedArrayWithNoDummyEntry);
                }
                localPermutedArrayWithNoDummyEntryBase = index;
                localPermutedArrayWithNoDummyEntry = getPermutedArrayWithNoDummyEntryPartially(index, bucketSizeZ);
                localPermutedArrayWithNoDummyEntry[index - localPermutedArrayWithNoDummyEntryBase] = inp;
            }
        } else {
            permutedArrayWithNoDummy[index] = inp;
        }
    }

    vector<pair<prf_type, prf_type>> localPermutedArrayWithNoDummyEntry2;
    vector<prf_type> localPermutedArrayWithNoDummyEntry;
    int localPermutedArrayWithNoDummyEntry2Base = -1;
    int localPermutedArrayWithNoDummyEntryBase = -1;

    void setPermutedArrayWithNoDummyEntry2(int index, pair<prf_type, prf_type> inp) {
        if (useDisk) {
            if (index >= localPermutedArrayWithNoDummyEntry2Base && localPermutedArrayWithNoDummyEntry2Base + bucketSizeZ > index && localPermutedArrayWithNoDummyEntry2Base != -1) {
                localPermutedArrayWithNoDummyEntry2[index - localPermutedArrayWithNoDummyEntry2Base] = inp;
            } else {
                if (localPermutedArrayWithNoDummyEntry2Base != -1) {
                    permutedArrayWithNoDummy2disk->setVectorOfPairs(numOfIndices - 1, localPermutedArrayWithNoDummyEntry2Base, localPermutedArrayWithNoDummyEntry2);
                }
                localPermutedArrayWithNoDummyEntry2Base = index;
                localPermutedArrayWithNoDummyEntry2 = getPermutedArrayWithNoDummyEntry2Partially(index, bucketSizeZ);
                localPermutedArrayWithNoDummyEntry2[index - localPermutedArrayWithNoDummyEntry2Base] = inp;
            }
        } else {
            permutedArrayWithNoDummy2[index] = inp;
        }
    }

    void flushPermutedArrayWithNoDummyEntry2() {
        if (useDisk) {
            if (localPermutedArrayWithNoDummyEntry2Base != -1) {
                permutedArrayWithNoDummy2disk->setVectorOfPairs(numOfIndices - 1, localPermutedArrayWithNoDummyEntry2Base, localPermutedArrayWithNoDummyEntry2);
                localPermutedArrayWithNoDummyEntry2.clear();
                localPermutedArrayWithNoDummyEntry2Base = -1;
            }
        }
    }

    void flushPermutedArrayWithNoDummyEntry() {
        if (useDisk) {
            if (localPermutedArrayWithNoDummyEntryBase != -1) {
                permutedArrayWithNoDummydisk->setVectorOfEntries(numOfIndices - 1, localPermutedArrayWithNoDummyEntryBase, localPermutedArrayWithNoDummyEntry);
                localPermutedArrayWithNoDummyEntry.clear();
                localPermutedArrayWithNoDummyEntryBase = -1;
            }
        }
    }

    void clearLeftArray() {
        if (useDisk) {
            leftArraydisk->clear(numOfIndices - 1);
            localLeftArrayBase = -1;
            localLeftArray.clear();
        } else {
            leftArray.clear();
        }
    }

    void clearRightArray() {
        if (useDisk) {
            rightArraydisk->clear(numOfIndices - 1);
            localRightArrayBase = -1;
            localRightArray.clear();
        } else {
            rightArray.clear();
        }
    }

    void clearLeftArray3() {
        if (useDisk) {
            leftArray3disk->clear(numOfIndices - 1);
            localLeftArray3Base = -1;
            localLeftArray3.clear();
        } else {
            leftArray3.clear();
        }
    }

    void clearRightArray3() {
        if (useDisk) {
            rightArray3disk->clear(numOfIndices - 1);
            localRightArray3Base = -1;
            localRightArray3.clear();
        } else {
            rightArray3.clear();
        }
    }

    void insertInLeftArray(int index, prf_type input) {
        if (useDisk) {
            if (index >= localLeftArrayBase && localLeftArrayBase + bucketSizeZ > index && localLeftArrayBase != -1) {
                if (localLeftArray.size()>(index - localLeftArrayBase)) {
                    localLeftArray[index - localLeftArrayBase] = input;
                } else {
                    if (localLeftArray.size() == (index - localLeftArrayBase)) {
                        localLeftArray.push_back(input);
                    } else {
                        cout << "What is going on" << endl;
                    }
                }
            } else {
                if (localLeftArrayBase != -1) {
                    leftArraydisk->setVectorOfEntries(numOfIndices - 1, localLeftArrayBase, localLeftArray);
                }
                localLeftArrayBase = index;
                localLeftArray = getLeftArrayPartially(index, bucketSizeZ);
                if (localLeftArray.size() == (index - localLeftArrayBase)) {
                    localLeftArray.push_back(input);
                } else {
                    cout << "What is going on" << endl;
                }
            }
        } else {
            leftArray.push_back(input);
        }
    }

    void insertInRightArray(int index, prf_type input) {
        if (useDisk) {
            if (index >= localRightArrayBase && localRightArrayBase + bucketSizeZ > index && localRightArrayBase != -1) {
                if (localRightArray.size()>(index - localRightArrayBase)) {
                    localRightArray[index - localRightArrayBase] = input;
                } else {
                    if (localRightArray.size() == (index - localRightArrayBase)) {
                        localRightArray.push_back(input);
                    } else {
                        cout << "What is going on" << endl;
                    }
                }
            } else {
                if (localRightArrayBase != -1) {
                    rightArraydisk->setVectorOfEntries(numOfIndices - 1, localRightArrayBase, localRightArray);
                }
                localRightArrayBase = index;
                localRightArray = getRightArrayPartially(index, bucketSizeZ);
                if (localRightArray.size() == (index - localRightArrayBase)) {
                    localRightArray.push_back(input);
                } else {
                    cout << "What is going on" << endl;
                }
            }
        } else {
            rightArray.push_back(input);
        }
    }

    void insertInLeftArray3(int index, pair<prf_type, prf_type> input) {
        if (useDisk) {
            if (index >= localLeftArray3Base && localLeftArray3Base + bucketSizeZ > index && localLeftArray3Base != -1) {
                if (localLeftArray3.size()>(index - localLeftArray3Base)) {
                    localLeftArray3[index - localLeftArray3Base] = input;
                } else {
                    if (localLeftArray3.size() == (index - localLeftArray3Base)) {
                        localLeftArray3.push_back(input);
                    } else {
                        cout << "What is going on" << endl;
                    }
                }
            } else {
                if (localLeftArray3Base != -1) {
                    leftArray3disk->setVectorOfPairs(numOfIndices - 1, localLeftArray3Base, localLeftArray3);
                }
                localLeftArray3Base = index;
                localLeftArray3 = getLeftArray3Partially(index, bucketSizeZ);
                if (localLeftArray3.size() == (index - localLeftArray3Base)) {
                    localLeftArray3.push_back(input);
                } else {
                    cout << "What is going on" << endl;
                }
            }
        } else {
            leftArray3.push_back(input);
        }
    }

    void insertInRightArray3(int index, pair<prf_type, prf_type> input) {
        if (useDisk) {
            if (index >= localRightArray3Base && localRightArray3Base + bucketSizeZ > index && localRightArray3Base != -1) {
                if (localRightArray3.size()>(index - localRightArray3Base)) {
                    localRightArray3[index - localRightArray3Base] = input;
                } else {
                    if (localRightArray3.size() == (index - localRightArray3Base)) {
                        localRightArray3.push_back(input);
                    } else {
                        cout << "What is going on" << endl;
                    }
                }
            } else {
                if (localRightArray3Base != -1) {
                    rightArray3disk->setVectorOfPairs(numOfIndices - 1, localRightArray3Base, localRightArray3);
                }
                localRightArray3Base = index;
                localRightArray3 = getRightArray3Partially(index, bucketSizeZ);
                if (localRightArray3.size() == (index - localRightArray3Base)) {
                    localRightArray3.push_back(input);
                } else {
                    cout << "What is going on" << endl;
                }
            }
        } else {
            rightArray3.push_back(input);
        }
    }

    prf_type getLeftArrayEntry(int index) {
        if (useDisk) {
            if (index >= localLeftArrayBase && localLeftArrayBase + bucketSizeZ > index && localLeftArrayBase != -1) {
                return localLeftArray[index - localLeftArrayBase];
            } else {
                if (localLeftArrayBase != -1) {
                    leftArraydisk->setVectorOfEntries(numOfIndices - 1, localLeftArrayBase, localLeftArray);
                }
                localLeftArrayBase = index;
                localLeftArray = getLeftArrayPartially(index, bucketSizeZ);
                return localLeftArray[index - localLeftArrayBase];
            }
        } else {
            return leftArray[index];
        }
    }

    prf_type getRightArrayEntry(int index) {
        if (useDisk) {
            if (index >= localRightArrayBase && localRightArrayBase + bucketSizeZ > index && localRightArrayBase != -1) {
                return localRightArray[index - localRightArrayBase];
            } else {
                if (localRightArrayBase != -1) {
                    rightArraydisk->setVectorOfEntries(numOfIndices - 1, localRightArrayBase, localRightArray);
                }
                localRightArrayBase = index;
                localRightArray = getRightArrayPartially(index, bucketSizeZ);
                return localRightArray[index - localRightArrayBase];
            }
        } else {
            return rightArray[index];
        }
    }

    vector<pair<prf_type, prf_type>> localLeftArray3;
    int localLeftArray3Base = -1;
    vector<prf_type> localLeftArray;
    int localLeftArrayBase = -1;

    pair<prf_type, prf_type> getLeftArrayEntry3(int index) {
        if (useDisk) {
            if (index >= localLeftArray3Base && localLeftArray3Base + bucketSizeZ > index && localLeftArray3Base != -1) {
                return localLeftArray3[index - localLeftArray3Base];
            } else {
                if (localLeftArray3Base != -1) {
                    leftArray3disk->setVectorOfPairs(numOfIndices - 1, localLeftArray3Base, localLeftArray3);
                }
                localLeftArray3Base = index;
                localLeftArray3 = getLeftArray3Partially(index, bucketSizeZ);
                return localLeftArray3[index - localLeftArray3Base];
            }
        } else {
            return leftArray3[index];
        }
    }

    vector<pair<prf_type, prf_type>> localRightArray3;
    int localRightArray3Base = -1;
    vector<prf_type> localRightArray;
    int localRightArrayBase = -1;

    pair<prf_type, prf_type> getRightArrayEntry3(int index) {
        if (useDisk) {
            if (index >= localRightArray3Base && localRightArray3Base + bucketSizeZ > index && localRightArray3Base != -1) {
                return localRightArray3[index - localRightArray3Base];
            } else {
                if (localRightArray3Base != -1) {
                    rightArray3disk->setVectorOfPairs(numOfIndices - 1, localRightArray3Base, localRightArray3);
                }
                localRightArray3Base = index;
                localRightArray3 = getRightArray3Partially(index, bucketSizeZ);
                return localRightArray3[index - localRightArray3Base];
            }
        } else {
            return rightArray3[index];
        }
    }

    void insertSortedKeywords(prf_type input) {
        if (useDisk) {
            sortedKeywordsdisk->insertEntry(numOfIndices - 1, input);
        } else {
            sortedKeywords.push_back(input);
        }
    }

    void transferFromPermutedArrayWithNoDummyEntryToSortedKeywords(vector<prf_type> input) {
        if (useDisk) {
            sortedKeywordsdisk->insertEntryVector(numOfIndices - 1, input, 0, input.size());
        } else {
            for (int i = 0; i < input.size(); i++) {
                sortedKeywords.push_back(input[i]);
            }
        }
    }

    prf_type getSortedKeywords(int index) {
        if (useDisk) {
            return sortedKeywordsdisk->getEntry(numOfIndices - 1, index);
        } else {
            return sortedKeywords[index];
        }
    }

    vector<prf_type> getSortedKeywordsVector(int index, int count) {
        if (useDisk) {
            return sortedKeywordsdisk->getEntryVector(numOfIndices - 1, index, count);
        } else {
            vector<prf_type> res;
            for (int i = 0; i < count; i++) {
                res.push_back(sortedKeywords[index + i]);
            }
            return res;
        }
    }

    int getSortedKeywordsSize() {
        if (useDisk) {
            return sortedKeywordsdisk->counter;
        } else {
            return sortedKeywords.size();
        }
    }

    void insertSortedBUF1(pair<prf_type, prf_type> input) {
        if (useDisk) {
            sortedBUF1disk->insertPair(numOfIndices - 1, input);
        } else {
            sortedBUF1.push_back(input);
        }
    }

    void insertVectorSortedBUF1(vector<pair<prf_type, prf_type>> input) {
        if (useDisk) {
            sortedBUF1disk->insertPairVector(numOfIndices - 1, input, 0, input.size());
        } else {
            for (int i = 0; i < input.size(); i++) {
                sortedBUF1.push_back(input[i]);
            }
        }
    }

    void clearCiphertexts() {
        if (!useDisk) {
            (*ciphertexts).clear();
        }
    }

    void pushBackVectorInCiphertexts(vector<prf_type> input) {
        if (!useDisk) {
            (*ciphertexts).push_back(input);
        }
    }

    pair<prf_type, prf_type> getSortedBUF1(int index) {
        if (useDisk) {
            return sortedBUF1disk->getPair(numOfIndices - 1, index);
        } else {
            return sortedBUF1[index];
        }
    }

    vector<pair<prf_type, prf_type>> getSortedBUF1Vector(int index, int count) {
        if (useDisk) {
            return sortedBUF1disk->getPairVector(numOfIndices - 1, index, count);
        } else {
            vector<pair<prf_type, prf_type>> res;
            for (int i = 0; i < count; i++) {
                res.push_back(sortedBUF1[index + i]);
            }
            return res;
        }
    }

    //    void insertCiphertext(int index, prf_type input) {
    //        if (useDisk) {
    //            ciphertextsdisk[index]->insertEntry(numOfIndices - 1, input);
    //        } else {
    //            (*ciphertexts)[index].push_back(input);
    //        }
    //    }

    void insertVectorCiphertext(int index, vector<prf_type> input) {
        if (useDisk) {
            ciphertextsdisk[index]->insertEntryVector(numOfIndices - 1, input, 0, input.size());
        } else {
            for (int i = 0; i < input.size(); i++) {
                (*ciphertexts)[index].push_back(input[i]);
            }
        }
    }

    void clearForThirdSort() {
        if (useDisk) {
            leftArray3disk->clear(numOfIndices - 1);
            rightArray3disk->clear(numOfIndices - 1);
            inputArray2disk->clear(numOfIndices - 1);

            for (int i = 0; i < numberOfLevels; i++) {
                for (int j = 0; j < bucketNumberB; j++) {
                    arrayAs2disk->clear(numOfIndices - 1, i, j);
                }
            }
            randomLabels2disk->clear(numOfIndices - 1);
            inputAssignedBuckets2disk->clear(numOfIndices - 1);
            permutedArrayWithNoDummy2disk->clear(numOfIndices - 1);
        } else {
            inputArray2.clear();
            arrayAs2.clear();
            randomLabels2.clear();
            inputAssignedBuckets2.clear();
            permutedArrayWithNoDummy2.clear();
        }
        labeledEntries2.clear();
        leftArray4.clear();
        rightArray4.clear();
    }

    void insertSortedBUF2(pair<prf_type, prf_type> input) {
        if (useDisk) {
            sortedBUF2disk->insertPair(numOfIndices - 1, input);
        } else {
            sortedBUF2.push_back(input);
        }
    }

    void transferFromPermutedArrayWithNoDummyEntry2ToSortedBUF2(vector<pair<prf_type, prf_type>> input) {
        if (useDisk) {
            sortedBUF2disk->insertPairVector(numOfIndices - 1, input, 0, input.size());
        } else {
            for (int i = 0; i < input.size(); i++) {
                sortedBUF2.push_back(input[i]);
            }
        }
    }

    int getSortedBUF2Size() {
        if (useDisk) {
            return sortedBUF2disk->counter;
        } else {
            return sortedBUF2.size();
        }
    }

    pair<prf_type, prf_type> getSortedBUF2(int index) {
        if (useDisk) {
            return sortedBUF2disk->getPair(numOfIndices - 1, index);
        } else {
            return sortedBUF2[index];
        }
    }

    vector<pair<prf_type, prf_type>> getSortedBUF2Vector(int index, int count) {
        if (useDisk) {
            return sortedBUF2disk->getPairVector(numOfIndices - 1, index, count);
        } else {
            vector<pair<prf_type, prf_type>> res;
            for (int i = 0; i < count; i++) {
                res.push_back(sortedBUF2[index + i]);
            }
            return res;
        }
    }

    void clearPermutedArrayWithNoDummyEntry() {
        if (useDisk) {
            permutedArrayWithNoDummydisk->clear(numOfIndices - 1);
            localPermutedArrayWithNoDummyEntryBase = -1;
            permutedArrayWithNoDummydisk->clear(numOfIndices - 1);
        } else {
            permutedArrayWithNoDummy.clear();
        }
    }

    void clearPermutedArrayWithNoDummyEntry2() {
        if (useDisk) {
            localPermutedArrayWithNoDummyEntry2.clear();
            localPermutedArrayWithNoDummyEntry2Base = -1;
            permutedArrayWithNoDummy2disk->clear(numOfIndices - 1);
        } else {
            permutedArrayWithNoDummy2.clear();
        }
    }

    int bucketNumberB = 0;
    int numberOfLevels = 0;
    int initialPerBucketCount = 0;
    int bucketSizeZ = 1024;
    int numberOfDataEntries = 0;
    int fixedNumberOfDataEntries = 0;
    int totalNumberOfSteps = 0;
    int fixedTotalNumberOfSteps = 0;

    bool useDisk = true;
    int numOfIndices;
    int curIndex;

    UpdateData(int n, int curIndex, int numOfIndices) {
        this->curIndex = curIndex;
        this->numOfIndices = numOfIndices;
        numberOfDataEntries = n;
        fixedNumberOfDataEntries = n;
    };

    int getTotalNumberOfSteps(int n) {
        int curbucketNumberB = (int) ceil(2 * n / bucketSizeZ);
        int power = 1;
        while (power < curbucketNumberB) {
            power *= 2;
        }
        curbucketNumberB = power == 1 ? 2 : power;
        int curnumberOfLevels = (int) (log2(curbucketNumberB)) + 1;

        return 1 + (curnumberOfLevels * curbucketNumberB) + (2 * n) + n + (curbucketNumberB * bucketSizeZ) +
                (((curnumberOfLevels - 1) * (curbucketNumberB / 2) * (2 * bucketSizeZ * 2)) + curbucketNumberB * bucketSizeZ * log2(bucketSizeZ)) +
                (curbucketNumberB * bucketSizeZ) + (n * ceil(log2(n)));
    };

    void clear() {
        if (useDisk) {
            leftArraydisk->clear(numOfIndices - 1);
            leftArray3disk->clear(numOfIndices - 1);
            rightArraydisk->clear(numOfIndices - 1);
            rightArray3disk->clear(numOfIndices - 1);
            inputArraydisk->clear(numOfIndices - 1);
            inputArray2disk->clear(numOfIndices - 1);
            for (int i = 0; i < numberOfLevels; i++) {
                for (int j = 0; j < bucketNumberB; j++) {
                    arrayAsdisk->clear(numOfIndices - 1, i, j);
                    arrayAs2disk->clear(numOfIndices - 1, i, j);
                }
            }
            randomLabelsdisk->clear(numOfIndices - 1);
            randomLabels2disk->clear(numOfIndices - 1);
            inputAssignedBucketsdisk->clear(numOfIndices - 1);
            inputAssignedBuckets2disk->clear(numOfIndices - 1);
            permutedArrayWithNoDummydisk->clear(numOfIndices - 1);
            permutedArrayWithNoDummy2disk->clear(numOfIndices - 1);
            sortedKeywordsdisk->clear(numOfIndices - 1);
            for (int i = 0; i < maxBinSize; i++) {
                ciphertextsdisk[i]->clear(numOfIndices - 1);
            }
            sortedBUF1disk->clear(numOfIndices - 1);
            sortedBUF2disk->clear(numOfIndices - 1);
            kwCountersdisk->clear(numOfIndices - 1);
        } else {

            arrayAs.clear();
            arrayAs2.clear();
            randomLabels.clear();
            randomLabels2.clear();
            inputAssignedBuckets.clear();
            inputAssignedBuckets2.clear();
            permutedArrayWithNoDummy.clear();
            permutedArrayWithNoDummy2.clear();
            leftArray.clear();
            leftArray3.clear();
            rightArray.clear();
            rightArray3.clear();
            sortedKeywords.clear();
            ciphertexts = new vector<vector<prf_type> >();
            sortedBUF1.clear();
            sortedBUF2.clear();
            kwCounters = new unordered_map<prf_type, prf_type, PRFHasher>();
            inputArray.clear();
            inputArray2.clear();
        }
        indexOfSubArrayOne.clear();
        indexOfSubArrayTwo.clear();
        indexOfMergedArray.clear();

        labeledEntries.clear();
        labeledEntries2.clear();
        leftArray2.clear();
        leftArray4.clear();
        rightArray2.clear();
        rightArray4.clear();
    }
};

class EachSet2 {
public:
    unordered_map<prf_type, prf_type, PRFHasher>* setData;

    EachSet2() {
        setData = new unordered_map<prf_type, prf_type, PRFHasher>();
    }

    ~EachSet2() {
        delete setData;
    }

};

class TransientData {
public:
    vector<vector<prf_type> > BUF1;
    vector<vector<pair<prf_type, prf_type> > > binAssignedEntries;
    vector<vector<pair<prf_type, prf_type> > > BUF2;

    TransientStorage** buf1disks;
    TransientStorage** bindisks;
    TransientStorage** buf2disks;

    int numOfIndecies;
public:
    bool useDisk = true;

    void setup(int numOfIndices) {
        this->numOfIndecies = numOfIndices;
        buf1disks = new TransientStorage*[numOfIndices];
        bindisks = new TransientStorage*[numOfIndices];
        buf2disks = new TransientStorage*[numOfIndices];
        for (int i = 0; i < numOfIndices; i++) {
            buf1disks[i] = new TransientStorage(false, numOfIndices, Utilities::rootAddress + "BUF1ServerTransient-" + to_string(i), false);
            buf1disks[i]->setup(true, numOfIndices - 1);
            bindisks[i] = new TransientStorage(false, numOfIndices, Utilities::rootAddress + "BINServerTransient-" + to_string(i), false);
            bindisks[i]->setup(true, numOfIndices - 1);
            buf2disks[i] = new TransientStorage(false, numOfIndices, Utilities::rootAddress + "BUF2ServerTransient-" + to_string(i), false);
            buf2disks[i]->setup(true, numOfIndices - 1);
        }
        for (int i = 0; i < numOfIndices; i++) {
            BUF1.push_back(vector<prf_type>());
            BUF2.push_back(vector<pair<prf_type, prf_type> >());
            binAssignedEntries.push_back(vector<pair<prf_type, prf_type> >());
        }
    }

    void endSetup() {
        useDisk = true;
        for (int i = 0; i < numOfIndecies; i++) {
            for (int j = 0; j < BUF1[i].size(); j++) {
                buf1disks[i]->insertEntry(numOfIndecies - 1, BUF1[i][j]);
            }
            for (int j = 0; j < binAssignedEntries[i].size(); j++) {
                bindisks[i]->insertPair(numOfIndecies - 1, binAssignedEntries[i][j]);
            }
            for (int j = 0; j < BUF2[i].size(); j++) {
                buf2disks[i]->insertPair(numOfIndecies - 1, BUF2[i][j]);
            }
        }
    }

    void clear(int srcIndex) {
        if (useDisk) {
            buf1disks[srcIndex]->clear(numOfIndecies - 1);
            bindisks[srcIndex]->clear(numOfIndecies - 1);
            buf2disks[srcIndex]->clear(numOfIndecies - 1);
        } else {
            BUF1[srcIndex].clear();
            BUF2[srcIndex].clear();
            binAssignedEntries[srcIndex].clear();
        }
    }

    int getBuf1Size(int index) {
        if (useDisk) {
            return buf1disks[index]->counter;
        } else {
            return BUF1[index].size();
        }
    }

    int getBinAssignedEntriesSize(int index) {
        if (useDisk) {
            return bindisks[index]->counter;
        } else {
            return binAssignedEntries[index].size();
        }
    }

    int getBUF2Size(int index) {
        if (useDisk) {
            return buf2disks[index]->counter;
        } else {
            return BUF2[index].size();
        }
    }

    void pushBackBuf1(int index, prf_type inp) {
        if (useDisk) {
            buf1disks[index]->insertEntry(numOfIndecies - 1, inp);
        } else {
            BUF1[index].push_back(inp);
        }
    }

    void pushBackBuf1Vector(int index, vector<prf_type> inp, int beginIndex, int count) {
        if (useDisk) {
            buf1disks[index]->insertEntryVector(numOfIndecies - 1, inp, beginIndex, count);
        } else {
            for (int i = beginIndex; i < beginIndex + count; i++) {
                BUF1[index].push_back(inp[i]);
            }
        }
    }

    void pushBackBinAssignedEntries(int index, pair<prf_type, prf_type> input) {
        if (useDisk) {
            bindisks[index]->insertPair(numOfIndecies - 1, input);
        } else {
            binAssignedEntries[index].push_back(input);
        }

    }

    void pushBackVectorBinAssignedEntries(int index, vector<pair<prf_type, prf_type> > input) {
        if (useDisk) {
            bindisks[index]->insertPairVector(numOfIndecies - 1, input, 0, input.size());
        } else {
            for (int i = 0; i < input.size(); i++) {
                binAssignedEntries[index].push_back(input[i]);
            }
        }

    }

    void pushBackBuf2(int index, pair<prf_type, prf_type> input) {
        if (useDisk) {
            buf2disks[index]->insertPair(numOfIndecies - 1, input);
        } else {
            BUF2[index].push_back(input);
        }
    }

    void pushBackVectorBuf2(int index, vector<pair<prf_type, prf_type>> input) {
        if (useDisk) {
            buf2disks[index]->insertPairVector(numOfIndecies - 1, input, 0, input.size());
        } else {
            for (int i = 0; i < input.size(); i++) {
                BUF2[index].push_back(input[i]);
            }
        }
    }

    prf_type getBUF1(int index, int pos) {
        if (useDisk) {
            return buf1disks[index]->getEntry(numOfIndecies - 1, pos);
        } else {
            return BUF1[index][pos];
        }
    }

    vector<prf_type> getBUF1Vector(int index, int begin, int count) {
        if (useDisk) {
            return buf1disks[index]->getEntryVector(numOfIndecies - 1, begin, count);
        } else {
            vector<prf_type> res;
            for (int i = 0; i < count; i++) {
                res.push_back(BUF1[index][begin + i]);
            }
            return res;
        }
    }

    pair<prf_type, prf_type> getBinAssignedEntries(int index, int pos) {
        if (useDisk) {
            return bindisks[index]->getPair(numOfIndecies - 1, pos);
        } else {
            return binAssignedEntries[index][pos];
        }
    }

    vector<pair<prf_type, prf_type>> getBinAssignedEntriesVector(int index, int begin, int count) {
        if (useDisk) {
            return bindisks[index]->getPairVector(numOfIndecies - 1, begin, count);
        } else {
            vector<pair<prf_type, prf_type>> res;
            for (int i = 0; i < count; i++) {
                res.push_back(binAssignedEntries[index][begin + i]);
            }
            return res;
        }
    }

    pair<prf_type, prf_type> getBUF2(int index, int pos) {
        if (useDisk) {
            return buf2disks[index]->getPair(numOfIndecies - 1, pos);
        } else {
            return BUF2[index][pos];
        }
    }
};

class OneChoiceSDdGeneralServer {
public:
    OneChoiceStorage** storage = NULL;
    Storage** keywordCounters = NULL;
    bool profile = false;
    bool storeKWCounter = false;
    vector<int> numberOfBins;
    vector<int> sizeOfEachBin;
    TransientData transData;

    int dataIndex;
    vector<UpdateData > updateData;
    prf_type initialDummy;
    pair<prf_type, prf_type> initialDummy2;
    OneChoiceSDdGeneralClient* client;
    bool hdd = true;
    vector<vector< vector<vector<prf_type> >* > > data;
    vector<vector< EachSet2* > > keywordData; //OLDEST, OLDER, OLD, NEW;





    bool obliviousBucketSort(int beginStep, int count, int index, int inputSize, bool (OneChoiceSDdGeneralClient::*cmpFunc)(prf_type, prf_type));
    bool obliviousBucketSort2(int beginStep, int count, int index, int inputSize, bool (OneChoiceSDdGeneralClient::*cmpFunc)(pair<prf_type, prf_type>, pair<prf_type, prf_type>));
    void merge(int const left, int const mid, int const right, int& count, int index, int innerMapCounter, bool (OneChoiceSDdGeneralClient::*cmpFunc)(prf_type, prf_type));
    void merge2(int const left, int const mid, int const right, int& count, int index, int innerMapCounter, bool (OneChoiceSDdGeneralClient::*cmpFunc)(pair<prf_type, prf_type>, pair<prf_type, prf_type>));
    void mergeSort(int const begin, int const end, int beginStep, int& count, int index, bool (OneChoiceSDdGeneralClient::*cmpFunc)(prf_type, prf_type));
    void mergeSort2(int const begin, int const end, int beginStep, int& count, int index, bool (OneChoiceSDdGeneralClient::*cmpFunc)(pair<prf_type, prf_type>, pair<prf_type, prf_type>));

    void phase0(int srcIndex);
    void phase1(int srcIndex, int beginIndex, int& count);
    void phase2(int srcIndex, int beginIndex, int& count);
    void phase3(int srcIndex, int beginIndex, int& count);
    void storeCiphers(long instance, long dataIndex);

public:
    long serverSearchTime = 0;
    OneChoiceSDdGeneralServer(long dataIndex, bool inMemory, bool overwrite, bool profile, prf_type initialDummy, OneChoiceSDdGeneralClient* client, bool storeKWCounter = true);
    void clear(long instance, long index);
    virtual ~OneChoiceSDdGeneralServer();
    void storeKeywordCounters(long instance, long dataIndex, unordered_map<prf_type, prf_type, PRFHasher>* keywordCounters);
    void storeCiphers(long instance, long dataIndex, vector<vector<prf_type> >* ciphers, unordered_map<prf_type, prf_type, PRFHasher>* keywordCounters);
    void storeCiphers(long instance, long dataIndex, vector<prf_type> ciphers, bool firstRun);
    void storeCiphers(long instance, long dataIndex, vector<vector<prf_type> >* ciphers);
    void resetup(long instance, long dataIndex);
    vector<prf_type> search(long instance, long dataIndex, prf_type token, long keywordCnt);
    vector<prf_type> getAllDataFlat(long instance, long dataIndex);
    vector<vector<prf_type> >* getAllData(long instance, long dataIndex);
    unordered_map<prf_type, prf_type, PRFHasher>* getAllKWCounters(long instance, long dataIndex);
    long getCounter(long instance, long dataIndex, prf_type tokkw);
    void obliviousMerge(int oldestAndOldIndex, int beginStep, int count);
    int getTotalNumberOfSteps(int oldestAndOldIndex);
    void move(int fromInstance, int fromIndex, int toInstance, int toIndex);
    void endSetup(bool overwrite);
    void beginSetup();
    void decryptPermutedArrayWithNoDummyEntry(int size, int index);
    void decryptPermutedArrayWithNoDummyEntry2(int size, int index);
    void encryptPermutedArrayWithNoDummyEntry(int size, int index);
    void encryptPermutedArrayWithNoDummyEntry2(int size, int index);
    //    void storeCiphers(long instance, long dataIndex, vector<vector<prf_type> > ciphers, bool firstRun);

};

#endif /* ONECHOICESERVER_H */
