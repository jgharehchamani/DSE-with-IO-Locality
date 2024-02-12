#ifndef OneChoiceSDdGeneralClient_H
#define OneChoiceSDdGeneralClient_H

#include <string>
#include <stdio.h>
#include <string.h>
#include <map>
#include <vector>
#include <array>
#include "Server.h"
#include <iostream>
#include <sstream>
#include "Server.h"
#include "Utilities.h"
#include "AES.hpp"
#include "OMAP.h"
#include "Bitonic.h"
#include <unordered_map>
#include "OneChoiceSDdGeneralServer.h"

class ClientTransientData {
public:
    vector<map<int, int> > BIN;
    vector<map<string, int> > CNT;
    Storage** bindisks;
    Storage** cntdisks;
    int numOfIndecies;
public:
    bool useDisk = true;

    void setup(int numOfIndices, vector<int> numOfBins) {
        this->numOfIndecies = numOfIndices;
        bindisks = new Storage*[numOfIndices];
        cntdisks = new Storage*[numOfIndices];
        for (int i = 0; i < numOfIndices; i++) {
            bindisks[i] = new Storage(false, numOfIndices, Utilities::rootAddress + "BINClientTransient-" + to_string(i), false);
            bindisks[i]->setup(true, numOfIndices - 1);
            cntdisks[i] = new Storage(false, numOfIndices, Utilities::rootAddress + "CNTClientTransient-" + to_string(i), false);
            cntdisks[i]->setup(true, numOfIndices - 1);
            for (int j = 0; j < numOfBins[i]; j++) {
                bindisks[i]->insert(j, 0);
            }
        }
        for (int i = 0; i < numOfIndices; i++) {
            BIN.push_back(map<int, int>());
            for (int j = 0; j < numOfBins[i]; j++) {
                BIN[i][j] = 0;
            }
            CNT.push_back(map<string, int>());
        }
    }

    void endSetup() {
        useDisk = true;
        for (int i = 0; i < numOfIndecies; i++) {
            for (auto item : BIN[i]) {
                bindisks[i]->insert(item.first, item.second);
            }
            for (auto item : CNT[i]) {
                cntdisks[i]->insert(item.first, item.second);
            }
        }
    }

    void resetBIN(int i, int numberOfBins) {
        if (useDisk) {
            //            cout<<"index:"<<i<<"set to 0 up to:" << numberOfBins <<endl;
            for (int j = 0; j < numberOfBins; j++) {
                bindisks[i]->insert(j, 0);
            }
        } else {
            for (int j = 0; j < numberOfBins; j++) {
                BIN[i][j] = 0;
            }
        }

    }

    void clearBIN(int index) {
        if (useDisk) {
            //            cout<<"index:"<<index<<"clear bin"<<endl;
            bindisks[index]->clear(numOfIndecies - 1);
        } else {
            BIN[index].clear();
        }
    }

    void clearCNT(int index) {
        if (useDisk) {
            cntdisks[index]->clear(numOfIndecies - 1);
        } else {
            CNT[index].clear();
        }
    }

    bool CNTkeyExist(int index, string keyword) {
        if (useDisk) {
            int val;
            return cntdisks[index]->get(keyword, val);
        } else {
            return CNT[index].count(keyword) > 0;
        }
    }

    bool BINKeyExist(int index, int key) {
        if (useDisk) {
            int val;
            return bindisks[index]->get(key, val);
        } else {
            return BIN[index].count(key) > 0;
        }
    }

    void insertCNT(int index, string keyword, int value) {
        if (useDisk) {
            cntdisks[index]->insert(keyword, value);
        } else {
            CNT[index][keyword] = value;
        }
    }

    void replaceCNT(int index, string keyword, int value) {
        if (useDisk) {
            cntdisks[index]->replace(keyword, value);
        } else {
            CNT[index][keyword] = value;
        }
    }

    int getCNT(int index, string keyword) {
        if (useDisk) {
            int val;
            cntdisks[index]->get(keyword, val);
            return val;
        } else {
            return CNT[index][keyword];
        }
    }

    int getBIN(int index, int key) {
        if (useDisk) {
            int val;
            bindisks[index]->get(key, val);
            return val;
        } else {
            return BIN[index][key];
        }
    }

    void replaceBIN(int index, int key, int val) {
        if (useDisk) {
            //            cout<<"index:"<<index<<"replace key:"<<key<<endl;
            bindisks[index]->replace(key, val);
        } else {
            BIN[index][key] = val;
        }
    }

    void insertBIN(int index, int key, int val) {
        if (useDisk) {
            //            cout<<"insert key:"<<key<<endl;
            bindisks[index]->insert(key, val);
        } else {
            BIN[index][key] = val;
        }
    }

    void eraseCNT(int index, string keyword) {
        if (useDisk) {
            cntdisks[index]->erase(keyword);
        } else {
            CNT[index].erase(keyword);
        }
    }
};

class OneChoiceSDdGeneralClient {
public:
    OneChoiceSDdGeneralServer* server;
    bool profile = false;
    unsigned char EncKey[TMP_AES_KEY_SIZE];
    unsigned char A0KEY[TMP_AES_KEY_SIZE];
    unsigned char A1KEY[TMP_AES_KEY_SIZE];
    unsigned char NEWKEY[TMP_AES_KEY_SIZE];

    ClientTransientData transData;

public:
    virtual ~OneChoiceSDdGeneralClient();
    OneChoiceSDdGeneralClient(int maxUpdate, bool inMemory, bool overwrite, bool profile);
    int totalCommunication = 0;
    vector<int> numberOfBins;
    vector<int> sizeOfEachBin;
    vector<int> indexSize;
    vector<vector<vector<prf_type>>> setupFiles;
    prf_type nullKey;
    int numOfIndices;
    map<string, int> counters;
    vector<int> numNEW;
    vector<int> NEWsize;
    vector<int> KWsize;
    int b;
    double searchTime;
    double TotalCacheTime;
    vector<vector<bool>> exist;

    void merge(vector<pair<Entry, unsigned int> >* array, int const left, int const mid, int const right, int& count, int index, int innerMapCounter, UpdateData& updateData);
    void merge(vector<pair<Entry2, unsigned int> >* array, int const left, int const mid, int const right, int& count, int index, int innerMapCounter, UpdateData& updateData);
    void mergeSort(vector<pair<Entry, unsigned int> >* array, int const begin, int const end, int beginStep, int& count, int index, UpdateData& updateData);
    void mergeSort(vector<pair<Entry2, unsigned int> >* array, int const begin, int const end, int beginStep, int& count, int index, UpdateData& updateData);
    void permuteBucket(vector<Entry >& bucket, int beginStep, int count, int index, UpdateData& updateData);
    void permuteBucket(vector<Entry2 >& bucket, int beginStep, int count, int index, UpdateData& updateData);
    void mergeSplit(vector<Entry > A0, vector<Entry > A1, unsigned int bitIndex, vector<Entry >& A0prime, vector<Entry >& A1prime, bool permute, int n, int beginStep, int count, int bucketSizeZ, int index, UpdateData& updateData);
    //    void mergeSplit(int A0_index1,int A0_index2, int A1_index1,int A1_index2, unsigned int bitIndex, int A0prime_index1,int A0prime_index2, int A1prime_index1,int A1prime_index2, bool permute, int n, int beginStep, int count, int bucketSizeZ, int index, UpdateData& updateData);
    //    void mergeSplit2(int A0_index1,int A0_index2, int A1_index1,int A1_index2, unsigned int bitIndex, int A0prime_index1,int A0prime_index2, int A1prime_index1,int A1prime_index2, bool permute, int n, int beginStep, int count, int bucketSizeZ, int index, UpdateData& updateData);
    void mergeSplit(vector<Entry2 > A0, vector<Entry2 > A1, unsigned int bitIndex, vector<Entry2 >& A0prime, vector<Entry2 >& A1prime, bool permute, int n, int beginStep, int count, int bucketSizeZ, int index, UpdateData& updateData);
    vector<prf_type> getRandomKeys(int n, int bucketNumberB, int begin, int count, int index);
    vector<prf_type> getRandomKeys2(int n, int bucketNumberB, int begin, int count, int index);
    void removeDummies(int level, int bucketSizeZ, int beginStep, int count, int index, UpdateData& updateData);
    void removeDummies2(int level, int bucketSizeZ, int beginStep, int count, int index, UpdateData& updateData);
    bool compare(prf_type lhs, prf_type rhs);
    bool keywordCompare(prf_type lhs, prf_type rhs);
    bool binCompare(pair<prf_type, prf_type> lhs, pair<prf_type, prf_type> rhs);
    bool buf2Compare(pair<prf_type, prf_type> lhs, pair<prf_type, prf_type> rhs);
    bool compare(pair<Entry, unsigned int> lhs, pair<Entry, unsigned int> rhs);
    bool compare(pair<Entry2, unsigned int> lhs, pair<Entry2, unsigned int> rhs);
    //    vector<prf_type> loadArray(int begin, int count, int index, UpdateData& updateData);
    pair<prf_type, prf_type> assignToNewBin(prf_type entry, int newIndex);
    pair<prf_type, prf_type> createBuf2Entry(prf_type entry, int newIndex);
    vector<pair<prf_type, prf_type> > getExtraDummies(int newIndex, int binNumber, int beginStep, int& count);
    pair<prf_type, prf_type> prepareKWCounter(pair<prf_type, prf_type> encCounter);

    prf_type makeReadyForStore(prf_type encryptedValue);
    pair<prf_type, prf_type> getInitialDummy2();
    void endSetup(bool overwrite);
    void beginSetup();


    void setup(long index, long instance, unordered_map<string, vector<prf_type> > pairs, unsigned char* key);
    void setup2(long index, long instance, unordered_map<string, vector<tmp_prf_type> > pairs, unsigned char* key);
    vector<prf_type> search(int index, int instance, string keyword, unsigned char* key);
    vector<prf_type> convertTmpCiphersToFinalCipher(vector<pair<std::pair<string, long>, tmp_prf_type> > ciphers, unsigned char* key);
    void destry(int instance, int index);
    void destryAndClear(int instance, int index);
    void move(int fromInstance, int fromIndex, int toInstance, int toIndex);
    void obliviousMerge(unsigned char* oldestKey, unsigned char* olderKey, unsigned char* newKey, int oldestAndOldIndex, int beginStep, int maxSteps);
    int getTotalNumberOfSteps(int oldestAndOldIndex);
    vector<prf_type> updateKeys(vector<prf_type> input, bool isA0);
    void phase0(int srcIndex);
    prf_type decryptEntity(prf_type input);
    pair<prf_type, prf_type> decryptEntity2(pair<prf_type, prf_type> input);
    prf_type decryptEntity2(prf_type input);
    prf_type encryptEntity(prf_type input);
    pair<prf_type, prf_type> encryptEntity2(pair<prf_type, prf_type> input);
    double serverTime;
};


#endif /* OneChoiceSDdGeneralClient */
