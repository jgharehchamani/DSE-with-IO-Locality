#ifndef ONECHOICECLIENT_H
#define ONECHOICECLIENT_H

#include <string>
#include <stdio.h>
#include <string.h>
#include <map>
#include<set>
#include <vector>
#include <array>
#include "Server.h"
#include <iostream>
#include <sstream>
#include "Server.h"
#include "Utilities.h"
#include "AES.hpp"
#include "OneChoiceSDdNoOMAPServer.h"
#include "OMAP.h"
#include <unordered_map>

class OneChoiceSDdNoOMAPClient {
private:
    OneChoiceSDdNoOMAPServer* server;
    bool profile = false;

public:
    vector<OMAP*> omaps;
    virtual ~OneChoiceSDdNoOMAPClient();
    OneChoiceSDdNoOMAPClient(int maxUpdate, bool inMemory, bool overwrite, bool profile);
    int totalCommunication = 0;
    vector<int> numberOfBins;
    vector<int> sizeOfEachBin;
    vector<int> indexSize;
    prf_type nullKey;
    int numOfIndices;
    vector<int> numNEW;
    vector<int> NEWsize;
    vector<int> KWsize;
    vector<unordered_map<string, int>> P;
    int b;
    vector<vector<int>> Bins;

    vector<vector<bool>> exist;
    vector<vector<set<string>>> setk;
    void destroy(int index);
    void setup(int index, unordered_map<string, vector<prf_type> >pairs, unsigned char* key);
    vector<prf_type> search(int index, int instance, string keyword, unsigned char* key);
    vector<prf_type> NIsearch(int index, int instance, string keyword, unsigned char* key);
    vector<prf_type> getAllData(int index, int instance, unsigned char* key);
    void move(int index, int toInstance, int fromInstance);
    void copy(int index, int toInstance);
    void append(int instance, prf_type keyVal, unsigned char* key);
    void appendTokwCounter(int instance, prf_type keyVal, unsigned char* key);
    void destroy(int index, int instance);
    void resize(int index, int size);
    void reSize(int index, int size);
    void getBin(int newindex, int instance, int start, int end, unsigned char* key1, unsigned char* key2);
    void addDummy(int index, int count, unsigned char* key, int s, int r1, int r2);
    void deAmortizedBitSort(int step, int counter, int size, int index, unsigned char* key);
    void deAmortizedBitSortC(int step, int count, int size, int index, unsigned char* key);
    void nonOblSort(int index, unsigned char* key);
    int hashKey(string w, int cnt, int index, unsigned char* key);
    void updateHashTable(int index, unsigned char* key);
    Bid getBid(string str, int cnt);
    vector<prf_type> searchNEW(int index, string keyword);
    void ensureNEWSize(int index, int bin, int cnt);
    int getNEWsize(int index);
    void pad(int index, int newSize, unsigned char* key);
    void updateCounters(int index, unsigned char* key);
    void updateCounters(int index, unsigned char* key, int count, int r1, int r2);
    void kwCount(int index, unsigned char* key, int count, int r1, int r2);
    void updateOMAP(int index, string keyword, unsigned char* key);
    bool sorted(int index, unsigned char* key);

    ///SDd without OMAP
    void Phase1(int index, int binNumber, int numberOfBins, unsigned char* keynew, unsigned char* key0, unsigned char* key1);
    void Phase2(int index, int binNumber, int numberOfBins, unsigned char* keynew, unsigned char* key0, unsigned char* key1);
    void LinearScanBinCount(int index, int binNumber, int numberOfBins, unsigned char* key);
    void addDummy(int index, int binNumber, int numberOfBins, unsigned char* key);
    void deAmortizedBitSort();
    void createKeyVal(string keyword, int ind, int op, int cntw, int newbin, prf_type& keyVal);
};

#endif /* ONECHOICECLIENT_H */

