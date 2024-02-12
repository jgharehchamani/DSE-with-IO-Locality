#ifndef OneChoiceSDdOMAPClient_H
#define OneChoiceSDdOMAPClient_H

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
#include "OneChoiceSDdOMAPServer.h"
#include "OMAP.h"
#include "Bitonic.h"
#include <unordered_map>
#include "OneChoiceServer.h"

class OneChoiceSDdOMAPClient {
private:
    OneChoiceServer** server;
    Bitonic* bitonic;
    bool profile = false;

public:
    vector<OMAP*> omaps;
    virtual ~OneChoiceSDdOMAPClient();
    OneChoiceSDdOMAPClient(int maxUpdate, bool inMemory, bool overwrite, bool profile);
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
    //    void setup(int index, unordered_map<string, vector<prf_type> >pairs, unsigned char* key);
    void setup(long index, long instance, unordered_map<string, vector<prf_type> > pairs, unsigned char* key);
    void setup2(long index, long instance, unordered_map<string, vector<tmp_prf_type> > pairs, unsigned char* key);
    vector<prf_type> search(int index, int instance, string keyword, unsigned char* key);
    vector<vector<prf_type> > convertTmpCiphersToFinalCipher(vector<pair<std::pair<string, long>, tmp_prf_type> > ciphers, unsigned char* key);
    //    vector<prf_type> searchSetup(int index, int instance, string keyword, unsigned char* key);
    //    void endSetup(int index, int instance, unsigned char* key, bool setup);

    //    void getBin(int newindex, int instance, int start, int end, unsigned char* key1, unsigned char* key2, bool setup);
    //    void kwCount(int index, int count, int bin, unsigned char* key, bool setup);
    //    void addDummy(int index, int count, int numBin, unsigned char* key, bool setup);
    //    void deAmortBitSort(int step, int counter, int size, int index, unsigned char* key, bool setup);
    //    void deAmortBitSortC(int step, int count, int size, int index, unsigned char* key, bool setup);
    //    void updateHashTable(int index, unsigned char* key, bool setup);
    //    void resize(int index, int size, bool setup);
    //    void move(int index, int toInstance, int fromInstance, bool setup);
    //    void destroy(int index, int instance, bool setup);
    //    void appendTokwCounter(int instance, prf_type keyVal, unsigned char* key, bool setup);
    //    void append(int instance, prf_type keyVal, unsigned char* key, bool setup);
    //    void pad(int index, int newSize, unsigned char* key, bool setup);
    //
    //    int hashKey(string w, int cnt, int index, unsigned char* key);
    //    int PRP(string w, int index, unsigned char* key);
    //    Bid getBid(string str, int cnt);
    //    int getNEWsize(int index);
    //    bool sorted(int index, unsigned char* key);
};

#endif /* OneChoiceSDdOMAPClient */

