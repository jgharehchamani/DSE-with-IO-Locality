#ifndef TWOCHOICECLIENT_H
#define TWOCHOICECLIENT_H

#include <string>
#include <stdio.h>
#include <string.h>
#include <map>
#include <vector>
#include <array>
#include "Server.h"
#include <iostream>
#include <sstream>
#include<assert.h>
#include "Server.h"
#include "Utilities.h"
#include "AES.hpp"
#include "TwoChoicePPwithStashServer.h"
#include <unordered_map>

class TwoChoicePPwithStashClient {
public:
    TwoChoicePPwithStashServer* server;
    bool profile = false;
    long countTotal(map<long, long> fullness, long bin, long size);
    long countTotal(vector<long> fullness, long bin, long size);
    static bool cmpp(pair<string, vector<prf_type>> &a, pair<string, vector<prf_type>> &b);
    static bool cmpp2(pair<string, vector<tmp_prf_type>> &a, pair<string, vector<tmp_prf_type>> &b);
    static vector<pair<string, vector<prf_type>>> sort(unordered_map<string, vector<prf_type>> &M);
    static vector<pair<string, vector<tmp_prf_type>>> sort2(unordered_map<string, vector<tmp_prf_type>> &M);

public:
    virtual ~TwoChoicePPwithStashClient();
    TwoChoicePPwithStashClient(long maxUpdate, bool inMemory, bool overwrite, bool profile);
    long totalCommunication = 0;
    double TotalCacheTime;
    vector<long> numberOfBins;
    prf_type nullKey;
    vector<long> sizeOfEachBin;
    map<long, long> position;
    vector<bool> exist;
    void destroy(long index);
    void setup(long index, unordered_map<string, vector<prf_type> >pairs, unsigned char* key);
    void setup2(long index, unordered_map<string, vector<tmp_prf_type> >pairs, unsigned char* key);
    vector<prf_type> search(long index, string keyword, unsigned char* key);
    vector<prf_type> getAllData(long index, unsigned char* key);
    void truncateToMpl(long pss, long mpl, long index, string keyword, vector<prf_type> fileids, unsigned char* key);
    void writeToCuckooHT(long index, long mpl, string keyword, vector<prf_type> fileids, unsigned char* key);
    void writeToCuckooHT2(long index, long size, string keyword, vector<tmp_prf_type> fileids, unsigned char* key);
    void writeToCuckooStash(vector<prf_type> fileids, long cnt, long index, long tableNum, unsigned char* key);
    void place(string keyw, vector<prf_type> fileids, long cuckooID, long cnt, long index, long tableNum, unsigned char* key);
    void writeToStash(long pss, long mpl, vector<prf_type> fileids, unsigned char* key, vector<prf_type> &stashCiphers);
    void writeToStash2(string keyword, long pss, long mpl, vector<tmp_prf_type> fileids, unsigned char* key, vector<prf_type> &stashCiphers);
    vector<vector<prf_type> > convertTmpCiphersToFinalCipher(vector<pair<std::pair<string, long>, tmp_prf_type> > ciphers, unsigned char* key);
    long maxPossibleLen(long index);
};

#endif /* TWOCHOICECLIENT_H */

