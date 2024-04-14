#ifndef TWOCHOICEPPWITHTUNABLELOCALITYCLIENT_H
#define TWOCHOICEPPWITHTUNABLELOCALITYCLIENT_H

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
#include "TwoChoicePPWithTunableLocalityServer.h"
#include "OneChoiceServer.h"
#include <unordered_map>

class TwoChoicePPWithTunableLocalityClient {
private:
    TwoChoicePPWithTunableLocalityServer* server;
    OneChoiceServer* oneChoiceServer;
    bool profile = false;

public:
    virtual ~TwoChoicePPWithTunableLocalityClient();
    TwoChoicePPWithTunableLocalityClient(long maxUpdate, bool inMemory, bool overwrite, bool profile);
    long totalCommunication = 0;
    vector<long> numberOfBins;
    vector<long> nB;
    prf_type nullKey;
    vector<long> sizeOfEachBin;
    vector<long> sEB;
    vector<bool> exist;
    vector<bool> existone;
    void destroy(long index);
    void setup(long index, unordered_map<string, vector<prf_type> >pairs, unsigned char* key);
    //vector<prf_type> search(long index, string keyword, unsigned char* key);
    vector<prf_type> search(long index, string keyword, unsigned char* key);
    vector<prf_type> getAllData(long index, unsigned char* key);
    void writeToCuckooHT(long index, long mpl, string keyword, vector<prf_type> fileids, unsigned char* key);
    void writeToCuckooStash(vector<prf_type> fileids, long cnt, long index, long tableNum, unsigned char* key);
    void place(string keyw, vector<prf_type> fileids, long cuckooID, long cnt, long index, long tableNum, unsigned char* key);
    void writeToStash(long pss, long mpl, vector<prf_type> fileids, unsigned char* key, vector<prf_type> &stashCiphers);
    long maxPossibleLen(long index);
    void setup2(long index, unordered_map<string, vector<tmp_prf_type> >pairs, unsigned char* key);
    void writeToCuckooHT2(long index, long size, string keyword, vector<tmp_prf_type> fileids, unsigned char* key);
    vector<vector<prf_type> > convertTmpCiphersToFinalCipher(vector<pair<std::pair<string, long>, tmp_prf_type> > ciphers, unsigned char* key);
    long countTotal(vector<long> fullness, long bin, long size);
};

#endif /* TWOCHOICEPPWITHTUNABLELOCALITYCLIENT_H */

