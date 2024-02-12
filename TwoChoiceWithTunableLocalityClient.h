#ifndef TWOCHOICWITHTUNABLELOCALITYLCLIENT_H
#define TWOCHOICWITHTUNABLELOCALITYLCLIENT_H

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
#include "OneChoiceServer.h"
#include "TwoChoiceWithTunableLocalityServer.h"
#include <unordered_map>

class TwoChoiceWithTunableLocalityClient {
private:
    TwoChoiceWithTunableLocalityServer* server;
    OneChoiceServer* oneChoiceServer;
    bool profile = false;

public:
    virtual ~TwoChoiceWithTunableLocalityClient();
    TwoChoiceWithTunableLocalityClient(long maxUpdate, bool inMemory, bool overwrite, bool profile);
    prf_type nullKey;
    long totalCommunication = 0;
    long searchCommunication = 0;
    long searchTime = 0;
    double TotalCacheTime;
    vector<long> numberOfBins;
    vector<long> sizeOfEachBin;
    map<long, long> position;
    vector<bool> exist;
    vector<bool> stashExist;
    vector<long> nB;
    vector<long> sEB;
    void destroy(long index);
    void setup(long index, unordered_map<string, vector<prf_type>>pairs, unsigned char* key);
    void setup2(long index, unordered_map<string, vector<tmp_prf_type> > pairs, unsigned char* key);
    vector<vector<prf_type> > convertTmpCiphersToFinalCipher(vector<pair<std::pair<string, long>, tmp_prf_type> > ciphers, unsigned char* key);
    vector<prf_type> search(long index, string keyword, unsigned char* key);
    vector<prf_type> getAllData(long index, unsigned char* key);
    void printStashSizes();
    long maxPossibleLen(long index);
};

#endif /* TWOCHOICWITHTUNABLELOCALITYLCLIENT_H */

