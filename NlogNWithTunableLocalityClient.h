#ifndef NLOGNWITHTUNABLELOCALITYCLIENT_H
#define NLOGNWITHTUNABLELOCALITYCLIENT_H

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
#include "NlogNWithTunableLocalityServer.h"
#include <unordered_map>

class NlogNWithTunableLocalityClient {
public:
    NlogNWithTunableLocalityServer* server;
    bool profile = false;
    static vector<pair<string, vector<prf_type> > > sort(unordered_map<string, vector<prf_type>> &M);
    static vector<pair<string, vector<tmp_prf_type> > > sort2(unordered_map<string, vector<tmp_prf_type>> &M);
    static bool cmpp(pair<string, vector<prf_type> > &a, pair<string, vector<prf_type>> &b);
    static bool cmpp2(pair<string, vector<tmp_prf_type>> &a, pair<string, vector<tmp_prf_type>> &b);
    long countTotal(vector<long> fullness, long bin, long size);
    vector<vector<prf_type> > convertTmpCiphersToFinalCipher(vector<pair<std::pair<string, long>, tmp_prf_type> > ciphers, unsigned char* key);


public:
    virtual ~NlogNWithTunableLocalityClient();
    NlogNWithTunableLocalityClient(long maxUpdate, bool inMemory, bool overwrite, bool profile);
    prf_type nullKey;
    long totalCommunication = 0;
    long searchCommunication = 0;
    double TotalCacheTime;
    long searchTime = 0;
    vector<long> numberOfBins;
    vector<long> sizeOfEachBin;
    map<long, long> position;
    vector<bool> exist;
    vector<long> nB;
    vector<long> sEB;
    void destroy(long index);
    void setup(long index, unordered_map<string, vector<prf_type> >pairs, unsigned char* key);
    void setup2(long index, unordered_map<string, vector<tmp_prf_type> > pairs, unsigned char* key);
    vector<prf_type> search(long index, string keyword, unsigned char* key);
    vector<prf_type> getAllData(long index, unsigned char* key);
    void truncateToMpl(long pss, long mpl, long index, string keyword, vector<prf_type> fileids, unsigned char* key);
    long maxPossibleLen(long index);
};

#endif /* NLOGNWITHTUNABLELOCALITYCLIENT_H */

