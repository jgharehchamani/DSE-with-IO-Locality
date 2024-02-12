#ifndef NLOGNCLIENT_H
#define NLOGNCLIENT_H

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
#include "NlogNServer.h"
#include <unordered_map>

class NlogNClient {
public:
    NlogNServer* server;
    bool profile = false;
    static vector<pair<string, vector<prf_type> > > sort(unordered_map<string, vector<prf_type>> &M);
    static vector<pair<string, vector<tmp_prf_type> > > sort2(unordered_map<string, vector<tmp_prf_type>> &M);
    vector<vector<prf_type> > convertTmpCiphersToFinalCipher(vector<vector<std::pair<string, tmp_prf_type> > > ciphers, unsigned char* key);
    int getCorrespondingLevel(int index, int size);
    void permuteLevel(vector<vector<prf_type> >& buckets, vector<pair<string, int> >& counter);
    void permuteLevel(vector<vector<pair<string, tmp_prf_type> > >& buckets, vector<pair<string, int> >& counters);


public:
    virtual ~NlogNClient();
    NlogNClient(long maxUpdate, bool inMemory, bool overwrite, bool profile);
    prf_type nullKey;
    long totalCommunication = 0;
    long searchCommunication = 0;
    double TotalCacheTime;
    vector<bool> exist;
    void destroy(long index);
    void setup(long index, unordered_map<string, vector<prf_type> >pairs, unsigned char* key);
    void setup2(long index, unordered_map<string, vector<tmp_prf_type> > pairs, unsigned char* key);
    vector<prf_type> search(long index, string keyword, unsigned char* key);
    vector<prf_type> getAllData(long index, unsigned char* key);
    void endSetup();
    double searchTime = 0;
};

#endif /* NLOGNCLIENT_H */

