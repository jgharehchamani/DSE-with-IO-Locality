#ifndef NlogNSDdGeneralClient_H
#define NlogNSDdGeneralClient_H

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
#include "NlogNServer.h"

class NlogNSDdGeneralClient {
private:
    NlogNServer** server;
    Bitonic* bitonic;
    bool profile = false;

public:
    vector<OMAP*> omaps;
    virtual ~NlogNSDdGeneralClient();
    NlogNSDdGeneralClient(int maxUpdate, bool inMemory, bool overwrite, bool profile);
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
    void setup(long index, long instance, unordered_map<string, vector<prf_type> > pairs, unsigned char* key);
    void setup2(long index, long instance, unordered_map<string, vector<tmp_prf_type> > pairs, unsigned char* key);
    vector<prf_type> search(int index, int instance, string keyword, unsigned char* key);
    vector<vector<prf_type> > convertTmpCiphersToFinalCipher(vector<vector<std::pair<string, tmp_prf_type> > > ciphers, unsigned char* key);
    void permuteLevel(vector<vector<prf_type> >& buckets, vector<pair<string, int> >& counter);
    void permuteLevel(vector<vector<pair<string, tmp_prf_type> > >& buckets, vector<pair<string, int> >& counters);
    vector<prf_type> getAllData(long instance, long index, unsigned char* key);
    int getCorrespondingLevel(int index, int size);
    void destroy(long instance, long index);
    void endSetup();
};

#endif /* NlogNSDdGeneralClient */
