#ifndef BASCLIENT_H
#define BASCLIENT_H
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
#include "AmortizedBASServer.h"
#include <unordered_map>

using namespace std;

class AmortizedBASClient {
public:
    AmortizedBASServer* server;
    bool profile = false;

public:
    virtual ~AmortizedBASClient();
    AmortizedBASClient(int maxUpdate, bool inMemory, bool overwrite, bool profile);
    int totalCommunication = 0;
    double TotalCacheTime;
    double searchTime;

    vector<bool> exist;
    void destroy(int index);
    void setup(int index, unordered_map<string, vector<prf_type> >pairs, unsigned char* key);
    void setup2(int index, unordered_map<string, vector<tmp_prf_type> > pairs, unsigned char* key);
    vector<prf_type> search(int index, string keyword, unsigned char* key);
    vector<prf_type> getAllData(int index, unsigned char* key);
    void endSetup();

};

#endif /* BASCLIENT_H */

