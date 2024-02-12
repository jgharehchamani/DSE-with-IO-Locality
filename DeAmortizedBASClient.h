#ifndef DEBASCLIENT_H
#define DEBASCLIENT_H
#include <string>
#include <stdio.h>
#include <string.h>
#include <map>
#include <vector>
#include <array>
#include <iostream>
#include <sstream>
#include "Utilities.h"
#include "DeAmortizedBASServer.h"

using namespace std;

class DeAmortizedBASClient {
public:
    DeAmortizedBASServer* server;
    //    void getAESRandomValue(unsigned char* keyword, int cnt, unsigned char* result);

public:
    virtual ~DeAmortizedBASClient();
    DeAmortizedBASClient(int maxUpdate, bool inMemory, bool overwrite, bool profile);
    int totalCommunication = 0;

    vector<vector<bool> > exist;
    void destry(int instance, int index);
    void destryAndClear(int instance, int index);
    void setup(int instance, int index, vector<pair<string, prf_type> >pairs, unsigned char* key);
    vector<prf_type> search(int instance, int index, string keyword, unsigned char* key);
    vector<prf_type> getAllData(int instance, int index, unsigned char* key);
    void move(int fromInstance, int fromIndex, int toInstance, int toIndex);
    int size(int instance, int index);
    prf_type get(int instance, int index, int pos, unsigned char* key);
    void add(int instance, int index, pair<string, prf_type> pair, int cnt, unsigned char* key);
    void setup(int instance, int index, unordered_map<string, vector<prf_type> > pairs, unsigned char* key);
    void endSetup(bool overwrite);
    void beginSetup();
};

#endif /* DEBASCLIENT_H */


