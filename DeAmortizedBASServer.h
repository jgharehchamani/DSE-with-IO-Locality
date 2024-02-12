#ifndef DEBASSERVER_H
#define DEBASSERVER_H
#include <string>
#include <map>
#include <vector>
#include <array>
#include <iostream>
#include <sstream>
#include "Utilities.h"
#include "Types.hpp"
#include <unordered_map>
#include "StorageSDDPiBAS.h"

using namespace std;

//struct PRFHasher {
//
//    std::size_t operator()(const prf_type &key) const {
//        std::hash<byte_t> hasher;
//        size_t result = 0; // I would still seed this.
//        for (size_t i = 0; i < AES_KEY_SIZE; ++i) {
//            result = (result << 1) ^ hasher(key[i]); // ??
//        }
//        return result;
//    }
//};

class EachSet {
public:
    unordered_map<prf_type, prf_type, PRFHasher> setData;
};

class DeAmortizedBASServer {
public:
    vector<vector< EachSet* > > data; //OLDEST, OLDER, OLD, NEW;
    //    void getAESRandomValue(unsigned char* keyword, int cnt, unsigned char* result);

public:
    StorageSDDPiBAS** storage;
    bool profile = false;
    bool hdd = true;

    DeAmortizedBASServer(int dataIndex, bool inMemory, bool overwrite, bool profile);
    void clear(int instance, int index);
    virtual ~DeAmortizedBASServer();
    void storeCiphers(int instance, int dataIndex, map<prf_type, prf_type> ciphers, bool setupMode);
    //    void storeCiphers(long instance, long dataIndex, vector<pair<pair<prf_type, prf_type>, pair<long, long> > > ciphers, long tail, long size);
    vector<prf_type> search(int instance, int dataIndex, prf_type token);
    vector<prf_type> getAllData(int instance, int dataIndex);
    void move(int fromInstance, int fromIndex, int toInstance, int toIndex);
    int size(int instance, int index);
    prf_type get(int instance, int index, int pos);
    void add(int instance, int index, pair<prf_type, prf_type> pair);
    void endSetup(bool overwrite);
    void beginSetup();
    //    vector<pair<pair<prf_type, prf_type>, pair<long, long> > > getAllDataForCopy(int instance, int dataIndex, long& tail, long& size);
};


#endif /* BASSERVER_H */

