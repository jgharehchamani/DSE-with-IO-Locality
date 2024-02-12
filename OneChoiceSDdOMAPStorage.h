#ifndef OneChoiceSDdOMAPStorage_H
#define OneChoiceSDdOMAPStorage_H

#include <string>
#include <map>
#include <vector>
#include <array>
#include "Server.h"
#include <iostream>
#include <sstream>
#include "Server.h"
#include "Utilities.h"
#include "Types.hpp"
#include "AES.hpp"
#include <unordered_map>
#include <iostream>
#include <fstream>

using namespace std;

class OneChoiceSDdOMAPStorage {
private:
    bool inMemoryStorage;
    bool profile = false;
    vector<vector<string>> filenames;
    vector<string> fileCounter;
    prf_type nullKey;
    string fileAddressPrefix = "/tmp/";
    int dataIndex;
    vector<int> numberOfBins;
    vector<int> sizeOfEachBin;
    int KEY_VALUE_SIZE = (2 * AES_KEY_SIZE);
    vector< vector<pair<prf_type, prf_type> > > data;

public:
    int readBytes = 0;
    int SeekG = 0;
    OneChoiceSDdOMAPStorage(bool inMemory, int dataIndex, string fileAddressPrefix, bool profile);
    virtual ~OneChoiceSDdOMAPStorage();
    bool setup(bool overwrite);

    void insertAll(int dataIndex, int instance, vector<prf_type> ciphers);
    void insertAll(int dataIndex, int instance, vector<vector<prf_type>> ciphers);
    int writeToNEW(int index, prf_type keyVal, int pos);
    int writeToKW(int index, prf_type keyVal, int pos);
    void move(int index, int toInstance, int fromInstance, int size);
    void clear(int index, int instance);

    vector<prf_type> find(int index, int instance, prf_type mapKey, int cnt);
    vector<prf_type> getAllData(int dataIndex, int instance);
    vector<prf_type> getElements(int index, int instance, int start, int end);
    int putElements(int index, int instance, int start, int end, vector<prf_type> encNEW);
    vector<prf_type> getKW(int index, int cnt, int ressize);
    void truncate(int index, int size, int filesize);

};

#endif /* ONECHOICESTORAGE_H */

