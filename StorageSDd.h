#ifndef StorageSDd_H
#define StorageSDd_H

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
//#include <stxxl/vector>
//#include <stxxl/unordered_map>

using namespace std;

class StorageSDd {
private:
    bool inMemoryStorage;
    bool profile = false;
    vector< unordered_map<prf_type, prf_type, PRFHasher> > data;
    //stxxl::unordered_map<prf_type, prf_type, PRFHasher, CompareLess, SUB_BLOCK_SIZE, SUB_BLOCKS_PER_BLOCK>** diskData;
    vector<vector<string>> filenames;
    int dataIndex;
    prf_type nullKey;
    string fileAddressPrefix;

public:
    int seekgCount = 0;
    int KEY_VALUE_SIZE = (2 * AES_KEY_SIZE + sizeof (int));
    StorageSDd(bool inMemory, int dataIndex, string fileAddressPrefix, bool profile);
    bool setup(bool overwrite);
    void insert(int dataIndex, int instance, map<prf_type, prf_type> ciphers);
    map<prf_type, prf_type> getAllData(int dataIndex, int instance);
    vector<pair<prf_type, prf_type>> getAll(int dataIndex, int instance);
    void clear(int index, int instance);
    prf_type find(int index, int instance, prf_type mapKey, bool& found);
    void move(int index, int toInstance, int fromInstance);
    virtual ~StorageSDd();


};

#endif /* StorageSDd */

