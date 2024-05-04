#ifndef DEAMORTIZEDSDDGENERAL_H
#define DEAMORTIZEDSDDGENERAL_H

#include <string>
#include <map>
#include <unordered_map>
#include <vector>
#include <array>
#include <iostream>
#include <sstream>
#include "Utilities.h"
#include "AES.hpp"
#include "OneChoiceSDdGeneralClient.h"
#include "OMAP.h"
#include "DSEScheme.h"

using namespace std;

class DeAmortizedSDdGeneral : public DSEScheme{
public:
    inline prf_type bitwiseXOR(int input1, int op, prf_type input2);
    inline prf_type bitwiseXOR(prf_type input1, prf_type input2);
    inline void getAESRandomValue(unsigned char* keyword, int op, int srcCnt, int counter, unsigned char* result);
    bool deleteFiles;
    vector< vector<unsigned char*> > keys;
    vector<int> cnt;
    prf_type nullKey;
    vector<int> numberOfBins;
    vector<int> sizeOfEachBin;
    vector<int> indexSize;
    OneChoiceSDdGeneralClient* L;
    vector<vector< vector<pair<string, prf_type>>*> > data; //OLDEST, OLDER, OLD, NEW;
    vector<map<string, string> > localmap;
    int updateCounter = 0;
    int localSize = -1;
    int l;
    int b, numOfIndices;
    pair<string, prf_type> getElementAt(int instance, int index, int pos);
    double totalUpdateCommSize;
    double totalSearchCommSize;
    bool overwrite;
    std::vector<pair<string, int> > setupPairs;
    std::vector<int> setupOps;
    bool generalSetup = false;
    int computeLocalCacheSize();

public:
    double totalCacheTime = 0;
    prf_type createKeyVal(string keyword, int ind, OP op);
    prf_type createKeyVal(string keyword, int cntw);
    DeAmortizedSDdGeneral(int N, bool inMemory, bool overwrite);
    void update(OP op, string keyword, int ind, bool setup);
    vector<int> search(string keyword);
    virtual ~DeAmortizedSDdGeneral();
    void updateKey(int index, int toInstance, int fromInstance);
    void beginSetup();
    void endSetup();
    bool setupFromFile(string filename);
};

#endif /* BAS_H */

