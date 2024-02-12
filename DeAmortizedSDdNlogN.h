#ifndef DEAMORTIZEDSDDNLOGN_H
#define DEAMORTIZEDSDDNLOGN_H

#include <string>
#include <map>
#include <unordered_map>
#include <vector>
#include <array>
//#include "Server.h"
#include <iostream>
#include <sstream>
#include "Utilities.h"
#include "AES.hpp"
#include "NlogNSDdGeneralClient.h"
//#include "OneChoiceClient.h"
#include "OMAP.h"
//#include "mitra/Server.h"
//#include <boost/algorithm/string/split.hpp>
//#include <boost/algorithm/string/classification.hpp>
//#include <sse/crypto/hash.hpp>

using namespace std;

/*
enum OP 
{
    INS, DEL
};
 */
class DeAmortizedSDdNlogN {
private:
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
    //vector< map<Bid, string> > setupOMAPS;
    //vector<int> setupOMAPSDummies;
    NlogNSDdGeneralClient* L;
    vector<vector< unordered_map<string, prf_type> > > data; //OLDEST, OLDER, OLD, NEW;
    vector<map<string, string> > localmap;
    int updateCounter = 0;
    int localSize = 0;
    int l;
    //int s = SPACE_OVERHEAD;
    int b, numOfIndices;
    prf_type getElementAt(int instance, int index, int pos);
    double totalUpdateCommSize;
    double totalSearchCommSize;
    bool overwrite;
    bool setup = false;
    std::vector<pair<string, int> > setupPairs;
    std::vector<byte> setupPairs2;

public:
    prf_type createKeyVal(string keyword, int ind, OP op);
    prf_type createKeyVal(string keyword, int cntw);
    DeAmortizedSDdNlogN(int N, bool inMemory, bool overwrite);
    void update(OP op, string keyword, int ind, bool setup);
    vector<int> search(string keyword);
    virtual ~DeAmortizedSDdNlogN();
    void updateKey(int index, int toInstance, int fromInstance);
    void beginSetup();
    void endSetup();
    //double getTotalSearchCommSize() const;
    //double getTotalUpdateCommSize() const;
    //int numberOfBins(int i);
    bool setupFromFile(string filename);
};

#endif /* BAS_H */
