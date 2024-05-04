#ifndef DEAMORTIZED_H
#define DEAMORTIZED_H

#include <string>
#include <map>
#include <vector>
#include <array>
#include <iostream>
#include <sstream>
#include "Utilities.h"
#include "DeAmortizedBASClient.h"
#include "OMAP.h"
#include "DSEScheme.h"

using namespace std;

class DeAmortizedSDdBAS: public DSEScheme {
private:
    inline prf_type bitwiseXOR(int input1, int op, prf_type input2);
    inline prf_type bitwiseXOR(prf_type input1, prf_type input2);
    Bid getBid(string str, int cnt);
    bool deleteFiles;
    vector< vector<unsigned char*> > keys;
    vector<int> cnt;
    vector<OMAP*> omaps;
    vector< map<Bid, string> > setupOMAPS;
    vector<int> setupOMAPSDummies;
    DeAmortizedBASClient* L;
    vector<vector< unordered_map<string, prf_type>* > > data; //OLDEST, OLDER, OLD, NEW;
    vector<map<string, string> > localmap;
    int updateCounter = 0;
    int localSize = 1;
    int l;
    int b, numOfIndices;
    prf_type getElementAt(int instance, int index, int pos);
    double totalUpdateCommSize;
    double totalSearchCommSize;
    std::vector<pair<string, int> > setupPairs;
    std::vector<int> setupOps;
    bool overwrite;
    bool generalSetup = false;
    int computeLocalCacheSize();

public:
    double totalCacheTime;
    DeAmortizedSDdBAS(bool deleteFiles, int keyworsSize, int N, bool inMemory, bool overwrite);
    void update(OP op, string keyword, int ind, bool setup);
    vector<int> search(string keyword);
    virtual ~DeAmortizedSDdBAS();
    void endSetup();
    void dumpStatus();

    void beginSetup();
    double getTotalSearchCommSize() const;
    double getTotalUpdateCommSize() const;
    bool setupFromFile(string filename);

};

#endif /* BAS_H */


