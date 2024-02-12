#ifndef DEAMORTIZEDPLAINTEXT_H
#define DEAMORTIZEDPLAINTEXT_H

#include <string>
#include <map>
#include <vector>
#include <array>
#include <iostream>
#include <sstream>
#include "Utilities.h"
#include "DeAmortizedBASClient.h"
#include "OMAP.h"

using namespace std;

class DeAmortizedSDdPlaintext {
private:
    bool deleteFiles;
    vector<int> cnt;
    vector<vector< unordered_map<string, pair<int, byte> >* > > data; //OLDEST, OLDER, OLD, NEW;
    vector<map<string, string> > localmap;
    int updateCounter = 0;
    int localSize = 1;
    int l;
    int b, numOfIndices;
    double totalUpdateCommSize;
    double totalSearchCommSize;
    bool overwrite;
    bool generalSetup = false;

public:
    double totalCacheTime;
    DeAmortizedSDdPlaintext(bool deleteFiles, int keyworsSize, int N, bool inMemory, bool overwrite);
    void update(OP op, string keyword, int ind, bool setup);
    vector<int> search(string keyword);
    virtual ~DeAmortizedSDdPlaintext();
    void endSetup();
    void dumpStatus();

    void beginSetup();
    double getTotalSearchCommSize() const;
    double getTotalUpdateCommSize() const;
    bool setupFromFile(string filename);

};

#endif /* BAS_H */


