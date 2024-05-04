#ifndef AMORTIZEDNLOGN_H
#define AMORTIZEDNLOGN_H

#include <string>
#include <map>
#include <vector>
#include <array>
#include "Server.h"
#include <iostream>
#include <sstream>
#include "Server.h"
#include "Utilities.h"
#include "AmortizedBASClient.h"
#include "OneChoiceClient.h"
#include "TwoChoiceWithOneChoiceClient.h"
#include "NlogNClient.h"
#include "AES.hpp"
#include <set>
#include <unordered_map>
#include "DSEScheme.h"

using namespace std;

/*
enum OP {
    INS, DEL
};
 */
class AmortizedNlogN : public DSEScheme {
private:
    inline prf_type bitwiseXOR(int input1, int op, prf_type input2);
    inline prf_type bitwiseXOR(prf_type input1, prf_type input2);
    vector<unsigned char*> keys;
    NlogNClient* L;
    int updateCounter = 0;
    double totalUpdateCommSize;
    double totalSearchCommSize;
    vector< unordered_map< string, vector<prf_type > > > data;
    vector< unordered_map< string, vector<tmp_prf_type > > > setupData;
    int localSize = 0;
    int tmpLocalSize = 0;
    bool profile = true;
    bool setup = false;

public:
    AmortizedNlogN(int N, bool inMemory, bool overwrite);
    void update(OP op, string keyword, int ind, bool setup);
    vector<int> search(string keyword);
    virtual ~AmortizedNlogN();
    double getTotalSearchCommSize() const;
    double getTotalUpdateCommSize() const;
    void endSetup();
    void beginSetup();
    bool setupFromFile(string filename);
    double totalCacheTime = 0;
};

#endif /* BAS_H */

