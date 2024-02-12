//#include "Amortized.h"
#include "AmortizedOneChoice.h"
#include "AmortizedTwoChoice.h"
#include "Utilities.h"
#include <algorithm>
#include <iostream>
#include <vector>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include "AmortizedPiBAS.h"
#include "AmortizedNlogN.h"
#include "DeAmortizedSDdBAS.h"
#include "DeAmortizedSDdGeneral.h"
#include "DeAmortizedSDdPlaintext.h"
#include "DeAmortizedSDdNlogN.h"
#include <typeinfo>

using namespace std;

int main(int argc, char** argv) {


    int N = 16; //total number of key-value pairs
    int K = 5;  //total number of keywords

    system("rm /tmp/tmp -rf");      //the temporary folder for s
    system("mkdir /tmp/tmp");

    //---------------------------------------
    //Amortized Schemes
    //---------------------------------------
        AmortizedOneChoice client1(N, false, true);
    //    AmortizedPiBAS client1(N, false, true);
    //    AmortizedTwoChoice client1(N, false, true);
    //    AmortizedNlogN client1(N, false, true);

    //DE-Amortized Schemes
    //    DeAmortizedSDdGeneral client1(N, false, true); //SOME CODES SHOULD BE UNCOMMENTED FOR UPDATE
    //    DeAmortizedSDdBAS client1(false, K, N, false, true);

    client1.update(OP::INS, "test", 1, false);
    client1.update(OP::INS, "test", 2, false);
    client1.update(OP::INS, "test", 3, false);
    client1.update(OP::INS, "test", 4, false);
    client1.update(OP::INS, "test", 5, false);
    client1.update(OP::INS, "test", 6, false);
    vector<int> res = client1.search("test");
    cout << "Number of return item:" << res.size() << endl;

    return 0;
}
