#ifndef BITONIC_H
#define BITONIC_H

#include<algorithm>
#include <string>
#include <stdio.h>
#include <string.h>
#include <map>
#include <vector>
#include <array>
#include <iostream>
#include <sstream>
#include <unordered_map>
#include<string>
#include<map>
#include<vector>
#include<algorithm>
#include<assert.h>
#include <cmath>
//#include "Utilities.h"

class Bitonic {
public:

    Bitonic() {
    };

    virtual ~Bitonic() {
    };

    void compAndSwap(int a[], int i, int j);
    void bitonicMerge(int a[], int low, int cnt, std::vector<int>& memseq);
    void bitMerge(int a[], int low, int cnt, std::vector<int>& memseq);
    void bitonicSort(int a[], int low, int cnt, std::vector<int>& memseq);
    void generateSeq(int a[], int N, std::vector<int>& memseq);
    std::vector<int> getSeq(int step, int count, int size);
    std::vector<int> remDup(std::vector<int> v);
};

#endif /* BITONIC_H */
