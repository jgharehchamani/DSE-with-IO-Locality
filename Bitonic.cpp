#include "Bitonic.h"

using namespace::std;

/*
Bitonic::Bitonic() 
{
}
Bitonic::~Bitonic() { }
 */
void Bitonic::compAndSwap(int a[], int i, int j) {
    if ((a[i] > a[j]))
        swap(a[i], a[j]);
}

void Bitonic::bitonicMerge(int a[], int low, int cnt, vector<int>& memseq) {
    if (cnt > 1) {
        int k = cnt / 2;
        for (int i = low; i < low + k; i++) {
            compAndSwap(a, i, i + k);
            memseq.push_back(i);
            memseq.push_back(i + k);
        }
        bitonicMerge(a, low, k, memseq);
        bitonicMerge(a, low + k, k, memseq);
    }
}

void Bitonic::bitMerge(int a[], int low, int cnt, vector<int>& memseq) {
    if (cnt > 1) {
        int k = cnt / 2;
        for (int i = low, j = low + cnt - 1; i < low + k, j >= low + k; i++, j--) {
            compAndSwap(a, i, j);
            memseq.push_back(i);
            memseq.push_back(j);
        }
        bitonicMerge(a, low, k, memseq);
        bitonicMerge(a, low + k, k, memseq);
    }
}

void Bitonic::bitonicSort(int a[], int low, int cnt, vector<int>& memseq) {
    if (cnt > 1) {
        int k = cnt / 2;
        bitonicSort(a, low, k, memseq);
        bitonicSort(a, low + k, k, memseq);
        bitMerge(a, low, cnt, memseq);
    }
}

void Bitonic::generateSeq(int a[], int N, vector<int>& memseq) {
    bitonicSort(a, 0, N, memseq);
}

vector<int> Bitonic::getSeq(int step, int count, int size) {
    vector<int> memseq;
    int a[size];
    memset(a, 0, size);
    generateSeq(a, size, memseq);
    //for(auto m : memseq)
    //	cout<<"("<<m<<")";
    //cout<<endl;
    assert(memseq.size() == 2 * ceil((float) (size * log2(size)*(log2(size) + 1) / (float) 4)));
    int start = count*step;
    vector<int> res;
    for (int i = start; i < start + step; i++) {
        res.push_back(memseq[i]);
    }
    return res;
}

vector<int> Bitonic::remDup(vector<int> v) {
    int vsize = v.size();
    vector<int>::iterator ip;
    ip = std::unique(v.begin(), v.begin() + vsize);
    v.resize(std::distance(v.begin(), ip));
    return v;
}
