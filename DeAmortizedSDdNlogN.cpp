#include "DeAmortizedSDdNlogN.h"
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <vector>
#include<cstdlib>
#include<algorithm>
#include <bits/stdc++.h>
using namespace std;

DeAmortizedSDdNlogN::DeAmortizedSDdNlogN(int N, bool inMemory, bool overwrite) : DSEScheme(){
    L = new NlogNSDdGeneralClient(N, inMemory, overwrite, false);
    this->overwrite = overwrite;
    this->deleteFiles = deleteFiles;
    l = floor(log2(N)) + 1;
    memset(nullKey.data(), 0, AES_KEY_SIZE);
    numOfIndices = l;
    for (int j = 0; j < numOfIndices; j++) {
        int curNumberOfBins = j > 1 ?
                (int) ceil(((float) pow(2, j)) / (float) (log2(pow(2, j)) * log2(log2(pow(2, j))))) : 1;
        int curSizeOfEachBin = j > 1 ? 3 * (log2(pow(2, j))*(log2(log2(pow(2, j))))) : pow(2, j);
        numberOfBins.push_back(curNumberOfBins);
        sizeOfEachBin.push_back(curSizeOfEachBin);
        int is = curNumberOfBins*curSizeOfEachBin;
        indexSize.push_back(is);
        //      printf("DeAm:%d #Bins:%d size of bin:%d is:%d\n", j, curNumberOfBins, curSizeOfEachBin, is);
    }
    for (int j = 0; j < 4; j++) {
        for (int i = 0; i < numOfIndices; i++) {
            keys.push_back(vector<unsigned char*> ());

            unsigned char* tmpKey = new unsigned char[16];
            memset(tmpKey, 0, 16);
            keys[j].push_back(tmpKey);
        }
    }
    for (int i = 0; i < numOfIndices; i++)
        cnt.push_back(0);
    for (int i = 0; i < localSize; i++)
        localmap.push_back(map<string, string>());
    for (int j = 0; j < 4; j++) {
        vector< unordered_map<string, prf_type> > curVec;
        for (int i = 0; i < localSize; i++)
            curVec.push_back(unordered_map<string, prf_type>());
        data.push_back(curVec);
    }
    if (!overwrite) {
        fstream file(Utilities::rootAddress + "existStatus.txt", std::ofstream::in);
        if (file.fail()) {
            file.close();
            return;
        }
        for (int j = 0; j < 3; j++) {
            for (unsigned int i = 0; i < numOfIndices; i++) {

                string data;
                getline(file, data);
                if (data == "true") {
                    L->exist[j][i] = true;
                    unsigned char* newKey = new unsigned char[16];
                    memset(newKey, 0, 16);
                    keys[j][i] = newKey;
                } else {
                    L->exist[j][i] = false;
                }
            }
        }
        file.close();
    }
}

DeAmortizedSDdNlogN::~DeAmortizedSDdNlogN() {
    if (overwrite) {
        fstream file(Utilities::rootAddress + "existStatus.txt", std::ofstream::out);
        if (file.fail()) {
            cerr << "Error: " << strerror(errno);
        }
        for (int j = 0; j < 3; j++) {
            for (unsigned int i = 0; i < numOfIndices; i++) {

                if (L->exist[j][i]) {
                    file << "true" << endl;
                } else {
                    file << "false" << endl;
                }
            }
        }
        file.close();
    }
}

float bySDd(int a, int b) {
    float d = ((float) a / (float) b);
    return d;
}

void DeAmortizedSDdNlogN::update(OP op, string keyword, int ind, bool setup) {
    setupPairs.push_back(pair<string, int>(keyword, ind));
    setupPairs2.push_back(op);
    //    for (int i = numOfIndices; i > 0; i--) {
    //        int t = numberOfBins[i - 1];
    //        int m = numberOfBins[i];
    //        if (L->exist[i - 1][0] && L->exist[i - 1][1]) {
    //            if (i > 3) {
    //                //assert(2*t+m+2 < pow(2,i) || i<= 3);
    //                if (0 <= cnt[i] && cnt[i] < t) {
    //                    L->getBin(i, 0, cnt[i], 1, keys[i - 1][0], keys[i][3], setup);
    //                    L->getBin(i, 1, cnt[i], 1, keys[i - 1][1], keys[i][3], setup);
    //                } else if (t <= cnt[i] && cnt[i] < 2 * t) {
    //                    L->kwCount(i, cnt[i] - t, 2, keys[i][3], setup);
    //                } else if (2 * t <= cnt[i] && cnt[i] < 2 * t + m) {
    //                    L->addDummy(i, cnt[i] - 2 * t, 1, keys[i][3], setup);
    //                } else if (2 * t + m <= cnt[i] && cnt[i] < 2 * t + m + pow(2, i)) {
    //                    int count = cnt[i]-(2 * t + m);
    //                    int times = pow(2, i) - (2 * t + m);
    //                    int N = L->getNEWsize(i);
    //                    int totStepsi = 2 * (bySDd(N * log2(N)*(log2(N) + 1), 4));
    //                    int stepi = bySDd(totStepsi, times);
    //                    stepi = pow(2, ceil(log2(stepi)));
    //                    if (!setup)
    //                        assert(stepi > 1);
    //                    if (stepi * count < totStepsi) {
    //                        L->deAmortBitSortC(stepi, count, N, i, keys[i][3], setup);
    //                        L->deAmortBitSort(stepi, count, N, i, keys[i][3], setup);
    //                    }
    //                }
    //            } else {
    //                if (cnt[i] == 0) {
    //                    L->getBin(i, 0, cnt[i], numberOfBins[i - 1], keys[i - 1][0], keys[i][3], setup);
    //                    L->getBin(i, 1, cnt[i], numberOfBins[i - 1], keys[i - 1][1], keys[i][3], setup);
    //                    L->kwCount(i, cnt[i], 2 * numberOfBins[i - 1], keys[i][3], setup);
    //                    L->addDummy(i, cnt[i], numberOfBins[i], keys[i][3], setup);
    //                    int N = L->getNEWsize(i);
    //                    int totSteps = 2 * (bySDd(N * log2(N)*(log2(N) + 1), 4));
    //                    L->deAmortBitSortC(totSteps, cnt[i], N, i, keys[i][3], setup);
    //                    L->deAmortBitSort(totSteps, cnt[i], N, i, keys[i][3], setup);
    //                }
    //            }
    //            cnt[i] = cnt[i] + 1;
    //            if (cnt[i] == pow(2, i)) {
    //                //assert(L->sorted(i,keys[i][3]));  
    //                L->updateHashTable(i, keys[i][3], setup);
    //                L->resize(i, indexSize[i], setup);
    //                L->move(i - 1, 0, 2, setup);
    //                updateKey(i - 1, 0, 2);
    //                L->destroy(i - 1, 1, setup);
    //                if (!(L->exist[i][0])) {
    //                    L->move(i, 0, 3, setup);
    //                    updateKey(i, 0, 3);
    //                } else if (!(L->exist[i][1])) {
    //                    L->move(i, 1, 3, setup);
    //                    updateKey(i, 1, 3);
    //                } else {
    //                    L->move(i, 2, 3, setup);
    //                    updateKey(i, 2, 3);
    //                }
    //                unsigned char* newKey = new unsigned char[16];
    //                memset(newKey, 0, 16);
    //                keys[i][3] = newKey;
    //                cnt[i] = 0;
    //            }
    //        }
    //    }
    //    prf_type keyVal = createKeyVal(keyword, ind, op);
    //    L->append(0, keyVal, keys[0][3], setup);
    //    prf_type kwc = createKeyVal(keyword, 1);
    //    L->appendTokwCounter(0, kwc, keys[0][3], setup);
    //    L->updateHashTable(0, keys[0][3], setup);
    //
    //    if (!(L->exist[0][0])) {
    //        L->move(0, 0, 3, setup);
    //        updateKey(0, 0, 3);
    //    } else if (!(L->exist[0][1])) {
    //        L->move(0, 1, 3, setup);
    //        updateKey(0, 1, 3);
    //    } else {
    //        L->move(0, 2, 3, setup);
    //        updateKey(0, 2, 3);
    //    }
    //    unsigned char* newKey = new unsigned char[16];
    //    memset(newKey, 0, 16);
    //    keys[0][3] = newKey;
    //    updateCounter++;
}

prf_type DeAmortizedSDdNlogN::createKeyVal(string keyword, int ind, OP op) {
    prf_type keyVal;
    memset(keyVal.data(), 0, AES_KEY_SIZE);
    std::copy(keyword.begin(), keyword.end(), keyVal.begin()); //keyword
    *(int*) (&(keyVal.data()[AES_KEY_SIZE - 5])) = ind; //fileid
    keyVal.data()[AES_KEY_SIZE - 6] = (byte) (op == OP::INS ? 0 : 1); //op
    *(int*) (&(keyVal.data()[AES_KEY_SIZE - 11])) = 0; //index 0 has only bin 0
    return keyVal;
}

prf_type DeAmortizedSDdNlogN::createKeyVal(string keyword, int cntw) {
    prf_type keyVal;
    memset(keyVal.data(), 0, AES_KEY_SIZE);
    std::copy(keyword.begin(), keyword.end(), keyVal.begin()); //keyword
    *(int*) (&(keyVal.data()[AES_KEY_SIZE - 5])) = cntw; //fileid
    *(int*) (&(keyVal.data()[AES_KEY_SIZE - 11])) = 1; //PRP
    return keyVal;
}

void DeAmortizedSDdNlogN::updateKey(int index, int toInstance, int fromInstance) {
    keys[index][toInstance] = keys[index][fromInstance];
}

vector<int> DeAmortizedSDdNlogN::search(string keyword) {
    //    for (int i = 0; i < l; i++) {
    //        L->omaps[i]->treeHandler->oram->totalRead = 0;
    //        L->omaps[i]->treeHandler->oram->totalWrite = 0;
    //    }
    L->totalCommunication = 0;
    totalSearchCommSize = 0;
    L->TotalCacheTime = 0;
    L->searchTime = 0;
    Utilities::startTimer(33);
    vector<int> finalRes;
    vector<prf_type> encIndexes;
    vector<prf_type> encIndexes1;
    for (int i = 0; i < numOfIndices; i++) {
        for (int j = 0; j < 3; j++) {
            if (L->exist[j][i]) {
                vector<prf_type> tmpRes;
                tmpRes = L->search(i, j, keyword, keys[j][i]);
                encIndexes.insert(encIndexes.end(), tmpRes.begin(), tmpRes.end());
            }
        }
    }
    double filterationTime = 0;
    auto searchTime = Utilities::stopTimer(33);
    Utilities::startTimer(99);
    map<int, int> remove;
    int ressize = 0;
    for (auto i = encIndexes.begin(); i != encIndexes.end(); i++) {
        prf_type decodedString = *i;
        int id = *(int*) (&(decodedString.data()[AES_KEY_SIZE - 5]));
        int op = ((byte) decodedString.data()[AES_KEY_SIZE - 6]);
        remove[id] += (2 * op - 1);
        if ((strcmp((char*) decodedString.data(), keyword.data()) == 0))
            ressize++;
    }
    //cout <<"remove:"<<remove.size()<<"/"<<ressize<<"/"<<encIndexes.size()<<endl;
    for (auto const& cur : remove) {
        if (cur.second < 0) {
            finalRes.emplace_back(cur.first);
        }
    }
    filterationTime = Utilities::stopTimer(99);
//    cout << "TOTAL search TIME:[[" << L->searchTime << "]]" << endl;
//    printf("filteration time:%f\n", filterationTime);

//    cout << "Total Amortized1 Search time:" << searchTime << "/" << L->searchTime << endl;
//    cout << "Total drop cache command time for Storage:[" << L->TotalCacheTime << "]" << endl;
//    cout << "Amort search time - cache drop time =[" << searchTime + filterationTime - L->TotalCacheTime << "]" << endl;
    //    for (int i = 0; i < l; i++) {
    //        totalSearchCommSize += (L->omaps[i]->treeHandler->oram->totalRead +
    //                L->omaps[i]->treeHandler->oram->totalWrite)*(sizeof (prf_type) + sizeof (int));
    //    }
    totalSearchCommSize += L->totalCommunication;
    totalSearchTime = searchTime + filterationTime - L->TotalCacheTime;
    return finalRes;
}

void DeAmortizedSDdNlogN::beginSetup() {
    setup = true;
}

void DeAmortizedSDdNlogN::endSetup() {
    //    if (setup) {
    //        for (int i = 0; i <= numOfIndices; i++) {
    //            for (int j = 0; j < 3; j++) {
    //                if (L->exist[i][j]){
    //                    
    //                }
    ////                    L->endSetup(i, j, keys[i][j], setup);
    //            }
    //        }
    //        setup = false;
    //    }
    reverse(setupPairs.begin(), setupPairs.end());
    reverse(setupPairs2.begin(), setupPairs2.end());
    for (int j = 0; j < numOfIndices && setupPairs.size() != 0; j++) {
        for (int i = 0; i < 3 && setupPairs.size() != 0; i++) {
            std::vector<pair<string, int> > curPairs;
            std::vector<byte > curPairs2;
            long endIndex = min((int) setupPairs.size(), (int) pow(2, j));
            curPairs.insert(curPairs.begin(), setupPairs.begin(), setupPairs.begin() + endIndex);
            curPairs2.insert(curPairs2.begin(), setupPairs2.begin(), setupPairs2.begin() + endIndex);

            setupPairs.erase(setupPairs.begin(), setupPairs.begin() + endIndex);
            setupPairs2.erase(setupPairs2.begin(), setupPairs2.begin() + endIndex);
            unordered_map<string, vector<tmp_prf_type> > curLevelData;
            for (int z = 0; z < curPairs.size(); z++) {
                if (curLevelData.count(curPairs[z].first) == 0) {
                    curLevelData[curPairs[z].first] = vector<tmp_prf_type>();
                }
                //                                if (curPairs[z].first == "ZYXO$o*") {
                //                                    cout << "level:" << j << " instance:" << i << " size:"<<curPairs[z].second<<endl;
                //                                }
                tmp_prf_type value;
                std::fill(value.begin(), value.end(), 0);
                std::copy(curPairs[z].first.begin(), curPairs[z].first.end(), value.begin());
                *(int*) (&(value.data()[TMP_AES_KEY_SIZE - 5])) = curPairs[z].second;
                value.data()[TMP_AES_KEY_SIZE - 6] = (byte) curPairs2[z];
                curLevelData[curPairs[z].first].push_back(value);
            }
            L->setup2(j, i, curLevelData, keys[i][j]);
        }
    }
    setup = false;
    L->endSetup();
    /*for (unsigned int i = 0; i < setupOMAPS.size(); i++) 
        {
        omaps[i]->setDummy(setupOMAPSDummies[i]);
        omaps[i]->setupInsert(setupOMAPS[i]);
    }*/
}

/*
double DeAmortizedSDdNlogN::getTotalSearchCommSize() const {
    return totalSearchCommSize;
}

double DeAmortizedSDdNlogN::getTotalUpdateCommSize() const {
    return totalUpdateCommSize;
}
 */

bool DeAmortizedSDdNlogN::setupFromFile(string filename) {
    return false;
    //    L->beginSetup();
    //    ifstream MyFile(filename);
    //    string line;
    //    if (MyFile) {
    //        while (getline(MyFile, line)) {
    //            std::vector<pair<string, int> > curPairs;
    //            std::vector<int> curOps;
    //            auto parts = Utilities::splitData(line, ",");
    //            int i = stoi(parts[0]);
    //            int j = stoi(parts[1]);
    //            int size = stoi(parts[2]);
    //            int cn = stoi(parts[3]);
    //            cnt[j] = cn;
    //
    //            string tmp;
    //            for (int k = 0; k < size; k++) {
    //                getline(MyFile, tmp);
    //                string keyword = tmp;
    //                getline(MyFile, tmp);
    //                int index = stoi(tmp);
    //                getline(MyFile, tmp);
    //                byte op = (byte) stoi(tmp);
    //                curPairs.push_back(pair<string, int>(keyword, index));
    //                curOps.push_back(op);
    //            }
    //            unordered_map<string, vector<tmp_prf_type> > curLevelData;
    //            for (int z = 0; z < curPairs.size(); z++) {
    //                if (curLevelData.count(curPairs[z].first) == 0) {
    //                    curLevelData[curPairs[z].first] = vector<tmp_prf_type>();
    //                }
    //                tmp_prf_type value;
    //                std::fill(value.begin(), value.end(), 0);
    //                std::copy(curPairs[z].first.begin(), curPairs[z].first.end(), value.begin());
    //                *(int*) (&(value.data()[TMP_AES_KEY_SIZE - 5])) = curPairs[z].second;
    //                value.data()[TMP_AES_KEY_SIZE - 6] = (byte) 0;
    //                *(byte*) (&value.data()[TMP_AES_KEY_SIZE - 6]) = (byte) (curOps[z] == OP::INS ? 0 : 1);
    //                curLevelData[curPairs[z].first].push_back(value);
    //            }
    //            if (curLevelData.size() > 0) {
    //                L->setup2(j, i, curLevelData, keys[i][j]);
    //            }
    //        }
    //        MyFile.close();
    //        for (int i = l - 1; i > 0; i--) {
    //            for (int j = 0; j < cnt[i]; j++) {
    //                L->obliviousMerge(keys[0][i - 1], keys[1][i - 1], keys[3][i], i - 1, j + 1, pow(2, i));
    //            }
    //        }
    //        return true;
    //    } else {
    //        return false;
    //    }
}