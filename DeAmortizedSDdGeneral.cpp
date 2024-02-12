#include "DeAmortizedSDdGeneral.h"
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <vector>
#include<cstdlib>
#include<algorithm>
#include <bits/stdc++.h>
using namespace std;

DeAmortizedSDdGeneral::DeAmortizedSDdGeneral(int N, bool inMemory, bool overwrite) {
    cout << "=====================Running SDd+OneChoiceAllocation======================" << endl;
    L = new OneChoiceSDdGeneralClient(N, inMemory, overwrite, false);
    this->overwrite = overwrite;
    this->deleteFiles = deleteFiles;
    l = floor(log2(N)) + 1;
    memset(nullKey.data(), 0, AES_KEY_SIZE);
    numOfIndices = l;
    //    localSize = computeLocalCacheSize();
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
    for (int i = 0; i <= localSize; i++)
        localmap.push_back(map<string, string>());
    for (int j = 0; j < 4; j++) {
        vector< vector < pair<string, prf_type> >* > curVec;
        for (int i = 0; i <= localSize; i++) {
            auto item = new vector<pair < string, prf_type >> ();
            curVec.push_back(item);
        }
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

        FILE* f = fopen((Utilities::rootAddress + "keys.txt").c_str(), "rb+");
        fseek(f, 0, SEEK_SET);

        for (int j = 0; j < 3; j++) {
            for (unsigned int i = 0; i < numOfIndices; i++) {
                fread(keys[j][i], 16, 1, f);
            }
        }
        fclose(f);
    }
}

DeAmortizedSDdGeneral::~DeAmortizedSDdGeneral() {
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

        FILE* f = fopen((Utilities::rootAddress + "keys.txt").c_str(), "wb+");
        fseek(f, 0, SEEK_SET);

        for (int j = 0; j < 3; j++) {
            for (unsigned int i = 0; i < numOfIndices; i++) {
                fwrite((char*) keys[j][i], 16, 1, f);
            }
        }
        fclose(f);
    }
}

void DeAmortizedSDdGeneral::update(OP op, string keyword, int ind, bool setup) {
    if (generalSetup) {
        setupPairs.push_back(pair<string, int>(keyword, ind));
        setupOps.push_back(op);
        return;
    }
    if (!setup) {
        L->totalCommunication = 0;
        totalUpdateCommSize = 0;
        L->server->storage[0]->cacheTime = 0;
        L->server->storage[1]->cacheTime = 0;
        L->server->storage[2]->cacheTime = 0;
        L->server->storage[3]->cacheTime = 0;
        for (int i = 0; i < numOfIndices; i++) {
            L->transData.cntdisks[i]->cacheTime = 0;
            L->transData.bindisks[i]->cacheTime = 0;
            L->server->transData.buf1disks[i]->cacheTime = 0;
            L->server->transData.buf2disks[i]->cacheTime = 0;
            L->server->transData.bindisks[i]->cacheTime = 0;
            L->server->updateData[i].leftArraydisk->cacheTime = 0;
            L->server->updateData[i].leftArray3disk->cacheTime = 0;
            L->server->updateData[i].rightArraydisk->cacheTime = 0;
            L->server->updateData[i].rightArray3disk->cacheTime = 0;
            L->server->updateData[i].inputArraydisk->cacheTime = 0;
            L->server->updateData[i].inputArray2disk->cacheTime = 0;
            L->server->updateData[i].randomLabelsdisk->cacheTime = 0;
            L->server->updateData[i].randomLabels2disk->cacheTime = 0;
            L->server->updateData[i].inputAssignedBucketsdisk->cacheTime = 0;
            L->server->updateData[i].inputAssignedBuckets2disk->cacheTime = 0;
            L->server->updateData[i].permutedArrayWithNoDummydisk->cacheTime = 0;
            L->server->updateData[i].permutedArrayWithNoDummy2disk->cacheTime = 0;
            L->server->updateData[i].sortedKeywordsdisk->cacheTime = 0;
            L->server->updateData[i].sortedBUF1disk->cacheTime = 0;
            L->server->updateData[i].sortedBUF2disk->cacheTime = 0;
            L->server->updateData[i].arrayAsdisk->cacheTime = 0;
            L->server->updateData[i].arrayAs2disk->cacheTime = 0;
            L->server->updateData[i].tempCacheTime = 0;

            for (int j = 0; j < L->server->updateData[i].maxBinSize; j++) {
                L->server->updateData[i].ciphertextsdisk[j]->cacheTime = 0;
            }
        }

    } else {
        L->beginSetup();
    }


    totalCacheTime = 0;
    updateCounter++;
    for (int i = l - 1; i > 0; i--) {
        if (Utilities::DEBUG_MODE) {
            cout << "General level:" << i << endl;
        }
        if (i > localSize && L->exist[0][i - 1] && L->exist[1][i - 1] || (i <= localSize && (*data[0][i - 1]).size() > 0 && (*data[1][i - 1]).size() > 0)) {
            bool isCompletelyBuilt = false;
            if (i <= localSize) {

                pair<string, prf_type> x;
                if (cnt[i] < pow(2, i - 1)) {
                    x = getElementAt(0, i - 1, cnt[i]);
                } else {
                    x = getElementAt(1, i - 1, cnt[i] % (int) pow(2, i - 1));
                }
                cnt[i]++;

                (*data[3][i]).push_back(x);
                if (i == localSize && cnt[i] == pow(2, i)) {
                    unordered_map<string, vector<prf_type> > pairs;
                    for (auto item : (*data[3][i])) {
                        string kw = item.first;
                        if (pairs.count(kw) == 0) {
                            pairs[kw] = vector<prf_type>();
                        }
                        pairs[kw].push_back(item.second);
                    }
                    L->setup(i, 3, pairs, keys[3][i]);
                    delete data[3][i];
                    data[3][i] = new vector<pair < string, prf_type >> ();
                }
                if (cnt[i] == pow(2, i)) {
                    isCompletelyBuilt = true;
                }
            } else {
                if (Utilities::PROFILE_MODE) {
                    Utilities::startTimer(456);
                }
                cnt[i]++;
                L->obliviousMerge(keys[0][i - 1], keys[1][i - 1], keys[3][i], i - 1, cnt[i], pow(2, i));
                if (cnt[i] == pow(2, i)) {
                    //                L->obliviousMerge(keys[0][i - 1], keys[1][i - 1], keys[3][i], i - 1, cnt[i], pow(2, i));  
                    isCompletelyBuilt = true;
                }
                if (Utilities::PROFILE_MODE) {
                    auto gg = Utilities::stopTimer(456);
                    cout << "oblivious merge:" << gg << endl;
                }
            }


            if (isCompletelyBuilt) {
                if (i <= localSize) {
                    data[1][i - 1]->clear();
                    delete data[0][i - 1];
                    data[0][i - 1] = data[2][i - 1];
                    data[2][i - 1] = new vector<pair < string, prf_type >> ();
                } else {
                    L->destry(0, i - 1);
                    L->destryAndClear(1, i - 1);
                    L->move(2, i - 1, 0, i - 1);
                    L->destry(2, i - 1);
                }

                memcpy(keys[0][i - 1], keys[2][i - 1], 16);
                cnt[i] = 0;

                if ((i >= localSize && L->exist[0][i] == false) || (i < localSize && (*data[0][i]).size() == 0)) {
                    if (i < localSize) {
                        delete data[0][i];
                        data[0][i] = data[3][i];
                        data[3][i] = new vector<pair < string, prf_type >> ();
                    } else {
                        L->move(3, i, 0, i);
                        L->destry(3, i);
                    }
                    memcpy(keys[0][i], keys[3][i], 16);
                } else if ((i >= localSize && L->exist[1][i] == false) || (i < localSize && (*data[1][i]).size() == 0)) {
                    if (i < localSize) {
                        delete data[1][i];
                        data[1][i] = data[3][i];
                        data[3][i] = new vector<pair < string, prf_type >> ();
                    } else {
                        L->move(3, i, 1, i);
                        L->destry(3, i);
                    }
                    memcpy(keys[1][i], keys[3][i], 16);
                } else if ((i >= localSize && L->exist[2][i] == false) || (i < localSize && (*data[2][i]).size() == 0)) {
                    if (i < localSize) {
                        delete data[2][i];
                        data[2][i] = data[3][i];
                        data[3][i] = new vector<pair < string, prf_type >> ();

                    } else {
                        L->move(3, i, 2, i);
                        L->destry(3, i);
                    }
                    memcpy(keys[2][i], keys[3][i], 16);
                }
                if (i >= localSize) {
                    for (int j = 0; j < 16; j++) {
                        keys[3][i][j] = (unsigned char) rand() % 256;
                    }
                }
            }
        }
    }

    if (Utilities::DEBUG_MODE) {
        cout << "General level end of loops" << endl;
    }
    prf_type value;
    std::fill(value.begin(), value.end(), 0);
    std::copy(keyword.begin(), keyword.end(), value.begin());
    *(int*) (&(value.data()[AES_KEY_SIZE - 5])) = ind;
    *(byte*) (&value.data()[AES_KEY_SIZE - 6]) = (byte) (op == OP::INS ? 0 : 1);

    if (localSize >= 0) {
        (*data[3][0]).push_back(pair<string, prf_type>(keyword, value));
        if ((*data[0][0]).size() == 0) {
            delete data[0][0];
            data[0][0] = data[3][0];
            data[3][0] = new vector<pair < string, prf_type >> ();
        } else if ((*data[1][0]).size() == 0) {
            delete data[1][0];
            data[1][0] = data[3][0];
            data[3][0] = new vector<pair < string, prf_type >> ();
        } else {
            delete data[2][0];
            data[2][0] = data[3][0];
            data[3][0] = new vector<pair < string, prf_type >> ();
        }
    } else {
        unordered_map<string, vector<prf_type> > pairs;
        auto vals = vector<prf_type>();
        vals.push_back(value);
        pairs[keyword] = vals;
        L->setup(0, 3, pairs, keys[3][0]);

        if (L->exist[0][0] == false) {
            L->move(3, 0, 0, 0);
            L->destry(3, 0);
        } else if (L->exist[1][0] == false) {
            L->move(3, 0, 1, 0);
            L->destry(3, 0);
        } else {
            L->move(3, 0, 2, 0);
            L->destry(3, 0);
        }
    }
    if (!setup) {
        totalUpdateCommSize += L->totalCommunication;
        totalCacheTime += L->server->storage[0]->cacheTime;
        totalCacheTime += L->server->storage[1]->cacheTime;
        totalCacheTime += L->server->storage[2]->cacheTime;
        totalCacheTime += L->server->storage[3]->cacheTime;
        for (int i = 0; i < numOfIndices; i++) {
            totalCacheTime += L->transData.cntdisks[i]->cacheTime;
            totalCacheTime += L->transData.bindisks[i]->cacheTime;
            totalCacheTime += L->server->transData.buf1disks[i]->cacheTime;
            totalCacheTime += L->server->transData.buf2disks[i]->cacheTime;
            totalCacheTime += L->server->transData.bindisks[i]->cacheTime;
            totalCacheTime += L->server->updateData[i].leftArraydisk->cacheTime;
            totalCacheTime += L->server->updateData[i].leftArray3disk->cacheTime;
            totalCacheTime += L->server->updateData[i].rightArraydisk->cacheTime;
            totalCacheTime += L->server->updateData[i].rightArray3disk->cacheTime;
            totalCacheTime += L->server->updateData[i].inputArraydisk->cacheTime;
            totalCacheTime += L->server->updateData[i].inputArray2disk->cacheTime;
            totalCacheTime += L->server->updateData[i].randomLabelsdisk->cacheTime;
            totalCacheTime += L->server->updateData[i].randomLabels2disk->cacheTime;
            totalCacheTime += L->server->updateData[i].inputAssignedBucketsdisk->cacheTime;
            totalCacheTime += L->server->updateData[i].inputAssignedBuckets2disk->cacheTime;
            totalCacheTime += L->server->updateData[i].permutedArrayWithNoDummydisk->cacheTime;
            totalCacheTime += L->server->updateData[i].permutedArrayWithNoDummy2disk->cacheTime;
            totalCacheTime += L->server->updateData[i].sortedKeywordsdisk->cacheTime;
            totalCacheTime += L->server->updateData[i].sortedBUF1disk->cacheTime;
            totalCacheTime += L->server->updateData[i].sortedBUF2disk->cacheTime;
            totalCacheTime += L->server->updateData[i].arrayAsdisk->cacheTime;
            totalCacheTime += L->server->updateData[i].arrayAs2disk->cacheTime;
            totalCacheTime += L->server->updateData[i].tempCacheTime;

            for (int j = 0; j < L->server->updateData[i].maxBinSize; j++) {
                totalCacheTime += L->server->updateData[i].ciphertextsdisk[j]->cacheTime;
            }
        }
    }

}

pair<string, prf_type> DeAmortizedSDdGeneral::getElementAt(int instance, int index, int pos) {
    auto iter = (*data[instance][index]).begin();
    for (int i = 0; i < pos; i++) {
        iter++;
    }
    return (*iter);
}

prf_type DeAmortizedSDdGeneral::createKeyVal(string keyword, int ind, OP op) {
    prf_type keyVal;
    memset(keyVal.data(), 0, AES_KEY_SIZE);
    std::copy(keyword.begin(), keyword.end(), keyVal.begin()); //keyword
    *(int*) (&(keyVal.data()[AES_KEY_SIZE - 5])) = ind; //fileid
    keyVal.data()[AES_KEY_SIZE - 6] = (byte) (op == OP::INS ? 0 : 1); //op
    *(int*) (&(keyVal.data()[AES_KEY_SIZE - 11])) = 0; //index 0 has only bin 0
    return keyVal;
}

prf_type DeAmortizedSDdGeneral::createKeyVal(string keyword, int cntw) {
    prf_type keyVal;
    memset(keyVal.data(), 0, AES_KEY_SIZE);
    std::copy(keyword.begin(), keyword.end(), keyVal.begin()); //keyword
    *(int*) (&(keyVal.data()[AES_KEY_SIZE - 5])) = cntw; //fileid
    *(int*) (&(keyVal.data()[AES_KEY_SIZE - 11])) = 1; //PRP
    return keyVal;
}

void DeAmortizedSDdGeneral::updateKey(int index, int toInstance, int fromInstance) {
    keys[index][toInstance] = keys[index][fromInstance];
}

vector<int> DeAmortizedSDdGeneral::search(string keyword) {
    L->totalCommunication = 0;
    totalSearchCommSize = 0;
    L->TotalCacheTime = 0;
    L->searchTime = 0;
    Utilities::startTimer(33);
    vector<int> finalRes;
    vector<prf_type> encIndexes;
    for (int j = 0; j < 3; j++) {
        for (int i = 0; i < localSize; i++) {
            if ((*data[j][i]).size() > 0) {
                for (int k = 0; k < (*data[j][i]).size(); k++) {
                    if ((*data[j][i])[k].first == keyword) {
                        encIndexes.push_back((*data[j][i])[k].second);
                    }
                }
            }
        }
    }
    double serverTime = 0;
    for (int i = 0; i < numOfIndices; i++) {
        for (int j = 0; j < 3; j++) {
            if (L->exist[j][i]) {
                vector<prf_type> tmpRes;
                tmpRes = L->search(i, j, keyword, keys[j][i]);
                serverTime += L->serverTime;
                encIndexes.insert(encIndexes.end(), tmpRes.begin(), tmpRes.end());
            }
        }
    }
    cout << "ServerTime:" << serverTime << endl;
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
    for (auto const& cur : remove) {
        if (cur.second < 0) {
            finalRes.emplace_back(cur.first);
        }
    }
    filterationTime = Utilities::stopTimer(99);
    cout << endl << endl << "TOTAL search BYTES read:{" << L->totalCommunication << "}" << endl;
    cout << "TOTAL search TIME:[[" << L->searchTime << "]]" << endl;
    printf("filteration time:%f\n", filterationTime);

    cout << "Total Amortized1 Search time:" << searchTime << "/" << L->searchTime << endl;
    cout << "Total drop cache command time for Storage:[" << L->TotalCacheTime << "]" << endl;
    cout << "Amort search time - cache drop time =[" << searchTime + filterationTime - L->TotalCacheTime << "]" << endl;
    totalSearchCommSize += L->totalCommunication;
    return finalRes;
}

void DeAmortizedSDdGeneral::beginSetup() {
    generalSetup = true;
    L->beginSetup();
}

void DeAmortizedSDdGeneral::endSetup() {
    if (overwrite) {
        if (generalSetup) {
            reverse(setupPairs.begin(), setupPairs.end());
            reverse(setupOps.begin(), setupOps.end());
            for (int j = 0; j < numOfIndices && setupPairs.size() != 0; j++) {
                for (int i = 0; i < 3 && setupPairs.size() != 0; i++) {
                    std::vector<pair<string, int> > curPairs;
                    std::vector<int> curOps;
                    long endIndex = min((int) setupPairs.size(), (int) pow(2, j));
                    curPairs.insert(curPairs.begin(), setupPairs.begin(), setupPairs.begin() + endIndex);
                    curOps.insert(curOps.begin(), setupOps.begin(), setupOps.begin() + endIndex);

                    setupPairs.erase(setupPairs.begin(), setupPairs.begin() + endIndex);
                    setupOps.erase(setupOps.begin(), setupOps.begin() + endIndex);
                    unordered_map<string, vector<tmp_prf_type> > curLevelData;
                    for (int z = 0; z < curPairs.size(); z++) {
                        if (curLevelData.count(curPairs[z].first) == 0) {
                            curLevelData[curPairs[z].first] = vector<tmp_prf_type>();
                        }
                        tmp_prf_type value;
                        std::fill(value.begin(), value.end(), 0);
                        std::copy(curPairs[z].first.begin(), curPairs[z].first.end(), value.begin());
                        *(int*) (&(value.data()[TMP_AES_KEY_SIZE - 5])) = curPairs[z].second;
                        value.data()[TMP_AES_KEY_SIZE - 6] = (byte) 0;
                        *(byte*) (&value.data()[TMP_AES_KEY_SIZE - 6]) = (byte) (curOps[z] == OP::INS ? 0 : 1);
                        curLevelData[curPairs[z].first].push_back(value);
                    }
                    L->setup2(j, i, curLevelData, keys[i][j]);
                }
            }
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

            generalSetup = false;
            L->endSetup(true);
        } else {

        }
    } else {
        L->endSetup(false);
    }
}

int DeAmortizedSDdGeneral::computeLocalCacheSize() {
    int maxCapacity = Utilities::TotalCacheSize / 2;
    int res = 0;
    int used = 0;
    int level = 0;
    while (used < maxCapacity) {
        int currentCap = 4 * pow(2, level) * 2 * AES_KEY_SIZE;
        used += currentCap;
        level++;
    }
    res = level;
    return res;
}

bool DeAmortizedSDdGeneral::setupFromFile(string filename) {
    return false;
    L->beginSetup();
    ifstream MyFile(filename);
    string line;
    if (MyFile) {
        while (getline(MyFile, line)) {
            std::vector<pair<string, int> > curPairs;
            std::vector<int> curOps;
            auto parts = Utilities::splitData(line, ",");
            int i = stoi(parts[0]);
            int j = stoi(parts[1]);
            int size = stoi(parts[2]);
            int cn = stoi(parts[3]);
            cnt[j] = cn;

            string tmp;
            for (int k = 0; k < size; k++) {
                getline(MyFile, tmp);
                string keyword = tmp;
                getline(MyFile, tmp);
                int index = stoi(tmp);
                getline(MyFile, tmp);
                byte op = (byte) stoi(tmp);
                curPairs.push_back(pair<string, int>(keyword, index));
                curOps.push_back(op);
            }
            unordered_map<string, vector<tmp_prf_type> > curLevelData;
            for (int z = 0; z < curPairs.size(); z++) {
                if (curLevelData.count(curPairs[z].first) == 0) {
                    curLevelData[curPairs[z].first] = vector<tmp_prf_type>();
                }
                tmp_prf_type value;
                std::fill(value.begin(), value.end(), 0);
                std::copy(curPairs[z].first.begin(), curPairs[z].first.end(), value.begin());
                *(int*) (&(value.data()[TMP_AES_KEY_SIZE - 5])) = curPairs[z].second;
                value.data()[TMP_AES_KEY_SIZE - 6] = (byte) 0;
                *(byte*) (&value.data()[TMP_AES_KEY_SIZE - 6]) = (byte) (curOps[z] == OP::INS ? 0 : 1);
                curLevelData[curPairs[z].first].push_back(value);
            }
            if (curLevelData.size() > 0) {
                L->setup2(j, i, curLevelData, keys[i][j]);
            }
        }
        MyFile.close();
        for (int i = l - 1; i > 0; i--) {
            for (int j = 0; j < cnt[i]; j++) {
                L->obliviousMerge(keys[0][i - 1], keys[1][i - 1], keys[3][i], i - 1, j + 1, pow(2, i));
            }
        }
        return true;
    } else {
        return false;
    }
}