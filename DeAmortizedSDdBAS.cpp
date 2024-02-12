#include "DeAmortizedSDdBAS.h"
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <vector>
using namespace std;

DeAmortizedSDdBAS::DeAmortizedSDdBAS(bool deleteFiles, int keyworsSize, int N, bool inMemory, bool overwrite) {
    this->deleteFiles = deleteFiles;
    this->overwrite = overwrite;
    l = ceil(log2(N));
    int lK = ceil(log2(keyworsSize));
    numOfIndices = l;
    //    localSize = computeLocalCacheSize();
    L = new DeAmortizedBASClient(l, inMemory, overwrite, true);
    for (int j = 0; j < 4; j++) {
        keys.push_back(vector<unsigned char*> ());
        for (int i = 0; i < l; i++) {
            unsigned char* tmpKey = new unsigned char[16];
            keys[j].push_back(tmpKey);
        }
    }
    for (int i = 0; i < l; i++) {
        cnt.push_back(0);
        bytes<Key> key{0};
        OMAP* omap = new OMAP(max((int) min((int) pow(2, i), lK), 4), key); //SHOULD BE CHANGEd to  OMAP* omap = new OMAP(max((int) pow(2, i), 4), key);
        omaps.push_back(omap);
        setupOMAPS.push_back(map<Bid, string>());
        setupOMAPSDummies.push_back(0);
    }
    for (int i = 0; i < localSize; i++) {
        localmap.push_back(map<string, string>());
    }
    for (int j = 0; j < 4; j++) {
        vector< unordered_map<string, prf_type>* > curVec;
        for (int i = 0; i < localSize; i++) {
            auto item = new unordered_map<string, prf_type>();
            curVec.push_back(item);
        }
        data.push_back(curVec);
    }
    for (int j = 0; j < 3; j++) {
        for (unsigned int i = 0; i < numOfIndices; i++) {
            unsigned char* newKey = new unsigned char[16];
            memset(newKey, 0, 16);
            keys[j][i] = newKey;
        }
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

DeAmortizedSDdBAS::~DeAmortizedSDdBAS() {
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

void DeAmortizedSDdBAS::update(OP op, string keyword, int ind, bool setup) {
    if (generalSetup) {
        setupPairs.push_back(pair<string, int>(keyword, ind));
        setupOps.push_back(op);
        return;
    }
    if (!setup) {
        for (int i = 0; i < l; i++) {
            omaps[i]->treeHandler->oram->totalRead = 0;
            omaps[i]->treeHandler->oram->totalWrite = 0;
            omaps[i]->treeHandler->oram->store->cacheTime = 0;
        }
        L->totalCommunication = 0;
        totalUpdateCommSize = 0;
        L->server->storage[0]->cacheTime = 0;
        L->server->storage[1]->cacheTime = 0;
        L->server->storage[2]->cacheTime = 0;
        L->server->storage[3]->cacheTime = 0;
    } else {
        //        L->beginSetup();
    }
    totalCacheTime = 0;
    updateCounter++;
    for (int i = l - 1; i > 0; i--) {
        if ((i > localSize && L->exist[0][i - 1] && L->exist[1][i - 1]) || (i <= localSize && (*data[0][i - 1]).size() > 0 && (*data[1][i - 1]).size() > 0)) {
            prf_type x;
            if (cnt[i] < pow(2, i - 1)) {
                x = (i <= localSize ? getElementAt(0, i - 1, cnt[i]) : L->get(0, i - 1, cnt[i], keys[0][i - 1]));
            } else {
                x = (i <= localSize ? getElementAt(1, i - 1, cnt[i] % (int) pow(2, i - 1)) : L->get(1, i - 1, cnt[i] % (int) pow(2, i - 1), keys[1][i - 1]));
            }
            cnt[i]++;
            string curKeyword((char*) x.data());
            int upCnt = (int) ceil((updateCounter - (6 * pow(2, i - 1) - 2)) / pow(2, i)) + 1;
            string c;
            c = (i < localSize ? (localmap[i].count(curKeyword + "-" + to_string(upCnt)) == 0 ? "" : localmap[i][curKeyword + "-" + to_string(upCnt)])
                    : (setup ? (setupOMAPS[i].count(getBid(curKeyword, upCnt)) == 0 ? "" : setupOMAPS[i][getBid(curKeyword, upCnt)]) : omaps[i]->incrementCnt(getBid(curKeyword, upCnt))));
            if (c == "") {
                if (i < localSize) {
                    localmap[i][curKeyword + "-" + to_string(upCnt)] = "1";
                } else {
                    if (setup) {
                        setupOMAPS[i][getBid(curKeyword, upCnt)] = "1"; //The else condition is satisfied by omaps[i]->incrementCnt
                    }
                }
                c = "1";
            } else {
                c = to_string(stoi(c) + 1);
                if (i < localSize) {
                    localmap[i][curKeyword + "-" + to_string(upCnt)] = c;
                } else {
                    if (setup) {
                        setupOMAPS[i][getBid(curKeyword, upCnt)] = c; //The else condition is satisfied by omaps[i]->incrementCnt
                    }
                }
            }

            if (i < localSize) {
                (*data[3][i])[curKeyword + "-" + c] = x;
            } else {
                L->add(3, i, pair<string, prf_type>(curKeyword, x), stoi(c), keys[3][i]);
            }

            if ((i >= localSize && L->size(3, i) == pow(2, i)) || (i < localSize && (*data[3][i]).size() == pow(2, i))) {
                if (i <= localSize) {
                    if (i == localSize) {
                        if (setup) {
                            setupOMAPSDummies[i] = upCnt;
                        } else {
                            omaps[i]->setDummy(upCnt);
                        }
                    } else {
                        localmap[i].erase(curKeyword + "-" + to_string(upCnt));
                    }
                    delete data[0][i - 1];
                    data[1][i - 1]->clear();
                    data[0][i - 1] = data[2][i - 1];
                    data[2][i - 1] = new unordered_map<string, prf_type>();
                } else {
                    if (setup) {
                        setupOMAPSDummies[i] = upCnt;
                    } else {
                        omaps[i]->setDummy(upCnt);
                    }
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
                        data[3][i] = new unordered_map<string, prf_type>();
                    } else {
                        L->move(3, i, 0, i);
                        L->destry(3, i);
                    }
                    memcpy(keys[0][i], keys[3][i], 16);
                } else if ((i >= localSize && L->exist[1][i] == false) || (i < localSize && (*data[1][i]).size() == 0)) {
                    if (i < localSize) {
                        delete data[1][i];
                        data[1][i] = data[3][i];
                        data[3][i] = new unordered_map<string, prf_type>();
                    } else {
                        L->move(3, i, 1, i);
                        L->destry(3, i);
                    }
                    memcpy(keys[1][i], keys[3][i], 16);
                } else if ((i >= localSize && L->exist[2][i] == false) || (i < localSize && (*data[2][i]).size() == 0)) {
                    if (i < localSize) {
                        delete data[2][i];
                        data[2][i] = data[3][i];
                        data[3][i] = new unordered_map<string, prf_type>();
                    } else {
                        L->move(3, i, 2, i);
                        L->destry(3, i);
                    }
                    memcpy(keys[2][i], keys[3][i], 16);
                }
                if (i >= localSize) {
                    for (int j = 0; j < 16; j++) {
                        if (setup) {
                            keys[3][i][j] = 0;
                        } else {
                            keys[3][i][j] = (unsigned char) rand() % 256;
                        }
                    }
                }
            }
        }
    }

    prf_type value;
    std::fill(value.begin(), value.end(), 0);
    std::copy(keyword.begin(), keyword.end(), value.begin());
    *(int*) (&(value.data()[AES_KEY_SIZE - 5])) = ind;
    *(byte*) (&value.data()[AES_KEY_SIZE - 6]) = (byte) (op == OP::INS ? 0 : 1);

    (*data[3][0])[keyword + "-1"] = value;

    if ((*data[0][0]).size() == 0) {
        delete data[0][0];
        data[0][0] = data[3][0];
        data[3][0] = new unordered_map<string, prf_type>();
    } else if ((*data[1][0]).size() == 0) {
        delete data[1][0];
        data[1][0] = data[3][0];
        data[3][0] = new unordered_map<string, prf_type>();
    } else {
        delete data[2][0];
        data[2][0] = data[3][0];
        data[3][0] = new unordered_map<string, prf_type>();
    }
    if (updateCounter == 1000 || updateCounter == 10000 || updateCounter == 100000 || updateCounter == 1000000 || updateCounter == 10000000 ||
            updateCounter == 100000000 || updateCounter == 8388607 || updateCounter == 2000000 || updateCounter == 5000000) {
        dumpStatus();
    }
    if (!setup) {
        for (int i = 0; i < l; i++) {
            totalUpdateCommSize += (omaps[i]->treeHandler->oram->totalRead + omaps[i]->treeHandler->oram->totalWrite)*(sizeof (prf_type) + sizeof (int));
        }
        totalUpdateCommSize += L->totalCommunication;
        totalCacheTime += L->server->storage[0]->cacheTime;
        totalCacheTime += L->server->storage[1]->cacheTime;
        totalCacheTime += L->server->storage[2]->cacheTime;
        totalCacheTime += L->server->storage[3]->cacheTime;
        for (int i = 0; i < l; i++) {
            totalCacheTime += omaps[i]->treeHandler->oram->store->cacheTime;
        }
    }
}

vector<int> DeAmortizedSDdBAS::search(string keyword) {
    for (int i = 0; i < l; i++) {
        omaps[i]->treeHandler->oram->totalRead = 0;
        omaps[i]->treeHandler->oram->totalWrite = 0;
        omaps[i]->treeHandler->oram->store->cacheTime = 0;
    }
    totalCacheTime = 0;
    L->server->storage[0]->cacheTime = 0;
    L->server->storage[1]->cacheTime = 0;
    L->server->storage[2]->cacheTime = 0;
    L->server->storage[3]->cacheTime = 0;
    Utilities::startTimer(77);
    L->totalCommunication = 0;
    totalSearchCommSize = 0;
    vector<int> finalRes;
    vector<prf_type> encIndexes;
    for (int j = 0; j < 3; j++) {
        for (int i = 0; i < localSize; i++) {
            if ((*data[j][i]).size() > 0) {
                int curCounter = 1;
                bool exist = true;
                do {
                    if ((*data[j][i]).count(keyword + "-" + to_string(curCounter)) != 0) {
                        encIndexes.push_back((*data[j][i])[keyword + "-" + to_string(curCounter)]);
                        curCounter++;
                    } else {
                        exist = false;
                    }
                } while (exist);
            }
        }
    }
    auto searchTime1 = Utilities::stopTimer(77);
    cout << "Total Amortized1 Search time:" << searchTime1 << endl;
    Utilities::startTimer(99);
    for (int j = 0; j < 3; j++) {
        for (int i = localSize; i < l; i++) {
            if (L->exist[j][i]) {
                auto tmpRes = L->search(j, i, keyword, keys[j][i]);
                encIndexes.insert(encIndexes.end(), tmpRes.begin(), tmpRes.end());
            }
        }
    }

    map<int, int> remove;
    for (auto i = encIndexes.begin(); i != encIndexes.end(); i++) {
        prf_type decodedString = *i;
        int plaintext = *(int*) (&(decodedString.data()[AES_KEY_SIZE - 5]));
        remove[plaintext] += (2 * ((byte) decodedString.data()[AES_KEY_SIZE - 6]) - 1);
    }
    for (auto const& cur : remove) {
        if (cur.second < 0) {
            finalRes.emplace_back(cur.first);
        }
    }
    for (int i = 0; i < l; i++) {
        totalSearchCommSize += (omaps[i]->treeHandler->oram->totalRead + omaps[i]->treeHandler->oram->totalWrite)*(sizeof (prf_type) + sizeof (int));
    }
    totalSearchCommSize += L->totalCommunication;
    totalCacheTime += L->server->storage[0]->cacheTime;
    totalCacheTime += L->server->storage[1]->cacheTime;
    totalCacheTime += L->server->storage[2]->cacheTime;
    totalCacheTime += L->server->storage[3]->cacheTime;
    for (int i = 0; i < l; i++) {
        totalCacheTime += omaps[i]->treeHandler->oram->store->cacheTime;
    }
    auto filterationTime = Utilities::stopTimer(99);
    printf("filteration time:%f\n", filterationTime);

    cout << "Total Amortized1 Search time:" << searchTime1 << endl;
    cout << "Total drop cache command time for Storage:[" << totalCacheTime << "]" << endl;
    cout << "Amort search time - cache drop time =[" << searchTime1 + filterationTime - totalCacheTime << "]" << endl;

    return finalRes;
}

prf_type DeAmortizedSDdBAS::bitwiseXOR(int input1, int op, prf_type input2) {
    prf_type result;
    result[3] = input2[3] ^ ((input1 >> 24) & 0xFF);
    result[2] = input2[2] ^ ((input1 >> 16) & 0xFF);
    result[1] = input2[1] ^ ((input1 >> 8) & 0xFF);
    result[0] = input2[0] ^ (input1 & 0xFF);
    result[4] = input2[4] ^ (op & 0xFF);
    for (int i = 5; i < AES_KEY_SIZE; i++) {
        result[i] = (rand() % 255) ^ input2[i];
    }
    return result;
}

prf_type DeAmortizedSDdBAS::bitwiseXOR(prf_type input1, prf_type input2) {
    prf_type result;
    for (unsigned int i = 0; i < input2.size(); i++) {
        result[i] = input1.at(i) ^ input2[i];
    }
    return result;
}

Bid DeAmortizedSDdBAS::getBid(string input, int cnt) {
    std::array< uint8_t, ID_SIZE> value;
    std::fill(value.begin(), value.end(), 0);
    std::copy(input.begin(), input.end(), value.begin());
    *(int*) (&value[ID_SIZE - 4]) = cnt;
    Bid res(value);
    return res;
}

prf_type DeAmortizedSDdBAS::getElementAt(int instance, int index, int pos) {
    auto iter = (*data[instance][index]).begin();
    for (int i = 0; i < pos; i++) {
        iter++;
    }
    return (*iter).second;
}

void DeAmortizedSDdBAS::dumpStatus() {
    ofstream MyFile("StatusAt-" + to_string(updateCounter) + ".txt");
    int test = 0;
    for (int i = 0; i < 3; i++) {
        for (int j = 0; j < 1; j++) {

            auto curData = (*data[i][j]);
            MyFile << to_string(i) << "," << to_string(j) << "," << to_string(curData.size()) << "," << to_string(cnt[j]) << endl;
            test += curData.size();
            for (auto item : curData) {

                string keyword((char*) item.first.data());
                int index = *(int*) (&(item.second.data()[AES_KEY_SIZE - 5]));
                byte op = *(byte*) (&item.second.data()[AES_KEY_SIZE - 6]);
                MyFile << keyword << endl;
                MyFile << to_string(index) << endl;
                MyFile << to_string(op) << endl;
            }
        }
        for (int j = 1; j < numOfIndices; j++) {

            vector<prf_type> curData = L->getAllData(i, j, keys[i][j]);
            MyFile << to_string(i) << "," << to_string(j) << "," << to_string(curData.size()) << "," << to_string(cnt[j]) << endl;
            test += curData.size();
            for (int k = 0; k < curData.size(); k++) {
                string keyword((char*) curData[k].data());
                int index = *(int*) (&(curData[k].data()[AES_KEY_SIZE - 5]));
                byte op = *(byte*) (&curData[k].data()[AES_KEY_SIZE - 6]);
                MyFile << keyword << endl;
                MyFile << to_string(index) << endl;
                MyFile << to_string(op) << endl;
            }
        }
    }
    MyFile.close();
}

void DeAmortizedSDdBAS::endSetup() {
    for (unsigned int i = 0; i < setupOMAPS.size(); i++) {
        omaps[i]->setDummy(setupOMAPSDummies[i]);
        omaps[i]->setupInsert(setupOMAPS[i]);
    }

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
                    unordered_map<string, vector<prf_type> > curLevelData;
                    for (int z = 0; z < curPairs.size(); z++) {
                        if (curLevelData.count(curPairs[z].first) == 0) {
                            curLevelData[curPairs[z].first] = vector<prf_type>();
                        }
                        prf_type value;
                        std::fill(value.begin(), value.end(), 0);
                        std::copy(curPairs[z].first.begin(), curPairs[z].first.end(), value.begin());
                        *(int*) (&(value.data()[AES_KEY_SIZE - 5])) = curPairs[z].second;
                        value.data()[AES_KEY_SIZE - 6] = (byte) 0;
                        *(byte*) (&value.data()[AES_KEY_SIZE - 6]) = (byte) (curOps[z] == OP::INS ? 0 : 1);
                        curLevelData[curPairs[z].first].push_back(value);
                    }
                    L->setup(i, j, curLevelData, keys[i][j]);
                }
            }
            L->endSetup(true);

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

            generalSetup = false;
        } else {

        }
    } else {
        L->endSetup(false);
    }
}

void DeAmortizedSDdBAS::beginSetup() {
    generalSetup = true;
    L->beginSetup();
}

double DeAmortizedSDdBAS::getTotalSearchCommSize() const {
    return totalSearchCommSize;
}

double DeAmortizedSDdBAS::getTotalUpdateCommSize() const {
    return totalUpdateCommSize;
}

int DeAmortizedSDdBAS::computeLocalCacheSize() {
    int maxCapacity = Utilities::TotalCacheSize;
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

bool DeAmortizedSDdBAS::setupFromFile(string filename) {
    //                return false;
    L->beginSetup();
    ifstream MyFile(filename);
    string line;
    updateCounter = 0;
    vector<vector< vector< pair<string, prf_type > > > > ldata;
    for (int j = 0; j < 4; j++) {
        vector< vector< pair<string, prf_type > > > curVec;
        for (int i = 0; i < l; i++) {
            vector< pair<string, prf_type > > item;
            curVec.push_back(item);
        }
        ldata.push_back(curVec);
    }

    if (MyFile) {
        while (getline(MyFile, line)) {
            std::vector<pair<string, int> > curPairs;
            std::vector<int> curOps;
            auto parts = Utilities::splitData(line, ",");
            int i = stoi(parts[0]);
            int j = stoi(parts[1]);
            int size = stoi(parts[2]);
            int cn = stoi(parts[3]);
            updateCounter += size;
            cnt[j] = cn;

            cout << "loading level:" << j << " instance:" << i << endl;

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

            unordered_map<string, vector<prf_type> > curLevelData;
            for (int z = 0; z < curPairs.size(); z++) {
                if (curLevelData.count(curPairs[z].first) == 0) {
                    curLevelData[curPairs[z].first] = vector<prf_type>();
                }
                prf_type value;
                std::fill(value.begin(), value.end(), 0);
                std::copy(curPairs[z].first.begin(), curPairs[z].first.end(), value.begin());
                *(int*) (&(value.data()[AES_KEY_SIZE - 5])) = curPairs[z].second;
                value.data()[AES_KEY_SIZE - 6] = (byte) 0;
                *(byte*) (&value.data()[AES_KEY_SIZE - 6]) = (byte) (curOps[z] == OP::INS ? 0 : 1);
                curLevelData[curPairs[z].first].push_back(value);
                ldata[i][j].push_back(pair<string, prf_type>(curPairs[z].first, value));
            }
            if (j == 0) {
                if (curLevelData.size() > 0) {
                    (*data[i][0])[curPairs[0].first + "-1"] = curLevelData[curPairs[0].first][0];
                }
            } else {
                if (curLevelData.size() > 0) {
                    L->setup(i, j, curLevelData, keys[i][j]);
                }
            }
        }

        for (int i = l - 1; i > 0; i--) {
            cout << "fixing level:" << i << " with " << cnt[i] << " updates" << endl;
            for (int p = 0; p < cnt[i]; p++) {
                if (L->exist[0][i - 1] && L->exist[1][i - 1]) {
                    if (p < pow(2, i - 1)) {
                        L->add(3, i, pair<string, prf_type>(ldata[0][i - 1][p].first, ldata[0][i - 1][p].second), p + 1, keys[3][i]);
                    } else {
                        L->add(3, i, pair<string, prf_type>(ldata[1][i - 1][p % (int) pow(2, i - 1)].first, ldata[1][i - 1][p % (int) pow(2, i - 1)].second), p + 1, keys[3][i]);
                    }
                }
            }

            if (L->exist[0][i - 1] && L->exist[1][i - 1] && cnt[i] > 0) {
                int upCnt = (int) floor(updateCounter / pow(2, i)) - 1;
                setupOMAPS[i][getBid(ldata[0][i - 1][0].first, upCnt)] = to_string(cnt[i]);
            }
        }

        MyFile.close();
        return true;
    } else {
        return false;
    }
}
