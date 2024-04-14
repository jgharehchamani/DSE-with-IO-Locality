//#include "DeAmortizedSDdPlaintext.h"
//#include <openssl/conf.h>
//#include <openssl/evp.h>
//#include <openssl/err.h>
//#include <string.h>
//#include <vector>
//using namespace std;
//
//DeAmortizedSDdPlaintext::DeAmortizedSDdPlaintext(bool deleteFiles, int keyworsSize, int N, bool inMemory, bool overwrite) {
//    this->deleteFiles = deleteFiles;
//    this->overwrite = overwrite;
//    l = floor(log2(N)) + 1;
//    numOfIndices = l;
//    //    localSize = computeLocalCacheSize();
//    L = new DeAmortizedBASClient(l, inMemory, overwrite, true);
//    for (int j = 0; j < 4; j++) {
//        keys.push_back(vector<unsigned char*> ());
//        for (int i = 0; i < l; i++) {
//            unsigned char* tmpKey = new unsigned char[16];
//            keys[j].push_back(tmpKey);
//        }
//    }
//    for (int i = 0; i < l; i++) {
//        cnt.push_back(0);
//        bytes<Key> key{0};
//        OMAP* omap = new OMAP(max((int) pow(2, i), 4), key);
//        omaps.push_back(omap);
//        setupOMAPS.push_back(map<Bid, string>());
//        setupOMAPSDummies.push_back(0);
//    }
//    for (int i = 0; i < localSize; i++) {
//        localmap.push_back(map<string, string>());
//    }
//    for (int j = 0; j < 4; j++) {
//        vector< unordered_map<string, prf_type>* > curVec;
//        for (int i = 0; i < localSize; i++) {
//            auto item = new unordered_map<string, prf_type>();
//            curVec.push_back(item);
//        }
//        data.push_back(curVec);
//    }
//    for (int j = 0; j < 3; j++) {
//        for (unsigned int i = 0; i < numOfIndices; i++) {
//            unsigned char* newKey = new unsigned char[16];
//            memset(newKey, 0, 16);
//            keys[j][i] = newKey;
//        }
//    }
//    if (!overwrite) {
//        fstream file(Utilities::rootAddress + "existStatus.txt", std::ofstream::in);
//        if (file.fail()) {
//            file.close();
//            return;
//        }
//        for (int j = 0; j < 3; j++) {
//            for (unsigned int i = 0; i < numOfIndices; i++) {
//                string data;
//                getline(file, data);
//                if (data == "true") {
//                    L->exist[j][i] = true;
//                } else {
//                    L->exist[j][i] = false;
//                }
//            }
//        }
//        file.close();
//
//        FILE* f = fopen((Utilities::rootAddress + "keys.txt").c_str(), "rb+");
//        fseek(f, 0, SEEK_SET);
//
//        for (int j = 0; j < 3; j++) {
//            for (unsigned int i = 0; i < numOfIndices; i++) {
//                fread(keys[j][i], 16, 1, f);
//            }
//        }
//        fclose(f);
//    }
//}
//
//DeAmortizedSDdPlaintext::~DeAmortizedSDdPlaintext() {
//    fstream file(Utilities::rootAddress + "existStatus.txt", std::ofstream::out);
//    if (file.fail()) {
//        cerr << "Error: " << strerror(errno);
//    }
//    for (int j = 0; j < 3; j++) {
//        for (unsigned int i = 0; i < numOfIndices; i++) {
//
//            if (L->exist[j][i]) {
//                file << "true" << endl;
//            } else {
//                file << "false" << endl;
//            }
//        }
//    }
//    file.close();
//
//    FILE* f = fopen((Utilities::rootAddress + "keys.txt").c_str(), "wb+");
//    fseek(f, 0, SEEK_SET);
//
//    for (int j = 0; j < 3; j++) {
//        for (unsigned int i = 0; i < numOfIndices; i++) {
//            fwrite((char*) keys[j][i], 16, 1, f);
//        }
//    }
//    fclose(f);
//}
//
//void DeAmortizedSDdPlaintext::update(OP op, string keyword, int ind, bool setup) {
//    if (generalSetup) {
//        setupPairs.push_back(pair<string, int>(keyword, ind));
//        setupOps.push_back(op);
//        return;
//    }
//    if (!setup) {
//        for (int i = 0; i < l; i++) {
//            omaps[i]->treeHandler->oram->totalRead = 0;
//            omaps[i]->treeHandler->oram->totalWrite = 0;
//            omaps[i]->treeHandler->oram->store->cacheTime = 0;
//        }
//        L->totalCommunication = 0;
//        totalUpdateCommSize = 0;
//        L->server->storage[0]->cacheTime = 0;
//        L->server->storage[1]->cacheTime = 0;
//        L->server->storage[2]->cacheTime = 0;
//        L->server->storage[3]->cacheTime = 0;
//    } else {
//        L->beginSetup();
//    }
//    totalCacheTime = 0;
//    if (updateCounter == 1000 || updateCounter == 10000 || updateCounter == 100000 || updateCounter == 1000000 || updateCounter == 10000000 ||
//            updateCounter == 100000000 || updateCounter == 8388607 || updateCounter == 2000000 || updateCounter == 5000000) {
//        dumpStatus();
//    }
//    updateCounter++;
//    for (int i = l - 1; i > 0; i--) {
//        if ((i > localSize && L->exist[0][i - 1] && L->exist[1][i - 1]) || (i <= localSize && (*data[0][i - 1]).size() > 0 && (*data[1][i - 1]).size() > 0)) {
//            prf_type x;
//            if (cnt[i] < pow(2, i - 1)) {
//                x = (i <= localSize ? getElementAt(0, i - 1, cnt[i]) : L->get(0, i - 1, cnt[i], keys[0][i - 1]));
//            } else {
//                x = (i <= localSize ? getElementAt(1, i - 1, cnt[i] % (int) pow(2, i - 1)) : L->get(1, i - 1, cnt[i] % (int) pow(2, i - 1), keys[1][i - 1]));
//            }
//            cnt[i]++;
//            string curKeyword((char*) x.data());
//            int upCnt = (int) ceil((updateCounter - (6 * pow(2, i - 1) - 2)) / pow(2, i)) + 1;
//            string c;
//            c = (i < localSize ? (localmap[i].count(curKeyword + "-" + to_string(upCnt)) == 0 ? "" : localmap[i][curKeyword + "-" + to_string(upCnt)])
//                    : (setup ? (setupOMAPS[i].count(getBid(curKeyword, upCnt)) == 0 ? "" : setupOMAPS[i][getBid(curKeyword, upCnt)]) : omaps[i]->incrementCnt(getBid(curKeyword, upCnt))));
//            if (c == "") {
//                if (i < localSize) {
//                    localmap[i][curKeyword + "-" + to_string(upCnt)] = "1";
//                } else {
//                    if (setup) {
//                        setupOMAPS[i][getBid(curKeyword, upCnt)] = "1"; //The else condition is satisfied by omaps[i]->incrementCnt
//                    }
//                }
//                c = "1";
//            } else {
//                c = to_string(stoi(c) + 1);
//                if (i < localSize) {
//                    localmap[i][curKeyword + "-" + to_string(upCnt)] = c;
//                } else {
//                    if (setup) {
//                        setupOMAPS[i][getBid(curKeyword, upCnt)] = c; //The else condition is satisfied by omaps[i]->incrementCnt
//                    }
//                }
//            }
//
//            if (i < localSize) {
//                (*data[3][i])[curKeyword + "-" + c] = x;
//            } else {
//                L->add(3, i, pair<string, prf_type>(curKeyword, x), stoi(c), keys[3][i]);
//            }
//
//            if ((i >= localSize && L->size(3, i) == pow(2, i)) || (i < localSize && (*data[3][i]).size() == pow(2, i))) {
//                if (i <= localSize) {
//                    if (i == localSize) {
//                        if (setup) {
//                            setupOMAPSDummies[i] = upCnt;
//                        } else {
//                            omaps[i]->setDummy(upCnt);
//                        }
//                    } else {
//                        localmap[i].erase(curKeyword + "-" + to_string(upCnt));
//                    }
//                    delete data[0][i - 1];
//                    //                    (*data[0][i - 1]).clear();
//                    //                    (*data[1][i - 1]).clear();
//                    //                    (*data[0][i - 1]).insert((*data[2][i - 1]).begin(), (*data[2][i - 1]).end());
//                    //                    (*data[2][i - 1]).clear();
//                    data[1][i - 1]->clear();
//                    data[0][i - 1] = data[2][i - 1];
//                    data[2][i - 1] = new unordered_map<string, prf_type>();
//                } else {
//                    if (setup) {
//                        setupOMAPSDummies[i] = upCnt;
//                    } else {
//                        omaps[i]->setDummy(upCnt);
//                    }
//                    L->destry(0, i - 1);
//                    L->destryAndClear(1, i - 1);
//                    L->move(2, i - 1, 0, i - 1);
//                    L->destry(2, i - 1);
//                }
//
//                memcpy(keys[0][i - 1], keys[2][i - 1], 16);
//                cnt[i] = 0;
//                if ((i >= localSize && L->exist[0][i] == false) || (i < localSize && (*data[0][i]).size() == 0)) {
//                    if (i < localSize) {
//                        delete data[0][i];
//                        data[0][i] = data[3][i];
//                        data[3][i] = new unordered_map<string, prf_type>();
//                        //                        (*data[0][i]).clear();
//                        //                        (*data[0][i]).insert((*data[3][i]).begin(), (*data[3][i]).end());
//                        //                        (*data[3][i]).clear();
//                    } else {
//                        L->move(3, i, 0, i);
//                        L->destry(3, i);
//                    }
//                    memcpy(keys[0][i], keys[3][i], 16);
//                } else if ((i >= localSize && L->exist[1][i] == false) || (i < localSize && (*data[1][i]).size() == 0)) {
//                    if (i < localSize) {
//                        //                        (*data[1][i]).clear();
//                        //                        (*data[1][i]).insert((*data[3][i]).begin(), (*data[3][i]).end());
//                        //                        (*data[3][i]).clear();
//                        delete data[1][i];
//                        data[1][i] = data[3][i];
//                        data[3][i] = new unordered_map<string, prf_type>();
//                    } else {
//                        L->move(3, i, 1, i);
//                        L->destry(3, i);
//                    }
//                    memcpy(keys[1][i], keys[3][i], 16);
//                } else if ((i >= localSize && L->exist[2][i] == false) || (i < localSize && (*data[2][i]).size() == 0)) {
//                    if (i < localSize) {
//                        //                        (*data[2][i]).clear();
//                        //                        (*data[2][i]).insert((*data[3][i]).begin(), (*data[3][i]).end());
//                        //                        (*data[3][i]).clear();
//                        delete data[2][i];
//                        data[2][i] = data[3][i];
//                        data[3][i] = new unordered_map<string, prf_type>();
//                    } else {
//                        L->move(3, i, 2, i);
//                        L->destry(3, i);
//                    }
//                    memcpy(keys[2][i], keys[3][i], 16);
//                }
//                if (i >= localSize) {
//                    for (int j = 0; j < 16; j++) {
//                        if (setup) {
//                            keys[3][i][j] = 0;
//                        } else {
//                            keys[3][i][j] = (unsigned char) rand() % 256;
//                        }
//                    }
//                }
//            }
//        }
//    }
//
//    prf_type value;
//    std::fill(value.begin(), value.end(), 0);
//    std::copy(keyword.begin(), keyword.end(), value.begin());
//    *(int*) (&(value.data()[AES_KEY_SIZE - 5])) = ind;
//    *(byte*) (&value.data()[AES_KEY_SIZE - 6]) = (byte) (op == OP::INS ? 0 : 1);
//
//    (*data[3][0])[keyword + "-1"] = value;
//
//    if ((*data[0][0]).size() == 0) {
//        //        (*data[0][0]).insert((*data[3][0]).begin(), (*data[3][0]).end());
//        //        (*data[3][0]).clear();
//        delete data[0][0];
//        data[0][0] = data[3][0];
//        data[3][0] = new unordered_map<string, prf_type>();
//    } else if ((*data[1][0]).size() == 0) {
//        //        (*data[1][0]).insert((*data[3][0]).begin(), (*data[3][0]).end());
//        //        (*data[3][0]).clear();
//        delete data[1][0];
//        data[1][0] = data[3][0];
//        data[3][0] = new unordered_map<string, prf_type>();
//    } else {
//        //        (*data[2][0]).insert((*data[3][0]).begin(), (*data[3][0]).end());
//        //        (*data[3][0]).clear();
//        delete data[2][0];
//        data[2][0] = data[3][0];
//        data[3][0] = new unordered_map<string, prf_type>();
//    }
//    if (!setup) {
//        for (int i = 0; i < l; i++) {
//            totalUpdateCommSize += (omaps[i]->treeHandler->oram->totalRead + omaps[i]->treeHandler->oram->totalWrite)*(sizeof (prf_type) + sizeof (int));
//        }
//        totalUpdateCommSize += L->totalCommunication;
//        totalCacheTime += L->server->storage[0]->cacheTime;
//        totalCacheTime += L->server->storage[1]->cacheTime;
//        totalCacheTime += L->server->storage[2]->cacheTime;
//        totalCacheTime += L->server->storage[3]->cacheTime;
//        for (int i = 0; i < l; i++) {
//            totalCacheTime += omaps[i]->treeHandler->oram->store->cacheTime;
//        }
//    }
//}
//
//vector<int> DeAmortizedSDdPlaintext::search(string keyword) {
//    vector<int> finalRes;
//    vector<prf_type> encIndexes;
//    for (int j = 0; j < 3; j++) {
//        for (int i = 0; i < numOfIndices; i++) {
//            if ((*data[j][i]).size() > 0) {
//                int curCounter = 1;
//                bool exist = true;
//                do {
//                    if ((*data[j][i]).count(keyword + "-" + to_string(curCounter)) != 0) {
//                        encIndexes.push_back((*data[j][i])[keyword + "-" + to_string(curCounter)]);
//                        curCounter++;
//                    } else {
//                        exist = false;
//                    }
//                } while (exist);
//            }
//        }
//    }
//
//    map<int, int> remove;
//    for (auto i = encIndexes.begin(); i != encIndexes.end(); i++) {
//        prf_type decodedString = *i;
//        int plaintext = *(int*) (&(decodedString.data()[AES_KEY_SIZE - 5]));
//        remove[plaintext] += (2 * ((byte) decodedString.data()[AES_KEY_SIZE - 6]) - 1);
//    }
//    for (auto const& cur : remove) {
//        if (cur.second < 0) {
//            finalRes.emplace_back(cur.first);
//        }
//    }
//
//    return finalRes;
//}
//
//void DeAmortizedSDdPlaintext::dumpStatus() {
//    ofstream MyFile("StatusAt-" + to_string(updateCounter) + ".txt");
//
//    for (int i = 0; i < 3; i++) {
//        for (int j = 0; j < numOfIndices; j++) {
//
//            auto curData = data[i][j];
//            MyFile << to_string(i) << "," << to_string(j) << "," << to_string(curData->size()) << "," << to_string(cnt[j]) << endl;
//            for (auto item: (*curData)) {
//                string keyword((char*) item.first.data());
//                int index = item.second.first;
//                byte op = item.second.second;
//                MyFile << keyword << endl;
//                MyFile << to_string(index) << endl;
//                MyFile << to_string(op) << endl;
//            }
//        }
//    }
//    MyFile.close();
//}
//
//void DeAmortizedSDdPlaintext::endSetup() {
//    if (!generalSetup) {
//        dumpStatus();
//    }
//}
//
//void DeAmortizedSDdPlaintext::beginSetup() {
//    generalSetup = true;
//}
//
//double DeAmortizedSDdPlaintext::getTotalSearchCommSize() const {
//    return totalSearchCommSize;
//}
//
//double DeAmortizedSDdPlaintext::getTotalUpdateCommSize() const {
//    return totalUpdateCommSize;
//}
//
//bool DeAmortizedSDdPlaintext::setupFromFile(string filename) {
//    return false;
//}
