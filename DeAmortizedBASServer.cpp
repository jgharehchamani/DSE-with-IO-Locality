#include "DeAmortizedBASServer.h"
#include <string.h>
#include "AES.hpp"
#include "StorageSDDPiBAS.h"

DeAmortizedBASServer::DeAmortizedBASServer(int dataIndex, bool inMemory, bool overwrite, bool profile) {
    //    if (hdd) {
    storage = new StorageSDDPiBAS*[4];
    storage[0] = new StorageSDDPiBAS(inMemory, dataIndex, Utilities::rootAddress + "ins1-", profile);
    storage[0]->setup(overwrite);
    storage[1] = new StorageSDDPiBAS(inMemory, dataIndex, Utilities::rootAddress + "ins2-", profile);
    storage[1]->setup(overwrite);
    storage[2] = new StorageSDDPiBAS(inMemory, dataIndex, Utilities::rootAddress + "ins3-", profile);
    storage[2]->setup(overwrite);
    storage[3] = new StorageSDDPiBAS(inMemory, dataIndex, Utilities::rootAddress + "ins4-", profile);
    storage[3]->setup(overwrite);
    //    } else {
    for (int j = 0; j < 4; j++) {
        data.push_back(vector<EachSet*>());
        for (int i = 0; i < dataIndex; i++) {
            EachSet* curData = new EachSet();
            data[j].push_back(curData);
        }
    }
    //    }
}

DeAmortizedBASServer::~DeAmortizedBASServer() {
}

void DeAmortizedBASServer::storeCiphers(int instance, int dataIndex, map<prf_type, prf_type> ciphers, bool setupMode) {
    if (hdd) {
        storage[instance]->insert(dataIndex, ciphers, setupMode);
    } else {
        data[instance][dataIndex]->setData.insert(ciphers.begin(), ciphers.end());
    }


}

//void DeAmortizedBASServer::storeCiphers(long instance, long dataIndex, vector<pair<pair<prf_type, prf_type>, pair<long, long> > > ciphers, long tail, long size) {
//    if (hdd) {
//        storage[instance]->insertAll(dataIndex, ciphers, tail, size);
//    } else {
//        cout << "has to be implemented" << endl;
//    }
//}

vector<prf_type> DeAmortizedBASServer::search(int instance, int dataIndex, prf_type token) {
    vector<prf_type> results;
    bool exist = false;
    double serverSearchTime = 0;
    int cnt = 1;
    do {
        if (cnt % 100 == 0) {
            cout << "searching for:" << cnt << endl;
        }
        prf_type curToken = token, mapKey;
        unsigned char cntstr[AES_KEY_SIZE];
        memset(cntstr, 0, AES_KEY_SIZE);
        *(int*) (&(cntstr[AES_KEY_SIZE - 5])) = cnt;
        mapKey = Utilities::generatePRF(cntstr, curToken.data());
        if (hdd) {
            bool found = false;
            if (profile) {
                Utilities::startTimer(45);
            }
            prf_type res = storage[instance]->find(dataIndex, mapKey, found);
            if (profile) {
                serverSearchTime += Utilities::stopTimer(45);
            }
            if (found) {
                results.push_back(res);
                cout << "instance:" << instance << " level:" << dataIndex << endl;
                exist = true;
                cnt++;
            } else {
                exist = false;
            }
        } else {


            if (data[instance][dataIndex]->setData.count(mapKey) != 0) {
                results.push_back(data[instance][dataIndex]->setData[mapKey]);
                exist = true;
                cnt++;
            } else {
                exist = false;
            }
        }
    } while (exist);
    return results;
}

//vector<pair<pair<prf_type, prf_type>, pair<long, long> > > DeAmortizedBASServer::getAllDataForCopy(int instance, int dataIndex, long& tail, long& size) {
//    if (hdd) {
//        return storage[instance]->getAllDataForCopy(dataIndex, tail, size);
//    }
//}

vector<prf_type> DeAmortizedBASServer::getAllData(int instance, int dataIndex) {
    if (hdd) {
        return storage[instance]->getAllData(dataIndex);
    } else {
        vector<prf_type> results;
        for (auto item : data[instance][dataIndex]->setData) {
            results.push_back(item.second);
        }
        return results;
    }
}

void DeAmortizedBASServer::clear(int instance, int index) {
    if (hdd) {
        storage[instance]->clear(index);
    } else {

        data[instance][index] = new EachSet();
    }
}

void DeAmortizedBASServer::move(int fromInstance, int fromIndex, int toInstance, int toIndex) {
    if (hdd) {
        string inputFileName = storage[fromInstance]->getName(fromIndex);
        storage[fromInstance]->closeHandle(fromIndex);
        storage[toInstance]->rename(toIndex, inputFileName, storage[fromInstance]->sizes[fromIndex], storage[fromInstance]->tails[fromIndex]);
        storage[fromInstance]->resetup(fromIndex);
    } else {
        delete data[toInstance][toIndex];
        data[toInstance][toIndex] = data[fromInstance][fromIndex];
        data[fromInstance][fromIndex] = new EachSet();
    }
}

int DeAmortizedBASServer::size(int instance, int index) {
    if (hdd) {
        //        cout<<"ins:"<<instance<<" index:"<<index<<" size:"<<storage[instance]->size<<endl;
        return storage[instance]->sizes[index];
    } else {
        //        cout<<"ins:"<<instance<<" index:"<<index<<" size:"<<data[instance][index]->setData.size()<<endl;
        return data[instance][index]->setData.size();
    }


}

prf_type DeAmortizedBASServer::get(int instance, int index, int pos) {
    if (hdd) {
        pair<prf_type, prf_type> res = storage[instance]->getPos(index, pos);
        //        printf("get %d %d to instance:%d index:%d\n",res.first[0],res.first[1],instance,index);
        return res.second;
    } else {
        auto iter = data[instance][index]->setData.begin();
        for (int i = 0; i < pos; i++) {
            iter++;
        }
        //        printf("get %d %d to instance:%d index:%d\n",(*iter).first[0],(*iter).first[1],instance,index);
        return (*iter).second;
    }
}

void DeAmortizedBASServer::add(int instance, int index, pair<prf_type, prf_type> keyValue) {
    //    printf("add %d %d to instance:%d index:%d\n",keyValue.first[0],keyValue.first[1],instance,index);
    if (hdd) {
        map<prf_type, prf_type> ciphers;
        ciphers[keyValue.first] = keyValue.second;
        storage[instance]->insert(index, ciphers);
    } else {
        data[instance][index]->setData[keyValue.first] = keyValue.second;
    }


}

void DeAmortizedBASServer::beginSetup() {
    storage[0]->setupMode = true;
    storage[1]->setupMode = true;
    storage[2]->setupMode = true;
    storage[3]->setupMode = true;
    hdd = false;
}

void DeAmortizedBASServer::endSetup(bool overwrite) {
    hdd = true;
    if (overwrite) {
        for (int j = 0; j < 4; j++) {
            for (int i = 0; i < data[j].size(); i++) {
                cout << "inserting instance:" << j << "/4 index:" << i << "/" << data[j].size() << endl;
                map<prf_type, prf_type> ciphers;
                ciphers.insert(data[j][i]->setData.begin(), data[j][i]->setData.end());
                storage[j]->insert(i, ciphers, true);
            }
        }
    }
    storage[0]->setupMode = false;
    storage[1]->setupMode = false;
    storage[2]->setupMode = false;
    storage[3]->setupMode = false;

    storage[0]->loadCache();
    storage[1]->loadCache();
    storage[2]->loadCache();
    storage[3]->loadCache();
}
