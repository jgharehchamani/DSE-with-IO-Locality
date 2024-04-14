#include "TwoChoicePPwithStashStorage.h"
#include<string.h>
#include<assert.h>

TwoChoicePPwithStashStorage::TwoChoicePPwithStashStorage(bool inMemory, long dataIndex, string fileAddressPrefix, bool profile) {
    this->inMemoryStorage = inMemory;
    this->fileAddressPrefix = fileAddressPrefix;
    this->dataIndex = dataIndex;
    this->profile = profile;
    memset(nullKey.data(), 0, AES_KEY_SIZE);
    for (long i = 0; i < dataIndex; i++) {
        long curNumberOfBins = i > 3 ? ((long) ceil((float) pow(2, i) / (log2(log2(log2(pow(2, i))))))) : 1;
        curNumberOfBins = pow(2, (long) ceil(log2(curNumberOfBins)));
        long curSizeOfEachBin = i > 3 ? SPACE_OVERHEAD * (log2(log2(log2(pow(2, i)))))
                : SPACE_OVERHEAD * pow(2, i);
        numberOfBins.push_back(curNumberOfBins);
        sizeOfEachBin.push_back(curSizeOfEachBin);
        cout << "TwoChoicePPwithStashStorage Level:" << i << " number of bins:" << curNumberOfBins << " size of each bin:" << curSizeOfEachBin << endl;
    }
}

bool TwoChoicePPwithStashStorage::setup(bool overwrite) {
    if (inMemoryStorage) {
        for (long i = 0; i < dataIndex; i++) {
            vector<prf_type> curData;
            data.push_back(curData);
        }
    } else {
        cuckoofilenames.resize(dataIndex);
        stashfilenames.resize(dataIndex);
        cuckooStashLen.resize(dataIndex);
        for (long i = 0; i < dataIndex; i++) {
            string filename = fileAddressPrefix + "MAP-" + to_string(i) + ".dat";
            filenames.push_back(filename);
            fstream testfile(filename.c_str(), std::ofstream::in);
            if (testfile.fail() || overwrite) {
                testfile.close();
                fstream file(filename.c_str(), std::ofstream::out);
                if (file.fail()) {
                    cerr << "Error: " << strerror(errno);
                }
                long maxSize = numberOfBins[i] * sizeOfEachBin[i];
                for (long j = 0; j < maxSize; j++) {
                    file.write((char*) nullKey.data(), AES_KEY_SIZE);
                }
                file.close();
            }
            string st = fileAddressPrefix + "STASH-" + to_string(i) + ".dat";
            stashes.push_back(st);
            fstream stest(st.c_str(), std::ofstream::in);
            if (stest.fail() || overwrite) {
                stest.close();
                fstream sfile(st.c_str(), std::ofstream::out);
                if (sfile.fail()) {
                    cerr << "Error: " << strerror(errno);
                }
                long maxSize = pow(2, i); //numberOfBins[i] * sizeOfEachBin[i];
                for (long j = 0; j < maxSize; j++) {
                    sfile.write((char*) nullKey.data(), AES_KEY_SIZE);
                }
                sfile.close();
            }
            cuckoofilenames[i].resize(dataIndex);
            stashfilenames[i].resize(dataIndex);
            cuckooStashLen[i].resize(dataIndex);
            for (long k = 0; k < dataIndex; k++) // k < log2(pow(2, dataIndex))
            {
                cuckoofilenames[i][k].resize(2);
                for (long c = 0; c < 2; c++) {
                    string cuckoo = fileAddressPrefix + "CUCKOO-" + to_string(i) + "-" + to_string(k) + "-" + to_string(c) + ".dat";
                    cuckoofilenames[i][k][c] = cuckoo;
                    fstream cfile(cuckoo.c_str(), std::ofstream::in);
                    if (cfile.fail() || overwrite) {
                        cfile.close();
                        fstream c1file(cuckoo.c_str(), std::ofstream::out);
                        if (c1file.fail())
                            cerr << "Error: " << strerror(errno);
                        long maxSize = 2 * pow(2, i); //numberOfBins[i] * sizeOfEachBin[i];
                        for (long j = 0; j < maxSize; j++) {
                            c1file.write((char*) nullKey.data(), AES_KEY_SIZE);
                        }
                        c1file.close();
                    }
                }
                string stashfilename = fileAddressPrefix + "CUCKOOSTASH-" + to_string(i) + "-" + to_string(k) + ".dat";
                stashfilenames[i][k] = stashfilename;
                cuckooStashLen[i][k] = 0;
                fstream tfile(stashfilename.c_str(), std::ofstream::in);
                if (tfile.fail() || overwrite) {
                    tfile.close();
                    fstream sfile(stashfilename.c_str(), std::ofstream::out);
                    if (sfile.fail())
                        cerr << "Error: " << strerror(errno);
                    long maxSize = 2 * pow(2, i); //numberOfBins[i] * sizeOfEachBin[i]; 
                    for (long j = 0; j < maxSize; j++) {
                        sfile.write((char*) nullKey.data(), AES_KEY_SIZE);
                    }
                    sfile.close();
                }
            }
        }
    }
}

pair<prf_type, vector<prf_type>> TwoChoicePPwithStashStorage::insertCuckooHT(long index, long tableNum, long cuckooID, long hash, prf_type keyword, vector<prf_type> fileids) {
    fstream cuckoo(cuckoofilenames[index][tableNum][cuckooID].c_str(),
            ios::binary | ios::out | ios::in);
    cout << "insertCuckooHT:" << cuckoofilenames[index][tableNum][cuckooID].c_str() << endl;
    if (cuckoo.fail())
        cerr << "Error in cuckoo hash table read: " << strerror(errno);

    vector<prf_type> results;
    long entrySize = pow(2, tableNum);
    long readPos = hash * (entrySize + 1) * AES_KEY_SIZE;
    cuckoo.seekg(readPos, ios::beg);
    SeekG++;

    char* oldKey = new char[AES_KEY_SIZE];
    cuckoo.read(oldKey, AES_KEY_SIZE);
    prf_type keyw;
    copy(oldKey + 0, oldKey + AES_KEY_SIZE, keyw.begin());
    delete oldKey;
    readBytes += AES_KEY_SIZE;

    results.resize(entrySize);
    long readLength = entrySize*AES_KEY_SIZE;
    //cout <<"["<<keyw.data()<<"]"<<" " <<"["<<nullKey.data()<<"]"<<endl;
    cuckoo.seekg(readPos + AES_KEY_SIZE, ios::beg); //cuckoo.seekg(AES_KEY_SIZE, ios::cur);
    if (keyw != nullKey) {
        char* keyValues = new char[readLength];
        cuckoo.read(keyValues, readLength);
        readBytes += readLength;
        for (long i = 0; i < entrySize; i++) {
            prf_type tmp;
            std::copy(keyValues + i*AES_KEY_SIZE, keyValues + i * AES_KEY_SIZE + AES_KEY_SIZE, tmp.begin());
            //if (tmp != nullKey)
            //{
            results.push_back(tmp);
            //}
        }
    } else {
        cuckoo.clear();
        long readPos = hash * (entrySize + 1) * AES_KEY_SIZE;
        cuckoo.seekg(readPos, ios::beg);
        SeekG++;
        unsigned char newRecord[AES_KEY_SIZE];
        memset(newRecord, 0, AES_KEY_SIZE);
        std::copy(keyword.begin(), keyword.end(), newRecord);
        cuckoo.write((char*) newRecord, AES_KEY_SIZE);
        for (auto c : fileids) {
            memset(newRecord, 0, AES_KEY_SIZE);
            std::copy(c.begin(), c.end(), newRecord);
            cuckoo.write((char*) newRecord, AES_KEY_SIZE);
        }
    }
    cuckoo.close();
    auto result = make_pair(keyw, results);
    return result;
}

void TwoChoicePPwithStashStorage::insertCuckooStash(long index, long tableNum, vector<prf_type> ctCiphers) {
    fstream file(stashfilenames[index][tableNum].c_str(), ios::binary | ios::out | ios::ate);
    if (file.fail())
        cerr << "(Error in Cuckoo Stash insert: " << strerror(errno) << ")" << endl;
    cuckooStashLen[index][tableNum] = cuckooStashLen[index][tableNum] + ctCiphers.size();
    for (auto item : ctCiphers) {
        unsigned char newRecord[AES_KEY_SIZE];
        memset(newRecord, 0, AES_KEY_SIZE);
        std::copy(item.begin(), item.end(), newRecord);
        file.write((char*) newRecord, AES_KEY_SIZE);
    }
    file.close();
}

void TwoChoicePPwithStashStorage::insertStash(long index, vector<prf_type> ciphers) {
    fstream file(stashes[index].c_str(), ios::binary | ios::out);
    if (file.fail()) {
        cout << "StashXX:" << index << endl;
        cerr << "(Error in Stash insert: " << strerror(errno) << ")" << endl;
    }
    for (auto item : ciphers) {
        unsigned char newRecord[AES_KEY_SIZE];
        memset(newRecord, 0, AES_KEY_SIZE);
        std::copy(item.begin(), item.end(), newRecord);
        file.write((char*) newRecord, AES_KEY_SIZE);
    }
    file.close();
}

vector<prf_type> TwoChoicePPwithStashStorage::getStash(long index) {
    vector<prf_type> results;
    fstream file(stashes[index].c_str(), ios::binary | ios::in | ios::ate);
    if (file.fail())
        cerr << "Error in read: " << strerror(errno);
    if (Utilities::DROP_CACHE) {
        Utilities::startTimer(113);
        if (KERNEL_CACHE)system("echo 3 | sudo tee /proc/sys/vm/drop_caches");
        auto t = Utilities::stopTimer(113);
        printf("drop cache time:%f\n", t);
        cacheTime += t;
    }
    long size = file.tellg();
    file.seekg(0, ios::beg);
    SeekG++;
    char* keyValues = new char[size];
    file.read(keyValues, size);
    file.close();

    for (long i = 0; i < size / AES_KEY_SIZE; i++) {
        prf_type tmp;
        std::copy(keyValues + i*AES_KEY_SIZE, keyValues + i * AES_KEY_SIZE + AES_KEY_SIZE, tmp.begin());
        if (tmp != nullKey) {
            results.push_back(tmp);
        }
    }
    delete keyValues;
    return results;
}

vector<prf_type> TwoChoicePPwithStashStorage::getCuckooHT(long index) {
    vector<prf_type> results;
    for (long tn = 0; tn < index; tn++) {
        for (long c = 0; c < 2; c++) {
            fstream cuckoo(cuckoofilenames[index][tn][c].c_str(), ios::binary | ios::in | ios::ate);
            if (cuckoo.fail())
                cerr << "Error in read: " << strerror(errno);
            long entryNum = pow(2, (index - tn));
            long entrySize = pow(2, tn);
            if (Utilities::DROP_CACHE) {
                Utilities::startTimer(113);
                if (KERNEL_CACHE)system("echo 3 | sudo tee /proc/sys/vm/drop_caches");
                auto t = Utilities::stopTimer(113);
                printf("drop cache time:%f\n", t);
                cacheTime += t;
            }
            long size = cuckoo.tellg();
            cuckoo.seekg(0, ios::beg);
            SeekG++;
            char* keyValues = new char[size];
            cuckoo.read(keyValues, size);
            for (long e = 0; e < entryNum; e++) {
                for (long es = 0; es <= entrySize; es++) // one extra entry for the keyword
                {
                    prf_type entry;
                    //std::copy(keyValues+(e+1)*es*AES_KEY_SIZE, 
                    //		keyValues+(e+1)*es*AES_KEY_SIZE+AES_KEY_SIZE, entry.begin());
                    std::copy(keyValues + e * es*AES_KEY_SIZE,
                            keyValues + e * es * AES_KEY_SIZE + AES_KEY_SIZE, entry.begin());
                    if (es != 0 && entry != nullKey) {
                        results.push_back(entry);
                    }
                    if (es == 0 && entry != nullKey)
                        cout << "cuckoo key(encrypted):[" << entry.data() << "]" << endl;
                }
            }
            delete keyValues;
            cuckoo.close();
        }
        fstream file(stashfilenames[index][tn].c_str(), ios::binary | ios::in | ios::ate);
        if (file.fail())
            cerr << "Error in read: " << strerror(errno);
        if (Utilities::DROP_CACHE) {
            Utilities::startTimer(113);
            if (KERNEL_CACHE)system("echo 3 | sudo tee /proc/sys/vm/drop_caches");
            auto t = Utilities::stopTimer(113);
            printf("drop cache time:%f\n", t);
            cacheTime += t;
        }
        //        long size = file.tellg();
        long size = cuckooStashLen[index][tn];
        file.seekg(0, ios::beg);
        SeekG++;
        char* keyValues = new char[size];
        file.read(keyValues, size);
        file.close();
        for (long i = 0; i < size / AES_KEY_SIZE; i++) {
            prf_type tmp;
            std::copy(keyValues + i*AES_KEY_SIZE, keyValues + i * AES_KEY_SIZE + AES_KEY_SIZE, tmp.begin());
            if (tmp != nullKey)
                results.push_back(tmp);
        }
        delete keyValues;
    }
    return results;
}

void TwoChoicePPwithStashStorage::insertAll(long index, vector<vector< prf_type > > ciphers, bool append, bool firstRun) {
    if (inMemoryStorage) {
        for (auto item : ciphers) {
            data[index].insert(data[index].end(), item.begin(), item.end());
        }
    } else {
        if (USE_XXL) {
            //            for (auto item : ciphers) {
            //                for (auto pair : item) {
            //                    diskData[index]->push_back(pair);
            //                }
            //
            //            }
        } else {
            if (append && !firstRun) {
                fstream file(filenames[index].c_str(), ios::binary | std::ios::app);
                if (file.fail()) {
                    cerr << "Error in insert: " << strerror(errno);
                }
                for (auto item : ciphers) {
                    for (auto pair : item) {
                        file.write((char*) pair.data(), AES_KEY_SIZE);
                    }
                }
                file.close();
            } else {
                fstream file(filenames[index].c_str(), ios::binary | ios::out);
                if (file.fail()) {
                    cerr << "Error in insert: " << strerror(errno);
                }
                for (auto item : ciphers) {
                    for (auto pair : item) {
                        file.write((char*) pair.data(), AES_KEY_SIZE);
                    }
                }
                file.close();
            }
        }
    }
}

vector<prf_type> TwoChoicePPwithStashStorage::getAllData(long index) {
    if (inMemoryStorage) {
        return data[index];
    } else {
        vector<prf_type> results;
        fstream file(filenames[index].c_str(), ios::binary | ios::in | ios::ate);
        if (file.fail()) {
            cerr << "Error in read: " << strerror(errno);
        }
        long size = file.tellg();
        if (Utilities::DROP_CACHE) {
            Utilities::startTimer(113);
            if (KERNEL_CACHE)system("echo 3 | sudo tee /proc/sys/vm/drop_caches");
            auto t = Utilities::stopTimer(113);
            printf("drop cache time:%f\n", t);
            cacheTime += t;
        }
        file.seekg(0, ios::beg);
        char* keyValues = new char[size];
        file.read(keyValues, size);
        file.close();

        for (long i = 0; i < size / AES_KEY_SIZE; i++) {
            prf_type tmp;
            std::copy(keyValues + i*AES_KEY_SIZE, keyValues + i * AES_KEY_SIZE + AES_KEY_SIZE, tmp.begin());
            //            std::copy(keyValues + i * KEY_VALUE_SIZE + AES_KEY_SIZE, keyValues + i * KEY_VALUE_SIZE + AES_KEY_SIZE + AES_KEY_SIZE, restmp.begin());
            //            if (tmp != nullKey) //dummy added to fillup bins 
            //            {
            results.push_back(tmp);
            //            }
        }
        delete keyValues;
        return results;
    }
}

void TwoChoicePPwithStashStorage::clear(long index) {
    if (inMemoryStorage)
        data[index].clear();
    else {
        fstream file(filenames[index].c_str(), std::ios::binary | std::ofstream::out);
        if (file.fail()) {
            cerr << "Error: " << strerror(errno);
        }
        long maxSize = numberOfBins[index] * sizeOfEachBin[index];
        for (long j = 0; j < maxSize; j++) {
            file.write((char*) nullKey.data(), AES_KEY_SIZE);
        }
        file.close();
        fstream sfile(stashes[index].c_str(), std::ios::binary | std::ofstream::out);
        if (sfile.fail()) {
            cerr << "Error: " << strerror(errno);
        }
        maxSize = pow(2, index);
        for (long j = 0; j < maxSize; j++) {
            sfile.write((char*) nullKey.data(), AES_KEY_SIZE);
        }
        sfile.close();
        for (long k = 0; k < index; k++) {
            fstream sfile(stashfilenames[index][k].c_str(), std::ios::binary | std::ofstream::out);
            if (sfile.fail()) {
                cerr << "Error: " << strerror(errno);
            }
            long maxSize = 2 * pow(2, index);
            for (long j = 0; j < maxSize; j++) {
                sfile.write((char*) nullKey.data(), AES_KEY_SIZE);
            }
            sfile.close();
            cuckooStashLen[index][k] = 0;
        }
        for (long k = 0; k < index; k++) {
            for (long c = 0; c < 2; c++) {
                fstream sfile(cuckoofilenames[index][k][c].c_str(), std::ios::binary | std::ofstream::out);
                if (sfile.fail()) {
                    cerr << "Error: " << strerror(errno);
                }
                long maxSize = 2 * pow(2, index);
                for (long j = 0; j < maxSize; j++) {
                    sfile.write((char*) nullKey.data(), AES_KEY_SIZE);
                }
                sfile.close();
            }
        }
    }
}

TwoChoicePPwithStashStorage::~TwoChoicePPwithStashStorage() {
}

vector <prf_type> TwoChoicePPwithStashStorage::cuckooSearch(long index, long tableNum, long h[2]) {
    vector<prf_type> results;
    //results.resize(0);
    for (long c = 0; c < 2; c++) {
        std::fstream cuckoo(cuckoofilenames[index][tableNum][c].c_str(), ios::binary | ios::in | ios::ate);
        if (cuckoo.fail())
            cerr << "Error in read: " << strerror(errno);
        long entrySize = pow(2, tableNum);
        long readPos = h[c]*(entrySize + 1) * AES_KEY_SIZE;
        readPos = readPos + AES_KEY_SIZE;
        long readLength = entrySize*AES_KEY_SIZE;
        if (Utilities::DROP_CACHE) {
            Utilities::startTimer(113);
            if (KERNEL_CACHE)system("echo 3 | sudo tee /proc/sys/vm/drop_caches");
            auto t = Utilities::stopTimer(113);
            printf("drop cache time:%f\n", t);
            cacheTime += t;
        }
        cuckoo.seekg(readPos, ios::beg);
        SeekG++;
        char* keyValues = new char[readLength];
        cuckoo.read(keyValues, readLength);
        readBytes += readLength;

        for (long i = 0; i < entrySize; i++) {
            prf_type tmp;
            std::copy(keyValues + i*AES_KEY_SIZE, keyValues + i * AES_KEY_SIZE + AES_KEY_SIZE, tmp.begin());
            if (tmp != nullKey) {
                results.push_back(tmp);
                cout << "cuckoo result SIZE:" << results.size() << endl;
            }
        }
        cuckoo.close();
    }
    fstream file(stashfilenames[index][tableNum].c_str(), ios::binary | ios::in | ios::ate);
    if (file.fail()) {
        cerr << "Error in read: " << strerror(errno);
    }
    long size = file.tellg();
    if (Utilities::DROP_CACHE) {
        Utilities::startTimer(113);
        if (KERNEL_CACHE)system("echo 3 | sudo tee /proc/sys/vm/drop_caches");
        auto t = Utilities::stopTimer(113);
        printf("drop cache time:%f\n", t);
        cacheTime += t;
    }
    file.seekg(0, ios::beg);
    SeekG++;
    char* keyValues = new char[size];
    file.read(keyValues, size);
    file.close();
    readBytes += size;
    for (long i = 0; i < size / AES_KEY_SIZE; i++) {
        prf_type tmp;
        std::copy(keyValues + i*AES_KEY_SIZE, keyValues + i * AES_KEY_SIZE + AES_KEY_SIZE, tmp.begin());
        if (tmp != nullKey) {
            results.push_back(tmp);
        }
    }
    delete keyValues;
    return results;
}

vector<prf_type> TwoChoicePPwithStashStorage::find(long index, prf_type mapKey, long cnt) {
    vector<prf_type> results;
    std::fstream file(filenames[index].c_str(), ios::binary | ios::in);
    if (file.fail())
        cerr << "Error in read: " << strerror(errno);
    unsigned char* hash = Utilities::sha256((char*) mapKey.data(), AES_KEY_SIZE);
    if (cnt >= numberOfBins[index]) {
        //read everything
        long fileLength = numberOfBins[index] * sizeOfEachBin[index] * AES_KEY_SIZE;
        char* keyValues = new char[fileLength];
        if (Utilities::DROP_CACHE) {
            Utilities::startTimer(113);
            if (KERNEL_CACHE)system("echo 3 | sudo tee /proc/sys/vm/drop_caches");
            auto t = Utilities::stopTimer(113);
            printf("drop cache time:%f\n", t);
            cacheTime += t;
        }
        file.read(keyValues, fileLength);
        SeekG++;
        readBytes += fileLength;
        for (long i = 0; i < numberOfBins[index] * sizeOfEachBin[index]; i++) {
            prf_type tmp;
            std::copy(keyValues + i*AES_KEY_SIZE, keyValues + i * AES_KEY_SIZE + AES_KEY_SIZE, tmp.begin());
            //            std::copy(keyValues + i * AES_KEY_SIZE + AES_KEY_SIZE, keyValues + i * AES_KEY_SIZE + (2 * AES_KEY_SIZE), restmp.begin());
            //            if (restmp != nullKey) {
            results.push_back(tmp);
            //            }
        }
    } else {
        long superBins = ceil((float) numberOfBins[index] / cnt);
        long pos = (unsigned long) (*((long*) hash)) % superBins; //numberOfBins[index];
        long readPos = pos * cnt * AES_KEY_SIZE * sizeOfEachBin[index];
        long fileLength = numberOfBins[index] * sizeOfEachBin[index] * AES_KEY_SIZE;
        long remainder = fileLength - readPos;
        long totalReadLength = cnt * AES_KEY_SIZE * sizeOfEachBin[index];
        long readLength = 0;
        if (totalReadLength > remainder) {
            readLength = remainder;
            totalReadLength -= remainder;
        } else {
            readLength = totalReadLength;
            totalReadLength = 0;
        }
        if (Utilities::DROP_CACHE) {
            Utilities::startTimer(113);
            if (KERNEL_CACHE)system("echo 3 | sudo tee /proc/sys/vm/drop_caches");
            auto t = Utilities::stopTimer(113);
            printf("drop cache time:%f\n", t);
            cacheTime += t;
        }
        file.seekg(readPos, ios::beg);
        SeekG++;
        char* keyValues = new char[readLength];
        file.read(keyValues, readLength);
        readBytes += readLength;
        for (long i = 0; i < readLength / AES_KEY_SIZE; i++) {
            prf_type tmp;
            std::copy(keyValues + i * AES_KEY_SIZE, keyValues + i * AES_KEY_SIZE + AES_KEY_SIZE, tmp.begin());
            results.push_back(tmp);
        }
        if (totalReadLength > 0) {
            readLength = totalReadLength;
            if (Utilities::DROP_CACHE) {
                Utilities::startTimer(113);
                if (KERNEL_CACHE)system("echo 3 | sudo tee /proc/sys/vm/drop_caches");
                auto t = Utilities::stopTimer(113);
                printf("drop cache time:%f\n", t);
                cacheTime += t;
            }
            file.seekg(0, ios::beg);
            char* keyValues = new char[readLength];
            file.read(keyValues, readLength);
            readBytes += readLength;
            SeekG++;
            for (long i = 0; i < readLength / AES_KEY_SIZE; i++) {
                prf_type tmp;
                std::copy(keyValues + i * AES_KEY_SIZE, keyValues + i * AES_KEY_SIZE + AES_KEY_SIZE, tmp.begin());
                results.push_back(tmp);
            }
        }
    }
    file.close();
    return results;
}


