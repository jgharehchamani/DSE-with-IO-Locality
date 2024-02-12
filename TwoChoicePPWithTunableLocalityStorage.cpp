#include "TwoChoicePPWithTunableLocalityStorage.h"
#include<string.h>
#include<assert.h>
#include "Utilities.h"

TwoChoicePPWithTunableLocalityStorage::TwoChoicePPWithTunableLocalityStorage(bool inMemory, long dataIndex, string fileAddressPrefix, bool profile) {
    this->inMemoryStorage = inMemory;
    this->fileAddressPrefix = fileAddressPrefix;
    this->dataIndex = dataIndex;
    this->profile = profile;
    memset(nullKey.data(), 0, AES_KEY_SIZE);
    for (long i = 0; i < dataIndex; i++) {
        long curNumberOfBins = i > 3 ? ((long) ceil((float) pow(2, i) / (log2(log2(log2(pow(2, i))))))) : 1;
        curNumberOfBins = pow(2, (long) ceil(log2(curNumberOfBins)));
        long curSizeOfEachBin = i > 3 ? SPACE_OVERHEAD * ((log2(log2(log2(pow(2, i)))))) : SPACE_OVERHEAD * pow(2, i);
        numberOfBins.push_back(curNumberOfBins);
        sizeOfEachBin.push_back(curSizeOfEachBin);
        cout << "Level:" << i << " number of bins:" << curNumberOfBins << " size of each bin:" << curSizeOfEachBin << endl;
    }
    cout << "----------------------------------------------------------" << endl;
}

bool TwoChoicePPWithTunableLocalityStorage::setup(bool overwrite) {
    cuckoofilenames.resize(dataIndex);
    cuckooStashfilenames.resize(dataIndex);
    cuckooStashLength.resize(dataIndex);
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
        cuckoofilenames[i].resize(dataIndex);
        cuckooStashfilenames[i].resize(dataIndex);
        cuckooStashLength[i].resize(dataIndex);
        for (long k = 0; k < dataIndex; k++) {
            cuckoofilenames[i][k].resize(2);
            for (long c = 0; c < 2; c++) {
                string cuckoo = fileAddressPrefix + "CUCKOO-" + to_string(i) + "-" +
                        to_string(k) + "-" + to_string(c) + ".dat";
                cuckoofilenames[i][k][c] = cuckoo;
                fstream cfile(cuckoo.c_str(), std::ofstream::in);
                if (cfile.fail() || overwrite) {
                    cfile.close();
                    fstream c1file(cuckoo.c_str(), std::ofstream::out);
                    if (c1file.fail())
                        cerr << "Error: " << strerror(errno);
                    long maxSize = 2 * pow(2, i);
                    for (long j = 0; j < maxSize; j++)
                        c1file.write((char*) nullKey.data(), AES_KEY_SIZE);
                    c1file.close();
                }
            }
            string cuckooStashfilename = fileAddressPrefix + "CUCKOOSTASH-"
                    + to_string(i) + "-" + to_string(k) + ".dat";
            cuckooStashfilenames[i][k] = cuckooStashfilename;
            fstream tfile(cuckooStashfilename.c_str(), std::ofstream::in);
            if (tfile.fail() || overwrite) {
                tfile.close();
                fstream sfile(cuckooStashfilename.c_str(), std::ofstream::out);
                if (sfile.fail())
                    cerr << "Error: " << strerror(errno);
                long maxSize = 2 * pow(2, i); //cuckooStashLength[i][k]; 
                for (long j = 0; j < maxSize; j++)
                    sfile.write((char*) nullKey.data(), AES_KEY_SIZE);
                sfile.close();
                cuckooStashLength[i][k] = 0;
            }
        }
    }
}

void TwoChoicePPWithTunableLocalityStorage::insertAll(int index, vector<vector<prf_type>> ciphers, bool append, bool firstRun) {
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

pair<prf_type, vector<prf_type>> TwoChoicePPWithTunableLocalityStorage::insertCuckooHT(long index, long tableNum, long cuckooID, long hash, prf_type keyword, vector<prf_type> fileids) {
    fstream cuckoo(cuckoofilenames[index][tableNum][cuckooID].c_str(),
            ios::binary | ios::out | ios::in);
    if (cuckoo.fail())
        cerr << "Error in cuckoo hash table read: " << strerror(errno);

    vector<prf_type> results;
    long entrySize = pow(2, tableNum);
    long readPos = hash * (entrySize + 1) * AES_KEY_SIZE;
    if (Utilities::DROP_CACHE) {
        Utilities::startTimer(113);
        if (KERNEL_CACHE)system("echo 3 | sudo tee /proc/sys/vm/drop_caches");
        auto t = Utilities::stopTimer(113);
        printf("drop cache time:%f\n", t);
        cacheTime += t;
    }
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
    if (Utilities::DROP_CACHE) {
        Utilities::startTimer(113);
        if (KERNEL_CACHE)system("echo 3 | sudo tee /proc/sys/vm/drop_caches");
        auto t = Utilities::stopTimer(113);
        printf("drop cache time:%f\n", t);
        cacheTime += t;
    }
    cuckoo.seekg(readPos + AES_KEY_SIZE, ios::beg); //cuckoo.seekg(AES_KEY_SIZE, ios::cur);
    if (keyw != nullKey) {
        char* keyValues = new char[readLength];
        cuckoo.read(keyValues, readLength);
        readBytes += readLength;
        for (long i = 0; i < entrySize; i++) {
            prf_type tmp;
            std::copy(keyValues + i*AES_KEY_SIZE, keyValues + i * AES_KEY_SIZE + AES_KEY_SIZE, tmp.begin());
            results.push_back(tmp);
        }
    } else {
        cuckoo.clear();
        long readPos = hash * (entrySize + 1) * AES_KEY_SIZE;
        if (Utilities::DROP_CACHE) {
            Utilities::startTimer(113);
            if (KERNEL_CACHE)system("echo 3 | sudo tee /proc/sys/vm/drop_caches");
            auto t = Utilities::stopTimer(113);
            printf("drop cache time:%f\n", t);
            cacheTime += t;
        }
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

void TwoChoicePPWithTunableLocalityStorage::insertCuckooStash(long index, long tableNum, vector<prf_type> ctCiphers) {
    fstream file(cuckooStashfilenames[index][tableNum].c_str(), ios::binary | ios::out | ios::ate);
    if (file.fail())
        cerr << "(Error in Cuckoo Stash insert: " << strerror(errno) << ")" << endl;

    int readPos = cuckooStashLength[index][tableNum] * AES_KEY_SIZE;
    if (Utilities::DROP_CACHE) {
        Utilities::startTimer(113);
        if (KERNEL_CACHE)system("echo 3 | sudo tee /proc/sys/vm/drop_caches");
        auto t = Utilities::stopTimer(113);
        printf("drop cache time:%f\n", t);
        cacheTime += t;
    }
    file.seekg(readPos, ios::beg);
    SeekG++;
    cuckooStashLength[index][tableNum] = cuckooStashLength[index][tableNum] + ctCiphers.size();

    for (auto item : ctCiphers) {
        unsigned char newRecord[AES_KEY_SIZE];
        memset(newRecord, 0, AES_KEY_SIZE);
        std::copy(item.begin(), item.end(), newRecord);
        file.write((char*) newRecord, AES_KEY_SIZE);
    }
    file.close();
}

vector<prf_type> TwoChoicePPWithTunableLocalityStorage::getCuckooHT(long index) {
    vector<prf_type> results;
    for (long tn = 0; tn < index; tn++) {
        for (long c = 0; c < 2; c++) {
            fstream cuckoo(cuckoofilenames[index][tn][c].c_str(), ios::binary | ios::in | ios::ate);
            if (cuckoo.fail())
                cerr << "Error in getCuckooHT read: " << strerror(errno);
            long entryNum = pow(2, (index - tn));
            long entrySize = pow(2, tn);
            long size = cuckoo.tellg();
            if (Utilities::DROP_CACHE) {
                Utilities::startTimer(113);
                if (KERNEL_CACHE)system("echo 3 | sudo tee /proc/sys/vm/drop_caches");
                auto t = Utilities::stopTimer(113);
                printf("drop cache time:%f\n", t);
                cacheTime += t;
            }
            cuckoo.seekg(0, ios::beg);
            SeekG++;
            char* keyValues = new char[size];
            cuckoo.read(keyValues, size);
            for (long e = 0; e < entryNum; e++) {
                for (long es = 0; es <= entrySize; es++) // one extra entry for the keyword
                {
                    prf_type entry;
                    std::copy(keyValues + e * es*AES_KEY_SIZE,
                            keyValues + e * es * AES_KEY_SIZE + AES_KEY_SIZE, entry.begin());
                    if (es != 0 && entry != nullKey) {
                        results.push_back(entry);
                    }
                    //if(es == 0)
                    //	cout <<"cuckoo key(encrypted):["<<entry.data()<<"]"<<endl;
                }
            }
            delete keyValues;
            cuckoo.close();
        }
        fstream file(cuckooStashfilenames[index][tn].c_str(), ios::binary | ios::in | ios::ate);
        if (file.fail())
            cerr << "Error in cuckooStash read: " << strerror(errno);
        //long size = file.tellg();
        long size = cuckooStashLength[index][tn];
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
        for (long i = 0; i < size / AES_KEY_SIZE; i++) {
            prf_type tmp;
            std::copy(keyValues + i*AES_KEY_SIZE, keyValues + i * AES_KEY_SIZE + AES_KEY_SIZE, tmp.begin());
            results.push_back(tmp);
        }
        delete keyValues;
    }
    return results;
}

void TwoChoicePPWithTunableLocalityStorage::insertAll(long index, vector<vector< prf_type > > ciphers) {
    fstream file(filenames[index].c_str(), ios::binary | ios::out);
    if (file.fail()) {
        cout << "XX:" << index << endl;
        cerr << "(Error in insertALL: " << strerror(errno) << ")" << endl;
    }
    for (auto item : ciphers) {
        for (auto pair : item) {
            unsigned char newRecord[AES_KEY_SIZE];
            memset(newRecord, 0, AES_KEY_SIZE);
            std::copy(pair.begin(), pair.end(), newRecord);
            file.write((char*) newRecord, AES_KEY_SIZE);
        }
    }
    file.close();
}

vector<prf_type> TwoChoicePPWithTunableLocalityStorage::getAllData(long index) {
    vector<prf_type> results;
    fstream file(filenames[index].c_str(), ios::binary | ios::in | ios::ate);
    if (file.fail()) {
        cerr << "Error in getAllData read: " << strerror(errno);
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
        results.push_back(tmp);
    }
    delete keyValues;
    return results;
}

void TwoChoicePPWithTunableLocalityStorage::clear(long index) {
    if (inMemoryStorage)
        data[index].clear();
    else {
        fstream file(filenames[index].c_str(), std::ios::binary | std::ofstream::out);
        if (file.fail())
            cerr << "Error: " << strerror(errno);
        long maxSize = numberOfBins[index] * sizeOfEachBin[index];
        for (long j = 0; j < maxSize; j++) {
            file.write((char*) nullKey.data(), AES_KEY_SIZE);
        }
        file.close();
        for (long k = 0; k < index; k++) {
            fstream sfile(cuckooStashfilenames[index][k].c_str(), std::ios::binary | std::ofstream::out);
            if (sfile.fail())
                cerr << "Error: " << strerror(errno);
            long maxSize = cuckooStashLength[index][k];
            for (long j = 0; j < maxSize; j++)
                sfile.write((char*) nullKey.data(), AES_KEY_SIZE);
            sfile.close();
            cuckooStashLength[index][k] = 0;

        }
        for (long k = 0; k < index; k++) {
            for (long c = 0; c < 2; c++) {
                fstream sfile(cuckoofilenames[index][k][c].c_str(),
                        std::ios::binary | std::ofstream::out);
                if (sfile.fail())
                    cerr << "Error: " << strerror(errno);
                long maxSize = 2 * pow(2, index);
                for (long j = 0; j < maxSize; j++)
                    sfile.write((char*) nullKey.data(), AES_KEY_SIZE);
                sfile.close();
            }
        }
    }
}

TwoChoicePPWithTunableLocalityStorage::~TwoChoicePPWithTunableLocalityStorage() {
}

vector <prf_type> TwoChoicePPWithTunableLocalityStorage::cuckooSearch(long index, long tableNum, long h[2]) {
    vector<prf_type> results;
    //results.resize(0);
    for (long c = 0; c < 2; c++) {
        std::fstream cuckoo(cuckoofilenames[index][tableNum][c].c_str(), ios::binary | ios::in | ios::ate);
        if (cuckoo.fail())
            cerr << "Error in cuckooSearch read: " << strerror(errno);
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
            if (tmp != nullKey) //**PLEASE DONT REMOVE THIS LINE
                results.push_back(tmp);
        }
        cuckoo.close();
    }
    fstream file(cuckooStashfilenames[index][tableNum].c_str(), ios::binary | ios::in | ios::ate);
    if (file.fail())
        cerr << "Error in cuckoo Stash read: " << strerror(errno);
    //long size = file.tellg();
    long size = cuckooStashLength[index][tableNum];
    //cout <<"CUCKOO_STASH SIZE:"<<cuckooStashLength[index][tableNum]<<endl;
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
        results.push_back(tmp);
    }
    delete keyValues;
    return results;
}

vector<prf_type> TwoChoicePPWithTunableLocalityStorage::find(long index, prf_type mapKey, long cnt) {
    vector<prf_type> results;
    std::fstream file(filenames[index].c_str(), ios::binary | ios::in);
    if (file.fail())
        cerr << "Error in read in find: " << strerror(errno);
    unsigned char* hash = Utilities::sha256((char*) mapKey.data(), AES_KEY_SIZE);
    if (cnt >= numberOfBins[index]) {
        long fileLength = numberOfBins[index] * sizeOfEachBin[index] * AES_KEY_SIZE;
        char* keyValues = new char[fileLength];
        file.read(keyValues, fileLength);
        SeekG++;
        readBytes += fileLength;
        for (long i = 0; i < numberOfBins[index] * sizeOfEachBin[index]; i++) {
            prf_type restmp;
            std::copy(keyValues + i * AES_KEY_SIZE, keyValues + i * AES_KEY_SIZE + AES_KEY_SIZE, restmp.begin());
            results.push_back(restmp);
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
            prf_type tmp, restmp;
            std::copy(keyValues + i * AES_KEY_SIZE,
                    keyValues + i * AES_KEY_SIZE + AES_KEY_SIZE, restmp.begin());
            results.push_back(restmp);
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
                prf_type tmp, restmp;
                std::copy(keyValues + i * AES_KEY_SIZE,
                        keyValues + i * AES_KEY_SIZE + AES_KEY_SIZE, restmp.begin());
                results.push_back(restmp);
            }
        }
    }
    file.close();
    return results;
}

