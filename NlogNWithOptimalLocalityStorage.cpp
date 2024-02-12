#include "NlogNWithOptimalLocalityStorage.h"
#include<string.h>

NlogNWithOptimalLocalityStorage::NlogNWithOptimalLocalityStorage(bool inMemory, long dataIndex, string fileAddressPrefix, bool profile) {
    this->inMemoryStorage = inMemory;
    this->fileAddressPrefix = fileAddressPrefix;
    this->dataIndex = dataIndex;
    this->profile = profile;
    memset(nullKey.data(), 0, AES_KEY_SIZE);
}

bool NlogNWithOptimalLocalityStorage::setup(bool overwrite) {
    filenames.resize(dataIndex);
    for (long i = 0; i < dataIndex; i++) {
        filenames[i].resize(S);
        long p = ceil((float) i / (float) S);
        if (p == 0)
            p = 1;
        for (long j = i, loop = S - 1; j >= 0 && loop >= 0; j = j - p, loop--) {
            string filename = fileAddressPrefix + "MAP-" + to_string(i) + "-" + to_string(j) + ".dat";
            //cout <<"index:"<<i<<" j:"<<j<<" loop:"<<loop<<" p:"<<p<<endl;
            filenames[i][loop] = filename;
            fstream testfile(filename.c_str(), std::ofstream::in);
            if (testfile.fail() || overwrite) {
                testfile.close();
                fstream file(filename.c_str(), std::ofstream::out);
                if (file.fail()) {
                    cerr << "Error: " << strerror(errno);
                }
                long maxSize = 2 * pow(2, i) + pow(2, j + 1);
                for (long k = 0; k < maxSize; k++) {
                    file.write((char*) nullKey.data(), AES_KEY_SIZE);
                }
                file.close();
            }
        }
    }
}

void NlogNWithOptimalLocalityStorage::insertAll(long index, long instance, vector<vector< prf_type>> ciphers, bool append, bool firstRun) {
    if (append && !firstRun) {
        fstream file(filenames[index][instance].c_str(), ios::binary | std::ios::app);
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
        fstream file(filenames[index][instance].c_str(), ios::binary | ios::out);
        //cout<<"["<<filenames[index][instance].c_str()<<"]"<<endl;
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

/*
vector<prf_type> NlogNWithOptimalLocalityStorage::getAllData(long index, long instance) 
{
    vector<prf_type> results;
        fstream file(filenames[index][instance].c_str(), ios::binary | ios::in | ios::ate);
        if (file.fail()) 
            cerr << "Error in read: " << strerror(errno);

        long size = file.tellg();
        if (Utilities::DROP_CACHE) 
        {
            Utilities::startTimer(113);
            if(KERNEL_CACHE)system("echo 3 | sudo tee /proc/sys/vm/drop_caches");
            auto t = Utilities::stopTimer(113);
            //printf("drop cache time:%f\n", t);
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
 */

vector<prf_type> NlogNWithOptimalLocalityStorage::getAllData(long index) {
    vector<prf_type> results;
    long i = 0;
    long p = ceil((float) index / (float) S);
    if (p == 0)
        p = 1;
    for (long level = index, i = S - 1; level >= 0 && i >= 0; level = level - p, i--) {
        fstream file(filenames[index][i].c_str(), ios::binary | ios::in | ios::ate);
        if (file.fail()) {
            cerr << "Error in read: " << strerror(errno);
        }
        long size = file.tellg();
        if (Utilities::DROP_CACHE) {
            Utilities::startTimer(113);
            if (KERNEL_CACHE)system("echo 3 | sudo tee /proc/sys/vm/drop_caches");
            auto t = Utilities::stopTimer(113);
            //printf("drop cache time:%f\n", t);
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
    }
    return results;
}

void NlogNWithOptimalLocalityStorage::clear(long index) {
    long p = ceil((float) index / (float) S);
    for (long instance = index, loop = S - 1; instance >= 0 && loop >= 0; instance = instance - p, loop--) {
        fstream file(filenames[index][loop].c_str(), std::ios::binary | std::ofstream::out);
        if (file.fail())
            cerr << "Error: " << strerror(errno);
        long maxSize = 2 * pow(2, index) + pow(2, instance + 1);
        for (long j = 0; j < maxSize; j++) {
            file.write((char*) nullKey.data(), AES_KEY_SIZE);
        }
        file.close();
    }
}

NlogNWithOptimalLocalityStorage::~NlogNWithOptimalLocalityStorage() {
}

vector<prf_type> NlogNWithOptimalLocalityStorage::find(long index, long level, long instance, prf_type mapKey, long cnt, long attempt) {
    vector<prf_type> results;
    std::fstream file(filenames[index][instance].c_str(), ios::binary | ios::in);
    if (file.fail())
        cerr << "Error in read: " << strerror(errno);
    unsigned char* hash = Utilities::sha256((char*) mapKey.data(), AES_KEY_SIZE);
    long numberOfEntries = (float) (2 * pow(2, index) + pow(2, level + 1)) / (float) pow(2, level);
    long pos = (((unsigned long) (*((long*) hash)) % numberOfEntries) + attempt) % numberOfEntries;
    long readPos = pos * AES_KEY_SIZE * pow(2, level);
    long readLength = pow(2, level) * AES_KEY_SIZE;
    if (Utilities::DROP_CACHE) {
        Utilities::startTimer(113);
        if (KERNEL_CACHE)system("echo 3 | sudo tee /proc/sys/vm/drop_caches");
        auto t = Utilities::stopTimer(113);
        cacheTime += t;
    }
    file.seekg(readPos, ios::beg);
    SeekG++;
    char* keyValues = new char[readLength];
    file.read(keyValues, readLength);
    readBytes += readLength;
    for (long i = 0; i < readLength / AES_KEY_SIZE; i++) {
        prf_type tmp;
        std::copy(keyValues + i*AES_KEY_SIZE, keyValues + i * AES_KEY_SIZE + AES_KEY_SIZE, tmp.begin());
        results.push_back(tmp);
    }
    file.close();
    return results;
}
