#include "StorageSDDPiBAS.h"
#include "assert.h"
#include <iostream>
#include <cstdio>

StorageSDDPiBAS::StorageSDDPiBAS(bool inMemory, long dataIndex, string fileAddressPrefix, bool profile) {
    this->inMemoryStorage = inMemory;
    this->fileAddressPrefix = fileAddressPrefix;
    this->dataIndex = dataIndex;
    this->profile = profile;
    memset(nullKey.data(), 0, AES_KEY_SIZE);
}

bool StorageSDDPiBAS::isInCache(long index, long pos) {
    long levelSize = pow(2, index + 1);
    long threshold = floor(levelSize * Utilities::CACHE_PERCENTAGE);
    if (pos < threshold) {
        return true;
    } else {
        return false;
    }
}

bool StorageSDDPiBAS::setup(bool overwrite) {
    for (long i = 0; i < dataIndex; i++) {
        sizes.push_back(0);
        tails.push_back(0);
        string filename = fileAddressPrefix + "MAP-" + to_string(i) + ".dat";
        filenames.push_back(filename);
        fstream testfile(filename.c_str(), std::ofstream::in);
        if (testfile.fail() || overwrite) {
            testfile.close();
            long maxSize = pow(2, i + 1); //double the size                                                                                              
            long alloc_size = KEY_VALUE_SIZE * maxSize;
            while (alloc_size > 0) {
                long bs = min(alloc_size, 2147483648);
                string command = string("dd if=/dev/zero bs=" + to_string(bs) + " count=1 status=none >> " + filename);
//                cout << "command:" << command << endl;
                system(command.c_str());
                alloc_size -= bs;
            }
            //            fstream file(filename.c_str(), std::ofstream::out);
            //            if (file.fail()) {
            //                cerr << "Error: " << strerror(errno);
            //            }
            //            long maxSize = pow(2, i + 1); //double the size
            //            //                system(("dd if=/dev/zero of=" + filename + " bs=" + to_string(maxSize * KEY_VALUE_SIZE) + " count=1; sync").c_str());
            //            long nextPtr = 0;
            //            //                file.seekp(maxSize * KEY_VALUE_SIZE);
            //            //                file.seekp(0);
            //            for (long j = 0; j < maxSize; j++) {
            //                file.write((char*) nullKey.data(), AES_KEY_SIZE);
            //                file.write((char*) nullKey.data(), AES_KEY_SIZE);
            //                file.write((char*) &nextPtr, sizeof (long));
            //                file.write((char*) &nextPtr, sizeof (long));
            //            }
            //            file.close();
        }
        FILE* file = fopen(filename.c_str(), "rb+");
        filehandles.push_back(file);
        data.push_back(vector<pair<prf_type, prf_type> >());
    }

}

void StorageSDDPiBAS::insert(long dataIndex, map<prf_type, prf_type> ciphers, bool setupMode) {
    if (setupMode) {
        long maxSize = pow(2, dataIndex + 1);
        //    FILE* file = fopen(filenames[dataIndex].c_str(), "rb+");
        FILE* file = filehandles[dataIndex];
        char* wholeFile = new char[maxSize * KEY_VALUE_SIZE];
        fseek(file, 0, SEEK_SET);
        fread(wholeFile, KEY_VALUE_SIZE*maxSize, 1, file);

        int tmpCounter = 0;
        auto item = ciphers.begin();
        for (int k = 0; k < ciphers.size(); k++) {
            unsigned char newRecord[KEY_VALUE_SIZE];
            memset(newRecord, 0, KEY_VALUE_SIZE);
            std::copy(item->first.begin(), item->first.end(), newRecord);
            std::copy(item->second.begin(), item->second.end(), newRecord + AES_KEY_SIZE);
            long nextPos = 0;
            memcpy(&newRecord[2 * AES_KEY_SIZE], &nextPos, sizeof (long));
            if (sizes[dataIndex] != 0) {
                long lasttail = tails[dataIndex];
                memcpy(&newRecord[2 * AES_KEY_SIZE + sizeof (long)], &lasttail, sizeof (long));
            }

            unsigned char* hash = Utilities::sha256((char*) item->first.data(), AES_KEY_SIZE);
            long pos = (unsigned long) (*((long*) hash)) % maxSize;
            //            fseek(file, pos*KEY_VALUE_SIZE, SEEK_SET);
            char chainHead[KEY_VALUE_SIZE];
            //            fread(chainHead, KEY_VALUE_SIZE, 1, file);

            memcpy(chainHead, &wholeFile[pos * KEY_VALUE_SIZE], KEY_VALUE_SIZE);

            prf_type tmp;
            std::copy(chainHead, chainHead + AES_KEY_SIZE, tmp.begin());
            int cnt = 1;
            while (tmp != nullKey && cnt < maxSize) {
                long oldPos = pos;
                pos = (pos + 1) % maxSize;
                cnt++;
                //                fseek(file, pos*KEY_VALUE_SIZE, SEEK_SET);
                //                fread(chainHead, KEY_VALUE_SIZE, 1, file);
                //                std::copy(chainHead, chainHead + AES_KEY_SIZE, tmp.begin());

                memcpy(chainHead, &wholeFile[pos * KEY_VALUE_SIZE], KEY_VALUE_SIZE);
                std::copy(chainHead, chainHead + AES_KEY_SIZE, tmp.begin());
            }
            if (cnt == maxSize) {
                cout << "DANGER" << endl;
                cerr << "Error in insert (space crunch): " << strerror(errno);
            }
            if (tmp == nullKey) {
                //                fseek(file, pos*KEY_VALUE_SIZE, SEEK_SET);
                //                fwrite((char*) newRecord, KEY_VALUE_SIZE, 1, file);
                memcpy(&wholeFile[pos * KEY_VALUE_SIZE], newRecord, KEY_VALUE_SIZE);
            }
            tails[dataIndex] = pos*KEY_VALUE_SIZE;
            sizes[dataIndex]++;
            item++;
        }
        fseek(file, 0, SEEK_SET);
        fwrite((char*) wholeFile, maxSize* KEY_VALUE_SIZE, 1, file);
        fflush(file);
        delete wholeFile;

    } else {
        long maxSize = pow(2, dataIndex + 1);
        //    FILE* file = fopen(filenames[dataIndex].c_str(), "rb+");
        FILE* file = filehandles[dataIndex];
        auto item = ciphers.begin();
        for (int k = 0; k < ciphers.size(); k++) {
            unsigned char newRecord[KEY_VALUE_SIZE];
            memset(newRecord, 0, KEY_VALUE_SIZE);
            std::copy(item->first.begin(), item->first.end(), newRecord);
            std::copy(item->second.begin(), item->second.end(), newRecord + AES_KEY_SIZE);
            long nextPos = 0;
            memcpy(&newRecord[2 * AES_KEY_SIZE], &nextPos, sizeof (long));
            if (sizes[dataIndex] != 0) {
                long lasttail = tails[dataIndex];
                memcpy(&newRecord[2 * AES_KEY_SIZE + sizeof (long)], &lasttail, sizeof (long));
            }

            unsigned char* hash = Utilities::sha256((char*) item->first.data(), AES_KEY_SIZE);
            long pos = (unsigned long) (*((long*) hash)) % maxSize;
            if (Utilities::DROP_CACHE && !setupMode) {
                Utilities::startTimer(113);
                if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
                if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
                auto t = Utilities::stopTimer(113);
                cacheTime += t;
            }
            fseek(file, pos*KEY_VALUE_SIZE, SEEK_SET);
            char chainHead[KEY_VALUE_SIZE];
            fread(chainHead, KEY_VALUE_SIZE, 1, file);
            prf_type tmp;
            std::copy(chainHead, chainHead + AES_KEY_SIZE, tmp.begin());
            int cnt = 1;
            while (tmp != nullKey && cnt < maxSize) {
                long oldPos = pos;
                pos = (pos + 1) % maxSize;
                cnt++;
                if (Utilities::DROP_CACHE && !setupMode) {
                    Utilities::startTimer(113);
                    if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
                    if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
                    auto t = Utilities::stopTimer(113);
                    cacheTime += t;
                }
                fseek(file, pos*KEY_VALUE_SIZE, SEEK_SET);
                fread(chainHead, KEY_VALUE_SIZE, 1, file);
                std::copy(chainHead, chainHead + AES_KEY_SIZE, tmp.begin());
            }
            if (cnt == maxSize) {
                cout << "DANGER" << endl;
                cerr << "Error in insert (space crunch): " << strerror(errno);
            }
            if (tmp == nullKey) {
                if (Utilities::DROP_CACHE && !setupMode) {
                    Utilities::startTimer(113);
                    if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
                    if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
                    auto t = Utilities::stopTimer(113);
                    cacheTime += t;
                }
                fseek(file, pos*KEY_VALUE_SIZE, SEEK_SET);
                fwrite((char*) newRecord, KEY_VALUE_SIZE, 1, file);
            }
            tails[dataIndex] = pos*KEY_VALUE_SIZE;
            sizes[dataIndex]++;
            item++;
        }
        fflush(file);
        if (Utilities::DROP_CACHE && !setupMode) {
            Utilities::startTimer(113);
            if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
            if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
            auto t = Utilities::stopTimer(113);
            cacheTime += t;
        }
    }
    //    fclose(file);
}

void StorageSDDPiBAS::resetup(long index) {
    sizes[index] = 0;
    tails[index] = 0;
    string filename = filenames[index];
    //    fstream file(filename.c_str(), std::ofstream::out);
    //    if (file.fail()) {
    //        cerr << "Error: " << strerror(errno);
    //    }
    //    long maxSize = pow(2, index + 1); //double the size
    //    //                system(("dd if=/dev/zero of=" + filename + " bs=" + to_string(maxSize * KEY_VALUE_SIZE) + " count=1; sync").c_str());
    //    long nextPtr = 0;
    //    if (Utilities::DROP_CACHE && !setupMode) {
    //        Utilities::startTimer(113);
    //        if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
    //        if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
    //        auto t = Utilities::stopTimer(113);
    //        cacheTime += t;
    //    }
    //    //    file.seekp(maxSize * KEY_VALUE_SIZE - (AES_KEY_SIZE + AES_KEY_SIZE + sizeof (long) + sizeof (long)));
    //    file.seekp(0);
    //    for (long j = 0; j < maxSize; j++) {
    //        file.write((char*) nullKey.data(), AES_KEY_SIZE);
    //        file.write((char*) nullKey.data(), AES_KEY_SIZE);
    //        file.write((char*) &nextPtr, sizeof (long));
    //        file.write((char*) &nextPtr, sizeof (long));
    //    }
    //    file.close();
    string command = string("dd if=/dev/zero bs=1 count=1 status=none > " + filename);
    system(command.c_str());

    long maxSize = pow(2, index + 1); //double the size                                                                                              
    long alloc_size = KEY_VALUE_SIZE * maxSize;
    while (alloc_size > 0) {
        long bs = min(alloc_size, 2147483648);
        command = string("dd if=/dev/zero bs=" + to_string(bs) + " count=1 status=none >> " + filename);
        system(command.c_str());
        alloc_size -= bs;
    }

    filehandles[index] = fopen(filename.c_str(), "rb+");
}

void StorageSDDPiBAS::closeHandle(long index) {
    fflush(filehandles[index]);
    fclose(filehandles[index]);
}

void StorageSDDPiBAS::rename(long toIndex, string inputFileName, long size, long tail) {
    fclose(filehandles[toIndex]);
    if (std::rename(inputFileName.c_str(), filenames[toIndex].c_str()) != 0) {
        perror("Error renaming file");
    } else {
        this->sizes[toIndex] = size;
        this->tails[toIndex] = tail;
        filehandles[toIndex] = fopen(filenames[toIndex].c_str(), "rb+");
    }
}

string StorageSDDPiBAS::getName(long dataIndex) {
    return filenames[dataIndex];
}

pair<prf_type, prf_type> StorageSDDPiBAS::getPos(long dataIndex, int pos) {
    //    FILE* file = fopen(filenames[dataIndex].c_str(), "rb+");
    FILE* file = filehandles[dataIndex];
    if (file == NULL) {
        cerr << "Error in insert: " << strerror(errno);
    }
    long lasttail = tails[dataIndex];
    for (int i = sizes[dataIndex] - 1; i > pos; i--) {
        long p = lasttail;
        if (Utilities::DROP_CACHE && !setupMode) {
            Utilities::startTimer(113);
            if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
            if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
            auto t = Utilities::stopTimer(113);
            cacheTime += t;
        }
        fseek(file, p, SEEK_SET);
        char chainHead[KEY_VALUE_SIZE];
        fread(chainHead, KEY_VALUE_SIZE, 1, file);
        lasttail = *((long*) (chainHead + KEY_VALUE_SIZE - sizeof (long)));
    }

    long p = lasttail;
    if (Utilities::DROP_CACHE && !setupMode) {
        Utilities::startTimer(113);
        if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
        if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
        auto t = Utilities::stopTimer(113);
        cacheTime += t;
    }
    fseek(file, p, SEEK_SET);
    char chainHead[KEY_VALUE_SIZE];
    fread(chainHead, KEY_VALUE_SIZE, 1, file);
    prf_type key, value;
    std::copy(chainHead, chainHead + AES_KEY_SIZE, key.begin());
    std::copy(chainHead + AES_KEY_SIZE, chainHead + AES_KEY_SIZE + AES_KEY_SIZE, value.begin());

    //    fclose(file);
    return pair<prf_type, prf_type>(key, value);
}

vector<prf_type> StorageSDDPiBAS::getAllData(long dataIndex) {
    vector<prf_type> results;
    if (inMemoryStorage) {
        for (auto item : data[dataIndex]) {
            results.push_back(item.second);
        }
    } else {
        //        fstream file(filenames[dataIndex].c_str(), ios::binary | ios::in | ios::ate);
        FILE* file = filehandles[dataIndex];
        //        if (file.fail()) {
        //            cerr << "Error in read: " << strerror(errno);
        //        }
        fseek(file, 0L, SEEK_END);
        long size = ftell(file);
        if (Utilities::DROP_CACHE) {
            Utilities::startTimer(113);
            if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
            if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
            auto t = Utilities::stopTimer(113);
            cacheTime += t;
        }
        fseek(file, 0L, SEEK_SET);
        char* keyValue = new char[size];
        fread(keyValue, size, 1, file);

        for (long i = 0; i < size / KEY_VALUE_SIZE; i++) {
            prf_type tmp, restmp;
            std::copy(keyValue + i*KEY_VALUE_SIZE, keyValue + i * KEY_VALUE_SIZE + AES_KEY_SIZE, tmp.begin());
            std::copy(keyValue + i * KEY_VALUE_SIZE + AES_KEY_SIZE, keyValue + i * KEY_VALUE_SIZE + AES_KEY_SIZE + AES_KEY_SIZE, restmp.begin());
            if (tmp != nullKey) {
                results.push_back(restmp);
            }
        }

        //        file.close();
        delete keyValue;
        return results;
    }
    return results;
}

void StorageSDDPiBAS::clear(long index) {
    //        fstream file(filenames[index].c_str(), std::ios::binary | std::ofstream::out);
    FILE* file = filehandles[index];
    //        if (file.fail()) {
    //            cerr << "Error: " << strerror(errno);
    //        }
    fseek(file, 0L, SEEK_SET);
    long maxSize = pow(2, index + 1);
    //        system(("dd if=/dev/zero of=" + filenames[index] + " bs=" + to_string(maxSize * KEY_VALUE_SIZE) + " count=1; sync").c_str());
    long nextPtr = 0;
    for (long j = 0; j < maxSize; j++) {
        //            file.write((char*) nullKey.data(), AES_KEY_SIZE);
        //            file.write((char*) nullKey.data(), AES_KEY_SIZE);
        //            file.write((char*) &nextPtr, sizeof (long));
        //            file.write((char*) &nextPtr, sizeof (long));
        fwrite((char*) nullKey.data(), AES_KEY_SIZE, 1, file);
        fwrite((char*) nullKey.data(), AES_KEY_SIZE, 1, file);
        fwrite((char*) &nextPtr, sizeof (long), 1, file);
        fwrite((char*) &nextPtr, sizeof (long), 1, file);
    }
    fflush(file);
    if (Utilities::DROP_CACHE && !setupMode) {
        Utilities::startTimer(113);
        if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
        if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
        auto t = Utilities::stopTimer(113);
        cacheTime += t;
    }
    //        file.close();
    sizes[index] = 0;
    tails[index] = 0;

}

StorageSDDPiBAS::~StorageSDDPiBAS() {
    for (int i = 0; i < dataIndex; i++) {
        fclose(filehandles[i]);
    }
}

prf_type StorageSDDPiBAS::find(long index, prf_type mapKey, bool& found) {
    Utilities::startTimer(124);
    auto previousCacheTime = cacheTime;
    prf_type result;
    FILE* file;
    if (Utilities::useRandomFolder) {
        file = fopen(filenames[index].c_str(), "rb+");
    } else {
        file = filehandles[index];
    }
    if (file == NULL)
        cerr << "Error in read: " << strerror(errno);
    unsigned char* hash = Utilities::sha256((char*) mapKey.data(), AES_KEY_SIZE);
    long maxSize = pow(2, index + 1);
    char chainHead[KEY_VALUE_SIZE];
    if (profile)
        seekgCount++;
    int cnt = 0;
    prf_type tmp;
    long pos;
    pos = (unsigned long) (*((long*) hash + cnt)) % maxSize;
    long bytesRead;
    do {
        cnt++;
        if (isInCache(index, pos)) {
            memcpy(chainHead, data[index][pos].first.begin(), AES_KEY_SIZE);
            memcpy(chainHead + AES_KEY_SIZE, data[index][pos].second.begin(), AES_KEY_SIZE);
        } else {
            if (Utilities::DROP_CACHE && !setupMode) {
                Utilities::startTimer(113);
                if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
                if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
                auto t = Utilities::stopTimer(113);
                cacheTime += t;
            }
            fseek(file, pos*KEY_VALUE_SIZE, SEEK_SET);
            fread(chainHead, KEY_VALUE_SIZE, 1, file);
        }
        std::copy(chainHead, chainHead + AES_KEY_SIZE, tmp.begin());
        prf_type restmp;
        std::copy(chainHead + AES_KEY_SIZE, chainHead + (2 * AES_KEY_SIZE), restmp.begin());
        if (tmp == mapKey) {
            found = true;
            getCounterTime = Utilities::stopTimer(124) - (cacheTime - previousCacheTime);
            if (Utilities::useRandomFolder) {
                fclose(file);
            }
            return restmp;
        }
        pos = (pos + 1) % maxSize;
    } while (tmp != nullKey && cnt < maxSize);

    found = false;
    getCounterTime = Utilities::stopTimer(124) - (cacheTime - previousCacheTime);
    if (Utilities::useRandomFolder) {
        fclose(file);
    }
    return nullKey;
}

void StorageSDDPiBAS::loadCache() {
    if (Utilities::CACHE_PERCENTAGE == 0) {
        return;
    }
    for (long index = 0; index < dataIndex; index++) {
        long levelSize = pow(2, index + 1);
        long size = floor(levelSize * Utilities::CACHE_PERCENTAGE);
        FILE* file = filehandles[index];
        if (file == NULL) {
            cerr << "Error in read: " << strerror(errno);
        }
        fseek(file, 0L, SEEK_SET);

        char* keyValue = new char[size * KEY_VALUE_SIZE];
        fread(keyValue, size*KEY_VALUE_SIZE, 1, file);

        for (long i = 0; i < size; i++) {
            prf_type key, value;
            std::copy(keyValue + i*KEY_VALUE_SIZE, keyValue + i * KEY_VALUE_SIZE + AES_KEY_SIZE, key.begin());
            std::copy(keyValue + i * KEY_VALUE_SIZE + AES_KEY_SIZE, keyValue + i * KEY_VALUE_SIZE + AES_KEY_SIZE + AES_KEY_SIZE, value.begin());
            data[index].push_back(pair<prf_type, prf_type>(key, value));
        }

        delete keyValue;
    }
}