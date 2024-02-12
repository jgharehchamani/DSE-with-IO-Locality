#include "Storage.h"
#include "assert.h"

Storage::Storage(bool inMemory, long dataIndex, string fileAddressPrefix, bool profile) {
    this->inMemoryStorage = inMemory;
    this->fileAddressPrefix = fileAddressPrefix;
    this->dataIndex = dataIndex;
    this->profile = profile;
    memset(nullKey.data(), 0, AES_KEY_SIZE);
}

bool Storage::isInCache(long index, long pos) {
    long levelSize = pow(2, index + 1);
    long threshold = floor(levelSize * CACHE_PERCENTAGE);
    if (pos < threshold) {
        return true;
    } else {
        return false;
    }
}

bool Storage::setup(bool overwrite) {
    for (long i = 0; i < dataIndex; i++) {
        string filename = fileAddressPrefix + "MAP-" + to_string(i) + ".dat";
        filenames.push_back(filename);
        //fstream testfile(filename.c_str(), std::ofstream::in);            
        FILE* testfile = fopen(filename.c_str(), "rb");
        if (testfile == NULL || overwrite) {
            //testfile.close();
            //				fclose(testfile);                
            long maxSize = pow(2, i + 1); //double the size                                                                                              
            long alloc_size = ((long) 2 * AES_KEY_SIZE + sizeof (long)) * maxSize;
            while (alloc_size > 0) {
                long bs = min(alloc_size, 2147483648);
                string command = string("dd if=/dev/zero bs=" + to_string(bs) + " count=1 >> " + filename);
                cout << "command:" << command << endl;
                system(command.c_str());
                alloc_size -= bs;
            }
            //                FILE* file = fopen(filename.c_str(), "wb");
            //                if (file == NULL) {
            //                    cerr << "Error: " << strerror(errno);
            //                }
            //                long maxSize = pow(2, i + 1); //double the size
            //                long nextPtr = 0;
            //                for (long j = 0; j < maxSize; j++) {                    
            //                    fwrite((char*) nullKey.data(), AES_KEY_SIZE, 1, file);
            //                    fwrite((char*) nullKey.data(), AES_KEY_SIZE, 1, file);
            //                    fwrite((char*) &nextPtr, sizeof (long), 1, file);
            //                }                
            //                fclose(file);
        }
        FILE* file = fopen(filename.c_str(), "rb+");
        filehandles.push_back(file);
        data.push_back(vector<pair<prf_type, prf_type> >());
    }
}

bool Storage::setup(bool overwrite, int index) {

    for (long i = 0; i < dataIndex; i++) {
        string filename = fileAddressPrefix + "MAP-" + to_string(i) + ".dat";
        filenames.push_back(filename);
        //fstream testfile(filename.c_str(), std::ofstream::in);
        if (index == i) {
            FILE* testfile = fopen(filename.c_str(), "rb");
            if (testfile == NULL || overwrite) {
                //testfile.close();
                //				fclose(testfile);
                //fstream file(filename.c_str(), std::ofstream::out);
                FILE* file = fopen(filename.c_str(), "wb");
                if (file == NULL) {
                    cerr << "Error: " << strerror(errno);
                }
                long maxSize = pow(2, i + 1); //double the size
                long nextPtr = 0;
                for (long j = 0; j < maxSize; j++) {
                    /*file.write((char*) nullKey.data(), AES_KEY_SIZE);
                    file.write((char*) nullKey.data(), AES_KEY_SIZE);
                    file.write((char*) &nextPtr, sizeof (long));*/
                    fwrite((char*) nullKey.data(), AES_KEY_SIZE, 1, file);
                    fwrite((char*) nullKey.data(), AES_KEY_SIZE, 1, file);
                    fwrite((char*) &nextPtr, sizeof (long), 1, file);
                }
                //file.write((char*) &nextPtr, sizeof (long));
                //file.close();
                fclose(file);
            }
        }
        FILE* file = fopen(filename.c_str(), "rb+");
        filehandles.push_back(file);
    }
}

void Storage::loadCache() {
    if (CACHE_PERCENTAGE == 0) {
        return;
    }
    for (long index = 0; index < dataIndex; index++) {
        long levelSize = pow(2, index + 1);
        long size = floor(levelSize * CACHE_PERCENTAGE);
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

void Storage::insert(long dataIndex, map<prf_type, prf_type> ciphers, bool setupMode, bool firstInsert) {
    long maxSize = pow(2, dataIndex + 1);
    //fstream file(filenames[dataIndex].c_str(), ios::binary | ios::in | ios::out | ios::ate);
    //    FILE* file = fopen(filenames[dataIndex].c_str(), "rb+");
    if (setupMode) {
        FILE* file = filehandles[dataIndex];
        if (file == NULL) {
            cerr << "Error in insert: " << strerror(errno);
        }
        char* wholeFile = new char[maxSize * KEY_VALUE_SIZE];
        if (!firstInsert) {
            fseek(file, 0, SEEK_SET);
            fread(wholeFile, KEY_VALUE_SIZE*maxSize, 1, file);
        } else {
            memset(wholeFile, 0, maxSize * KEY_VALUE_SIZE);
        }

        int tmpCounter = 0;
        for (auto item : ciphers) {
            if (tmpCounter % 100000 == 0) {
                cout << "inserted " << tmpCounter << "/" << ciphers.size() << endl;
            }
            unsigned char newRecord[KEY_VALUE_SIZE];
            memset(newRecord, 0, KEY_VALUE_SIZE);
            std::copy(item.first.begin(), item.first.end(), newRecord);
            std::copy(item.second.begin(), item.second.end(), newRecord + AES_KEY_SIZE);
            long nextPos = 0;
            memcpy(&newRecord[2 * AES_KEY_SIZE], &nextPos, sizeof (long));

            unsigned char* hash = Utilities::sha256((char*) item.first.data(), AES_KEY_SIZE);
            long pos = (unsigned long) (*((long*) hash)) % maxSize;

            char chainHead[KEY_VALUE_SIZE];
            memcpy(chainHead, &wholeFile[pos * KEY_VALUE_SIZE], KEY_VALUE_SIZE);
            prf_type tmp;
            std::copy(chainHead, chainHead + AES_KEY_SIZE, tmp.begin());
            int cnt = 1;
            while (tmp != nullKey && cnt < maxSize) {
                long oldPos = pos;
                pos = (pos + 1) % maxSize;
                cnt++;
                memcpy(chainHead, &wholeFile[pos * KEY_VALUE_SIZE], KEY_VALUE_SIZE);
                std::copy(chainHead, chainHead + AES_KEY_SIZE, tmp.begin());
            }
            if (cnt == maxSize) {
                cout << "DANGER" << endl;
                cerr << "Error in insert (space crunch): " << strerror(errno);
            }
            if (tmp == nullKey) {
                memcpy(&wholeFile[pos * KEY_VALUE_SIZE], newRecord, KEY_VALUE_SIZE);
            }
            //cout<<endl;
            tmpCounter++;
        }
        fseek(file, 0, SEEK_SET);
        fwrite((char*) wholeFile, maxSize* KEY_VALUE_SIZE, 1, file);
        fflush(file);
        delete wholeFile;
        //	file.close();
        //    fclose(file);
    } else {
        FILE* file = filehandles[dataIndex];
        if (file == NULL) {
            cerr << "Error in insert: " << strerror(errno);
        }
        for (auto item : ciphers) {
            unsigned char newRecord[KEY_VALUE_SIZE];
            memset(newRecord, 0, KEY_VALUE_SIZE);
            std::copy(item.first.begin(), item.first.end(), newRecord);
            std::copy(item.second.begin(), item.second.end(), newRecord + AES_KEY_SIZE);
            long nextPos = 0;
            memcpy(&newRecord[2 * AES_KEY_SIZE], &nextPos, sizeof (long));

            unsigned char* hash = Utilities::sha256((char*) item.first.data(), AES_KEY_SIZE);
            long pos = (unsigned long) (*((long*) hash)) % maxSize;
            //file.seekg(pos * KEY_VALUE_SIZE, ios::beg);
            if (Utilities::DROP_CACHE && !setupMode) {
                Utilities::startTimer(113);
                if (HDD_CACHE)system("sudo hdparm -A 0 /dev/sda >/dev/null 2>&1");
                if (KERNEL_CACHE)system("echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null 2>&1");
                auto t = Utilities::stopTimer(113);
                cacheTime += t;
                //            cout << "cache time:" << t << endl;
            }
            fseek(file, pos*KEY_VALUE_SIZE, SEEK_SET);
            char chainHead[KEY_VALUE_SIZE];
            //file.read(chainHead, KEY_VALUE_SIZE);
            fread(chainHead, KEY_VALUE_SIZE, 1, file);
            prf_type tmp;
            std::copy(chainHead, chainHead + AES_KEY_SIZE, tmp.begin());
            int cnt = 1;
            while (tmp != nullKey && cnt < maxSize) {
                long oldPos = pos;
                pos = (pos + 1) % maxSize;
                //cout <<"{"<<oldPos<<"-"<<pos<<"}";
                cnt++;
                //file.seekg(pos*KEY_VALUE_SIZE, ios::beg);
                if (Utilities::DROP_CACHE && !setupMode) {
                    Utilities::startTimer(113);
                    if (HDD_CACHE)system("sudo hdparm -A 0 /dev/sda >/dev/null 2>&1");
                    if (KERNEL_CACHE)system("echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null 2>&1");
                    auto t = Utilities::stopTimer(113);
                    cacheTime += t;
                    //            cout << "cache time:" << t << endl;
                }
                fseek(file, pos*KEY_VALUE_SIZE, SEEK_SET);
                //file.read(chainHead, KEY_VALUE_SIZE);
                fread(chainHead, KEY_VALUE_SIZE, 1, file);
                std::copy(chainHead, chainHead + AES_KEY_SIZE, tmp.begin());
            }
            if (cnt == maxSize) {
                cout << "DANGER" << endl;
                cerr << "Error in insert (space crunch): " << strerror(errno);
            }
            if (tmp == nullKey) {
                //file.seekg(pos*KEY_VALUE_SIZE, ios::beg);
                if (Utilities::DROP_CACHE && !setupMode) {
                    Utilities::startTimer(113);
                    if (HDD_CACHE)system("sudo hdparm -A 0 /dev/sda >/dev/null 2>&1");
                    if (KERNEL_CACHE)system("echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null 2>&1");
                    auto t = Utilities::stopTimer(113);
                    cacheTime += t;
                    //            cout << "cache time:" << t << endl;
                }
                fseek(file, pos*KEY_VALUE_SIZE, SEEK_SET);
                //file.write((char*) newRecord, KEY_VALUE_SIZE);
                fwrite((char*) newRecord, KEY_VALUE_SIZE, 1, file);

            }
            //cout<<endl;
        }
        fflush(file);
        //	file.close();
        //    fclose(file);
    }
}

void Storage::insert(long dataIndex, unordered_map<prf_type, prf_type, PRFHasher> ciphers, bool setupMode, bool firstInsert) {
    long maxSize = pow(2, dataIndex + 1);
    if (setupMode) {
        FILE* file = filehandles[dataIndex];
        if (file == NULL) {
            cerr << "Error in insert: " << strerror(errno);
        }
        char* wholeFile = new char[maxSize * KEY_VALUE_SIZE];
        if (!firstInsert) {
            fseek(file, 0, SEEK_SET);
            fread(wholeFile, KEY_VALUE_SIZE*maxSize, 1, file);
        } else {
            memset(wholeFile, 0, maxSize * KEY_VALUE_SIZE);
        }

        int tmpCounter = 0;
        for (auto item : ciphers) {
            if (tmpCounter % 100000 == 0) {
                cout << "inserted " << tmpCounter << "/" << ciphers.size() << endl;
            }
            unsigned char newRecord[KEY_VALUE_SIZE];
            memset(newRecord, 0, KEY_VALUE_SIZE);
            std::copy(item.first.begin(), item.first.end(), newRecord);
            std::copy(item.second.begin(), item.second.end(), newRecord + AES_KEY_SIZE);
            long nextPos = 0;
            memcpy(&newRecord[2 * AES_KEY_SIZE], &nextPos, sizeof (long));

            unsigned char* hash = Utilities::sha256((char*) item.first.data(), AES_KEY_SIZE);
            long pos = (unsigned long) (*((long*) hash)) % maxSize;

            char chainHead[KEY_VALUE_SIZE];
            memcpy(chainHead, &wholeFile[pos * KEY_VALUE_SIZE], KEY_VALUE_SIZE);
            prf_type tmp;
            std::copy(chainHead, chainHead + AES_KEY_SIZE, tmp.begin());
            int cnt = 1;
            while (tmp != nullKey && cnt < maxSize) {
                long oldPos = pos;
                pos = (pos + 1) % maxSize;
                cnt++;
                memcpy(chainHead, &wholeFile[pos * KEY_VALUE_SIZE], KEY_VALUE_SIZE);
                std::copy(chainHead, chainHead + AES_KEY_SIZE, tmp.begin());
            }
            if (cnt == maxSize) {
                cout << "DANGER" << endl;
                cerr << "Error in insert (space crunch): " << strerror(errno);
            }
            if (tmp == nullKey) {
                memcpy(&wholeFile[pos * KEY_VALUE_SIZE], newRecord, KEY_VALUE_SIZE);
            }
            //cout<<endl;
            tmpCounter++;
        }
        fseek(file, 0, SEEK_SET);
        fwrite((char*) wholeFile, maxSize* KEY_VALUE_SIZE, 1, file);
        fflush(file);
        delete wholeFile;
    } else {
        FILE* file = filehandles[dataIndex];
        if (file == NULL) {
            cerr << "Error in insert: " << strerror(errno);
        }
        for (auto item : ciphers) {
            unsigned char newRecord[KEY_VALUE_SIZE];
            memset(newRecord, 0, KEY_VALUE_SIZE);
            std::copy(item.first.begin(), item.first.end(), newRecord);
            std::copy(item.second.begin(), item.second.end(), newRecord + AES_KEY_SIZE);
            long nextPos = 0;
            memcpy(&newRecord[2 * AES_KEY_SIZE], &nextPos, sizeof (long));

            unsigned char* hash = Utilities::sha256((char*) item.first.data(), AES_KEY_SIZE);
            long pos = (unsigned long) (*((long*) hash)) % maxSize;
            //file.seekg(pos * KEY_VALUE_SIZE, ios::beg);
            if (Utilities::DROP_CACHE && !setupMode) {
                Utilities::startTimer(113);
                if (HDD_CACHE)system("sudo hdparm -A 0 /dev/sda >/dev/null 2>&1");
                if (KERNEL_CACHE)system("echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null 2>&1");
                auto t = Utilities::stopTimer(113);
                cacheTime += t;
                //            cout << "cache time:" << t << endl;
            }
            fseek(file, pos*KEY_VALUE_SIZE, SEEK_SET);
            char chainHead[KEY_VALUE_SIZE];
            //file.read(chainHead, KEY_VALUE_SIZE);
            fread(chainHead, KEY_VALUE_SIZE, 1, file);
            prf_type tmp;
            std::copy(chainHead, chainHead + AES_KEY_SIZE, tmp.begin());
            int cnt = 1;
            while (tmp != nullKey && cnt < maxSize) {
                long oldPos = pos;
                pos = (pos + 1) % maxSize;
                //cout <<"{"<<oldPos<<"-"<<pos<<"}";
                cnt++;
                //file.seekg(pos*KEY_VALUE_SIZE, ios::beg);
                if (Utilities::DROP_CACHE && !setupMode) {
                    Utilities::startTimer(113);
                    if (HDD_CACHE)system("sudo hdparm -A 0 /dev/sda >/dev/null 2>&1");
                    if (KERNEL_CACHE)system("echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null 2>&1");
                    auto t = Utilities::stopTimer(113);
                    cacheTime += t;
                    //            cout << "cache time:" << t << endl;
                }
                fseek(file, pos*KEY_VALUE_SIZE, SEEK_SET);
                //file.read(chainHead, KEY_VALUE_SIZE);
                fread(chainHead, KEY_VALUE_SIZE, 1, file);
                std::copy(chainHead, chainHead + AES_KEY_SIZE, tmp.begin());
            }
            if (cnt == maxSize) {
                cout << "DANGER" << endl;
                cerr << "Error in insert (space crunch): " << strerror(errno);
            }
            if (tmp == nullKey) {
                //file.seekg(pos*KEY_VALUE_SIZE, ios::beg);
                if (Utilities::DROP_CACHE && !setupMode) {
                    Utilities::startTimer(113);
                    if (HDD_CACHE)system("sudo hdparm -A 0 /dev/sda >/dev/null 2>&1");
                    if (KERNEL_CACHE)system("echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null 2>&1");
                    auto t = Utilities::stopTimer(113);
                    cacheTime += t;
                    //            cout << "cache time:" << t << endl;
                }
                fseek(file, pos*KEY_VALUE_SIZE, SEEK_SET);
                //file.write((char*) newRecord, KEY_VALUE_SIZE);
                fwrite((char*) newRecord, KEY_VALUE_SIZE, 1, file);

            }
            //cout<<endl;
        }
        fflush(file);
        //	file.close();
        //    fclose(file);
    }
}

vector<prf_type> Storage::getAllData(long dataIndex) {
    vector<prf_type> results;

    //fstream file(filenames[dataIndex].c_str(), ios::binary | ios::in | ios::ate);
    //        FILE* file = fopen(filenames[dataIndex].c_str(), "rb");
    FILE* file = filehandles[dataIndex];
    if (file == NULL) {
        cerr << "Error in insert: " << strerror(errno);
    }
    fseek(file, 0L, SEEK_END);
    long size = ftell(file);
    if (Utilities::DROP_CACHE && !setupMode) {
        Utilities::startTimer(113);
        if (HDD_CACHE)system("sudo hdparm -A 0 /dev/sda >/dev/null 2>&1");
        if (KERNEL_CACHE)system("echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null 2>&1");
        auto t = Utilities::stopTimer(113);
        cacheTime += t;
    }
    //file.seekg(0, ios::beg);
    fseek(file, 0L, SEEK_SET);

    char* keyValue = new char[size];
    //file.read(keyValue, size);
    fread(keyValue, size, 1, file);

    for (long i = 0; i < size / KEY_VALUE_SIZE; i++) {
        prf_type tmp, restmp;
        std::copy(keyValue + i*KEY_VALUE_SIZE, keyValue + i * KEY_VALUE_SIZE + AES_KEY_SIZE, tmp.begin());
        std::copy(keyValue + i * KEY_VALUE_SIZE + AES_KEY_SIZE, keyValue + i * KEY_VALUE_SIZE + AES_KEY_SIZE + AES_KEY_SIZE, restmp.begin());
        if (tmp != nullKey) {
            results.push_back(restmp);
        }
    }

    //		file.close();
    //        fclose(file);
    delete keyValue;
    //            printf("Storage getalldata Cache time:%f\n",cacheTime);

    //}
    return results;
}

unordered_map<prf_type, prf_type, PRFHasher>* Storage::getAllDataPairs(long dataIndex) {
    unordered_map<prf_type, prf_type, PRFHasher>* results = new unordered_map<prf_type, prf_type, PRFHasher>();

    //fstream file(filenames[dataIndex].c_str(), ios::binary | ios::in | ios::ate);
    //        FILE* file = fopen(filenames[dataIndex].c_str(), "rb");
    FILE* file = filehandles[dataIndex];
    if (file == NULL) {
        cerr << "Error in insert: " << strerror(errno);
    }
    fseek(file, 0L, SEEK_END);
    long size = ftell(file);
    if (Utilities::DROP_CACHE && !setupMode) {
        Utilities::startTimer(113);
        if (HDD_CACHE)system("sudo hdparm -A 0 /dev/sda >/dev/null 2>&1");
        if (KERNEL_CACHE)system("echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null 2>&1");
        auto t = Utilities::stopTimer(113);
        cacheTime += t;
    }
    //file.seekg(0, ios::beg);
    fseek(file, 0L, SEEK_SET);

    char* keyValue = new char[size];
    //file.read(keyValue, size);
    fread(keyValue, size, 1, file);

    for (long i = 0; i < size / KEY_VALUE_SIZE; i++) {
        prf_type tmp, restmp;
        std::copy(keyValue + i*KEY_VALUE_SIZE, keyValue + i * KEY_VALUE_SIZE + AES_KEY_SIZE, tmp.begin());
        std::copy(keyValue + i * KEY_VALUE_SIZE + AES_KEY_SIZE, keyValue + i * KEY_VALUE_SIZE + AES_KEY_SIZE + AES_KEY_SIZE, restmp.begin());
        if (tmp != nullKey) {
            (*results)[tmp] = restmp;
        }
    }

    //		file.close();
    //        fclose(file);
    delete keyValue;
    //            printf("Storage getalldata Cache time:%f\n",cacheTime);
    //}
    return results;
}

void Storage::clear(long index) {

    //        fstream file(filenames[index].c_str(), std::ios::binary | std::ofstream::out);
    FILE* file = filehandles[index];

    fseek(file, 0L, SEEK_SET);
    long maxSize = pow(2, index + 1);
    long nextPtr = 0;
    for (long j = 0; j < maxSize; j++) {
        fwrite((char*) nullKey.data(), AES_KEY_SIZE, 1, file);
        fwrite((char*) nullKey.data(), AES_KEY_SIZE, 1, file);
        fwrite((char*) &nextPtr, sizeof (long), 1, file);
        //            file.write((char*) nullKey.data(), AES_KEY_SIZE);
        //            file.write((char*) nullKey.data(), AES_KEY_SIZE);
        //            file.write((char*) &nextPtr, sizeof (long));
    }
    // file.write((char*) &nextPtr, sizeof (long));
    //        file.close();
    fflush(file);
    if (Utilities::DROP_CACHE && !setupMode) {
        Utilities::startTimer(113);
        if (HDD_CACHE)system("sudo hdparm -A 0 /dev/sda >/dev/null 2>&1");
        if (KERNEL_CACHE)system("echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null 2>&1");
        auto t = Utilities::stopTimer(113);
        cacheTime += t;
        //            cout << "cache time:" << t << endl;
    }

    //}
}

Storage::~Storage() {
    for (int i = 0; i < dataIndex; i++) {
        fclose(filehandles[i]);
    }
}

prf_type Storage::find(long index, prf_type mapKey, bool& found) {
    Utilities::startTimer(124);
    auto previousCacheTime = cacheTime;
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
    do {
        Utilities::startTimer(129);
        cnt++;
        if (isInCache(index, pos)) {
            memcpy(chainHead, data[index][pos].first.begin(), AES_KEY_SIZE);
            memcpy(chainHead + AES_KEY_SIZE, data[index][pos].second.begin(), AES_KEY_SIZE);
        } else {
            if (Utilities::DROP_CACHE && !setupMode) {
                Utilities::startTimer(113);
                if (HDD_CACHE)system("sudo hdparm -A 0 /dev/sda >/dev/null 2>&1");
                if (KERNEL_CACHE)system("echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null 2>&1");
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
            auto endtime2 = Utilities::stopTimer(124);
            getCounterTime = endtime2 - (cacheTime - previousCacheTime);
            if (Utilities::useRandomFolder) {
                fclose(file);
            }
            return restmp;
        }
        pos = (pos + 1) % maxSize;
    } while (tmp != nullKey && cnt < maxSize);

    found = false;
    auto endtime = Utilities::stopTimer(124);
    getCounterTime = endtime - (cacheTime - previousCacheTime);
    if (Utilities::useRandomFolder) {
        fclose(file);
    }
    return nullKey;
}

void Storage::insert(int key, int value) {
    prf_type K, V;
    memset(K.data(), 0, AES_KEY_SIZE);
    K[0] = 1;
    memset(V.data(), 0, AES_KEY_SIZE);
    *(int*) (&(K[1])) = key;
    *(int*) (&(V[0])) = value;
    map<prf_type, prf_type> input;
    input[K] = V;
    insert(this->dataIndex - 1, input);
}

void Storage::insert(string key, int value) {
    prf_type K, V;
    memset(K.data(), 0, AES_KEY_SIZE);
    memset(V.data(), 0, AES_KEY_SIZE);
    memcpy(K.data(), key.data(), key.length());
    *(int*) (&(V[0])) = value;
    map<prf_type, prf_type> input;
    input[K] = V;
    insert(this->dataIndex - 1, input);
}

void Storage::insert(prf_type key, prf_type value) {
    map<prf_type, prf_type> input;
    input[key] = value;
    insert(this->dataIndex - 1, input);
}

bool Storage::get(int key, int& value) {
    prf_type K, V;
    memset(K.data(), 0, AES_KEY_SIZE);
    K[0] = 1;
    *(int*) (&(K[1])) = key;
    bool found = false;
    V = find(this->dataIndex - 1, K, found);
    if (found) {
        value = *(int*) (&(V[0]));
        return true;
    } else {
        return false;
    }
}

bool Storage::get(string key, int& value) {
    prf_type K, V;
    memset(K.data(), 0, AES_KEY_SIZE);
    memcpy(K.data(), key.data(), key.length());
    bool found = false;
    V = find(this->dataIndex - 1, K, found);
    if (found) {
        value = *(int*) (&(V[0]));
        return true;
    } else {
        return false;
    }
}

void Storage::erase(string key) {
    prf_type K, V;
    memset(K.data(), 0, AES_KEY_SIZE);
    K[0] = 1;
    memcpy(K.data(), key.data(), key.length());
    bool found = false;
    erase(this->dataIndex - 1, K, found);
    if (found == false) {
        cout << "ERROR in erase" << endl;
    }
}

void Storage::erase(int key) {
    prf_type K, V;
    memset(K.data(), 0, AES_KEY_SIZE);
    K[0] = 1;
    *(int*) (&(K[1])) = key;
    bool found = false;
    erase(this->dataIndex - 1, K, found);
    if (found == false) {
        cout << "ERROR in erase" << endl;
    }
}

void Storage::replace(int key, int value) {
    prf_type K, V;
    memset(K.data(), 0, AES_KEY_SIZE);
    K[0] = 1;
    memset(V.data(), 0, AES_KEY_SIZE);
    *(int*) (&(K[1])) = key;
    *(int*) (&(V[0])) = value;
    bool found = false;
    replace(this->dataIndex - 1, K, found, V);
    if (found == false) {
        cout << "ERROR in replace" << endl;
    }
}

void Storage::replace(string key, int value) {
    prf_type K, V;
    memset(K.data(), 0, AES_KEY_SIZE);
    K[0] = 1;
    memset(V.data(), 0, AES_KEY_SIZE);
    memcpy(K.data(), key.data(), key.length());
    *(int*) (&(V[0])) = value;
    bool found = false;
    replace(this->dataIndex - 1, K, found, V);
    if (found == false) {
        cout << "ERROR in replace" << endl;
    }
}

bool Storage::erase(long index, prf_type mapKey, bool& found) {
    Utilities::startTimer(124);
    auto previousCacheTime = cacheTime;
    prf_type result;
    //std::fstream file(filenames[index].c_str(), ios::binary | ios::in);
    //    FILE* file = fopen(filenames[index].c_str(), "rb");
    FILE* file = filehandles[index];
    if (file == NULL)
        cerr << "Error in read: " << strerror(errno);
    unsigned char* hash = Utilities::sha256((char*) mapKey.data(), AES_KEY_SIZE);
    long maxSize = pow(2, index + 1);
    char chainHead[KEY_VALUE_SIZE], last[KEY_VALUE_SIZE];
    memset(chainHead, KEY_VALUE_SIZE, 0);

    if (profile)
        seekgCount++;
    int cnt = 0;
    prf_type tmp;
    //    memset(last.data(), AES_KEY_SIZE, 0);
    long pos, lastpos;
    pos = (unsigned long) (*((long*) hash + cnt)) % maxSize;
    long bytesRead;
    do {
        if (Utilities::DROP_CACHE && !setupMode) {
            Utilities::startTimer(113);
            if (HDD_CACHE)system("sudo hdparm -A 0 /dev/sda >/dev/null 2>&1");
            if (KERNEL_CACHE)system("echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null 2>&1");
            auto t = Utilities::stopTimer(113);
            cacheTime += t;
            //            cout << "cache time:" << t << endl;
        }

        cnt++;
        //        Utilities::startTimer(129);
        //file.seekg(pos*KEY_VALUE_SIZE, ios::beg);
        fseek(file, pos*KEY_VALUE_SIZE, SEEK_SET);
        //        auto seekgtime = Utilities::stopTimer(129);
        //        cout << "seekg time:" << seekgtime << " KEY_VALUE_SIZE:" << KEY_VALUE_SIZE << endl;
        Utilities::startTimer(129);
        //file.read(chainHead, KEY_VALUE_SIZE);
        //        memcpy(last, chainHead);
        fread(chainHead, KEY_VALUE_SIZE, 1, file);
        //        auto readtime = Utilities::stopTimer(129);
        //        cout << "read time:" << readtime << endl;
        std::copy(chainHead, chainHead + AES_KEY_SIZE, tmp.begin());
        prf_type restmp;
        std::copy(chainHead + AES_KEY_SIZE, chainHead + (2 * AES_KEY_SIZE), restmp.begin());
        if (tmp == mapKey) {
            //			file.close();
            //			fclose(file);
            found = true;
            auto endtime2 = Utilities::stopTimer(124);
            //            cout << "storage-middle: time:" << endtime2 << " cnt:" << cnt << endl;
            getCounterTime = endtime2 - (cacheTime - previousCacheTime);
            //            cout << index << ": Keyword Counter BYTES READ:" << cnt * AES_KEY_SIZE << "}" << endl;
            break;
        }
        lastpos = pos;
        pos = (pos + 1) % maxSize;
    } while (tmp != nullKey && cnt < maxSize);

    //file.close();
    //    fclose(file);
    if (found) {
        memset(chainHead, -1, AES_KEY_SIZE * 2);
        fseek(file, pos*KEY_VALUE_SIZE, SEEK_SET);
        //file.write((char*) newRecord, KEY_VALUE_SIZE);
        if (Utilities::DROP_CACHE && !setupMode) {
            Utilities::startTimer(113);
            if (HDD_CACHE)system("sudo hdparm -A 0 /dev/sda >/dev/null 2>&1");
            if (KERNEL_CACHE)system("echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null 2>&1");
            auto t = Utilities::stopTimer(113);
            cacheTime += t;
            //            cout << "cache time:" << t << endl;
        }
        fwrite((char*) chainHead, KEY_VALUE_SIZE, 1, file);
    }
    fflush(file);
    auto endtime = Utilities::stopTimer(124);
    //    cout << "storage-end: time:" << endtime << " cnt:" << cnt << endl;
    getCounterTime = endtime - (cacheTime - previousCacheTime);
    //    cout << index << ": Keyword Counter BYTES READ:{" << cnt * AES_KEY_SIZE << "}" << endl;
    return found;
}

bool Storage::replace(long index, prf_type mapKey, bool& found, prf_type newVal) {
    Utilities::startTimer(124);
    auto previousCacheTime = cacheTime;
    prf_type result;
    //std::fstream file(filenames[index].c_str(), ios::binary | ios::in);
    //    FILE* file = fopen(filenames[index].c_str(), "rb");
    FILE* file = filehandles[index];
    if (file == NULL)
        cerr << "Error in read: " << strerror(errno);
    unsigned char* hash = Utilities::sha256((char*) mapKey.data(), AES_KEY_SIZE);
    long maxSize = pow(2, index + 1);
    char chainHead[KEY_VALUE_SIZE], last[KEY_VALUE_SIZE];
    memset(chainHead, KEY_VALUE_SIZE, 0);

    if (profile)
        seekgCount++;
    int cnt = 0;
    prf_type tmp;
    //    memset(last.data(), AES_KEY_SIZE, 0);
    long pos, lastpos;
    pos = (unsigned long) (*((long*) hash + cnt)) % maxSize;
    long bytesRead;
    do {
        if (Utilities::DROP_CACHE && !setupMode) {
            Utilities::startTimer(113);
            if (HDD_CACHE)system("sudo hdparm -A 0 /dev/sda >/dev/null 2>&1");
            if (KERNEL_CACHE)system("echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null 2>&1");
            auto t = Utilities::stopTimer(113);
            cacheTime += t;
            //            cout << "cache time:" << t << endl;
        }

        cnt++;
        //        Utilities::startTimer(129);
        //file.seekg(pos*KEY_VALUE_SIZE, ios::beg);
        fseek(file, pos*KEY_VALUE_SIZE, SEEK_SET);
        //        auto seekgtime = Utilities::stopTimer(129);
        //        cout << "seekg time:" << seekgtime << " KEY_VALUE_SIZE:" << KEY_VALUE_SIZE << endl;
        Utilities::startTimer(129);
        //file.read(chainHead, KEY_VALUE_SIZE);
        //        memcpy(last, chainHead);
        fread(chainHead, KEY_VALUE_SIZE, 1, file);
        //        auto readtime = Utilities::stopTimer(129);
        //        cout << "read time:" << readtime << endl;
        std::copy(chainHead, chainHead + AES_KEY_SIZE, tmp.begin());
        prf_type restmp;
        std::copy(chainHead + AES_KEY_SIZE, chainHead + (2 * AES_KEY_SIZE), restmp.begin());
        if (tmp == mapKey) {
            //			file.close();
            //			fclose(file);
            found = true;
            auto endtime2 = Utilities::stopTimer(124);
            //            cout << "storage-middle: time:" << endtime2 << " cnt:" << cnt << endl;
            getCounterTime = endtime2 - (cacheTime - previousCacheTime);
            //            cout << index << ": Keyword Counter BYTES READ:" << cnt * AES_KEY_SIZE << "}" << endl;
            break;
        }
        lastpos = pos;
        pos = (pos + 1) % maxSize;
    } while (tmp != nullKey && cnt < maxSize);

    //file.close();
    //    fclose(file);
    if (found) {
        memcpy(chainHead + AES_KEY_SIZE, newVal.data(), AES_KEY_SIZE);
        fseek(file, pos*KEY_VALUE_SIZE, SEEK_SET);
        //file.write((char*) newRecord, KEY_VALUE_SIZE);
        if (Utilities::DROP_CACHE && !setupMode) {
            Utilities::startTimer(113);
            if (HDD_CACHE)system("sudo hdparm -A 0 /dev/sda >/dev/null 2>&1");
            if (KERNEL_CACHE)system("echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null 2>&1");
            auto t = Utilities::stopTimer(113);
            cacheTime += t;
            //            cout << "cache time:" << t << endl;
        }
        fwrite((char*) chainHead, KEY_VALUE_SIZE, 1, file);
    }
    fflush(file);
    auto endtime = Utilities::stopTimer(124);
    //    cout << "storage-end: time:" << endtime << " cnt:" << cnt << endl;
    getCounterTime = endtime - (cacheTime - previousCacheTime);
    //    cout << index << ": Keyword Counter BYTES READ:{" << cnt * AES_KEY_SIZE << "}" << endl;
    return found;
}

string Storage::getName(long dataIndex) {
    return filenames[dataIndex];
}

void Storage::closeHandle(long index) {
    fflush(filehandles[index]);
    fclose(filehandles[index]);
}

void Storage::rename(long toIndex, string inputFileName) {
    fclose(filehandles[toIndex]);
    if (std::rename(inputFileName.c_str(), filenames[toIndex].c_str()) != 0) {
        perror("Error renaming file");
    } else {
        filehandles[toIndex] = fopen(filenames[toIndex].c_str(), "rb+");
    }
}

void Storage::resetup(long index) {
    string filename = filenames[index];
    fstream file(filename.c_str(), std::ofstream::out);
    if (file.fail()) {
        cerr << "Error: " << strerror(errno);
    }
    long maxSize = pow(2, index + 1); //double the size
    long nextPtr = 0;
    if (Utilities::DROP_CACHE && !setupMode) {
        Utilities::startTimer(113);
        if (HDD_CACHE)system("sudo hdparm -A 0 /dev/sda > /dev/null 2>sda1");
        if (KERNEL_CACHE)system("echo 3 | sudo tee /proc/sys/vm/drop_caches > /dev/null 2>sda1");
        auto t = Utilities::stopTimer(113);
        cacheTime += t;
    }
    //    file.seekp(maxSize * AES_KEY_SIZE - (AES_KEY_SIZE+AES_KEY_SIZE+sizeof(long)));
    file.seekp(0);
    for (long j = 0; j < maxSize; j++) {
        file.write((char*) nullKey.data(), AES_KEY_SIZE);
        file.write((char*) nullKey.data(), AES_KEY_SIZE);
        file.write((char*) &nextPtr, sizeof (long));
    }
    file.close();
    filehandles[index] = fopen(filename.c_str(), "rb+");
}