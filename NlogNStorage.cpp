#include "NlogNStorage.h"
#include<string.h>

NlogNStorage::NlogNStorage(bool inMemory, long dataIndex, string fileAddressPrefix, bool profile) {
    this->inMemoryStorage = inMemory;
    this->fileAddressPrefix = fileAddressPrefix;
    this->dataIndex = dataIndex;
    this->profile = profile;
    memset(nullKey.data(), 0, AES_KEY_SIZE);
}

bool NlogNStorage::isInCache(long index, long instance, long pos) {
    long levelSize = 2 * pow(2, index);
    long threshold = floor(levelSize * Utilities::CACHE_PERCENTAGE);
    if (pos < threshold) {
        return true;
    } else {
        return false;
    }
}

bool NlogNStorage::setup(bool overwrite) {
    filenames.resize(dataIndex);
    for (long i = 0; i < dataIndex; i++) {
        data.push_back(vector<vector<prf_type> >());
        filenames[i].resize(i + 1);
        filehandles.push_back(vector<FILE*>());
        for (long j = 0; j < i + 1; j++) {
            string filename = fileAddressPrefix + "MAP-" + to_string(i) + "-" + to_string(j) + ".dat";
            filenames[i][j] = filename;
            //fstream testfile(filename.c_str(), std::ofstream::in);
            FILE *fp;
            if (overwrite) {
                //     testfile.close();
                //   fstream file(filename.c_str(), std::ofstream::out);
                //                fp = fopen(filename.c_str(), "wb");
                //                if (fp == NULL) {
                //                    cerr << "Error: " << strerror(errno);
                //                }                
                long maxSize = 2 * pow(2, i);
                long alloc_size = AES_KEY_SIZE*maxSize;
                while (alloc_size > 0) {
                    long bs = min(alloc_size, 2147483648);
                    string command = string("dd if=/dev/zero bs=" + to_string(bs) + " count=1 status=none >> " + filename);
                    system(command.c_str());
                    alloc_size -= bs;
                }
                //                for (long k = 0; k < maxSize; k++) {
                //                    fwrite((char*) nullKey.data(), AES_KEY_SIZE, 1, fp);
                //                }
                //                fclose(fp);
            }
            FILE* file = fopen(filename.c_str(), "rb+");
            filehandles[i].push_back(file);
            data[i].push_back(vector<prf_type>());
        }
    }
}

void NlogNStorage::insertAll(long index, long instance, vector<vector< prf_type>> ciphers, bool append, bool firstRun, bool setupMode) {
    if (setupMode) {
        if (append && !firstRun) {
            FILE* file = filehandles[index][instance];

            fseek(file, setupHeadPos, SEEK_SET);
            long totalSize = 0;
            for (auto item : ciphers) {
                totalSize += AES_KEY_SIZE * item.size();
            }

            char* tmpData = new char[totalSize];

            long tmpcnt = 0;
            for (auto item : ciphers) {
                for (auto pair : item) {
                    //                    fwrite((char*) pair.data(), AES_KEY_SIZE, 1, file);
                    memcpy(&tmpData[tmpcnt * AES_KEY_SIZE], (char*) pair.data(), AES_KEY_SIZE);
                    tmpcnt++;
                }
            }

            fwrite((char*) tmpData, totalSize, 1, file);
            setupHeadPos += totalSize;
            delete tmpData;
        } else {
            setupHeadPos = 0;
            FILE* file = filehandles[index][instance];
            fseek(file, 0L, SEEK_SET);

            long totalSize = 0;
            for (auto item : ciphers) {
                totalSize += AES_KEY_SIZE * item.size();
            }

            char* tmpData = new char[totalSize];

            long tmpcnt = 0;
            for (auto item : ciphers) {
                for (auto pair : item) {
                    //                    fwrite((char*) pair.data(), AES_KEY_SIZE, 1, file);
                    memcpy(&tmpData[tmpcnt * AES_KEY_SIZE], (char*) pair.data(), AES_KEY_SIZE);
                    tmpcnt++;
                }
            }

            fwrite((char*) tmpData, totalSize, 1, file);
            fflush(file);
            setupHeadPos = totalSize;
            delete tmpData;
        }
    } else {
        if (append && !firstRun) {
            //fstream file(filenames[index][instance].c_str(), ios::binary | std::ios::app);
            FILE *fp;
            fp = fopen(filenames[index][instance].c_str(), "ab");
            if (fp == NULL) {
                cerr << "Error in insert: " << strerror(errno);
            }
            for (auto item : ciphers) {
                for (auto pair : item) {
                    fwrite((char*) pair.data(), AES_KEY_SIZE, 1, fp);
                }
            }
            fclose(fp);
        } else {
            //fstream file(filenames[index][instance].c_str(), ios::binary | ios::out);
            FILE *fp;
            fp = fopen(filenames[index][instance].c_str(), "wb");
            if (fp == NULL) {
                cerr << "Error in insert: " << strerror(errno);
            }
            for (auto item : ciphers) {
                for (auto pair : item) {
                    fwrite((char*) pair.data(), AES_KEY_SIZE, 1, fp);
                }
            }
            fclose(fp);
        }
    }
}

vector<prf_type> NlogNStorage::getAllData(long index, long instance) {
    vector<prf_type> results;
    //fstream file(filenames[index][instance].c_str(), ios::binary | ios::in | ios::ate);
    FILE *fp;
    fp = fopen(filenames[index][instance].c_str(), "rb");
    if (fp == NULL) {
        cerr << "Error in insert: " << strerror(errno);
    }

    if (Utilities::DROP_CACHE) {
        Utilities::startTimer(113);
        if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
        if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());        
        auto t = Utilities::stopTimer(113);
        //printf("drop cache time:%f\n", t);
        cacheTime += t;
    }
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    char* keyValues = new char[size];
    fseek(fp, 0, SEEK_SET);
    fread(keyValues, size, 1, fp);
    fclose(fp);

    for (long i = 0; i < size / AES_KEY_SIZE; i++) {
        prf_type tmp;
        std::copy(keyValues + i*AES_KEY_SIZE, keyValues + i * AES_KEY_SIZE + AES_KEY_SIZE, tmp.begin());
        results.push_back(tmp);
    }
    delete keyValues;
    return results;
}

vector<prf_type> NlogNStorage::getAllData(long index) {
    vector<prf_type> results;
    for (int i = 0; i <= index; i++) {
        // fstream file(filenames[index][i].c_str(), ios::binary | ios::in | ios::ate);
        FILE *fp;
        fp = fopen(filenames[index][i].c_str(), "rb");
        if (fp == NULL) {
            cerr << "Error in insert: " << strerror(errno);
        }
        fseek(fp, 0, SEEK_END);
        long size = ftell(fp);
        if (Utilities::DROP_CACHE) {
            Utilities::startTimer(113);
            if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
            if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
            //     if(Utilities::KERNEL_CACHE)system("echo 3 | sudo tee /proc/sys/vm/drop_caches");
            auto t = Utilities::stopTimer(113);
            //printf("drop cache time:%f\n", t);
            cacheTime += t;
        }
        fseek(fp, 0, SEEK_SET);
        char* keyValues = new char[size];
        fread(keyValues, size, 1, fp);
        fclose(fp);

        for (long i = 0; i < size / AES_KEY_SIZE; i++) {
            prf_type tmp;
            std::copy(keyValues + i*AES_KEY_SIZE, keyValues + i * AES_KEY_SIZE + AES_KEY_SIZE, tmp.begin());
            results.push_back(tmp);
        }
        delete keyValues;
    }
    return results;
}

void NlogNStorage::clear(long index) {
    for (int instance = 0; instance <= index; instance++) {
        // fstream file(filenames[index][instance].c_str(), std::ios::binary | std::ofstream::out);
        FILE *fp;
        fp = fopen(filenames[index][instance].c_str(), "rb");
        if (fp == NULL) {
            cerr << "Error in insert: " << strerror(errno);
        }
        long maxSize = 2 * pow(2, index);
        for (long j = 0; j < maxSize; j++) {
            fwrite((char*) nullKey.data(), AES_KEY_SIZE, 1, fp);
        }
        fclose(fp);
    }
}

NlogNStorage::~NlogNStorage() {
    for (long i = 0; i < dataIndex; i++) {
        for (int j = 0; j < filehandles[i].size(); j++)
            fclose(filehandles[i][j]);
    }
}

vector<prf_type> NlogNStorage::find(long index, long instance, long targetPos) {
    //chain search pending
    vector<prf_type> results;
    // std::fstream file(filenames[index][instance].c_str(), ios::binary | ios::in);    
    FILE* fp;
    if (Utilities::useRandomFolder) {
        fp = fopen(filenames[index][instance].c_str(), "rb+");
    } else {
        fp = filehandles[index][instance];
    }
    if (fp == NULL) {
        cerr << "Error in insert: " << strerror(errno);
    }
    //    unsigned char* hash = Utilities::sha256((char*) mapKey.data(), AES_KEY_SIZE);
    long numberOfEntries = (float) pow(2, index) / (float) pow(2, instance);
    numberOfEntries = 2 * numberOfEntries;
    //    long pos = (((unsigned long) (*((long*) hash)) % numberOfEntries) + attempt) % numberOfEntries;    
    long readPos = targetPos * AES_KEY_SIZE * pow(2, instance);
    long cnt = pow(2, instance);
    long pos = targetPos * cnt;



    if (isInCache(index, instance, pos)) {
        long newCnt = cnt;
        for (long j = pos; j < min(pos + cnt, (long) data[index][instance].size()); j++) {
            results.push_back(data[index][instance][j]);
            newCnt--;
        }
        readPos = (min(pos + cnt, (long) data[index][instance].size())) * AES_KEY_SIZE;
        cnt = newCnt;
    }

    long readLength = cnt * AES_KEY_SIZE;

    if (cnt > 0) {
        if (Utilities::DROP_CACHE) {
            Utilities::startTimer(113);
            if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
            if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());            
            auto t = Utilities::stopTimer(113);
            cacheTime += t;
        }
        fseek(fp, readPos, SEEK_SET);
        SeekG++;
        char* keyValues = new char[readLength];
        fread(keyValues, readLength, 1, fp);
        readBytes += readLength;
        for (long i = 0; i < readLength / AES_KEY_SIZE; i++) {
            prf_type tmp;
            std::copy(keyValues + i*AES_KEY_SIZE, keyValues + i * AES_KEY_SIZE + AES_KEY_SIZE, tmp.begin());
            results.push_back(tmp);
        }
        delete keyValues;
    }
    //    fclose(fp);
    if (Utilities::useRandomFolder) {
        fclose(fp);
    }
    return results;
}

void NlogNStorage::loadCache() {
    if (Utilities::CACHE_PERCENTAGE == 0) {
        return;
    }
    for (long index = 0; index < dataIndex; index++) {
        long levelSize = 2 * pow(2, index);
        long size = floor(levelSize * Utilities::CACHE_PERCENTAGE);
        for (long j = 0; j < index + 1; j++) {
            FILE* file = filehandles[index][j];
            if (file == NULL) {
                cerr << "Error in read: " << strerror(errno);
            }
            fseek(file, 0L, SEEK_SET);

            char* keyValue = new char[size * AES_KEY_SIZE];
            fread(keyValue, size * AES_KEY_SIZE, 1, file);

            for (long i = 0; i < size; i++) {
                prf_type tmp;
                std::copy(keyValue + i * AES_KEY_SIZE, keyValue + i * AES_KEY_SIZE + AES_KEY_SIZE, tmp.begin());
                data[index][j].push_back(tmp);
            }
            delete keyValue;
        }
    }
}
