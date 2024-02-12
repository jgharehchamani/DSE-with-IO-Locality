#include "OneChoiceStorage.h"
#include "OneChoiceSDdGeneralServer.h"
#include <math.h>

OneChoiceStorage::OneChoiceStorage(bool inMemory, long dataIndex, string fileAddressPrefix, bool profile) {
    this->inMemoryStorage = inMemory;
    this->fileAddressPrefix = fileAddressPrefix;
    this->dataIndex = dataIndex;
    this->profile = profile;
    memset(nullKey.data(), 0, AES_KEY_SIZE);
    for (long i = 0; i < dataIndex; i++) {
        long curNumberOfBins = i > 1 ? (long) ceil((float) pow(2, i) / (float) (log2(pow(2, i)) * log2(log2(pow(2, i))))) : 1;
        long curSizeOfEachBin = i > 1 ? 3 * (log2(pow(2, i)) * log2(log2(pow(2, i)))) : pow(2, i);
        numberOfBins.push_back(curNumberOfBins);
        sizeOfEachBin.push_back(curSizeOfEachBin);
        cout << "One Choice Storage level:" << i << " number of bins:" << curNumberOfBins << " size of bins:" << curSizeOfEachBin << endl;
        //printf("OneChoiceStorage Level:%d number of Bins:%d size of bin:%d\n", i, curNumberOfBins, curSizeOfEachBin);
    }

}

bool OneChoiceStorage::isInCache(long index, long pos) {
    long levelSize = numberOfBins[index];
    long threshold = floor(levelSize * CACHE_PERCENTAGE);
    if (pos < threshold) {
        return true;
    } else {
        return false;
    }
}

OneChoiceStorage::~OneChoiceStorage() {
    for (long i = 0; i < dataIndex; i++) {
        fclose(filehandles[i]);
    }
}

bool OneChoiceStorage::setup(bool overwrite) {

    for (long i = 0; i < dataIndex; i++) {
        string filename = fileAddressPrefix + "MAP-" + to_string(i) + ".dat";
        filenames.push_back(filename);
        fstream testfile(filename.c_str(), std::ofstream::in);
        if (testfile.fail() || overwrite) {
            testfile.close();
            long maxSize = numberOfBins[i] * sizeOfEachBin[i];
            long alloc_size = AES_KEY_SIZE*maxSize;
            while (alloc_size > 0) {
                long bs = min(alloc_size, 2147483648);
                string command = string("dd if=/dev/zero bs=" + to_string(bs) + " count=1 >> " + filename);
                cout << "command:" << command << endl;
                system(command.c_str());
                alloc_size -= bs;
            }
            //                fstream file(filename.c_str(), std::ofstream::out);
            //                if (file.fail()) {
            //                    cerr << "Error: " << strerror(errno);
            //                }
            //
            //                long maxSize = numberOfBins[i] * sizeOfEachBin[i];
            //                for (long j = 0; j < maxSize; j++) {
            //                    file.write((char*) nullKey.data(), AES_KEY_SIZE);
            //                }
            //                file.close();
        }
        FILE* file = fopen(filename.c_str(), "rb+");
        filehandles.push_back(file);
        data.push_back(vector< vector<prf_type> >());
    }
}

void OneChoiceStorage::insertAll(long index, vector<vector< prf_type > > ciphers, bool append, bool firstRun, bool setupMode) {
    if (setupMode) {
        if (append && !firstRun) {
            FILE* file = filehandles[index];

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
            fflush(file);
            delete tmpData;
        } else {
            setupHeadPos = 0;
            FILE* file = filehandles[index];
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
            FILE* file = filehandles[index];

            fseek(file, 0, SEEK_END);
            for (auto item : ciphers) {
                for (auto pair : item) {
                    fwrite((char*) pair.data(), AES_KEY_SIZE, 1, file);
                }
            }
        } else {
            //            fstream file(filenames[index].c_str(), ios::binary | ios::out);
            FILE* file = filehandles[index];
            //            if (file.fail()) {
            //                cerr << "Error in insert: " << strerror(errno);
            //            }
            fseek(file, 0L, SEEK_SET);
            for (auto item : ciphers) {
                for (auto pair : item) {
                    fwrite((char*) pair.data(), AES_KEY_SIZE, 1, file);
                    //                    file.write((char*) pair.data(), AES_KEY_SIZE);
                }
            }
            //            file.close();
            fflush(file);
            if (Utilities::DROP_CACHE && !setupMode) {
                Utilities::startTimer(113);
                if (HDD_CACHE)system("sudo hdparm -A 0 /dev/sda >/dev/null 2>&1");
                if (KERNEL_CACHE)system("echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null 2>&1");
                auto t = Utilities::stopTimer(113);
                //printf("drop cache time:%f\n", t);
                cacheTime += t;
            }
        }
    }
}

void OneChoiceStorage::insertAll(long index, vector< prf_type > ciphers, bool append, bool firstRun, bool setupMode) {
    if (setupMode) {
        if (append && !firstRun) {
            FILE* file = filehandles[index];

            fseek(file, 0, SEEK_END);
            long totalSize = AES_KEY_SIZE * ciphers.size();

            char* tmpData = new char[totalSize];

            long tmpcnt = 0;
            for (auto item : ciphers) {
                memcpy(&tmpData[tmpcnt * AES_KEY_SIZE], (char*) item.data(), AES_KEY_SIZE);
            }

            fwrite((char*) tmpData, totalSize, 1, file);
            delete tmpData;

        } else {
            FILE* file = filehandles[index];
            fseek(file, 0L, SEEK_SET);

            long totalSize = AES_KEY_SIZE * ciphers.size();

            char* tmpData = new char[totalSize];

            long tmpcnt = 0;
            for (auto item : ciphers) {
                memcpy(&tmpData[tmpcnt * AES_KEY_SIZE], (char*) item.data(), AES_KEY_SIZE);
            }

            fwrite((char*) tmpData, totalSize, 1, file);
            fflush(file);
            delete tmpData;
        }
    } else {
        if (append && !firstRun) {
            //            fstream file(filenames[index].c_str(), ios::binary | std::ios::app);
            FILE* file = filehandles[index];
            fseek(file, 0, SEEK_END);
            for (auto item : ciphers) {
                fwrite((char*) item.data(), AES_KEY_SIZE, 1, file);
            }
            //            file.close();
        } else {
            //            fstream file(filenames[index].c_str(), ios::binary | ios::out);
            FILE* file = filehandles[index];
            fseek(file, 0L, SEEK_SET);
            for (auto item : ciphers) {
                fwrite((char*) item.data(), AES_KEY_SIZE, 1, file);
            }
            //            file.close();
            fflush(file);
            if (Utilities::DROP_CACHE && !setupMode) {
                Utilities::startTimer(113);
                if (HDD_CACHE)system("sudo hdparm -A 0 /dev/sda >/dev/null 2>&1");
                if (KERNEL_CACHE)system("echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null 2>&1");
                auto t = Utilities::stopTimer(113);
                //printf("drop cache time:%f\n", t);
                cacheTime += t;
            }
        }
    }
}

vector<prf_type> OneChoiceStorage::getAllDataFlat(long index) {

    vector<prf_type > results;
    FILE* file = filehandles[index];
    //        fstream file(filenames[index].c_str(), ios::binary | ios::in | ios::ate);
    //        if (file.fail()) {
    //            cerr << "Error in read: " << strerror(errno);
    //        }
    if (Utilities::DROP_CACHE && !setupMode) {
        Utilities::startTimer(113);
        if (HDD_CACHE)system("sudo hdparm -A 0 /dev/sda >/dev/null 2>&1");
        if (KERNEL_CACHE)system("echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null 2>&1");
        auto t = Utilities::stopTimer(113);
        //printf("drop cache time:%f\n", t);
        cacheTime += t;
    }
    fseek(file, 0L, SEEK_END);
    long size = ftell(file);
    //        long size = file.tellg();
    //        file.seekg(0, ios::beg);
    fseek(file, 0L, SEEK_SET);
    char* keyValues = new char[size];
    fread(keyValues, size, 1, file);
    //        file.read(keyValues, size);
    //        file.close();
    for (long i = 0; i < size / AES_KEY_SIZE; i++) {
        prf_type tmp;
        std::copy(keyValues + i*AES_KEY_SIZE, keyValues + i * AES_KEY_SIZE + AES_KEY_SIZE, tmp.begin());
        results.push_back(tmp);
    }

    delete keyValues;

    return results;
}

vector<vector<prf_type> >* OneChoiceStorage::getAllData(long index) {

    vector<vector<prf_type> >* results = new vector<vector<prf_type> >();
    FILE* file = filehandles[index];
    //        fstream file(filenames[index].c_str(), ios::binary | ios::in | ios::ate);
    //        if (file.fail()) {
    //            cerr << "Error in read: " << strerror(errno);
    //        }
    if (Utilities::DROP_CACHE && !setupMode) {
        Utilities::startTimer(113);
        if (HDD_CACHE)system("sudo hdparm -A 0 /dev/sda >/dev/null 2>&1");
        if (KERNEL_CACHE)system("echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null 2>&1");
        auto t = Utilities::stopTimer(113);
        //printf("drop cache time:%f\n", t);
        cacheTime += t;
    }
    fseek(file, 0L, SEEK_END);
    long size = ftell(file);
    //        long size = file.tellg();
    //        file.seekg(0, ios::beg);
    fseek(file, 0L, SEEK_SET);
    char* keyValues = new char[size];
    fread(keyValues, size, 1, file);
    //        file.read(keyValues, size);
    //        file.close();
    int counter = 0;
    vector<prf_type> tmpRes;
    for (long i = 0; i < size / AES_KEY_SIZE; i++) {
        prf_type tmp;
        std::copy(keyValues + i*AES_KEY_SIZE, keyValues + i * AES_KEY_SIZE + AES_KEY_SIZE, tmp.begin());
        tmpRes.push_back(tmp);
        counter++;
        if (counter == sizeOfEachBin[index]) {
            results->push_back(tmpRes);
            tmpRes.clear();
            counter = 0;
        }
    }

    delete keyValues;

    return results;
}

void OneChoiceStorage::clear(long index) {
    FILE* file = filehandles[index];
    fseek(file, 0L, SEEK_SET);
    long maxSize = numberOfBins[index] * sizeOfEachBin[index];
    for (long j = 0; j < maxSize; j++) {
        fwrite((char*) nullKey.data(), AES_KEY_SIZE, 1, file);
        //            file.write((char*) nullKey.data(), AES_KEY_SIZE);
    }
    //        file.close();
    fflush(file);
    if (Utilities::DROP_CACHE && !setupMode) {
        Utilities::startTimer(113);
        if (HDD_CACHE)system("sudo hdparm -A 0 /dev/sda >/dev/null 2>&1");
        if (KERNEL_CACHE)system("echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null 2>&1");
        auto t = Utilities::stopTimer(113);
        //printf("drop cache time:%f\n", t);
        cacheTime += t;
    }
}

vector<prf_type> OneChoiceStorage::find(long index, prf_type mapKey, long cnt) {
    Utilities::startTimer(104);
    Utilities::startTimer(610);
    auto previousCacheTime = cacheTime;
    vector<prf_type> results;
    //   std::fstream file(filenames[index].c_str(), ios::binary | ios::in);
    //    FILE* file = fopen(filenames[index].c_str(), "rb");
    FILE* file;
    if (Utilities::useRandomFolder) {
        file = fopen(filenames[index].c_str(), "rb+");
    } else {
        file = filehandles[index];
    }
    if (file == NULL) {
        //   if (file.fail()) {
        cerr << "Error in read: " << strerror(errno);
    }

    unsigned char* hash = Utilities::sha256((char*) mapKey.data(), AES_KEY_SIZE);
    auto hh = Utilities::stopTimer(610);
    //    printf("initial time:%f\n", hh);
    if (cnt >= numberOfBins[index]) {
        int cacheRead = 0;
        for (long i = 0; i < data[index].size(); i++) {
            for (long j = 0; j < data[index][i].size(); j++) {
                results.push_back(data[index][i][j]);
                cacheRead++;
            }
        }
        if (numberOfBins[index] * sizeOfEachBin[index] - cacheRead > 0) {
            //read everything
            long fileLength = numberOfBins[index] * sizeOfEachBin[index] * AES_KEY_SIZE - floor(numberOfBins[index] * CACHE_PERCENTAGE) * sizeOfEachBin[index] * AES_KEY_SIZE;
            fseek(file, floor(numberOfBins[index] * CACHE_PERCENTAGE) * sizeOfEachBin[index] * AES_KEY_SIZE, SEEK_SET);
            char* keyValues = new char[fileLength];
            if (Utilities::DROP_CACHE && !setupMode) {
                Utilities::startTimer(113);
                if (HDD_CACHE)system("sudo hdparm -A 0 /dev/sda >/dev/null 2>&1");
                if (KERNEL_CACHE)system("echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null 2>&1");
                auto t = Utilities::stopTimer(113);
                //                printf("drop cache time:%f\n", t);
                cacheTime += t;
            }
            //file.read(keyValues, fileLength);
            Utilities::startTimer(610);
            fread(keyValues, fileLength, 1, file);
            auto ss = Utilities::stopTimer(610);
            //            printf("1-read time:%f\n", ss);
            SeekG++;
            readBytes += fileLength;

            for (long i = 0; i < numberOfBins[index] * sizeOfEachBin[index] - cacheRead; i++) {
                prf_type tmp;
                std::copy(keyValues + i*AES_KEY_SIZE, keyValues + i * AES_KEY_SIZE + AES_KEY_SIZE, tmp.begin());
                results.push_back(tmp);
            }
        }
    } else {
        Utilities::startTimer(610);
        long pos = (unsigned long) (*((long*) hash)) % numberOfBins[index];
        int cacheRead = 0;
        if (isInCache(index, pos)) {
            long newCnt = cnt;
            for (long j = pos; j < min(pos + cnt, (long) data[index].size()); j++) {
                for (long i = 0; i < data[index][j].size(); i++) {
                    results.push_back(data[index][j][i]);
                    cacheRead++;
                }
                newCnt--;
            }
            pos = min(pos + cnt, (long) data[index].size());
            cnt = newCnt;
        }
        if (cnt == 0) {
            auto t = Utilities::stopTimer(104);
            searchTime = t - (cacheTime - previousCacheTime);
            if (Utilities::useRandomFolder) {
                fclose(file);
            }
            return results;
        }

        long readPos = pos * AES_KEY_SIZE * sizeOfEachBin[index];
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
        hh = Utilities::stopTimer(610);
        //        printf("second time:%f\n", hh);
        if (Utilities::DROP_CACHE && !setupMode) {
            Utilities::startTimer(113);
            if (HDD_CACHE)system("sudo hdparm -A 0 /dev/sda >/dev/null 2>&1");
            if (KERNEL_CACHE)system("echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null 2>&1");
            auto t = Utilities::stopTimer(113);
            //            printf("drop cache time:%f\n", t);
            cacheTime += t;
        }
        //       file.seekg(readPos, ios::beg);
        Utilities::startTimer(610);
        fseek(file, readPos, SEEK_SET);
        auto zz = Utilities::stopTimer(610);
        //        printf("seek time:%f\n", zz);
        SeekG++;
        char* keyValues = new char[readLength];
        //       file.read(keyValues, readLength);
        Utilities::startTimer(610);
        fread(keyValues, readLength, 1, file);
        auto ss = Utilities::stopTimer(610);
        //        printf("2-read time:%f\n", ss);
        Utilities::startTimer(610);
        readBytes += readLength;
        for (long i = 0; i < readLength / AES_KEY_SIZE; i++) {
            prf_type tmp;
            std::copy(keyValues + i*AES_KEY_SIZE, keyValues + i * AES_KEY_SIZE + AES_KEY_SIZE, tmp.begin());
            results.push_back(tmp);
        }
        ss = Utilities::stopTimer(610);
        //        printf("split time:%f\n", ss);
        if (totalReadLength > 0) {
            readLength = totalReadLength;
            cnt = readLength / (AES_KEY_SIZE * sizeOfEachBin[index]);
            pos = 0;

            cacheRead = 0;
            if (isInCache(index, pos)) {
                long newCnt = cnt;
                for (long j = pos; j < min(pos + cnt, (long) data[index].size()); j++) {
                    for (long i = 0; i < data[index][j].size(); i++) {
                        results.push_back(data[index][j][i]);
                        cacheRead++;
                    }
                    newCnt--;
                }
                pos = min(pos + cnt, (long) data[index].size());
                cnt = newCnt;

            }
            readPos = pos * AES_KEY_SIZE * sizeOfEachBin[index];


            if (Utilities::DROP_CACHE && !setupMode) {
                Utilities::startTimer(113);
                if (HDD_CACHE)system("sudo hdparm -A 0 /dev/sda >/dev/null 2>&1");
                if (KERNEL_CACHE)system("echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null 2>&1");
                auto t = Utilities::stopTimer(113);
                //                printf("drop cache time:%f\n", t);
                cacheTime += t;
            }
            //           file.seekg(0, ios::beg);
            fseek(file, readPos, SEEK_SET);
            readLength = cnt * AES_KEY_SIZE * sizeOfEachBin[index];
            char* keyValues = new char[readLength];
            //           file.read(keyValues, readLength);
            Utilities::startTimer(610);
            fread(keyValues, readLength, 1, file);
            ss = Utilities::stopTimer(610);
            //            printf("3-read time:%f\n", ss);
            readBytes += readLength;
            SeekG++;
            for (long i = 0; i < readLength / AES_KEY_SIZE; i++) {
                prf_type tmp;
                std::copy(keyValues + i*AES_KEY_SIZE, keyValues + i * AES_KEY_SIZE + AES_KEY_SIZE, tmp.begin());
                results.push_back(tmp);
            }

            delete keyValues;
        }
    }
    //   file.close();
    Utilities::startTimer(610);
    //    fclose(file);
    hh = Utilities::stopTimer(610);
    //    printf("close time:%f\n", hh);
    auto t = Utilities::stopTimer(104);
    //    cout << "storage time:" << t << endl;
    searchTime = t - (cacheTime - previousCacheTime);
    if (Utilities::useRandomFolder) {
        fclose(file);
    }
    return results;
}

string OneChoiceStorage::getName(long dataIndex) {
    return filenames[dataIndex];
}

void OneChoiceStorage::closeHandle(long index) {
    fflush(filehandles[index]);
    fclose(filehandles[index]);
}

void OneChoiceStorage::rename(long toIndex, string inputFileName) {
    fclose(filehandles[toIndex]);
    if (std::rename(inputFileName.c_str(), filenames[toIndex].c_str()) != 0) {
        perror("Error renaming file");
    } else {
        filehandles[toIndex] = fopen(filenames[toIndex].c_str(), "rb+");
    }
}

void OneChoiceStorage::resetup(long index) {
    string filename = filenames[index];
    fstream file(filename.c_str(), std::ofstream::out);
    if (file.fail()) {
        cerr << "Error: " << strerror(errno);
    }
    long maxSize = numberOfBins[index] * sizeOfEachBin[index];
    if (Utilities::DROP_CACHE && !setupMode) {
        Utilities::startTimer(113);
        if (HDD_CACHE)system("sudo hdparm -A 0 /dev/sda > /dev/null 2>sda1");
        if (KERNEL_CACHE)system("echo 3 | sudo tee /proc/sys/vm/drop_caches > /dev/null 2>sda1");
        auto t = Utilities::stopTimer(113);
        cacheTime += t;
    }
    file.seekp(maxSize * AES_KEY_SIZE - AES_KEY_SIZE);
    //    file.seekp(0);
    //            for (long j = 0; j < maxSize; j++) {
    file.write((char*) nullKey.data(), AES_KEY_SIZE);
    //            }
    file.close();
    filehandles[index] = fopen(filename.c_str(), "rb+");
}

void OneChoiceStorage::loadCache() {
    if (CACHE_PERCENTAGE == 0) {
        return;
    }
    for (long index = 0; index < dataIndex; index++) {
        long levelSize = numberOfBins[index];
        long size = floor(levelSize * CACHE_PERCENTAGE);
        FILE* file = filehandles[index];
        if (file == NULL) {
            cerr << "Error in read: " << strerror(errno);
        }
        fseek(file, 0L, SEEK_SET);

        char* keyValue = new char[size * sizeOfEachBin[index] * AES_KEY_SIZE];
        fread(keyValue, size * sizeOfEachBin[index] * AES_KEY_SIZE, 1, file);

        for (long i = 0; i < size; i++) {
            vector<prf_type> col;
            for (int j = 0; j < sizeOfEachBin[index]; j++) {
                prf_type tmp;
                std::copy(keyValue + i * (sizeOfEachBin[index] * AES_KEY_SIZE) + j * AES_KEY_SIZE, keyValue + i * (sizeOfEachBin[index] * AES_KEY_SIZE) + j * AES_KEY_SIZE + AES_KEY_SIZE, tmp.begin());
                col.push_back(tmp);
            }
            data[index].push_back(col);
        }

        delete keyValue;
    }
}