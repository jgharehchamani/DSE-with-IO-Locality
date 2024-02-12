#include "OneChoiceSDdOMAPStorage.h"
#include<assert.h>
#include<string.h>

OneChoiceSDdOMAPStorage::OneChoiceSDdOMAPStorage(bool inMemory, int dataIndex, string fileAddressPrefix, bool profile) {
    this->inMemoryStorage = inMemory;
    this->fileAddressPrefix = fileAddressPrefix;
    this->dataIndex = dataIndex;
    this->profile = profile;
    memset(nullKey.data(), 0, AES_KEY_SIZE);
    for (int j = 0; j <= dataIndex; j++) {
        int curNumberOfBins = j > 1 ?
                (int) ceil(((float) pow(2, j)) / (float) (log2(pow(2, j)) * log2(log2(pow(2, j))))) : 1;
        int curSizeOfEachBin = j > 1 ? 3 * (log2(pow(2, j))*(log2(log2(pow(2, j))))) : pow(2, j);
        numberOfBins.push_back(curNumberOfBins);
        sizeOfEachBin.push_back(curSizeOfEachBin);
        int is = curNumberOfBins*curSizeOfEachBin;
        //printf("Storage:%d #of Bins:%d size of bin:%d is:%d\n", j, curNumberOfBins, curSizeOfEachBin, is);
    }

}

bool OneChoiceSDdOMAPStorage::setup(bool overwrite) {
    filenames.resize(dataIndex + 1);
    fileCounter.resize(dataIndex + 1);
    for (int i = 0; i <= dataIndex; i++) {
        string filec = fileAddressPrefix + "CNT-" + to_string(i) + "-" + ".dat";
        fileCounter[i] = filec;
        fstream testfile(filec.c_str(), std::ofstream::in);
        if (testfile.fail() || overwrite) {
            testfile.close();
            fstream file(filec.c_str(), std::ofstream::out);
            if (file.fail())
                cerr << "Error: " << strerror(errno);
            int maxSize = 8 * numberOfBins[i] * sizeOfEachBin[i];
            for (int k = 0; k < maxSize; k++) {
                file.write((char*) nullKey.data(), AES_KEY_SIZE);
            }
            file.close();
        }
        filenames[i].resize(4);
        for (int j = 0; j < 4; j++) {
            string filename = fileAddressPrefix + "SDD-" + to_string(i) + "-" + to_string(j) + ".dat";
            filenames[i][j] = filename;
            fstream testfile(filename.c_str(), std::ofstream::in);
            if (testfile.fail() || overwrite) {
                testfile.close();
                fstream file(filename.c_str(), std::ofstream::out);
                if (file.fail())
                    cerr << "Error: " << strerror(errno);
                if (j < 3) {
                    int maxSize = 8 * numberOfBins[i] * sizeOfEachBin[i];
                    for (int k = 0; k < maxSize; k++) {
                        file.write((char*) nullKey.data(), AES_KEY_SIZE);
                    }
                } else {
                    int maxSize = 8 * numberOfBins[i] * sizeOfEachBin[i];
                    for (int k = 0; k < maxSize; k++) {
                        file.write((char*) nullKey.data(), AES_KEY_SIZE);
                    }
                }
                file.close();
            }
        }
    }
}

void OneChoiceSDdOMAPStorage::insertAll(int index, int instance, vector<prf_type> ciphers) {
    fstream file;
    if (instance <= 3)
        file.open(filenames[index][instance].c_str(), ios::binary | ios::out);
    else
        file.open(fileCounter[index].c_str(), ios::binary | ios::out);
    if (file.fail())
        cerr << "Error in insert: " << strerror(errno) << endl;

    file.seekg(0, ios::beg);
    SeekG++;
    for (auto ci : ciphers) {
        unsigned char newRecord[AES_KEY_SIZE];
        memset(newRecord, 0, AES_KEY_SIZE);
        std::copy(ci.begin(), ci.end(), newRecord);
        file.write((char*) newRecord, AES_KEY_SIZE);
    }
    file.close();
}

void OneChoiceSDdOMAPStorage::insertAll(int index, int instance, vector<vector<prf_type>> ciphers) {
    fstream file(filenames[index][instance].c_str(), ios::binary | ios::out);
    if (file.fail())
        cerr << "Error in insert: " << strerror(errno) << endl;

    file.seekg(0, ios::beg);
    SeekG++;
    for (auto bin : ciphers) {
        for (auto ci : bin) {
            unsigned char newRecord[AES_KEY_SIZE];
            memset(newRecord, 0, AES_KEY_SIZE);
            std::copy(ci.begin(), ci.end(), newRecord);
            file.write((char*) newRecord, AES_KEY_SIZE);
        }
    }
    file.close();
}

vector<prf_type> OneChoiceSDdOMAPStorage::getAllData(int index, int instance) {
    vector<prf_type> results;
    fstream file(filenames[index][instance].c_str(), ios::binary | ios::in);
    if (file.fail())
        cerr << "Error in read getAllData OneChoiceSDdOMAPStorage: " << strerror(errno);
    int actSize = sizeOfEachBin[index] * numberOfBins[index] * AES_KEY_SIZE;
    file.seekg(0, ios::beg);
    SeekG++;
    char* keyValues = new char[actSize];
    file.read(keyValues, actSize);
    file.close();
    for (int i = 0; i < actSize / AES_KEY_SIZE; i++) {
        prf_type tmp;
        std::copy(keyValues + i*AES_KEY_SIZE, keyValues + i * AES_KEY_SIZE + AES_KEY_SIZE, tmp.begin());
        results.push_back(tmp);
    }
    delete keyValues;
    return results;
}

vector<prf_type> OneChoiceSDdOMAPStorage::getKW(int index, int start, int numOfEl) {
    vector<prf_type> results;
    fstream file(fileCounter[index].c_str(), ios::binary | ios::in | ios::ate);
    if (file.fail())
        cerr << "Error in getKW: " << strerror(errno);
    int seek = AES_KEY_SIZE*start;
    file.seekg(seek, ios::beg);
    SeekG++;
    int readLength = (numOfEl) * AES_KEY_SIZE;
    int size = 8 * numberOfBins[index] * sizeOfEachBin[index] * AES_KEY_SIZE;
    int remainder = size - seek;
    if (readLength >= remainder)
        readLength = remainder;
    if (remainder < 0)
        readLength = 0;
    char* keyValues = new char[readLength];
    file.read(keyValues, readLength);
    file.close();
    for (int i = 0; i < readLength / AES_KEY_SIZE; i++) {
        prf_type restmp;
        std::copy(keyValues + i*AES_KEY_SIZE, keyValues + i * AES_KEY_SIZE + AES_KEY_SIZE, restmp.begin());
        results.push_back(restmp);
    }
    delete keyValues;
    return results;
}

void OneChoiceSDdOMAPStorage::truncate(int index, int size, int fileSize) {
    fstream file(filenames[index][3].c_str(), ios::binary | ios::out | ios::in | ios::ate);
    if (file.fail())
        cerr << "Error in truncate: " << strerror(errno);
    int filesize = fileSize*AES_KEY_SIZE;
    int seek = AES_KEY_SIZE*size;
    int rem = filesize - seek;
    file.seekg(seek, ios::beg);
    SeekG++;
    for (int j = 0; j < (fileSize - size); j++) {
        file.write((char*) nullKey.data(), AES_KEY_SIZE);
    }
    file.close();
}

void OneChoiceSDdOMAPStorage::move(int index, int toInstance, int fromInstance, int size) {
    fstream infile(filenames[index][fromInstance].c_str(), ios::binary | ios::in);
    if (infile.fail())
        cerr << "Error in read in move: " << strerror(errno);
    infile.seekg(0, ios::beg);
    SeekG++;
    char* keyValues = new char[size * AES_KEY_SIZE];
    infile.read(keyValues, size * AES_KEY_SIZE);
    infile.close();

    fstream outfile(filenames[index][toInstance].c_str(), ios::binary | ios::out);
    if (outfile.fail())
        cerr << "Error in write in move: " << strerror(errno);
    outfile.seekg(0, ios::beg);
    SeekG++;
    outfile.write(keyValues, size * AES_KEY_SIZE);
    outfile.close();
    delete keyValues;
}

int OneChoiceSDdOMAPStorage::writeToKW(int index, prf_type keyVal, int pos) {
    fstream file(fileCounter[index].c_str(), ios::binary | ios::out | ios::in | ios::ate);
    if (file.fail())
        cerr << "Error in writeToKW: " << strerror(errno);
    int seek = AES_KEY_SIZE*pos;
    file.seekg(seek, ios::beg); //
    SeekG++;
    unsigned char newRecord[AES_KEY_SIZE];
    memset(newRecord, 0, AES_KEY_SIZE);
    std::copy(keyVal.begin(), keyVal.end(), newRecord);
    file.write((char*) newRecord, AES_KEY_SIZE);
    int last = file.tellg();
    file.close();
    return last;
}

int OneChoiceSDdOMAPStorage::writeToNEW(int index, prf_type keyVal, int pos) {
    fstream file(filenames[index][3].c_str(), ios::binary | ios::out | ios::in | ios::ate);
    if (file.fail())
        cerr << "Error in writeToNEW: " << strerror(errno);
    int seek = AES_KEY_SIZE*pos;
    file.seekg(seek, ios::beg); //
    SeekG++;
    unsigned char newRecord[AES_KEY_SIZE];
    memset(newRecord, 0, AES_KEY_SIZE);
    std::copy(keyVal.begin(), keyVal.end(), newRecord);
    file.write((char*) newRecord, AES_KEY_SIZE);
    int last = file.tellg();
    file.close();
    return last;
}

int OneChoiceSDdOMAPStorage::putElements(int index, int instance, int start, int end, vector<prf_type> elems) {
    fstream file;
    if (instance <= 3)
        file.open(filenames[index][instance].c_str(), ios::binary | ios::out | ios::in | ios::ate);
    else
        file.open(fileCounter[index].c_str(), ios::binary | ios::out | ios::in | ios::ate);
    //fstream file(filenames[index][instance].c_str(), ios::binary | ios::out | ios::in | ios::ate);
    if (file.fail())
        cerr << "Error in putElements: " << instance << " " << strerror(errno);
    int seek = AES_KEY_SIZE*start;
    file.seekg(seek, ios::beg); //
    SeekG++;
    unsigned char newRecord[AES_KEY_SIZE];
    //cout <<"putting:"<<instance<<endl;
    for (auto keyVal : elems) {
        memset(newRecord, 0, AES_KEY_SIZE);
        std::copy(keyVal.begin(), keyVal.end(), newRecord);
        file.write((char*) newRecord, AES_KEY_SIZE);
    }
    int last = file.tellg();
    file.close();
    return last;
}

vector<prf_type> OneChoiceSDdOMAPStorage::getElements(int index, int instance, int start, int numOfEl) {
    vector<prf_type> results;
    fstream file;
    if (instance <= 3)
        file.open(filenames[index][instance].c_str(), ios::binary | ios::in | ios::ate);
    else
        file.open(fileCounter[index].c_str(), ios::binary | ios::in | ios::ate);
    //fstream file(filenames[index][instance].c_str(), ios::binary | ios::in | ios::ate);
    if (file.fail())
        cerr << "Error in getElements: " << strerror(errno);
    int seek = AES_KEY_SIZE*start;
    file.seekg(seek, ios::beg);
    SeekG++;
    int readLength = numOfEl * AES_KEY_SIZE;
    int size = 8 * numberOfBins[index] * sizeOfEachBin[index] * AES_KEY_SIZE;
    //cout <<"readPos:"<<seek<<"-"<<numOfEl<<"/"<<8*numberOfBins[index]*sizeOfEachBin[index]<<endl;
    int remainder = size - seek;
    if (readLength >= remainder)
        readLength = remainder;
    if (remainder < 0)
        readLength = 0;
    char* keyValues = new char[readLength];
    file.read(keyValues, readLength);
    file.close();
    for (int i = 0; i < readLength / AES_KEY_SIZE; i++) {
        prf_type restmp;
        std::copy(keyValues + i*AES_KEY_SIZE, keyValues + i * AES_KEY_SIZE + AES_KEY_SIZE, restmp.begin());
        results.push_back(restmp);
    }
    delete keyValues;
    return results;
}

void OneChoiceSDdOMAPStorage::clear(int index, int instance) {
    if (inMemoryStorage) {
        data[index].clear();
    } else if (instance <= 3) {
        fstream file(filenames[index][instance].c_str(), std::ios::binary | std::ofstream::out);
        if (file.fail())
            cerr << "Error: " << strerror(errno);
        int maxSize;
        if (instance == 3)
            maxSize = 8 * numberOfBins[index] * sizeOfEachBin[index];
        else
            maxSize = 8 * numberOfBins[index] * sizeOfEachBin[index];
        for (int j = 0; j < maxSize; j++) {
            file.write((char*) nullKey.data(), AES_KEY_SIZE);
            //file.write((char*) nullKey.data(), AES_KEY_SIZE);
        }
        file.close();
    } else if (instance == 4) {
        fstream filec(fileCounter[index].c_str(), std::ios::binary | std::ofstream::out);
        if (filec.fail())
            cerr << "Error: " << strerror(errno);
        int maxSize = 8 * numberOfBins[index] * sizeOfEachBin[index];
        for (int j = 0; j < maxSize; j++) {
            filec.write((char*) nullKey.data(), AES_KEY_SIZE);
        }
        filec.close();
    }
}

OneChoiceSDdOMAPStorage::~OneChoiceSDdOMAPStorage() {
}

vector<prf_type> OneChoiceSDdOMAPStorage::find(int index, int instance, prf_type mapKey, int cnt) {
    vector<prf_type> results;
    std::fstream file(filenames[index][instance].c_str(), ios::binary | ios::in);
    if (file.fail())
        cerr << "Error in read: " << strerror(errno);
    int fileLength = numberOfBins[index] * sizeOfEachBin[index] * AES_KEY_SIZE;
    int totalReadLength = cnt * AES_KEY_SIZE * sizeOfEachBin[index];
    int readLength = 0;
    if (totalReadLength > fileLength) {
        readLength = fileLength;
        file.seekg(0, ios::beg);
        SeekG++;
        char* keyValues = new char[readLength];
        file.read(keyValues, readLength);
        readBytes += readLength;
        for (int i = 0; i < readLength / AES_KEY_SIZE; i++) {
            prf_type restmp;
            std::copy(keyValues + i*AES_KEY_SIZE, keyValues + i * AES_KEY_SIZE + AES_KEY_SIZE, restmp.begin());
            if (restmp != nullKey)
                results.push_back(restmp);
        }
        delete keyValues;
    } else {
        unsigned char* hash = Utilities::sha256((char*) mapKey.data(), AES_KEY_SIZE);
        int pos = (unsigned int) (*((int*) hash)) % numberOfBins[index];
        int readPos = pos * AES_KEY_SIZE * sizeOfEachBin[index];
        int remainder = fileLength - readPos;
        if (totalReadLength > remainder) {
            readLength = remainder;
            totalReadLength = totalReadLength - readLength;
        } else {
            readLength = totalReadLength;
            totalReadLength = 0;
        }
        file.seekg(readPos, ios::beg);
        SeekG++;
        char* keyValues = new char[readLength];
        file.read(keyValues, readLength);
        readBytes += readLength;
        for (int i = 0; i < readLength / AES_KEY_SIZE; i++) {
            prf_type restmp;
            std::copy(keyValues + i*AES_KEY_SIZE, keyValues + i * AES_KEY_SIZE + AES_KEY_SIZE, restmp.begin());
            if (restmp != nullKey)
                results.push_back(restmp);
        }
        delete keyValues;
        if (totalReadLength > 0) {
            file.seekg(0, ios::beg);
            SeekG++;
            char* keyValues2 = new char[totalReadLength];
            file.read(keyValues2, totalReadLength);
            readBytes += totalReadLength;
            for (int i = 0; i < totalReadLength / AES_KEY_SIZE; i++) {
                prf_type restmp;
                std::copy(keyValues2 + i*AES_KEY_SIZE, keyValues2 + i * AES_KEY_SIZE + AES_KEY_SIZE, restmp.begin());
                if (restmp != nullKey)
                    results.push_back(restmp);
            }
            delete keyValues2;
        }
    }
    file.close();
    return results;
}
