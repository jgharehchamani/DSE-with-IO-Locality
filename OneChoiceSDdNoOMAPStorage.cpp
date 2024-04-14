#include "OneChoiceSDdNoOMAPStorage.h"
#include<assert.h>
#include<string.h>

OneChoiceSDdNoOMAPStorage::OneChoiceSDdNoOMAPStorage(bool inMemory, int dataIndex, string fileAddressPrefix, bool profile) {
    this->inMemoryStorage = inMemory;
    this->fileAddressPrefix = fileAddressPrefix;
    this->dataIndex = dataIndex;
    this->profile = profile;
    memset(nullKey.data(), 0, AES_KEY_SIZE);
    int prev = 0;
    int cprev = 0;
    for (int i = 0; i <= dataIndex; i++) {
        int j = i;
        int curNumberOfBins = j > 1 ?
                (int) ceil(((float) pow(2, j)) / (float) (log2(pow(2, j)) * log2(log2(pow(2, j))))) : 1;
        int curSizeOfEachBin = j > 1 ? 3 * (log2(pow(2, j))*(log2(log2(pow(2, j))))) : pow(2, j);
        /*if(curSizeOfEachBin*curNumberOfBins <= 2*prev*cprev)
        {
                curNumberOfBins = ceil((float)(2*prev*cprev+1)/(float)curSizeOfEachBin);
        }
        cprev = curSizeOfEachBin;
        prev = curNumberOfBins;*/
        numberOfBins.push_back(curNumberOfBins);
        sizeOfEachBin.push_back(curSizeOfEachBin);
        int is = curNumberOfBins*curSizeOfEachBin;
        //        printf("%d StLevel:%d number of Bins:%d size of bin:%d is:%d\n",j, i, curNumberOfBins, curSizeOfEachBin, is);
    }

}

bool OneChoiceSDdNoOMAPStorage::setup(bool overwrite) {
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
            int maxSize = 6 * numberOfBins[i] * sizeOfEachBin[i];
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
                    int maxSize = numberOfBins[i] * sizeOfEachBin[i];
                    for (int k = 0; k < maxSize; k++) {
                        file.write((char*) nullKey.data(), AES_KEY_SIZE);
                    }
                } else {
                    int maxSize = 6 * numberOfBins[i] * sizeOfEachBin[i];
                    for (int k = 0; k < maxSize; k++) {
                        file.write((char*) nullKey.data(), AES_KEY_SIZE);
                    }
                }
                file.close();
            }
        }
    }
}

void OneChoiceSDdNoOMAPStorage::insertAll(int index, int instance, vector<prf_type> ciphers) {
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

vector<prf_type> OneChoiceSDdNoOMAPStorage::getAllData(int index, int instance) {
    vector<prf_type> results;
    fstream file(filenames[index][instance].c_str(), ios::binary | ios::in);
    if (file.fail())
        cerr << "Error in read: " << strerror(errno);
    int actSize = sizeOfEachBin[index] * numberOfBins[index] * AES_KEY_SIZE;
    file.seekg(0, ios::beg);
    SeekG++;
    char* keyValues = new char[actSize];
    file.read(keyValues, actSize);
    file.close();
    for (int i = 0; i < actSize / AES_KEY_SIZE; i++) {
        prf_type tmp;
        std::copy(keyValues + i*AES_KEY_SIZE, keyValues + i * AES_KEY_SIZE + AES_KEY_SIZE, tmp.begin());
        //if (tmp != nullKey) 
        //{
        results.push_back(tmp);
        //if(index == 1)
        //cout <<index<<" getAll:["<<tmp.data()<<"]"<<endl;
        //}
    }
    delete keyValues;
    return results;
}

vector<prf_type> OneChoiceSDdNoOMAPStorage::getNEW(int index, int cnt, int ressize, bool NEW) //get all of NEW
{
    vector<prf_type> results;
    fstream file;
    if (NEW)
        file.open(filenames[index][3].c_str(), ios::binary | ios::in);
    else
        file.open(fileCounter[index].c_str(), ios::binary | ios::in);
    if (file.fail())
        cerr << "Error in read: " << strerror(errno);
    int readPos = cnt*AES_KEY_SIZE;
    file.seekg(0, ios::end);
    SeekG++;
    int filesize = file.tellg();
    int remainder = filesize - readPos;
    int size = AES_KEY_SIZE * ressize;
    if (size > remainder)
        size = remainder;
    file.seekg(readPos, ios::beg);
    SeekG++;
    char* keyValues = new char[size];
    file.read(keyValues, size);
    file.close();
    for (int i = 0; i < size / AES_KEY_SIZE; i++) {
        prf_type tmp;
        std::copy(keyValues + i*AES_KEY_SIZE, keyValues + i * AES_KEY_SIZE + AES_KEY_SIZE, tmp.begin());
        //if (tmp != nullKey) 
        //{
        results.push_back(tmp);
        //}
    }
    delete keyValues;
    return results;
}

void OneChoiceSDdNoOMAPStorage::truncate(int index, int size, int fileSize) {
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

int OneChoiceSDdNoOMAPStorage::writeToKW(int index, prf_type keyVal, int pos) {
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

int OneChoiceSDdNoOMAPStorage::writeToNEW(int index, prf_type keyVal, int pos) {
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

vector<prf_type> OneChoiceSDdNoOMAPStorage::getElements(int index, int instance, int start, int numOfEl) {
    assert(instance < 2);
    vector<prf_type> results;
    fstream file(filenames[index][instance].c_str(), ios::binary | ios::in | ios::ate);
    if (file.fail())
        cerr << "Error in getElements: " << strerror(errno);
    int seek = AES_KEY_SIZE*start;
    file.seekg(seek, ios::beg);
    SeekG++;
    int readLength = (numOfEl) * AES_KEY_SIZE;
    int size = numberOfBins[index] * sizeOfEachBin[index] * AES_KEY_SIZE;
    int remainder = size - seek;
    if (readLength >= remainder)
        readLength = remainder;
    if (remainder < 0)
        readLength = 0;
    char* keyValues = new char[readLength];
    //cout<<"seek:"<<seek<<" rem:"<<remainder<<" size:"<<size<< "read len:"<<readLength<<endl;
    file.read(keyValues, readLength);
    file.close();
    for (int i = 0; i < readLength / AES_KEY_SIZE; i++) {
        prf_type restmp;
        std::copy(keyValues + i*AES_KEY_SIZE, keyValues + i * AES_KEY_SIZE + AES_KEY_SIZE, restmp.begin());
        //if (restmp.data() != nullKey.data()) {
        results.push_back(restmp);
        //cout <<index<<" getEl:["<<restmp.data()<<"]"<<endl;
        //}
    }
    return results;
}

void OneChoiceSDdNoOMAPStorage::clear(int index, int instance) {
    if (inMemoryStorage) {
        data[index].clear();
    } else if (instance <= 3) {
        fstream file(filenames[index][instance].c_str(), std::ios::binary | std::ofstream::out);
        if (file.fail())
            cerr << "Error: " << strerror(errno);
        int maxSize;
        if (instance == 3)
            maxSize = 6 * numberOfBins[index] * sizeOfEachBin[index];
        else
            maxSize = numberOfBins[index] * sizeOfEachBin[index];
        for (int j = 0; j < maxSize; j++) {
            file.write((char*) nullKey.data(), AES_KEY_SIZE);
            //file.write((char*) nullKey.data(), AES_KEY_SIZE);
        }
        file.close();
    } else if (instance == 4) {
        fstream filec(fileCounter[index].c_str(), std::ios::binary | std::ofstream::out);
        if (filec.fail())
            cerr << "Error: " << strerror(errno);
        int maxSize = 6 * numberOfBins[index] * sizeOfEachBin[index];
        for (int j = 0; j < maxSize; j++) {
            filec.write((char*) nullKey.data(), AES_KEY_SIZE);
            //file.write((char*) nullKey.data(), AES_KEY_SIZE);
        }
        filec.close();
    }
}

OneChoiceSDdNoOMAPStorage::~OneChoiceSDdNoOMAPStorage() {
}

vector<prf_type> OneChoiceSDdNoOMAPStorage::searchBin(int index, int instance, int bin) {
    vector<prf_type> results;
    std::fstream file(filenames[index][instance].c_str(), ios::binary | ios::in);
    //cout<<filenames[index][instance].c_str()<<endl;
    if (file.fail())
        cerr << "Error in read: " << strerror(errno);
    int readPos = bin * AES_KEY_SIZE * sizeOfEachBin[index];
    int fileLength = numberOfBins[index] * sizeOfEachBin[index] * AES_KEY_SIZE;
    int remainder = fileLength - readPos;
    //int totalReadLength = cnt * KEY_VALUE_SIZE * sizeOfEachBin[index];
    int totalReadLength = AES_KEY_SIZE * sizeOfEachBin[index];
    int readLength = 0;
    if (totalReadLength > remainder)
        readLength = remainder;
    else
        readLength = totalReadLength;
    if (remainder < 0)
        readLength = 0;
    file.seekg(readPos, ios::beg);
    SeekG++;
    char* keyValues = new char[readLength];
    file.read(keyValues, readLength);
    readBytes += readLength;
    //cout <<"index:"<<index<<" bin:"<<bin<<" sizeOfBin:"<<sizeOfEachBin[index]<<endl;
    //cout <<"readPos:"<<readPos<<" readLen:"<<readLength<<" totalsize:"<< AES_KEY_SIZE*sizeOfEachBin[index]*numberOfBins[index]<<endl;
    //cout<<"rem:"<<remainder<<" read len:"<<readLength<<endl;
    assert(readLength >= AES_KEY_SIZE);
    for (int i = 0; i < readLength / AES_KEY_SIZE; i++) {
        prf_type restmp;
        std::copy(keyValues + i*AES_KEY_SIZE, keyValues + i * AES_KEY_SIZE + AES_KEY_SIZE, restmp.begin());
        if (restmp != nullKey) {
            results.push_back(restmp);
        }
    }
    file.close();
    return results;
}

vector<prf_type> OneChoiceSDdNoOMAPStorage::find(int index, int instance, prf_type mapKey, int cnt) {
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
