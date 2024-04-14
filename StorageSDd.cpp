#include "StorageSDd.h"
#include<string.h>

StorageSDd::StorageSDd(bool inMemory, int dataIndex, string fileAddressPrefix, bool profile) {
    this->inMemoryStorage = inMemory;
    this->fileAddressPrefix = fileAddressPrefix;
    this->dataIndex = dataIndex;
    this->profile = profile;
    memset(nullKey.data(), 0, AES_KEY_SIZE);
}

bool StorageSDd::setup(bool overwrite) {
    filenames.resize(dataIndex + 1);
    for (int i = 0; i <= dataIndex; i++) {
        filenames[i].resize(4);
        for (int j = 0; j < 4; j++) {
            string filename = fileAddressPrefix + "MAP-" + to_string(i) + "-" + to_string(j) + ".dat";
            filenames[i][j] = filename;
            fstream testfile(filename.c_str(), std::ofstream::in);
            if (testfile.fail() || overwrite) {
                testfile.close();
                fstream file(filename.c_str(), std::ofstream::out);
                if (file.fail())
                    cerr << "Error: " << strerror(errno);
                int maxSize = pow(2, i);
                int nextPtr = 0;
                for (int j = 0; j < maxSize; j++) {
                    file.write((char*) nullKey.data(), AES_KEY_SIZE);
                    file.write((char*) nullKey.data(), AES_KEY_SIZE);
                    file.write((char*) &nextPtr, sizeof (int));
                }
                //                file.write((char*) &nextPtr, sizeof (int));
                file.close();
            }
        }
    }
}

void StorageSDd::insert(int dataIndex, int instance, map<prf_type, prf_type> ciphers) {
    if (inMemoryStorage) {
        data[dataIndex].insert(ciphers.begin(), ciphers.end());
    } else {
        /*if (USE_XXL) {
            for (auto item : ciphers) {
                diskData[dataIndex]->insert(std::make_pair(item.first, item.second));
            }
        } else {*/
        int maxSize = pow(2, dataIndex);
        for (auto item : ciphers) {
            unsigned char newRecord[KEY_VALUE_SIZE];
            memset(newRecord, 0, KEY_VALUE_SIZE);
            std::copy(item.first.begin(), item.first.end(), newRecord);
            std::copy(item.second.begin(), item.second.end(), newRecord + AES_KEY_SIZE);

            unsigned char* hash = Utilities::sha256((char*) item.first.data(), AES_KEY_SIZE);
            int pos = (unsigned int) (*((int*) hash)) % maxSize;

            fstream file(filenames[dataIndex][instance].c_str(), ios::binary | ios::in | ios::out | ios::ate);
            if (file.fail()) {
                cout << "xx:" << dataIndex << endl;
                cerr << "[Error in insert: " << strerror(errno) << "]" << endl;
            }
            int tmpNextPos = file.tellp();
            file.seekg(pos * KEY_VALUE_SIZE, ios::beg);


            char chainHead[KEY_VALUE_SIZE];
            file.read(chainHead, KEY_VALUE_SIZE);
            int nextPos = 0;

            prf_type tmp;
            std::copy(chainHead, chainHead + KEY_VALUE_SIZE, tmp.begin());

            if (tmp != nullKey) {
                nextPos = tmpNextPos;
                file.seekp(nextPos, ios::beg);
                file.write(chainHead, KEY_VALUE_SIZE);
            }

            memcpy(&newRecord[2 * AES_KEY_SIZE], &nextPos, sizeof (int));
            //                for (int i = 0; i < 36; i++) {
            //                    printf("%X ", newRecord[i]);
            //                }
            //                printf("\n");


            file.seekp(pos* KEY_VALUE_SIZE, ios::beg);
            file.write((char*) newRecord, KEY_VALUE_SIZE);
            file.close();
        }

        //}
    }
}

/*
map<prf_type,prf_type> StorageSDd::getCounters(int dataIndex, int start, int length) 
{
    map<prf_type, prf_type> results;
    stream file(filenames[dataIndex][3].c_str(), ios::binary | ios::in | ios::ate);
    if (file.fail()) 
        cerr << "Error in read: " << strerror(errno);
    int size = file.tellg();
        int readLength = length*KEY_VALUE_SIZE;
        int readPos = start*KEY_VALUE_SIZE;
    file.seekg(readPos, ios::beg);
    char* keyValue = new char[readLength];
    file.read(keyValue, size);
    for (int i = 0; i < size / KEY_VALUE_SIZE; i++) 
        {
        prf_type tmp, restmp;
        std::copy(keyValue + i*KEY_VALUE_SIZE, keyValue + i * KEY_VALUE_SIZE + AES_KEY_SIZE, tmp.begin());
        std::copy(keyValue + i * KEY_VALUE_SIZE + AES_KEY_SIZE, keyValue + i * KEY_VALUE_SIZE + AES_KEY_SIZE + AES_KEY_SIZE, restmp.begin());
        if (tmp != nullKey) 
                {
            results[tmp]=restmp;
        }
    }

    file.close();
    delete keyValue;
    return results;
}
 */


vector<pair<prf_type, prf_type>> StorageSDd::getAll(int dataIndex, int instance) {
    vector<pair<prf_type, prf_type>> results;
    fstream file(filenames[dataIndex][instance].c_str(), ios::binary | ios::in | ios::ate);
    if (file.fail()) {
        cerr << "Error in read: " << strerror(errno);
    }
    int size = file.tellg();
    file.seekg(0, ios::beg);
    char* keyValue = new char[size];
    file.read(keyValue, size);

    for (int i = 0; i < size / KEY_VALUE_SIZE; i++) {
        prf_type tmp, restmp;
        std::copy(keyValue + i*KEY_VALUE_SIZE, keyValue + i * KEY_VALUE_SIZE + AES_KEY_SIZE, tmp.begin());
        std::copy(keyValue + i * KEY_VALUE_SIZE + AES_KEY_SIZE, keyValue + i * KEY_VALUE_SIZE + AES_KEY_SIZE + AES_KEY_SIZE, restmp.begin());
        if (tmp != nullKey) {

            results.push_back(make_pair(tmp, restmp));
        }
    }

    file.close();
    delete keyValue;
    return results;
}

map<prf_type, prf_type> StorageSDd::getAllData(int dataIndex, int instance) {
    map<prf_type, prf_type> results;
    /*
if (USE_XXL) {
    for (auto item : (*diskData[dataIndex])) {
        results.push_back(item.second);
    }
} else {*/
    fstream file(filenames[dataIndex][instance].c_str(), ios::binary | ios::in | ios::ate);
    if (file.fail()) {
        cerr << "Error in read: " << strerror(errno);
    }
    int size = file.tellg();
    file.seekg(0, ios::beg);
    char* keyValue = new char[size];
    file.read(keyValue, size);

    for (int i = 0; i < size / KEY_VALUE_SIZE; i++) {
        prf_type tmp, restmp;
        std::copy(keyValue + i*KEY_VALUE_SIZE, keyValue + i * KEY_VALUE_SIZE + AES_KEY_SIZE, tmp.begin());
        std::copy(keyValue + i * KEY_VALUE_SIZE + AES_KEY_SIZE, keyValue + i * KEY_VALUE_SIZE + AES_KEY_SIZE + AES_KEY_SIZE, restmp.begin());
        if (tmp != nullKey) {

            results[tmp] = restmp;
        }
    }

    file.close();
    delete keyValue;
    return results;
}

void StorageSDd::clear(int index, int instance) {
    if (inMemoryStorage) {
        data[index].clear();
    } else {
        /*
    if (USE_XXL) {
        diskData[index]->clear();
    } else {*/
        fstream file(filenames[index][instance].c_str(), std::ios::binary | std::ofstream::out);
        if (file.fail()) {
            cerr << "Error: " << strerror(errno);
        }
        int maxSize = pow(2, index);
        int nextPtr = 0;
        for (int j = 0; j < maxSize; j++) {
            file.write((char*) nullKey.data(), AES_KEY_SIZE);
            file.write((char*) nullKey.data(), AES_KEY_SIZE);
            file.write((char*) &nextPtr, sizeof (int));
        }
        file.close();
        //}
    }
}

StorageSDd::~StorageSDd() {
}

prf_type StorageSDd::find(int index, int instance, prf_type mapKey, bool& found) {
    prf_type result;
    if (inMemoryStorage) {
        if (data[index].count(mapKey) == 0) {
            found = false;
            return result;
        } else {
            found = true;
            return data[index][mapKey];
        }
    } else {
        /*
    if (USE_XXL) {
        if (diskData[index]->count(mapKey) == 0) {
            found = false;
            return result;
        } else {
            found = true;
            return (*diskData[index])[mapKey];
        }
    } else {*/

        std::fstream file(filenames[index][instance].c_str(), ios::binary | ios::in);
        if (file.fail()) {
            cerr << "Error in read: " << strerror(errno);
        }
        unsigned char* hash = Utilities::sha256((char*) mapKey.data(), AES_KEY_SIZE);
        int maxSize = pow(2, index);
        int readPos = (unsigned int) (*((int*) hash)) % maxSize;
        readPos = readPos*KEY_VALUE_SIZE;

        do {
            file.seekg(readPos, ios::beg);
            if (profile) {
                seekgCount++;
            }
            char chain[KEY_VALUE_SIZE];
            file.read(chain, KEY_VALUE_SIZE);
            prf_type tmp, restmp;
            std::copy(chain, chain + AES_KEY_SIZE, tmp.begin());
            std::copy(chain + AES_KEY_SIZE, chain + (2 * AES_KEY_SIZE), restmp.begin());
            memcpy(&readPos, chain + 2 * AES_KEY_SIZE, sizeof (int));
            if (tmp == mapKey) {
                file.close();
                found = true;
                return restmp;
            }

        } while (readPos != 0);
        file.close();
        found = false;
        return nullKey;
        //}
    }
}

void StorageSDd::move(int index, int toInstance, int fromInstance) {
    fstream infile(filenames[index][fromInstance].c_str(), ios::binary | ios::in | ios::out | ios::ate);
    if (infile.fail())
        cerr << "Error in read in move: " << strerror(errno);
    infile.seekg(0, ios::end);
    int infileSize = infile.tellg();
    //SeekG++;
    infile.seekg(0, ios::beg);
    //SeekG++;
    char* keyValues = new char[infileSize];
    infile.read(keyValues, infileSize);
    int maxSize = pow(2, index);
    int nextPtr = 0;
    for (int j = 0; j < maxSize; j++) {
        infile.write((char*) nullKey.data(), AES_KEY_SIZE);
        infile.write((char*) nullKey.data(), AES_KEY_SIZE);
        infile.write((char*) &nextPtr, sizeof (int));
    }
    infile.close();

    fstream outfile(filenames[index][toInstance].c_str(), ios::binary | ios::out);
    if (outfile.fail())
        cerr << "Error in write in move: " << strerror(errno);
    outfile.seekg(0, ios::beg);
    //SeekG++;
    outfile.write(keyValues, infileSize);
    outfile.close();
    delete keyValues;
}
