#include "TransientStorage2D.h"
#include "assert.h"

TransientStorage2D::TransientStorage2D(bool inMemory, long dataIndex, string fileAddressPrefix, bool profile, int D1, int D2, int D3) {
    this->inMemoryStorage = inMemory;
    this->fileAddressPrefix = fileAddressPrefix;
    this->dataIndex = dataIndex;
    this->profile = profile;
    memset(nullKey.data(), 0, AES_KEY_SIZE);
    this->D1 = D1;
    this->D2 = D2;
    this->D3 = D3;
    counter = new int*[D1];
    for (int i = 0; i < D1; i++) {
        counter[i] = new int[D2];
        for (int j = 0; j < D2; j++) {
            counter[i][j] = 0;
        }
    }
}

bool TransientStorage2D::setup(bool overwrite, int index) {
    for (long i = 0; i < dataIndex; i++) {
        string filename = fileAddressPrefix + "MAP-" + to_string(i) + ".dat";
        filenames.push_back(filename);
        //fstream testfile(filename.c_str(), std::ofstream::in);
        if (index == i) {
            FILE* testfile = fopen(filename.c_str(), "rb");
            if (testfile == NULL || overwrite) {
                //                long maxSize = pow(2, i + 1); //double the size
                //                system(("dd if=/dev/zero of=" + filename + "  bs=" + to_string(D3 * KEY_VALUE_SIZE) + "  count=" + to_string(D1 * D2) + ">/dev/null 2>&1").c_str());

                //                long maxSize = pow(2, i + 1); //double the size                                                                                              
                long alloc_size = ((long) D1 * D2 * D3 * KEY_VALUE_SIZE);
                while (alloc_size > 0) {
                    long bs = min(alloc_size, 2147483648);
                    string command = string("dd if=/dev/zero bs=" + to_string(bs) + " count=1 status=none >> " + filename);
//                    cout << "command:" << command << endl;
                    system(command.c_str());
                    alloc_size -= bs;
                }

            } else {
                fclose(testfile);
            }
            if (switchToOPEN) {
                FILE* file = fopen(filename.c_str(), "rb+");
                filehandles.push_back(file);
            }
        } else {
            filehandles.push_back(NULL);
        }
    }
}

//void TransientStorage2D::insertPairList(long dataIndex, map<long, pair<prf_type, prf_type> > ciphers,int d1,int d2) {
//    long maxSize = pow(2, dataIndex + 1);
//    //fstream file(filenames[dataIndex].c_str(), ios::binary | ios::in | ios::out | ios::ate);
//    FILE* file;
//    if (switchToOPEN) {
//        file = filehandles[dataIndex];
//    } else {
//        file = fopen(filenames[dataIndex].c_str(), "rb+");
//    }
//
//    //    FILE* file = filehandles[dataIndex];
//    for (auto item : ciphers) {
//        unsigned char newRecord[KEY_VALUE_SIZE];
//        memset(newRecord, 0, KEY_VALUE_SIZE);
//        std::copy(item.second.first.begin(), item.second.first.end(), newRecord);
//        std::copy(item.second.second.begin(), item.second.second.end(), newRecord + AES_KEY_SIZE);
//        long pos = item.first; //(unsigned long) (*((long*) hash)) % maxSize;
//        if (Utilities::DROP_CACHE && !setupMode) {
//            Utilities::startTimer(113);
//            if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
//            if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
//            auto t = Utilities::stopTimer(113);
//            cacheTime += t;
//            //            cout << "cache time:" << t << endl;
//        }
//        fseek(file, pos*KEY_VALUE_SIZE, SEEK_SET);
//        //file.write((char*) newRecord, KEY_VALUE_SIZE);
//        fwrite((char*) newRecord, KEY_VALUE_SIZE, 1, file);
//        counter++;
//        //        }
//        //cout<<endl;
//    }
//    fflush(file);
//
//    //	file.close();
//    if (!switchToOPEN) {
//        fclose(file);
//    }
//
//}
//

void TransientStorage2D::insertPair(long dataIndex, pair<prf_type, prf_type> cipher, int d1, int d2) {
    long maxSize = pow(2, dataIndex + 1);
    //    FILE* file = filehandles[dataIndex];
    FILE* file;
    if (switchToOPEN) {
        file = filehandles[dataIndex];
    } else {
        file = fopen(filenames[dataIndex].c_str(), "rb+");
    }
    unsigned char newRecord[KEY_VALUE_SIZE];
    memset(newRecord, 0, KEY_VALUE_SIZE);
    std::copy(cipher.first.begin(), cipher.first.end(), newRecord);
    std::copy(cipher.second.begin(), cipher.second.end(), newRecord + AES_KEY_SIZE);
    long pos = counter[d1][d2]; //(unsigned long) (*((long*) hash)) % maxSize;
    if (Utilities::DROP_CACHE && !setupMode) {
        Utilities::startTimer(113);
        if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
        if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
        auto t = Utilities::stopTimer(113);
        cacheTime += t;
    }
    fseek(file, (d1 * D2 + d2) * D3 * KEY_VALUE_SIZE + pos*KEY_VALUE_SIZE, SEEK_SET);
    fwrite((char*) newRecord, KEY_VALUE_SIZE, 1, file);
    fflush(file);
    counter[d1][d2]++;
    if (!switchToOPEN) {
        fclose(file);
    }
}

void TransientStorage2D::insertVectorOfPairs(long dataIndex, vector<pair<prf_type, prf_type> > ciphers, int d1, int d2) {
    //    FILE* file = filehandles[dataIndex];
    FILE* file;
    if (switchToOPEN) {
        file = filehandles[dataIndex];
    } else {
        file = fopen(filenames[dataIndex].c_str(), "rb+");
    }
    long pos = 0; //(unsigned long) (*((long*) hash)) % maxSize;
    if (Utilities::DROP_CACHE && !setupMode) {
        Utilities::startTimer(113);
        if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
        if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
        auto t = Utilities::stopTimer(113);
        cacheTime += t;
    }
    fseek(file, (d1 * D2 + d2) * D3 * KEY_VALUE_SIZE + pos*KEY_VALUE_SIZE, SEEK_SET);
    for (int i = 0; i < ciphers.size(); i++) {
        pair<prf_type, prf_type> cipher = ciphers[i];
        unsigned char newRecord[KEY_VALUE_SIZE];
        memset(newRecord, 0, KEY_VALUE_SIZE);
        std::copy(cipher.first.begin(), cipher.first.end(), newRecord);
        std::copy(cipher.second.begin(), cipher.second.end(), newRecord + AES_KEY_SIZE);
        fwrite((char*) newRecord, KEY_VALUE_SIZE, 1, file);
    }
    counter[d1][d2] = ciphers.size();
    fflush(file);
    if (!switchToOPEN) {
        fclose(file);
    }

}

//void TransientStorage2D::AddVectorOfPairs(long dataIndex, vector<pair<prf_type, prf_type> > ciphers, int d1, int d2) {
//    //    FILE* file = filehandles[dataIndex];
//    FILE* file;
//    if (switchToOPEN) {
//        file = filehandles[dataIndex];
//    } else {
//        file = fopen(filenames[dataIndex].c_str(), "rb+");
//    }
//    long pos = counter; //(unsigned long) (*((long*) hash)) % maxSize;
//    if (Utilities::DROP_CACHE && !setupMode) {
//        Utilities::startTimer(113);
//        if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
//        if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
//        auto t = Utilities::stopTimer(113);
//        cacheTime += t;
//    }
//    fseek(file, pos*KEY_VALUE_SIZE, SEEK_SET);
//    for (int i = 0; i < ciphers.size(); i++) {
//        pair<prf_type, prf_type> cipher = ciphers[i];
//        unsigned char newRecord[KEY_VALUE_SIZE];
//        memset(newRecord, 0, KEY_VALUE_SIZE);
//        std::copy(cipher.first.begin(), cipher.first.end(), newRecord);
//        std::copy(cipher.second.begin(), cipher.second.end(), newRecord + AES_KEY_SIZE);
//        fwrite((char*) newRecord, KEY_VALUE_SIZE, 1, file);
//    }
//    counter += ciphers.size();
//    fflush(file);
//    if (!switchToOPEN) {
//        fclose(file);
//    }
//
//}
//
//void TransientStorage2D::setVectorOfPairs(long dataIndex, long index, vector<pair<prf_type, prf_type> > ciphers, int d1, int d2) {
//    //    FILE* file = filehandles[dataIndex];
//    FILE* file;
//    if (switchToOPEN) {
//        file = filehandles[dataIndex];
//    } else {
//        file = fopen(filenames[dataIndex].c_str(), "rb+");
//    }
//    long count = min((long) ciphers.size(), (long) counter - index);
//    if (count < ciphers.size()) {
//        cout << "there is no storage in Transient Storage" << endl;
//    }
//    long pos = index; //(unsigned long) (*((long*) hash)) % maxSize;
//    if (Utilities::DROP_CACHE && !setupMode) {
//        Utilities::startTimer(113);
//        if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
//        if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
//        auto t = Utilities::stopTimer(113);
//        cacheTime += t;
//    }
//    fseek(file, pos*KEY_VALUE_SIZE, SEEK_SET);
//    for (int i = 0; i < count; i++) {
//        pair<prf_type, prf_type> cipher = ciphers[i];
//        unsigned char newRecord[KEY_VALUE_SIZE];
//        memset(newRecord, 0, KEY_VALUE_SIZE);
//        std::copy(cipher.first.begin(), cipher.first.end(), newRecord);
//        std::copy(cipher.second.begin(), cipher.second.end(), newRecord + AES_KEY_SIZE);
//        fwrite((char*) newRecord, KEY_VALUE_SIZE, 1, file);
//    }
//    fflush(file);
//    if (!switchToOPEN) {
//        fclose(file);
//    }
//
//}
//
//void TransientStorage2D::setVectorOfEntries(long dataIndex, long index, vector<prf_type> ciphers, int d1, int d2) {
//    //    FILE* file = filehandles[dataIndex];
//    FILE* file;
//    if (switchToOPEN) {
//        file = filehandles[dataIndex];
//    } else {
//        file = fopen(filenames[dataIndex].c_str(), "rb+");
//    }
//    long count = min((long) ciphers.size(), (long) counter - index);
//    if (count < ciphers.size()) {
//        cout << "there is no storage in Transient Storage" << endl;
//    }
//    long pos = index; //(unsigned long) (*((long*) hash)) % maxSize;
//    if (Utilities::DROP_CACHE && !setupMode) {
//        Utilities::startTimer(113);
//        if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
//        if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
//        auto t = Utilities::stopTimer(113);
//        cacheTime += t;
//    }
//    fseek(file, pos*KEY_VALUE_SIZE, SEEK_SET);
//    for (int i = 0; i < count; i++) {
//        unsigned char newRecord[KEY_VALUE_SIZE];
//        memset(newRecord, 0, KEY_VALUE_SIZE);
//        std::copy(ciphers[i].begin(), ciphers[i].end(), newRecord);
//        fwrite((char*) newRecord, KEY_VALUE_SIZE, 1, file);
//    }
//    fflush(file);
//    if (!switchToOPEN) {
//        fclose(file);
//    }
//
//}
//

void TransientStorage2D::insertVectorOfTriples(long dataIndex, vector<pair<pair<prf_type, prf_type>, prf_type> > ciphers, int d1, int d2) {
    FILE* file;
    if (switchToOPEN) {
        file = filehandles[dataIndex];
    } else {
        file = fopen(filenames[dataIndex].c_str(), "rb+");
    }
    long pos = 0; //(unsigned long) (*((long*) hash)) % maxSize;
    if (Utilities::DROP_CACHE && !setupMode) {
        Utilities::startTimer(113);
        if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
        if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
        auto t = Utilities::stopTimer(113);
        cacheTime += t;
    }
    fseek(file, (d1 * D2 + d2) * D3 * KEY_VALUE_SIZE + pos*KEY_VALUE_SIZE, SEEK_SET);
    for (int i = 0; i < ciphers.size(); i++) {
        pair<pair<prf_type, prf_type>, prf_type> cipher = ciphers[i];
        unsigned char newRecord[KEY_VALUE_SIZE];
        memset(newRecord, 0, KEY_VALUE_SIZE);
        std::copy(cipher.first.first.begin(), cipher.first.first.end(), newRecord);
        std::copy(cipher.first.second.begin(), cipher.first.second.end(), newRecord + AES_KEY_SIZE);
        std::copy(cipher.second.begin(), cipher.second.end(), newRecord + AES_KEY_SIZE * 2);
        fwrite((char*) newRecord, KEY_VALUE_SIZE, 1, file);
    }
    counter[d1][d2] = ciphers.size();
    fflush(file);
    if (!switchToOPEN) {
        fclose(file);
    }

}
//
//void TransientStorage2D::insertPairAndInt(long dataIndex, prf_type p1, prf_type p2, unsigned int p3, int d1, int d2) {
//    FILE* file;
//    if (switchToOPEN) {
//        file = filehandles[dataIndex];
//    } else {
//        file = fopen(filenames[dataIndex].c_str(), "rb+");
//    }
//    unsigned char newRecord[KEY_VALUE_SIZE];
//    memset(newRecord, 0, KEY_VALUE_SIZE);
//    std::copy(p1.begin(), p1.end(), newRecord);
//    std::copy(p2.begin(), p2.end(), newRecord + AES_KEY_SIZE);
//    *((unsigned int*) &newRecord[AES_KEY_SIZE * 2]) = p3;
//    long pos = counter; //(unsigned long) (*((long*) hash)) % maxSize;
//    if (Utilities::DROP_CACHE && !setupMode) {
//        Utilities::startTimer(113);
//        if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
//        if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
//        auto t = Utilities::stopTimer(113);
//        cacheTime += t;
//    }
//    fseek(file, pos*KEY_VALUE_SIZE, SEEK_SET);
//    fwrite((char*) newRecord, KEY_VALUE_SIZE, 1, file);
//    fflush(file);
//    counter++;
//    if (!switchToOPEN) {
//        fclose(file);
//    }
//}
//
//void TransientStorage2D::setPair(long dataIndex, long index, pair<prf_type, prf_type> cipher, int d1, int d2) {
//    long maxSize = pow(2, dataIndex + 1);
//    FILE* file;
//    if (switchToOPEN) {
//        file = filehandles[dataIndex];
//    } else {
//        file = fopen(filenames[dataIndex].c_str(), "rb+");
//    }
//    unsigned char newRecord[KEY_VALUE_SIZE];
//    memset(newRecord, 0, KEY_VALUE_SIZE);
//    std::copy(cipher.first.begin(), cipher.first.end(), newRecord);
//    std::copy(cipher.second.begin(), cipher.second.end(), newRecord + AES_KEY_SIZE);
//    long pos = index; //(unsigned long) (*((long*) hash)) % maxSize;
//    if (Utilities::DROP_CACHE && !setupMode) {
//        Utilities::startTimer(113);
//        if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
//        if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
//        auto t = Utilities::stopTimer(113);
//        cacheTime += t;
//    }
//    fseek(file, pos*KEY_VALUE_SIZE, SEEK_SET);
//    fwrite((char*) newRecord, KEY_VALUE_SIZE, 1, file);
//    fflush(file);
//    if (!switchToOPEN) {
//        fclose(file);
//    }
//}
//

void TransientStorage2D::insertTriple(long dataIndex, prf_type p1, prf_type p2, prf_type p3, int d1, int d2) {
    FILE* file;
    if (switchToOPEN) {
        file = filehandles[dataIndex];
    } else {
        file = fopen(filenames[dataIndex].c_str(), "rb+");
    }
    unsigned char newRecord[KEY_VALUE_SIZE];
    memset(newRecord, 0, KEY_VALUE_SIZE);
    std::copy(p1.begin(), p1.end(), newRecord);
    std::copy(p2.begin(), p2.end(), newRecord + AES_KEY_SIZE);
    std::copy(p3.begin(), p3.end(), newRecord + 2 * AES_KEY_SIZE);
    long pos = counter[d1][d2]; //(unsigned long) (*((long*) hash)) % maxSize;
    if (Utilities::DROP_CACHE && !setupMode) {
        Utilities::startTimer(113);
        if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
        if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
        auto t = Utilities::stopTimer(113);
        cacheTime += t;
    }
    fseek(file, (d1 * D2 + d2) * D3 * KEY_VALUE_SIZE + pos*KEY_VALUE_SIZE, SEEK_SET);
    fwrite((char*) newRecord, KEY_VALUE_SIZE, 1, file);
    fflush(file);
    counter[d1][d2]++;
    if (!switchToOPEN) {
        fclose(file);
    }
}
//
//void TransientStorage2D::insertTripleAndInt(long dataIndex, prf_type p1, prf_type p2, prf_type p3, unsigned int p4, int d1, int d2) {
//    FILE* file;
//    if (switchToOPEN) {
//        file = filehandles[dataIndex];
//    } else {
//        file = fopen(filenames[dataIndex].c_str(), "rb+");
//    }
//    unsigned char newRecord[KEY_VALUE_SIZE];
//    memset(newRecord, 0, KEY_VALUE_SIZE);
//    std::copy(p1.begin(), p1.end(), newRecord);
//    std::copy(p2.begin(), p2.end(), newRecord + AES_KEY_SIZE);
//    std::copy(p3.begin(), p3.end(), newRecord + 2 * AES_KEY_SIZE);
//    *((unsigned int*) &newRecord[AES_KEY_SIZE * 3]) = p4;
//    long pos = counter; //(unsigned long) (*((long*) hash)) % maxSize;
//    if (Utilities::DROP_CACHE && !setupMode) {
//        Utilities::startTimer(113);
//        if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
//        if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
//        auto t = Utilities::stopTimer(113);
//        cacheTime += t;
//    }
//    fseek(file, pos*KEY_VALUE_SIZE, SEEK_SET);
//    fwrite((char*) newRecord, KEY_VALUE_SIZE, 1, file);
//    fflush(file);
//    counter++;
//    if (!switchToOPEN) {
//        fclose(file);
//    }
//}
//
//void TransientStorage2D::insertEntry(long dataIndex, prf_type cipher, int d1, int d2) {
//    long maxSize = pow(2, dataIndex + 1);
//    FILE* file;
//    if (switchToOPEN) {
//        file = filehandles[dataIndex];
//    } else {
//        file = fopen(filenames[dataIndex].c_str(), "rb+");
//    }
//    unsigned char newRecord[KEY_VALUE_SIZE];
//    memset(newRecord, 0, KEY_VALUE_SIZE);
//    std::copy(cipher.begin(), cipher.end(), newRecord);
//    long pos = counter; //(unsigned long) (*((long*) hash)) % maxSize;
//    if (Utilities::DROP_CACHE && !setupMode) {
//        Utilities::startTimer(113);
//        if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
//        if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
//        auto t = Utilities::stopTimer(113);
//        cacheTime += t;
//    }
//    fseek(file, pos*KEY_VALUE_SIZE, SEEK_SET);
//    fwrite((char*) newRecord, KEY_VALUE_SIZE, 1, file);
//    fflush(file);
//    counter++;
//    if (!switchToOPEN) {
//        fclose(file);
//    }
//}
//
//void TransientStorage2D::insertEntryVector(long dataIndex, vector<prf_type> ciphers, long beginIndex, long count, int d1, int d2) {
//    FILE* file;
//    if (switchToOPEN) {
//        file = filehandles[dataIndex];
//    } else {
//        file = fopen(filenames[dataIndex].c_str(), "rb+");
//    }
//    long pos = counter; //(unsigned long) (*((long*) hash)) % maxSize;
//    if (Utilities::DROP_CACHE && !setupMode) {
//        Utilities::startTimer(113);
//        if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
//        if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
//        auto t = Utilities::stopTimer(113);
//        cacheTime += t;
//    }
//    fseek(file, pos*KEY_VALUE_SIZE, SEEK_SET);
//    for (int i = 0; i < count; i++) {
//        prf_type cipher = ciphers[beginIndex + i];
//        unsigned char newRecord[KEY_VALUE_SIZE];
//        memset(newRecord, 0, KEY_VALUE_SIZE);
//        std::copy(cipher.begin(), cipher.end(), newRecord);
//
//
//
//        fwrite((char*) newRecord, KEY_VALUE_SIZE, 1, file);
//        counter++;
//    }
//    fflush(file);
//    if (!switchToOPEN) {
//        fclose(file);
//    }
//}
//
//void TransientStorage2D::insertPairVector(long dataIndex, vector<pair<prf_type, prf_type> > ciphers, long beginIndex, long count, int d1, int d2) {
//    FILE* file;
//    if (switchToOPEN) {
//        file = filehandles[dataIndex];
//    } else {
//        file = fopen(filenames[dataIndex].c_str(), "rb+");
//    }
//    long pos = counter; //(unsigned long) (*((long*) hash)) % maxSize;
//    if (Utilities::DROP_CACHE && !setupMode) {
//        Utilities::startTimer(113);
//        if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
//        if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
//        auto t = Utilities::stopTimer(113);
//        cacheTime += t;
//    }
//    fseek(file, pos*KEY_VALUE_SIZE, SEEK_SET);
//    for (int i = 0; i < count; i++) {
//        pair<prf_type, prf_type> cipher = ciphers[beginIndex + i];
//        unsigned char newRecord[KEY_VALUE_SIZE];
//        memset(newRecord, 0, KEY_VALUE_SIZE);
//        std::copy(cipher.first.begin(), cipher.first.end(), newRecord);
//        std::copy(cipher.second.begin(), cipher.second.end(), newRecord + AES_KEY_SIZE);
//
//
//
//        fwrite((char*) newRecord, KEY_VALUE_SIZE, 1, file);
//        counter++;
//    }
//    fflush(file);
//    if (!switchToOPEN) {
//        fclose(file);
//    }
//}
//
//void TransientStorage2D::setEntry(long dataIndex, long index, prf_type cipher, int d1, int d2) {
//    long maxSize = pow(2, dataIndex + 1);
//    FILE* file;
//    if (switchToOPEN) {
//        file = filehandles[dataIndex];
//    } else {
//        file = fopen(filenames[dataIndex].c_str(), "rb+");
//    }
//    unsigned char newRecord[KEY_VALUE_SIZE];
//    memset(newRecord, 0, KEY_VALUE_SIZE);
//    std::copy(cipher.begin(), cipher.end(), newRecord);
//    long pos = index; //(unsigned long) (*((long*) hash)) % maxSize;
//    if (Utilities::DROP_CACHE && !setupMode) {
//        Utilities::startTimer(113);
//        if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
//        if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
//        auto t = Utilities::stopTimer(113);
//        cacheTime += t;
//    }
//    fseek(file, pos*KEY_VALUE_SIZE, SEEK_SET);
//    fwrite((char*) newRecord, KEY_VALUE_SIZE, 1, file);
//    fflush(file);
//    if (!switchToOPEN) {
//        fclose(file);
//    }
//}
//

vector<pair<prf_type, prf_type>> TransientStorage2D::getAllPairs(long dataIndex, int d1, int d2) {
    vector<pair<prf_type, prf_type>> results;

    FILE* file;
    if (switchToOPEN) {
        file = filehandles[dataIndex];
    } else {
        file = fopen(filenames[dataIndex].c_str(), "rb+");
    }
    if (file == NULL) {
        cerr << "Error in insert: " << strerror(errno);
    }
    long size = counter[d1][d2];
    if (Utilities::DROP_CACHE && !setupMode) {
        Utilities::startTimer(113);
        if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
        if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
        auto t = Utilities::stopTimer(113);
        cacheTime += t;
    }
    fseek(file, (d1 * D2 + d2) * D3 * KEY_VALUE_SIZE, SEEK_SET);

    char* keyValue = new char[size * KEY_VALUE_SIZE];
    fread(keyValue, size*KEY_VALUE_SIZE, 1, file);

    for (long i = 0; i < size; i++) {
        prf_type tmp, restmp;
        std::copy(keyValue + i*KEY_VALUE_SIZE, keyValue + i * KEY_VALUE_SIZE + AES_KEY_SIZE, tmp.begin());
        std::copy(keyValue + i * KEY_VALUE_SIZE + AES_KEY_SIZE, keyValue + i * KEY_VALUE_SIZE + AES_KEY_SIZE + AES_KEY_SIZE, restmp.begin());
        results.push_back(pair<prf_type, prf_type>(tmp, restmp));
    }
    if (!switchToOPEN) {
        fclose(file);
    }
    delete keyValue;
    return results;
}

vector<pair<pair<prf_type, prf_type>, prf_type> > TransientStorage2D::getAllTriples(long dataIndex, int d1, int d2) {
    vector<pair<pair<prf_type, prf_type>, prf_type> > results;

    FILE* file;
    if (switchToOPEN) {
        file = filehandles[dataIndex];
    } else {
        file = fopen(filenames[dataIndex].c_str(), "rb+");
    }
    if (file == NULL) {
        cerr << "Error in insert: " << strerror(errno);
    }
    long size = counter[d1][d2];
    if (Utilities::DROP_CACHE && !setupMode) {
        Utilities::startTimer(113);
        if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
        if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
        auto t = Utilities::stopTimer(113);
        cacheTime += t;
    }
    fseek(file, (d1 * D2 + d2) * D3 * KEY_VALUE_SIZE, SEEK_SET);

    char* keyValue = new char[size * KEY_VALUE_SIZE];
    fread(keyValue, size*KEY_VALUE_SIZE, 1, file);

    for (long i = 0; i < size; i++) {
        prf_type p1, p2, p3;
        std::copy(keyValue + i*KEY_VALUE_SIZE, keyValue + i * KEY_VALUE_SIZE + AES_KEY_SIZE, p1.begin());
        std::copy(keyValue + i * KEY_VALUE_SIZE + AES_KEY_SIZE, keyValue + i * KEY_VALUE_SIZE + AES_KEY_SIZE + AES_KEY_SIZE, p2.begin());
        std::copy(keyValue + i * KEY_VALUE_SIZE + 2 * AES_KEY_SIZE, keyValue + i * KEY_VALUE_SIZE + 3 * AES_KEY_SIZE, p3.begin());
        pair<prf_type, prf_type> tmp(p1, p2);
        results.push_back(pair<pair<prf_type, prf_type>, prf_type> (tmp, p3));
    }
    if (!switchToOPEN) {
        fclose(file);
    }
    delete keyValue;
    return results;
}
//
//vector<prf_type> TransientStorage2D::getAllData(long dataIndex, int d1, int d2) {
//    vector<prf_type> results;
//
//    //fstream file(filenames[dataIndex].c_str(), ios::binary | ios::in | ios::ate);
//    //        FILE* file = fopen(filenames[dataIndex].c_str(), "rb");
//    FILE* file;
//    if (switchToOPEN) {
//        file = filehandles[dataIndex];
//    } else {
//        file = fopen(filenames[dataIndex].c_str(), "rb+");
//    }
//    if (file == NULL) {
//        cerr << "Error in insert: " << strerror(errno);
//    }
//    long size = counter;
//    if (Utilities::DROP_CACHE && !setupMode) {
//        Utilities::startTimer(113);
//        if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
//        if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
//        auto t = Utilities::stopTimer(113);
//        cacheTime += t;
//    }
//    //file.seekg(0, ios::beg);
//    fseek(file, 0L, SEEK_SET);
//
//    char* keyValue = new char[size * KEY_VALUE_SIZE];
//    //file.read(keyValue, size);
//    fread(keyValue, size*KEY_VALUE_SIZE, 1, file);
//
//    for (long i = 0; i < size; i++) {
//        prf_type tmp;
//        std::copy(keyValue + i*KEY_VALUE_SIZE, keyValue + i * KEY_VALUE_SIZE + AES_KEY_SIZE, tmp.begin());
//        results.push_back(tmp);
//    }
//    if (!switchToOPEN) {
//        fclose(file);
//    }
//    //		file.close();
//    //        fclose(file);
//    delete keyValue;
//    //            printf("TransientStorage2D getalldata Cache time:%f\n",cacheTime);
//    return results;
//    //}
//}
//
//vector<prf_type> TransientStorage2D::getEntriesPartially(long dataIndex, int beginIndex, int incount, int d1, int d2) {
//    vector<prf_type> results;
//    int count = min(incount, counter - beginIndex);
//    if (count < incount) {
//        //        cout<<"asking for more than existing data"<<endl;
//    }
//    //fstream file(filenames[dataIndex].c_str(), ios::binary | ios::in | ios::ate);
//    //        FILE* file = fopen(filenames[dataIndex].c_str(), "rb");
//    FILE* file;
//    if (switchToOPEN) {
//        file = filehandles[dataIndex];
//    } else {
//        file = fopen(filenames[dataIndex].c_str(), "rb+");
//    }
//    if (file == NULL) {
//        cerr << "Error in insert: " << strerror(errno);
//    }
//    if (Utilities::DROP_CACHE && !setupMode) {
//        Utilities::startTimer(113);
//        if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
//        if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
//        auto t = Utilities::stopTimer(113);
//        cacheTime += t;
//    }
//    //file.seekg(0, ios::beg);
//    fseek(file, beginIndex*KEY_VALUE_SIZE, SEEK_SET);
//
//    char* keyValue = new char[count * KEY_VALUE_SIZE];
//    //file.read(keyValue, size);
//    fread(keyValue, count*KEY_VALUE_SIZE, 1, file);
//
//    for (long i = 0; i < count; i++) {
//        prf_type tmp;
//        std::copy(keyValue + i*KEY_VALUE_SIZE, keyValue + i * KEY_VALUE_SIZE + AES_KEY_SIZE, tmp.begin());
//        results.push_back(tmp);
//    }
//    if (!switchToOPEN) {
//        fclose(file);
//    }
//    //		file.close();
//    //        fclose(file);
//    delete keyValue;
//    //            printf("TransientStorage2D getalldata Cache time:%f\n",cacheTime);
//    return results;
//    //}
//}
//
//vector<pair<prf_type, prf_type> > TransientStorage2D::getPairsPartially(long dataIndex, int beginIndex, int incount, int d1, int d2) {
//    vector<pair<prf_type, prf_type>> results;
//    int count = min(incount, counter - beginIndex);
//    if (count < incount) {
//        //        cout<<"asking for more than existing data"<<endl;
//    }
//    //fstream file(filenames[dataIndex].c_str(), ios::binary | ios::in | ios::ate);
//    //        FILE* file = fopen(filenames[dataIndex].c_str(), "rb");
//    FILE* file;
//    if (switchToOPEN) {
//        file = filehandles[dataIndex];
//    } else {
//        file = fopen(filenames[dataIndex].c_str(), "rb+");
//    }
//    if (file == NULL) {
//        cerr << "Error in insert: " << strerror(errno);
//    }
//    if (Utilities::DROP_CACHE && !setupMode) {
//        Utilities::startTimer(113);
//        if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
//        if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
//        auto t = Utilities::stopTimer(113);
//        cacheTime += t;
//    }
//    //file.seekg(0, ios::beg);
//    fseek(file, beginIndex*KEY_VALUE_SIZE, SEEK_SET);
//
//    char* keyValue = new char[count * KEY_VALUE_SIZE];
//    //file.read(keyValue, size);
//    fread(keyValue, count*KEY_VALUE_SIZE, 1, file);
//
//    for (long i = 0; i < count; i++) {
//        prf_type tmp, tmp2;
//        std::copy(keyValue + i*KEY_VALUE_SIZE, keyValue + i * KEY_VALUE_SIZE + AES_KEY_SIZE, tmp.begin());
//        std::copy(keyValue + i * KEY_VALUE_SIZE + AES_KEY_SIZE, keyValue + i * KEY_VALUE_SIZE + 2 * AES_KEY_SIZE, tmp2.begin());
//        results.push_back(pair<prf_type, prf_type>(tmp, tmp2));
//    }
//    if (!switchToOPEN) {
//        fclose(file);
//    }
//    //		file.close();
//    //        fclose(file);
//    delete keyValue;
//    //            printf("TransientStorage2D getalldata Cache time:%f\n",cacheTime);
//    return results;
//    //}
//}
//

void TransientStorage2D::clear(long index, int d1, int d2) {
    if (inMemoryStorage) {
        data[index].clear();
    } else {
        counter[d1][d2] = 0;
    }
}

TransientStorage2D::~TransientStorage2D() {
    //    fclose(filehandles[dataIndex - 1]);
    if (switchToOPEN) {
        //        Utilities::numOfFile--;
        fclose(filehandles[dataIndex - 1]);
    }
    for (int i = 0; i < D1; i++) {
        delete counter[i];
    }
    delete counter;
}

pair<prf_type, prf_type> TransientStorage2D::getPair(long dataIndex, long index, int d1, int d2) {
    Utilities::startTimer(124);
    auto previousCacheTime = cacheTime;
    FILE* file;
    if (switchToOPEN) {
        file = filehandles[dataIndex];
    } else {
        file = fopen(filenames[dataIndex].c_str(), "rb+");
    }
    if (file == NULL)
        cerr << "Error in read: " << strerror(errno);
    char chainHead[KEY_VALUE_SIZE];
    prf_type tmp;
    long pos = index;
    if (Utilities::DROP_CACHE && !setupMode) {
        Utilities::startTimer(113);
        if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
        if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
        auto t = Utilities::stopTimer(113);
        cacheTime += t;
    }
    fseek(file, (d1 * D2 + d2) * D3 * KEY_VALUE_SIZE + pos*KEY_VALUE_SIZE, SEEK_SET);
    Utilities::startTimer(129);
    fread(chainHead, KEY_VALUE_SIZE, 1, file);
    std::copy(chainHead, chainHead + AES_KEY_SIZE, tmp.begin());
    prf_type restmp;
    std::copy(chainHead + AES_KEY_SIZE, chainHead + (2 * AES_KEY_SIZE), restmp.begin());
    auto endtime = Utilities::stopTimer(124);
    getCounterTime = endtime - (cacheTime - previousCacheTime);
    if (!switchToOPEN) {
        fclose(file);
    }
    return pair<prf_type, prf_type>(tmp, restmp);
}
//
//vector<pair<prf_type, prf_type> > TransientStorage2D::getPairVector(long dataIndex, long begin, int count, int d1, int d2) {
//    vector<pair<prf_type, prf_type> >res;
//    Utilities::startTimer(124);
//    auto previousCacheTime = cacheTime;
//    FILE* file;
//    if (switchToOPEN) {
//        file = filehandles[dataIndex];
//    } else {
//        file = fopen(filenames[dataIndex].c_str(), "rb+");
//    }
//    if (file == NULL)
//        cerr << "Error in read: " << strerror(errno);
//
//    char* chainHead = new char[KEY_VALUE_SIZE * count];
//    if (profile)
//        seekgCount++;
//    int cnt = 0;
//
//    long pos = begin;
//    if (Utilities::DROP_CACHE && !setupMode) {
//        Utilities::startTimer(113);
//        if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
//        if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
//        auto t = Utilities::stopTimer(113);
//        cacheTime += t;
//    }
//    fseek(file, pos*KEY_VALUE_SIZE, SEEK_SET);
//    Utilities::startTimer(129);
//    fread(chainHead, KEY_VALUE_SIZE*count, 1, file);
//
//    for (int i = 0; i < count; i++) {
//        prf_type p1, p2;
//        std::copy(chainHead + i*KEY_VALUE_SIZE, chainHead + i * KEY_VALUE_SIZE + AES_KEY_SIZE, p1.begin());
//        std::copy(chainHead + i * KEY_VALUE_SIZE + AES_KEY_SIZE, chainHead + i * KEY_VALUE_SIZE + (2 * AES_KEY_SIZE), p2.begin());
//        res.push_back(pair<prf_type, prf_type>(p1, p2));
//    }
//    auto endtime = Utilities::stopTimer(124);
//    getCounterTime = endtime - (cacheTime - previousCacheTime);
//    if (!switchToOPEN) {
//        fclose(file);
//    }
//    delete chainHead;
//    return res;
//}
//

void TransientStorage2D::getTriple(long dataIndex, long index, prf_type& p1, prf_type& p2, prf_type& p3, int d1, int d2) {
    Utilities::startTimer(124);
    auto previousCacheTime = cacheTime;
    FILE* file;
    if (switchToOPEN) {
        file = filehandles[dataIndex];
    } else {
        file = fopen(filenames[dataIndex].c_str(), "rb+");
    }
    if (file == NULL)
        cerr << "Error in read: " << strerror(errno);
    char chainHead[KEY_VALUE_SIZE];
    if (profile)
        seekgCount++;
    int cnt = 0;
    long pos = index;
    if (Utilities::DROP_CACHE && !setupMode) {
        Utilities::startTimer(113);
        if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
        if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
        auto t = Utilities::stopTimer(113);
        cacheTime += t;
    }
    fseek(file, (d1 * D2 + d2) * D3 * KEY_VALUE_SIZE + pos*KEY_VALUE_SIZE, SEEK_SET);
    Utilities::startTimer(129);
    fread(chainHead, KEY_VALUE_SIZE, 1, file);
    std::copy(chainHead, chainHead + AES_KEY_SIZE, p1.begin());
    std::copy(chainHead + AES_KEY_SIZE, chainHead + (2 * AES_KEY_SIZE), p2.begin());
    std::copy(chainHead + (2 * AES_KEY_SIZE), chainHead + (3 * AES_KEY_SIZE), p3.begin());
    auto endtime = Utilities::stopTimer(124);
    getCounterTime = endtime - (cacheTime - previousCacheTime);
    if (!switchToOPEN) {
        fclose(file);
    }
}
//
//void TransientStorage2D::getPairAndInt(long dataIndex, long index, prf_type& p1, prf_type& p2, unsigned int& p3, int d1, int d2) {
//    Utilities::startTimer(124);
//    auto previousCacheTime = cacheTime;
//    FILE* file;
//    if (switchToOPEN) {
//        file = filehandles[dataIndex];
//    } else {
//        file = fopen(filenames[dataIndex].c_str(), "rb+");
//    }
//    if (file == NULL)
//        cerr << "Error in read: " << strerror(errno);
//    char chainHead[KEY_VALUE_SIZE];
//    if (profile)
//        seekgCount++;
//    int cnt = 0;
//    long pos = index;
//    if (Utilities::DROP_CACHE && !setupMode) {
//        Utilities::startTimer(113);
//        if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
//        if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
//        auto t = Utilities::stopTimer(113);
//        cacheTime += t;
//    }
//    fseek(file, pos*KEY_VALUE_SIZE, SEEK_SET);
//    Utilities::startTimer(129);
//    fread(chainHead, KEY_VALUE_SIZE, 1, file);
//    std::copy(chainHead, chainHead + AES_KEY_SIZE, p1.begin());
//    std::copy(chainHead + AES_KEY_SIZE, chainHead + (2 * AES_KEY_SIZE), p2.begin());
//    p3 = *((unsigned int*) &chainHead[AES_KEY_SIZE * 2]);
//    auto endtime = Utilities::stopTimer(124);
//    getCounterTime = endtime - (cacheTime - previousCacheTime);
//    if (!switchToOPEN) {
//        fclose(file);
//    }
//}
//
//void TransientStorage2D::getTripleAndInt(long dataIndex, long index, prf_type& p1, prf_type& p2, prf_type& p3, unsigned int& p4, int d1, int d2) {
//    Utilities::startTimer(124);
//    auto previousCacheTime = cacheTime;
//    FILE* file;
//    if (switchToOPEN) {
//        file = filehandles[dataIndex];
//    } else {
//        file = fopen(filenames[dataIndex].c_str(), "rb+");
//    }
//    if (file == NULL)
//        cerr << "Error in read: " << strerror(errno);
//    char chainHead[KEY_VALUE_SIZE];
//    if (profile)
//        seekgCount++;
//    int cnt = 0;
//    long pos = index;
//    if (Utilities::DROP_CACHE && !setupMode) {
//        Utilities::startTimer(113);
//        if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
//        if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
//        auto t = Utilities::stopTimer(113);
//        cacheTime += t;
//    }
//    fseek(file, pos*KEY_VALUE_SIZE, SEEK_SET);
//    Utilities::startTimer(129);
//    fread(chainHead, KEY_VALUE_SIZE, 1, file);
//    std::copy(chainHead, chainHead + AES_KEY_SIZE, p1.begin());
//    std::copy(chainHead + AES_KEY_SIZE, chainHead + (2 * AES_KEY_SIZE), p2.begin());
//    std::copy(chainHead + AES_KEY_SIZE * 2, chainHead + (3 * AES_KEY_SIZE), p3.begin());
//    p4 = *((unsigned int*) &chainHead[AES_KEY_SIZE * 3]);
//    auto endtime = Utilities::stopTimer(124);
//    getCounterTime = endtime - (cacheTime - previousCacheTime);
//    if (!switchToOPEN) {
//        fclose(file);
//    }
//}
//
//prf_type TransientStorage2D::getEntry(long dataIndex, long index, int d1, int d2) {
//    Utilities::startTimer(124);
//    auto previousCacheTime = cacheTime;
//    FILE* file;
//    if (switchToOPEN) {
//        file = filehandles[dataIndex];
//    } else {
//        file = fopen(filenames[dataIndex].c_str(), "rb+");
//    }
//    if (file == NULL)
//        cerr << "Error in read: " << strerror(errno);
//    char chainHead[KEY_VALUE_SIZE];
//    if (profile)
//        seekgCount++;
//    int cnt = 0;
//    prf_type tmp;
//    long pos = index;
//    if (Utilities::DROP_CACHE && !setupMode) {
//        Utilities::startTimer(113);
//        if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
//        if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
//        auto t = Utilities::stopTimer(113);
//        cacheTime += t;
//    }
//    fseek(file, pos*KEY_VALUE_SIZE, SEEK_SET);
//    Utilities::startTimer(129);
//    fread(chainHead, KEY_VALUE_SIZE, 1, file);
//    std::copy(chainHead, chainHead + AES_KEY_SIZE, tmp.begin());
//    auto endtime = Utilities::stopTimer(124);
//    getCounterTime = endtime - (cacheTime - previousCacheTime);
//    if (!switchToOPEN) {
//        fclose(file);
//    }
//    return tmp;
//}
//
//vector<prf_type> TransientStorage2D::getEntryVector(long dataIndex, long begin, long count, int d1, int d2) {
//    vector<prf_type> res;
//    Utilities::startTimer(124);
//    auto previousCacheTime = cacheTime;
//    FILE* file;
//    if (switchToOPEN) {
//        file = filehandles[dataIndex];
//    } else {
//        file = fopen(filenames[dataIndex].c_str(), "rb+");
//    }
//    if (file == NULL)
//        cerr << "Error in read: " << strerror(errno);
//    if (Utilities::DROP_CACHE && !setupMode) {
//        Utilities::startTimer(113);
//        if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
//        if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
//        auto t = Utilities::stopTimer(113);
//        cacheTime += t;
//    }
//    fseek(file, begin*KEY_VALUE_SIZE, SEEK_SET);
//    char* chainHead = new char[KEY_VALUE_SIZE * count];
//    fread(chainHead, count*KEY_VALUE_SIZE, 1, file);
//    for (int i = 0; i < count; i++) {
//        prf_type tmp;
//        std::copy(chainHead + i*KEY_VALUE_SIZE, chainHead + (i * KEY_VALUE_SIZE) + AES_KEY_SIZE, tmp.begin());
//        res.push_back(tmp);
//    }
//    auto endtime = Utilities::stopTimer(124);
//    getCounterTime = endtime - (cacheTime - previousCacheTime);
//    if (!switchToOPEN) {
//        fclose(file);
//    }
//    delete chainHead;
//    return res;
//}
//
//char* TransientStorage2D::readRawData(long dataIndex, long begin, long count, int d1, int d2) {
//    Utilities::startTimer(124);
//    auto previousCacheTime = cacheTime;
//    FILE* file;
//    if (switchToOPEN) {
//        file = filehandles[dataIndex];
//    } else {
//        file = fopen(filenames[dataIndex].c_str(), "rb+");
//    }
//    if (file == NULL)
//        cerr << "Error in read: " << strerror(errno);
//    char* chainHead = new char[KEY_VALUE_SIZE * count];
//    if (profile)
//        seekgCount++;
//    long pos = begin;
//    if (Utilities::DROP_CACHE && !setupMode) {
//        Utilities::startTimer(113);
//        if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
//        if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
//        auto t = Utilities::stopTimer(113);
//        cacheTime += t;
//    }
//    fseek(file, pos*KEY_VALUE_SIZE, SEEK_SET);
//    Utilities::startTimer(129);
//    fread(chainHead, count*KEY_VALUE_SIZE, 1, file);
//    auto endtime = Utilities::stopTimer(124);
//    getCounterTime = endtime - (cacheTime - previousCacheTime);
//    if (!switchToOPEN) {
//        fclose(file);
//    }
//    return chainHead;
//}
//
//void TransientStorage2D::writeRawData(long dataIndex, char* data, long count, int d1, int d2) {
//    FILE* file;
//    if (switchToOPEN) {
//        file = filehandles[dataIndex];
//    } else {
//        file = fopen(filenames[dataIndex].c_str(), "rb+");
//    }
//    long pos = counter; //(unsigned long) (*((long*) hash)) % maxSize;
//    if (Utilities::DROP_CACHE && !setupMode) {
//        Utilities::startTimer(113);
//        if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
//        if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
//        auto t = Utilities::stopTimer(113);
//        cacheTime += t;
//    }
//    fseek(file, pos*KEY_VALUE_SIZE, SEEK_SET);
//    fwrite((char*) data, KEY_VALUE_SIZE*count, 1, file);
//    fflush(file);
//    counter += count;
//    delete data;
//    if (!switchToOPEN) {
//        fclose(file);
//    }
//}
//
//void TransientStorage2D::writeRawDataFrom(long dataIndex, long begin, char* data, long count, int d1, int d2) {
//    FILE* file;
//    if (switchToOPEN) {
//        file = filehandles[dataIndex];
//    } else {
//        file = fopen(filenames[dataIndex].c_str(), "rb+");
//    }
//    long pos = begin; //(unsigned long) (*((long*) hash)) % maxSize;
//    if (Utilities::DROP_CACHE && !setupMode) {
//        Utilities::startTimer(113);
//        if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
//        if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
//        auto t = Utilities::stopTimer(113);
//        cacheTime += t;
//    }
//    fseek(file, pos*KEY_VALUE_SIZE, SEEK_SET);
//    fwrite((char*) data, KEY_VALUE_SIZE*count, 1, file);
//    fflush(file);
//    delete data;
//    if (!switchToOPEN) {
//        fclose(file);
//    }
//}
//
//void TransientStorage2D::insertIntAtTheEnd(long dataIndex, int p, unsigned int p3, int d1, int d2) {
//    FILE* file;
//    if (switchToOPEN) {
//        file = filehandles[dataIndex];
//    } else {
//        file = fopen(filenames[dataIndex].c_str(), "rb+");
//    }
//    unsigned char newRecord[AES_KEY_SIZE];
//    *((unsigned int*) &newRecord[0]) = p3;
//    long pos = p; //(unsigned long) (*((long*) hash)) % maxSize;
//    if (Utilities::DROP_CACHE && !setupMode) {
//        Utilities::startTimer(113);
//        if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
//        if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
//        auto t = Utilities::stopTimer(113);
//        cacheTime += t;
//    }
//    fseek(file, pos * KEY_VALUE_SIZE + 3 * AES_KEY_SIZE, SEEK_SET);
//    fwrite((char*) newRecord, AES_KEY_SIZE, 1, file);
//    fflush(file);
//    if (!switchToOPEN) {
//        fclose(file);
//    }
//}