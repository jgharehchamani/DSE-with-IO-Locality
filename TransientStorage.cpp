#include "TransientStorage.h"
#include "assert.h"

TransientStorage::TransientStorage(bool inMemory, long dataIndex, string fileAddressPrefix, bool profile) {
    this->inMemoryStorage = inMemory;
    this->fileAddressPrefix = fileAddressPrefix;
    this->dataIndex = dataIndex;
    this->profile = profile;
    memset(nullKey.data(), 0, AES_KEY_SIZE);
    //    cout<<"num of files:"<<Utilities::numOfFile++<<endl;
}

//bool TransientStorage::setup(bool overwrite) {
//    if (inMemoryStorage) {
//        for (long i = 0; i < dataIndex; i++) {
//            unordered_map<prf_type, prf_type, PRFHasher> curData;
//            data.push_back(curData);
//        }
//    } else {
//        for (long i = 0; i < dataIndex; i++) {
//            string filename = fileAddressPrefix + "MAP-" + to_string(i) + ".dat";
//            filenames.push_back(filename);
//            //fstream testfile(filename.c_str(), std::ofstream::in);
//            FILE* testfile = fopen(filename.c_str(), "rb");
//            if (testfile == NULL || overwrite) {
//                //testfile.close();
//                //				fclose(testfile);
//                //fstream file(filename.c_str(), std::ofstream::out);
//                FILE* file = fopen(filename.c_str(), "wb");
//                if (file == NULL) {
//                    cerr << "Error: " << strerror(errno);
//                }
//                long maxSize = pow(2, i + 1); //double the size
//                //                posix_fallocate(fileno(file), 0, maxSize*KEY_VALUE_SIZE);
//                //                long nextPtr = 0;
//                //                for (long j = 0; j < maxSize; j++) {
//                //                    /*file.write((char*) nullKey.data(), AES_KEY_SIZE);
//                //                    file.write((char*) nullKey.data(), AES_KEY_SIZE);
//                //                    file.write((char*) &nextPtr, sizeof (long));*/
//                //                    fwrite((char*) nullKey.data(), AES_KEY_SIZE, 1, file);
//                //                    fwrite((char*) nullKey.data(), AES_KEY_SIZE, 1, file);
//                //                    fwrite((char*) nullKey.data(), AES_KEY_SIZE, 1, file);
//                //                    fwrite((char*) nullKey.data(), AES_KEY_SIZE, 1, file);
//                //
//                //                }
//                //file.write((char*) &nextPtr, sizeof (long));
//                //file.close();
//                fclose(file);
//            }else{
//                fclose(testfile);
//            }
//            if (switchToOPEN) {
//                FILE* file = fopen(filename.c_str(), "rb+");
//                filehandles.push_back(file);
//            }
//        }
//    }
//}

bool TransientStorage::setup(bool overwrite, int index) {
    if (inMemoryStorage) {
        for (long i = 0; i < dataIndex; i++) {
            unordered_map<prf_type, prf_type, PRFHasher> curData;
            data.push_back(curData);
        }
    } else {
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
                    //                    for (long j = 0; j < maxSize; j++) {
                    //                        /*file.write((char*) nullKey.data(), AES_KEY_SIZE);
                    //                        file.write((char*) nullKey.data(), AES_KEY_SIZE);
                    //                        file.write((char*) &nextPtr, sizeof (long));*/
                    //                        fwrite((char*) nullKey.data(), AES_KEY_SIZE, 1, file);
                    //                        fwrite((char*) nullKey.data(), AES_KEY_SIZE, 1, file);
                    //                        fwrite((char*) nullKey.data(), AES_KEY_SIZE, 1, file);
                    //                        fwrite((char*) nullKey.data(), AES_KEY_SIZE, 1, file);
                    //
                    //                    }
                    //file.write((char*) &nextPtr, sizeof (long));
                    //file.close();
                    fclose(file);
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
}

void TransientStorage::insertPairList(long dataIndex, map<long, pair<prf_type, prf_type> > ciphers) {
    long maxSize = pow(2, dataIndex + 1);
    //fstream file(filenames[dataIndex].c_str(), ios::binary | ios::in | ios::out | ios::ate);
    FILE* file;
    if (switchToOPEN) {
        file = filehandles[dataIndex];
    } else {
        file = fopen(filenames[dataIndex].c_str(), "rb+");
    }

    //    FILE* file = filehandles[dataIndex];
    for (auto item : ciphers) {
        unsigned char newRecord[KEY_VALUE_SIZE];
        memset(newRecord, 0, KEY_VALUE_SIZE);
        std::copy(item.second.first.begin(), item.second.first.end(), newRecord);
        std::copy(item.second.second.begin(), item.second.second.end(), newRecord + AES_KEY_SIZE);

        //        unsigned char* hash = Utilities::sha256((char*) item.first.data(), AES_KEY_SIZE);
        long pos = item.first; //(unsigned long) (*((long*) hash)) % maxSize;
        //file.seekg(pos * KEY_VALUE_SIZE, ios::beg);
        //        if (Utilities::DROP_CACHE && !setupMode) {
        //            Utilities::startTimer(113);
        //            if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
        //            if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
        //            auto t = Utilities::stopTimer(113);
        //            cacheTime += t;
        //            //            cout << "cache time:" << t << endl;
        //        }
        //        fseek(file, pos*KEY_VALUE_SIZE, SEEK_SET);
        //        char chainHead[KEY_VALUE_SIZE];
        //        //file.read(chainHead, KEY_VALUE_SIZE);
        //        fread(chainHead, KEY_VALUE_SIZE, 1, file);
        //        prf_type tmp;
        //        std::copy(chainHead, chainHead + AES_KEY_SIZE, tmp.begin());
        //        int cnt = 1;
        //        while (tmp != nullKey && cnt < maxSize) {
        //            pos = (pos + 1) % maxSize;
        //            //cout <<"{"<<oldPos<<"-"<<pos<<"}";
        //            cnt++;
        //            //file.seekg(pos*KEY_VALUE_SIZE, ios::beg);
        //            if (Utilities::DROP_CACHE && !setupMode) {
        //                Utilities::startTimer(113);
        //                if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
        //                if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
        //                auto t = Utilities::stopTimer(113);
        //                cacheTime += t;
        //                //            cout << "cache time:" << t << endl;
        //            }
        //            fseek(file, pos*KEY_VALUE_SIZE, SEEK_SET);
        //            //file.read(chainHead, KEY_VALUE_SIZE);
        //            fread(chainHead, KEY_VALUE_SIZE, 1, file);
        //            std::copy(chainHead, chainHead + AES_KEY_SIZE, tmp.begin());
        //        }
        //        if (cnt == maxSize) {
        //            cout << "DANGER" << endl;
        //            cerr << "Error in insert (space crunch): " << strerror(errno);
        //        }
        //        if (tmp == nullKey) {
        //file.seekg(pos*KEY_VALUE_SIZE, ios::beg);
        if (Utilities::DROP_CACHE && !setupMode) {
            Utilities::startTimer(113);
            if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
            if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
            auto t = Utilities::stopTimer(113);
            cacheTime += t;
            //            cout << "cache time:" << t << endl;
        }
        fseek(file, pos*KEY_VALUE_SIZE, SEEK_SET);
        //file.write((char*) newRecord, KEY_VALUE_SIZE);
        fwrite((char*) newRecord, KEY_VALUE_SIZE, 1, file);
        counter++;
        //        }
        //cout<<endl;
    }
    fflush(file);

    //	file.close();
    if (!switchToOPEN) {
        fclose(file);
    }

}

void TransientStorage::insertPair(long dataIndex, pair<prf_type, prf_type> cipher) {
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
    long pos = counter; //(unsigned long) (*((long*) hash)) % maxSize;
    if (Utilities::DROP_CACHE && !setupMode) {
        Utilities::startTimer(113);
        if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
        if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
        auto t = Utilities::stopTimer(113);
        cacheTime += t;
    }
    fseek(file, pos*KEY_VALUE_SIZE, SEEK_SET);
    fwrite((char*) newRecord, KEY_VALUE_SIZE, 1, file);
    fflush(file);
    counter++;
    if (!switchToOPEN) {
        fclose(file);
    }
}

void TransientStorage::insertVectorOfPairs(long dataIndex, vector<pair<prf_type, prf_type> > ciphers) {
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
    fseek(file, pos*KEY_VALUE_SIZE, SEEK_SET);
    for (int i = 0; i < ciphers.size(); i++) {
        pair<prf_type, prf_type> cipher = ciphers[i];
        unsigned char newRecord[KEY_VALUE_SIZE];
        memset(newRecord, 0, KEY_VALUE_SIZE);
        std::copy(cipher.first.begin(), cipher.first.end(), newRecord);
        std::copy(cipher.second.begin(), cipher.second.end(), newRecord + AES_KEY_SIZE);
        fwrite((char*) newRecord, KEY_VALUE_SIZE, 1, file);
    }
    counter = ciphers.size();
    fflush(file);
    if (!switchToOPEN) {
        fclose(file);
    }

}

void TransientStorage::AddVectorOfPairs(long dataIndex, vector<pair<prf_type, prf_type> > ciphers) {
    //    FILE* file = filehandles[dataIndex];
    FILE* file;
    if (switchToOPEN) {
        file = filehandles[dataIndex];
    } else {
        file = fopen(filenames[dataIndex].c_str(), "rb+");
    }
    long pos = counter; //(unsigned long) (*((long*) hash)) % maxSize;
    if (Utilities::DROP_CACHE && !setupMode) {
        Utilities::startTimer(113);
        if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
        if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
        auto t = Utilities::stopTimer(113);
        cacheTime += t;
    }
    fseek(file, pos*KEY_VALUE_SIZE, SEEK_SET);
    for (int i = 0; i < ciphers.size(); i++) {
        pair<prf_type, prf_type> cipher = ciphers[i];
        unsigned char newRecord[KEY_VALUE_SIZE];
        memset(newRecord, 0, KEY_VALUE_SIZE);
        std::copy(cipher.first.begin(), cipher.first.end(), newRecord);
        std::copy(cipher.second.begin(), cipher.second.end(), newRecord + AES_KEY_SIZE);
        fwrite((char*) newRecord, KEY_VALUE_SIZE, 1, file);
    }
    counter += ciphers.size();
    fflush(file);
    if (!switchToOPEN) {
        fclose(file);
    }

}

void TransientStorage::setVectorOfPairs(long dataIndex, long index, vector<pair<prf_type, prf_type> > ciphers) {
    //    FILE* file = filehandles[dataIndex];
    FILE* file;
    if (switchToOPEN) {
        file = filehandles[dataIndex];
    } else {
        file = fopen(filenames[dataIndex].c_str(), "rb+");
    }
    long count = min((long) ciphers.size(), (long) counter - index);
    if (count < ciphers.size()) {
        cout << "there is no storage in Transient Storage" << endl;
    }
    long pos = index; //(unsigned long) (*((long*) hash)) % maxSize;
    if (Utilities::DROP_CACHE && !setupMode) {
        Utilities::startTimer(113);
        if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
        if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
        auto t = Utilities::stopTimer(113);
        cacheTime += t;
    }
    fseek(file, pos*KEY_VALUE_SIZE, SEEK_SET);
    for (int i = 0; i < count; i++) {
        pair<prf_type, prf_type> cipher = ciphers[i];
        unsigned char newRecord[KEY_VALUE_SIZE];
        memset(newRecord, 0, KEY_VALUE_SIZE);
        std::copy(cipher.first.begin(), cipher.first.end(), newRecord);
        std::copy(cipher.second.begin(), cipher.second.end(), newRecord + AES_KEY_SIZE);
        fwrite((char*) newRecord, KEY_VALUE_SIZE, 1, file);
    }
    fflush(file);
    if (!switchToOPEN) {
        fclose(file);
    }

}

void TransientStorage::setVectorOfEntries(long dataIndex, long index, vector<prf_type> ciphers) {
    //    FILE* file = filehandles[dataIndex];
    FILE* file;
    if (switchToOPEN) {
        file = filehandles[dataIndex];
    } else {
        file = fopen(filenames[dataIndex].c_str(), "rb+");
    }
    long count = min((long) ciphers.size(), (long) counter - index);
    if (count < ciphers.size()) {
        cout << "there is no storage in Transient Storage" << endl;
    }
    long pos = index; //(unsigned long) (*((long*) hash)) % maxSize;
    if (Utilities::DROP_CACHE && !setupMode) {
        Utilities::startTimer(113);
        if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
        if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
        auto t = Utilities::stopTimer(113);
        cacheTime += t;
    }
    fseek(file, pos*KEY_VALUE_SIZE, SEEK_SET);
    for (int i = 0; i < count; i++) {
        unsigned char newRecord[KEY_VALUE_SIZE];
        memset(newRecord, 0, KEY_VALUE_SIZE);
        std::copy(ciphers[i].begin(), ciphers[i].end(), newRecord);
        fwrite((char*) newRecord, KEY_VALUE_SIZE, 1, file);
    }
    fflush(file);
    if (!switchToOPEN) {
        fclose(file);
    }

}

void TransientStorage::insertVectorOfTriples(long dataIndex, vector<pair<pair<prf_type, prf_type>, prf_type> > ciphers) {
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
    fseek(file, pos*KEY_VALUE_SIZE, SEEK_SET);
    for (int i = 0; i < ciphers.size(); i++) {
        pair<pair<prf_type, prf_type>, prf_type> cipher = ciphers[i];
        unsigned char newRecord[KEY_VALUE_SIZE];
        memset(newRecord, 0, KEY_VALUE_SIZE);
        std::copy(cipher.first.first.begin(), cipher.first.first.end(), newRecord);
        std::copy(cipher.first.second.begin(), cipher.first.second.end(), newRecord + AES_KEY_SIZE);
        std::copy(cipher.second.begin(), cipher.second.end(), newRecord + AES_KEY_SIZE * 2);
        fwrite((char*) newRecord, KEY_VALUE_SIZE, 1, file);
    }
    counter = ciphers.size();
    fflush(file);
    if (!switchToOPEN) {
        fclose(file);
    }

}

void TransientStorage::insertPairAndInt(long dataIndex, prf_type p1, prf_type p2, unsigned int p3) {
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
    *((unsigned int*) &newRecord[AES_KEY_SIZE * 2]) = p3;
    long pos = counter; //(unsigned long) (*((long*) hash)) % maxSize;
    if (Utilities::DROP_CACHE && !setupMode) {
        Utilities::startTimer(113);
        if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
        if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
        auto t = Utilities::stopTimer(113);
        cacheTime += t;
    }
    fseek(file, pos*KEY_VALUE_SIZE, SEEK_SET);
    fwrite((char*) newRecord, KEY_VALUE_SIZE, 1, file);
    fflush(file);
    counter++;
    if (!switchToOPEN) {
        fclose(file);
    }
}

void TransientStorage::setPair(long dataIndex, long index, pair<prf_type, prf_type> cipher) {
    long maxSize = pow(2, dataIndex + 1);
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
    long pos = index; //(unsigned long) (*((long*) hash)) % maxSize;
    if (Utilities::DROP_CACHE && !setupMode) {
        Utilities::startTimer(113);
        if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
        if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
        auto t = Utilities::stopTimer(113);
        cacheTime += t;
    }
    fseek(file, pos*KEY_VALUE_SIZE, SEEK_SET);
    fwrite((char*) newRecord, KEY_VALUE_SIZE, 1, file);
    fflush(file);
    if (!switchToOPEN) {
        fclose(file);
    }
}

void TransientStorage::insertTriple(long dataIndex, prf_type p1, prf_type p2, prf_type p3) {
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
    long pos = counter; //(unsigned long) (*((long*) hash)) % maxSize;
    if (Utilities::DROP_CACHE && !setupMode) {
        Utilities::startTimer(113);
        if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
        if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
        auto t = Utilities::stopTimer(113);
        cacheTime += t;
    }
    fseek(file, pos*KEY_VALUE_SIZE, SEEK_SET);
    fwrite((char*) newRecord, KEY_VALUE_SIZE, 1, file);
    fflush(file);
    counter++;
    if (!switchToOPEN) {
        fclose(file);
    }
}

void TransientStorage::insertTripleAndInt(long dataIndex, prf_type p1, prf_type p2, prf_type p3, unsigned int p4) {
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
    *((unsigned int*) &newRecord[AES_KEY_SIZE * 3]) = p4;
    long pos = counter; //(unsigned long) (*((long*) hash)) % maxSize;
    if (Utilities::DROP_CACHE && !setupMode) {
        Utilities::startTimer(113);
        if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
        if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
        auto t = Utilities::stopTimer(113);
        cacheTime += t;
    }
    fseek(file, pos*KEY_VALUE_SIZE, SEEK_SET);
    fwrite((char*) newRecord, KEY_VALUE_SIZE, 1, file);
    fflush(file);
    counter++;
    if (!switchToOPEN) {
        fclose(file);
    }
}

void TransientStorage::insertEntry(long dataIndex, prf_type cipher) {
    long maxSize = pow(2, dataIndex + 1);
    FILE* file;
    if (switchToOPEN) {
        file = filehandles[dataIndex];
    } else {
        file = fopen(filenames[dataIndex].c_str(), "rb+");
    }
    unsigned char newRecord[KEY_VALUE_SIZE];
    memset(newRecord, 0, KEY_VALUE_SIZE);
    std::copy(cipher.begin(), cipher.end(), newRecord);
    long pos = counter; //(unsigned long) (*((long*) hash)) % maxSize;
    if (Utilities::DROP_CACHE && !setupMode) {
        Utilities::startTimer(113);
        if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
        if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
        auto t = Utilities::stopTimer(113);
        cacheTime += t;
    }
    fseek(file, pos*KEY_VALUE_SIZE, SEEK_SET);
    fwrite((char*) newRecord, KEY_VALUE_SIZE, 1, file);
    fflush(file);
    counter++;
    if (!switchToOPEN) {
        fclose(file);
    }
}

void TransientStorage::insertEntryVector(long dataIndex, vector<prf_type> ciphers, long beginIndex, long count) {
    FILE* file;
    if (switchToOPEN) {
        file = filehandles[dataIndex];
    } else {
        file = fopen(filenames[dataIndex].c_str(), "rb+");
    }
    long pos = counter; //(unsigned long) (*((long*) hash)) % maxSize;
    if (Utilities::DROP_CACHE && !setupMode) {
        Utilities::startTimer(113);
        if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
        if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
        auto t = Utilities::stopTimer(113);
        cacheTime += t;
    }
    fseek(file, pos*KEY_VALUE_SIZE, SEEK_SET);
    for (int i = 0; i < count; i++) {
        prf_type cipher = ciphers[beginIndex + i];
        unsigned char newRecord[KEY_VALUE_SIZE];
        memset(newRecord, 0, KEY_VALUE_SIZE);
        std::copy(cipher.begin(), cipher.end(), newRecord);



        fwrite((char*) newRecord, KEY_VALUE_SIZE, 1, file);
        counter++;
    }
    fflush(file);
    if (!switchToOPEN) {
        fclose(file);
    }
}

void TransientStorage::insertPairVector(long dataIndex, vector<pair<prf_type, prf_type> > ciphers, long beginIndex, long count) {
    FILE* file;
    if (switchToOPEN) {
        file = filehandles[dataIndex];
    } else {
        file = fopen(filenames[dataIndex].c_str(), "rb+");
    }
    long pos = counter; //(unsigned long) (*((long*) hash)) % maxSize;
    if (Utilities::DROP_CACHE && !setupMode) {
        Utilities::startTimer(113);
        if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
        if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
        auto t = Utilities::stopTimer(113);
        cacheTime += t;
    }
    fseek(file, pos*KEY_VALUE_SIZE, SEEK_SET);
    for (int i = 0; i < count; i++) {
        pair<prf_type, prf_type> cipher = ciphers[beginIndex + i];
        unsigned char newRecord[KEY_VALUE_SIZE];
        memset(newRecord, 0, KEY_VALUE_SIZE);
        std::copy(cipher.first.begin(), cipher.first.end(), newRecord);
        std::copy(cipher.second.begin(), cipher.second.end(), newRecord + AES_KEY_SIZE);



        fwrite((char*) newRecord, KEY_VALUE_SIZE, 1, file);
        counter++;
    }
    fflush(file);
    if (!switchToOPEN) {
        fclose(file);
    }
}

void TransientStorage::setEntry(long dataIndex, long index, prf_type cipher) {
    long maxSize = pow(2, dataIndex + 1);
    FILE* file;
    if (switchToOPEN) {
        file = filehandles[dataIndex];
    } else {
        file = fopen(filenames[dataIndex].c_str(), "rb+");
    }
    unsigned char newRecord[KEY_VALUE_SIZE];
    memset(newRecord, 0, KEY_VALUE_SIZE);
    std::copy(cipher.begin(), cipher.end(), newRecord);
    long pos = index; //(unsigned long) (*((long*) hash)) % maxSize;
    if (Utilities::DROP_CACHE && !setupMode) {
        Utilities::startTimer(113);
        if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
        if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
        auto t = Utilities::stopTimer(113);
        cacheTime += t;
    }
    fseek(file, pos*KEY_VALUE_SIZE, SEEK_SET);
    fwrite((char*) newRecord, KEY_VALUE_SIZE, 1, file);
    fflush(file);
    if (!switchToOPEN) {
        fclose(file);
    }
}

vector<pair<prf_type, prf_type>> TransientStorage::getAllPairs(long dataIndex) {
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
    long size = counter;
    if (Utilities::DROP_CACHE && !setupMode) {
        Utilities::startTimer(113);
        if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
        if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
        auto t = Utilities::stopTimer(113);
        cacheTime += t;
    }
    fseek(file, 0L, SEEK_SET);

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

vector<pair<pair<prf_type, prf_type>, prf_type> > TransientStorage::getAllTriples(long dataIndex) {
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
    long size = counter;
    if (Utilities::DROP_CACHE && !setupMode) {
        Utilities::startTimer(113);
        if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
        if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
        auto t = Utilities::stopTimer(113);
        cacheTime += t;
    }
    fseek(file, 0L, SEEK_SET);

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

vector<prf_type> TransientStorage::getAllData(long dataIndex) {
    vector<prf_type> results;

    //fstream file(filenames[dataIndex].c_str(), ios::binary | ios::in | ios::ate);
    //        FILE* file = fopen(filenames[dataIndex].c_str(), "rb");
    FILE* file;
    if (switchToOPEN) {
        file = filehandles[dataIndex];
    } else {
        file = fopen(filenames[dataIndex].c_str(), "rb+");
    }
    if (file == NULL) {
        cerr << "Error in insert: " << strerror(errno);
    }
    long size = counter;
    if (Utilities::DROP_CACHE && !setupMode) {
        Utilities::startTimer(113);
        if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
        if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
        auto t = Utilities::stopTimer(113);
        cacheTime += t;
    }
    //file.seekg(0, ios::beg);
    fseek(file, 0L, SEEK_SET);

    char* keyValue = new char[size * KEY_VALUE_SIZE];
    //file.read(keyValue, size);
    fread(keyValue, size*KEY_VALUE_SIZE, 1, file);

    for (long i = 0; i < size; i++) {
        prf_type tmp;
        std::copy(keyValue + i*KEY_VALUE_SIZE, keyValue + i * KEY_VALUE_SIZE + AES_KEY_SIZE, tmp.begin());
        results.push_back(tmp);
    }
    if (!switchToOPEN) {
        fclose(file);
    }
    //		file.close();
    //        fclose(file);
    delete keyValue;
    //            printf("TransientStorage getalldata Cache time:%f\n",cacheTime);
    return results;
    //}
}

vector<prf_type> TransientStorage::getEntriesPartially(long dataIndex, int beginIndex, int incount) {
    vector<prf_type> results;
    int count = min(incount, counter - beginIndex);
    if (count < incount) {
        //        cout<<"asking for more than existing data"<<endl;
    }
    //fstream file(filenames[dataIndex].c_str(), ios::binary | ios::in | ios::ate);
    //        FILE* file = fopen(filenames[dataIndex].c_str(), "rb");
    FILE* file;
    if (switchToOPEN) {
        file = filehandles[dataIndex];
    } else {
        file = fopen(filenames[dataIndex].c_str(), "rb+");
    }
    if (file == NULL) {
        cerr << "Error in insert: " << strerror(errno);
    }
    if (Utilities::DROP_CACHE && !setupMode) {
        Utilities::startTimer(113);
        if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
        if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
        auto t = Utilities::stopTimer(113);
        cacheTime += t;
    }
    //file.seekg(0, ios::beg);
    fseek(file, beginIndex*KEY_VALUE_SIZE, SEEK_SET);

    char* keyValue = new char[count * KEY_VALUE_SIZE];
    //file.read(keyValue, size);
    fread(keyValue, count*KEY_VALUE_SIZE, 1, file);

    for (long i = 0; i < count; i++) {
        prf_type tmp;
        std::copy(keyValue + i*KEY_VALUE_SIZE, keyValue + i * KEY_VALUE_SIZE + AES_KEY_SIZE, tmp.begin());
        results.push_back(tmp);
    }
    if (!switchToOPEN) {
        fclose(file);
    }
    //		file.close();
    //        fclose(file);
    delete keyValue;
    //            printf("TransientStorage getalldata Cache time:%f\n",cacheTime);
    return results;
    //}
}

vector<pair<prf_type, prf_type> > TransientStorage::getPairsPartially(long dataIndex, int beginIndex, int incount) {
    vector<pair<prf_type, prf_type>> results;
    int count = min(incount, counter - beginIndex);
    if (count < incount) {
        //        cout<<"asking for more than existing data"<<endl;
    }
    //fstream file(filenames[dataIndex].c_str(), ios::binary | ios::in | ios::ate);
    //        FILE* file = fopen(filenames[dataIndex].c_str(), "rb");
    FILE* file;
    if (switchToOPEN) {
        file = filehandles[dataIndex];
    } else {
        file = fopen(filenames[dataIndex].c_str(), "rb+");
    }
    if (file == NULL) {
        cerr << "Error in insert: " << strerror(errno);
    }
    if (Utilities::DROP_CACHE && !setupMode) {
        Utilities::startTimer(113);
        if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
        if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
        auto t = Utilities::stopTimer(113);
        cacheTime += t;
    }
    //file.seekg(0, ios::beg);
    fseek(file, beginIndex*KEY_VALUE_SIZE, SEEK_SET);

    char* keyValue = new char[count * KEY_VALUE_SIZE];
    //file.read(keyValue, size);
    fread(keyValue, count*KEY_VALUE_SIZE, 1, file);

    for (long i = 0; i < count; i++) {
        prf_type tmp, tmp2;
        std::copy(keyValue + i*KEY_VALUE_SIZE, keyValue + i * KEY_VALUE_SIZE + AES_KEY_SIZE, tmp.begin());
        std::copy(keyValue + i * KEY_VALUE_SIZE + AES_KEY_SIZE, keyValue + i * KEY_VALUE_SIZE + 2 * AES_KEY_SIZE, tmp2.begin());
        results.push_back(pair<prf_type, prf_type>(tmp, tmp2));
    }
    if (!switchToOPEN) {
        fclose(file);
    }
    //		file.close();
    //        fclose(file);
    delete keyValue;
    //            printf("TransientStorage getalldata Cache time:%f\n",cacheTime);
    return results;
    //}
}

void TransientStorage::clear(long index) {
    if (inMemoryStorage) {
        data[index].clear();
    } else {/*
		   if (USE_XXL) {
		   diskData[index]->clear();
		   } else {*/
        //        fstream file(filenames[index].c_str(), std::ios::binary | std::ofstream::out);
        //        FILE* file = filehandles[index];
        //
        //        fseek(file, 0L, SEEK_SET);
        //        long maxSize = pow(2, index + 1);
        //        long nextPtr = 0;
        //        for (long j = 0; j < maxSize; j++) {
        //            fwrite((char*) nullKey.data(), AES_KEY_SIZE, 1, file);
        //            fwrite((char*) nullKey.data(), AES_KEY_SIZE, 1, file);
        //            fwrite((char*) nullKey.data(), AES_KEY_SIZE, 1, file);
        //            fwrite((char*) nullKey.data(), AES_KEY_SIZE, 1, file);
        //
        //            //            file.write((char*) nullKey.data(), AES_KEY_SIZE);
        //            //            file.write((char*) nullKey.data(), AES_KEY_SIZE);
        //            //            file.write((char*) &nextPtr, sizeof (long));
        //        }
        //        // file.write((char*) &nextPtr, sizeof (long));
        //        //        file.close();
        //        fflush(file);
        //        if (Utilities::DROP_CACHE && !setupMode) {
        //            Utilities::startTimer(113);
        //            if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
        //            if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
        //            auto t = Utilities::stopTimer(113);
        //            cacheTime += t;
        //            //            cout << "cache time:" << t << endl;
        //        }
        counter = 0;
    }
    //}
}

TransientStorage::~TransientStorage() {
    //    fclose(filehandles[dataIndex - 1]);
    if (switchToOPEN) {
        //        Utilities::numOfFile--;
        fclose(filehandles[dataIndex - 1]);
    }
}

pair<prf_type, prf_type> TransientStorage::getPair(long dataIndex, long index) {
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
    prf_type tmp;
    long pos = index;
    if (Utilities::DROP_CACHE && !setupMode) {
        Utilities::startTimer(113);
        if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
        if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
        auto t = Utilities::stopTimer(113);
        cacheTime += t;
    }
    fseek(file, pos*KEY_VALUE_SIZE, SEEK_SET);
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

vector<pair<prf_type, prf_type> > TransientStorage::getPairVector(long dataIndex, long begin, int count) {
    vector<pair<prf_type, prf_type> >res;
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

    char* chainHead = new char[KEY_VALUE_SIZE * count];
    if (profile)
        seekgCount++;
    int cnt = 0;

    long pos = begin;
    if (Utilities::DROP_CACHE && !setupMode) {
        Utilities::startTimer(113);
        if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
        if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
        auto t = Utilities::stopTimer(113);
        cacheTime += t;
    }
    fseek(file, pos*KEY_VALUE_SIZE, SEEK_SET);
    Utilities::startTimer(129);
    fread(chainHead, KEY_VALUE_SIZE*count, 1, file);

    for (int i = 0; i < count; i++) {
        prf_type p1, p2;
        std::copy(chainHead + i*KEY_VALUE_SIZE, chainHead + i * KEY_VALUE_SIZE + AES_KEY_SIZE, p1.begin());
        std::copy(chainHead + i * KEY_VALUE_SIZE + AES_KEY_SIZE, chainHead + i * KEY_VALUE_SIZE + (2 * AES_KEY_SIZE), p2.begin());
        res.push_back(pair<prf_type, prf_type>(p1, p2));
    }
    auto endtime = Utilities::stopTimer(124);
    getCounterTime = endtime - (cacheTime - previousCacheTime);
    if (!switchToOPEN) {
        fclose(file);
    }
    delete chainHead;
    return res;
}

void TransientStorage::getTriple(long dataIndex, long index, prf_type& p1, prf_type& p2, prf_type& p3) {
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
    fseek(file, pos*KEY_VALUE_SIZE, SEEK_SET);
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

void TransientStorage::getPairAndInt(long dataIndex, long index, prf_type& p1, prf_type& p2, unsigned int& p3) {
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
    fseek(file, pos*KEY_VALUE_SIZE, SEEK_SET);
    Utilities::startTimer(129);
    fread(chainHead, KEY_VALUE_SIZE, 1, file);
    std::copy(chainHead, chainHead + AES_KEY_SIZE, p1.begin());
    std::copy(chainHead + AES_KEY_SIZE, chainHead + (2 * AES_KEY_SIZE), p2.begin());
    p3 = *((unsigned int*) &chainHead[AES_KEY_SIZE * 2]);
    auto endtime = Utilities::stopTimer(124);
    getCounterTime = endtime - (cacheTime - previousCacheTime);
    if (!switchToOPEN) {
        fclose(file);
    }
}

void TransientStorage::getTripleAndInt(long dataIndex, long index, prf_type& p1, prf_type& p2, prf_type& p3, unsigned int& p4) {
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
    fseek(file, pos*KEY_VALUE_SIZE, SEEK_SET);
    Utilities::startTimer(129);
    fread(chainHead, KEY_VALUE_SIZE, 1, file);
    std::copy(chainHead, chainHead + AES_KEY_SIZE, p1.begin());
    std::copy(chainHead + AES_KEY_SIZE, chainHead + (2 * AES_KEY_SIZE), p2.begin());
    std::copy(chainHead + AES_KEY_SIZE * 2, chainHead + (3 * AES_KEY_SIZE), p3.begin());
    p4 = *((unsigned int*) &chainHead[AES_KEY_SIZE * 3]);
    auto endtime = Utilities::stopTimer(124);
    getCounterTime = endtime - (cacheTime - previousCacheTime);
    if (!switchToOPEN) {
        fclose(file);
    }
}

prf_type TransientStorage::getEntry(long dataIndex, long index) {
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
    prf_type tmp;
    long pos = index;
    if (Utilities::DROP_CACHE && !setupMode) {
        Utilities::startTimer(113);
        if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
        if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
        auto t = Utilities::stopTimer(113);
        cacheTime += t;
    }
    fseek(file, pos*KEY_VALUE_SIZE, SEEK_SET);
    Utilities::startTimer(129);
    fread(chainHead, KEY_VALUE_SIZE, 1, file);
    std::copy(chainHead, chainHead + AES_KEY_SIZE, tmp.begin());
    auto endtime = Utilities::stopTimer(124);
    getCounterTime = endtime - (cacheTime - previousCacheTime);
    if (!switchToOPEN) {
        fclose(file);
    }
    return tmp;
}

vector<prf_type> TransientStorage::getEntryVector(long dataIndex, long begin, long count) {
    vector<prf_type> res;
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
    if (Utilities::DROP_CACHE && !setupMode) {
        Utilities::startTimer(113);
        if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
        if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
        auto t = Utilities::stopTimer(113);
        cacheTime += t;
    }
    fseek(file, begin*KEY_VALUE_SIZE, SEEK_SET);
    char* chainHead = new char[KEY_VALUE_SIZE * count];
    fread(chainHead, count*KEY_VALUE_SIZE, 1, file);
    for (int i = 0; i < count; i++) {
        prf_type tmp;
        std::copy(chainHead + i*KEY_VALUE_SIZE, chainHead + (i * KEY_VALUE_SIZE) + AES_KEY_SIZE, tmp.begin());
        res.push_back(tmp);
    }
    auto endtime = Utilities::stopTimer(124);
    getCounterTime = endtime - (cacheTime - previousCacheTime);
    if (!switchToOPEN) {
        fclose(file);
    }
    delete chainHead;
    return res;
}

char* TransientStorage::readRawData(long dataIndex, long begin, long count) {
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
    char* chainHead = new char[KEY_VALUE_SIZE * count];
    if (profile)
        seekgCount++;
    long pos = begin;
    if (Utilities::DROP_CACHE && !setupMode) {
        Utilities::startTimer(113);
        if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
        if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
        auto t = Utilities::stopTimer(113);
        cacheTime += t;
    }
    fseek(file, pos*KEY_VALUE_SIZE, SEEK_SET);
    Utilities::startTimer(129);
    fread(chainHead, count*KEY_VALUE_SIZE, 1, file);
    auto endtime = Utilities::stopTimer(124);
    getCounterTime = endtime - (cacheTime - previousCacheTime);
    if (!switchToOPEN) {
        fclose(file);
    }
    return chainHead;
}

void TransientStorage::writeRawData(long dataIndex, char* data, long count) {
    FILE* file;
    if (switchToOPEN) {
        file = filehandles[dataIndex];
    } else {
        file = fopen(filenames[dataIndex].c_str(), "rb+");
    }
    long pos = counter; //(unsigned long) (*((long*) hash)) % maxSize;
    if (Utilities::DROP_CACHE && !setupMode) {
        Utilities::startTimer(113);
        if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
        if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
        auto t = Utilities::stopTimer(113);
        cacheTime += t;
    }
    fseek(file, pos*KEY_VALUE_SIZE, SEEK_SET);
    fwrite((char*) data, KEY_VALUE_SIZE*count, 1, file);
    fflush(file);
    counter += count;
    delete data;
    if (!switchToOPEN) {
        fclose(file);
    }
}

void TransientStorage::writeRawDataFrom(long dataIndex, long begin, char* data, long count) {
    FILE* file;
    if (switchToOPEN) {
        file = filehandles[dataIndex];
    } else {
        file = fopen(filenames[dataIndex].c_str(), "rb+");
    }
    long pos = begin; //(unsigned long) (*((long*) hash)) % maxSize;
    if (Utilities::DROP_CACHE && !setupMode) {
        Utilities::startTimer(113);
        if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
        if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
        auto t = Utilities::stopTimer(113);
        cacheTime += t;
    }
    fseek(file, pos*KEY_VALUE_SIZE, SEEK_SET);
    fwrite((char*) data, KEY_VALUE_SIZE*count, 1, file);
    fflush(file);
    delete data;
    if (!switchToOPEN) {
        fclose(file);
    }
}

void TransientStorage::insertIntAtTheEnd(long dataIndex, int p, unsigned int p3) {
    FILE* file;
    if (switchToOPEN) {
        file = filehandles[dataIndex];
    } else {
        file = fopen(filenames[dataIndex].c_str(), "rb+");
    }
    unsigned char newRecord[AES_KEY_SIZE];
    *((unsigned int*) &newRecord[0]) = p3;
    long pos = p; //(unsigned long) (*((long*) hash)) % maxSize;
    if (Utilities::DROP_CACHE && !setupMode) {
        Utilities::startTimer(113);
        if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
        if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
        auto t = Utilities::stopTimer(113);
        cacheTime += t;
    }
    fseek(file, pos * KEY_VALUE_SIZE + 3 * AES_KEY_SIZE, SEEK_SET);
    fwrite((char*) newRecord, AES_KEY_SIZE, 1, file);
    fflush(file);
    if (!switchToOPEN) {
        fclose(file);
    }
}