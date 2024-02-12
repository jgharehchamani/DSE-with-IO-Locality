#include "RAMStore.hpp"
#include <iostream>
#include "ORAM.hpp"
#include "Utilities.h"
#include <bits/stdc++.h>

using namespace std;

string RAMStore::randomString(int ch) {
    char alpha[26] = {'a', 'b', 'c', 'd', 'e', 'f', 'g',
        'h', 'i', 'j', 'k', 'l', 'm', 'n',
        'o', 'p', 'q', 'r', 's', 't', 'u',
        'v', 'w', 'x', 'y', 'z'};
    string result = "";
    for (int i = 0; i < ch; i++)
        result = result + alpha[rand() % 26];

    return result;
}

RAMStore::RAMStore(size_t count, size_t size)
: store(count), size(size) {
    filename = Utilities::rootAddress + "OMAP-" + randomString(15) + ".dat";

    long alloc_size = count * size;
    while (alloc_size > 0) {
        long bs = min(alloc_size, 2147483648);
        string command = string("dd if=/dev/zero bs=" + to_string(bs) + " count=1 >> " + filename);
        cout << "command:" << command << endl;
        system(command.c_str());
        alloc_size -= bs;
    }

    //    fstream file(filename.c_str(), std::ofstream::out);
    //    if (file.fail()) {
    //        cerr << "Error: " << strerror(errno);
    //    }
    //    vector<uint8_t> nullKey;
    //    for (int i = 0; i < size; i++) {
    //        nullKey.push_back(0);
    //    }
    //
    //    for (long j = 0; j < count; j++) {
    //        file.write((char*) nullKey.data(), size);
    //    }
    //    file.close();
    filehandle = fopen(filename.c_str(), "rb+");
}

RAMStore::~RAMStore() {
    fclose(filehandle);
}

block RAMStore::Read(int pos) {
    if (useHDD) {
        if (Utilities::DROP_CACHE && !setup) {
            Utilities::startTimer(113);
            if (HDD_CACHE)system("sudo hdparm -A 0 /dev/sda > /dev/null 2>&1");
            if (KERNEL_CACHE)system("echo 3 | sudo tee /proc/sys/vm/drop_caches > /dev/null 2>&1");
            auto t = Utilities::stopTimer(113);
            cacheTime += t;
        }
        fseek(filehandle, pos*size, SEEK_SET);
        block chainHead(size);
        fread(chainHead.data(), size, 1, filehandle);


        return chainHead;
    } else {
        return store[pos];
    }
}

void RAMStore::Write(int pos, block b) {
    if (useHDD) {
        if (Utilities::DROP_CACHE && !setup) {
            Utilities::startTimer(113);
            if (HDD_CACHE)system("sudo hdparm -A 0 /dev/sda > /dev/null 2>&1");
            if (KERNEL_CACHE)system("echo 3 | sudo tee /proc/sys/vm/drop_caches > /dev/null 2>&1");
            auto t = Utilities::stopTimer(113);
            cacheTime += t;
        }
        fseek(filehandle, pos*size, SEEK_SET);
        fwrite((char*) b.data(), size, 1, filehandle);
    } else {
        store[pos] = b;
    }
}
