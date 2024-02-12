#ifndef BASSERVER_H
#define BASSERVER_H
#include "Storage.h"

class AmortizedBASServer {
public:
    Storage* storage;
    bool profile = false;
    void getAESRandomValue(unsigned char* keyword, int cnt, unsigned char* result);

public:
    AmortizedBASServer(int dataIndex, bool inMemory, bool overwrite, bool profile);
    void clear(int index);
    virtual ~AmortizedBASServer();
    void storeCiphers(int dataIndex, map<prf_type, prf_type> ciphers);
    vector<prf_type> search(int dataIndex, prf_type token);
    vector<prf_type> getAllData(int dataIndex);
    void endSetup();

};


#endif /* BASSERVER_H */

