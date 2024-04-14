#ifndef UTILITIES_H
#define UTILITIES_H
#include <vector>
#include <string>
#include <algorithm>
#include <iostream>
#include <iterator>
#include <string>
#include <map>
#include <vector>
#include <fstream>
#include <chrono>
#include <stdlib.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <iostream>
#include<utility>
#include <fstream>
#include <algorithm>
#include <unistd.h>
#include <math.h>
#include <set>
#include <stdio.h>
#include <string.h>
#include "Types.hpp"

#define SUB_BLOCK_SIZE 4096
#define SUB_BLOCKS_PER_BLOCK 4096

using namespace std;

struct PRFHasher {

    std::size_t operator()(const prf_type &key) const {
        std::hash<byte_t> hasher;
        size_t result = 0;
        for (size_t i = 0; i < AES_KEY_SIZE; ++i) {
            result = (result << 1) ^ hasher(key[i]);
        }
        return result;
    }
};

struct CompareLess {

    bool operator()(const prf_type& a, const prf_type& b) const {
        for (int i = 0; i < AES_KEY_SIZE; i++) {
            if (a[i] > b[i]) {
                return false;
            } else if (a[i] < b[i]) {
                return true;
            }
        }
        //     return a < b; 
        return false;
    }

    static prf_type min_value() {
        prf_type result;
        for (int i = 0; i < AES_KEY_SIZE; i++) {
            result[i] = 0;
        }
        return result;
    }

    static prf_type max_value() {
        prf_type result;
        for (int i = 0; i < AES_KEY_SIZE; i++) {
            result[i] = 0xFF;
        }
        return result;
    }
};

template <typename T>
class TC {
public:
    uint N;
    uint K;
    std::vector<uint> Qs;
    std::vector<uint> delNumber;
    std::vector<std::string> keywords;
    std::vector<std::string> testKeywords;
    std::vector<std::string> filePairsKey;
    std::vector<std::vector<T> > filePairsValue;
};

class Utilities {
private:
    static int parseLine(char* line);
public:
    static bool DROP_CACHE;
    static bool DEBUG_MODE;
    static bool PROFILE_MODE;
    static bool useRandomFolder;


    Utilities();
    //        static std::string getSHA256(std::string input);
    //    static std::string encryptAndEncode(std::string input, unsigned char* key, unsigned char* iv);
    //    static std::string decodeAndDecrypt(std::string plaintext, unsigned char* key, unsigned char* iv);
    static unsigned char* sha256(char* input, int size);
    static std::string base64_encode(const char* bytes_to_encode, unsigned int in_len);
    static std::string base64_decode(std::string const& enc);
    static std::string XOR(std::string value, std::string key);
    static void startTimer(int id);
    static double stopTimer(int id);
    static std::map<int, std::chrono::time_point<std::chrono::high_resolution_clock> > m_begs;
    static std::map<std::string, std::ofstream*> handlers;
    static void logTime(std::string filename, std::string content);
    static void initializeLogging(std::string filename);
    static void finalizeLogging(std::string filename);
    static std::array<uint8_t, 16> convertToArray(std::string value);
    static int getMem();
    static double getTimeFromHist(int id);
    static int getBid(std::string srchIndex);
    static std::array<uint8_t, TMP_AES_KEY_SIZE> tmpencode(std::string keyword);
    static std::array<uint8_t, TMP_AES_KEY_SIZE> tmpencode(std::string keyword, unsigned char* curkey);
    static std::array<uint8_t, TMP_AES_KEY_SIZE> tmpencode(unsigned char* plaintext, unsigned char* curkey = NULL);
    static std::string tmpdecode(std::array<uint8_t, TMP_AES_KEY_SIZE> data, unsigned char* curkey = NULL);
    static unsigned char tmpkey[TMP_AES_KEY_SIZE], tmpiv[TMP_AES_KEY_SIZE];
    static std::array<uint8_t, AES_KEY_SIZE> encode(std::string keyword);
    static std::array<uint8_t, AES_KEY_SIZE> encode(std::string keyword, unsigned char* curkey);
    static std::array<uint8_t, AES_KEY_SIZE> encode2(std::string keyword, unsigned char* curkey);
    static std::array<uint8_t, AES_KEY_SIZE> encode3(std::string keyword, unsigned char* curkey);
    static std::array<uint8_t, AES_KEY_SIZE> encode(unsigned char* plaintext, unsigned char* curkey = NULL);
    static std::string decode(std::array<uint8_t, AES_KEY_SIZE> data, unsigned char* curkey = NULL);
    static unsigned char key[AES_KEY_SIZE], iv[AES_KEY_SIZE];
    static std::string testKeyword;
    static std::string rootAddress;
    static int numOfFile;
    static int TotalCacheSize;
    static int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext);
    static int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext);
    static void handleErrors(void);
    static std::vector<std::string> splitData(const std::string& str, const std::string& delim);
    static void decode(std::array<uint8_t, AES_KEY_SIZE> ciphertext, std::array<uint8_t, AES_KEY_SIZE>& plaintext, unsigned char* curkey = NULL);
    static void decode2(std::array<uint8_t, AES_KEY_SIZE> ciphertext, std::array<uint8_t, AES_KEY_SIZE>& plaintext, unsigned char* curkey = NULL);
    static void decode3(std::array<uint8_t, AES_KEY_SIZE> ciphertext, std::array<uint8_t, AES_KEY_SIZE>& plaintext, unsigned char* curkey = NULL);
    static void tmpdecode(std::array<uint8_t, TMP_AES_KEY_SIZE> ciphertext, std::array<uint8_t, TMP_AES_KEY_SIZE>& plaintext, unsigned char* curkey = NULL);
    static std::array<uint8_t, TMP_AES_KEY_SIZE> tmpgeneratePRF(unsigned char* keyword, unsigned char* prfkey);
    static std::array<uint8_t, AES_KEY_SIZE> generatePRF(unsigned char* keyword, unsigned char* prfkey);

    template <typename T>
    static void generateCrimeDataSet(std::vector<TC<T> >& testCases, string filename) {

    }

    template <typename T>
    static void readConfigFile(std::vector<TC<T> >& testCases, bool& inMemory, bool& overwrite) {


        /*
         * 
         * 
         * COLUMN 6 
         * 
         * 
1118148  BATTERY
12495  INTERFER
22  HUMANTRA
13960  GAMBLING
23056  CRIMSEXU
6257  KIDNAPPI
136  PUBLICIN
373285  ASSAULT
383  OBSCENIT
66666  PROSTITU
44471  PUBLICPE
289047  MOTORVEH
2909  STALKING
59704  WEAPONSV
13546  LIQUORLA
882136  CRIMINAL
23  RITUALIS
229541  ROBBERY
39711  OFFENSEI
111  NONCRIMI
7824  HOMICIDE
1268571  THEFT
10173  ARSON
111  OTHERNAR
66  CONCEALE
357878  BURGLARY
3572  INTIMIDA
215943  DECEPTIV
378935  OTHEROFF
22469  SEXOFFEN
1  DOMESTIC
682125  NARCOTIC
         * 
         * 
         * COLUMN 8
         * 
5280  OTHERRAI
311  CEMETARY
37  VEHICLED
941  COINOPER
46  GARAGE
1  CLEANERS
615506  SIDEWALK
57183  RESIDENT
24466  CHAHALLW
2  PUBLICHI
12779  GOVERNME
583  BOWLINGA
73305  DEPARTME
6858  ATHLETIC
2469  CARWASH
3  CHABREEZ
20622  TAVERNLI
2595  OTHERCOM
4517  CLEANING
5379  LIBRARY
1566  APPLIANC
45213  COMMERCI
79330  GROCERYF
15312  POLICEFA
911  HIGHWAYE
1  PUBLICGR
858  JAILLOCK
38  CHAGROUN
61  GANGWAY
6  LIQUORST
96833  VEHICLEN
138782  ALLEY
19813  CTATRAIN
2  CTALTRAI
17807  DRIVEWAY
9888  CURRENCY
124  VEHICLEO
34357  CHAAPART
7  DUMPSTER
13  OFFICE
34293  CTAPLATF
22163  VACANTLO
27816  DRUGSTOR
930  LAKEFRON
13  RAILROAD
11632  CONVENIE
2  RIVERBAN
9376  CTAGARAG
230516  OTHER
1475  null
6463  FACTORYM
11977  CONSTRUC
19534  CTABUS
89882  RESTAURA
54176  CHAPARKI
402  PAWNSHOP
66  RETAILST
47641  PARKPROP
6458  MEDICALD
78  HALLWAY
217  NEWSSTAN
3  SEWER
24995  BANK
2302  DAYCAREC
11559  NURSINGH
5  MOTEL
15  VESTIBUL
363  FORESTPR
1  BANQUETH
2  YMCA
1  JUNKYARD
8  CHASTAIR
1  EXPRESSW
1  LOADINGD
236  PORCH
2  PRAIRIE
8539  WAREHOUS
8  TRUCK
3  LAKE
2  LAUNDRYR
103472  SMALLRET
17642  HOSPITAL
29  BASEMENT
9  GARAGEAU
2  CHAELEVA
1  ROOMINGH
63407  GASSTATI
15744  SCHOOLPR
2266  MOVIEHOU
327  SAVINGSA
328  BRIDGE
161149  SCHOOLPU
1616  CTASTATI
449  HOUSE
1  ELEVATOR
1631721  STREET
31288  BARORTAV
15934  AIRPORTA
949  AUTO
851  AIRPORTB
4834  CTABUSST
7160  BARBERSH
4  RIVER
690  AIRPORTE
9  SCHOOLYA
6306  TAXICAB
2  CHURCHPR
6525  COLLEGEU
3  TRAILER
6  CHALOBBY
3  CHAPLAYL
754  POOLROOM
3  CTALPLAT
1  TRUCKING
1262971  RESIDENC
14  STAIRWEL
907  FIRESTAT
2  LIVERYST
585  BOATWATE
2  FACTORY
1  FUNERALP
175207  PARKINGL
434  AIRCRAFT
158  YARD
3  COACHHOU
41  CTATRACK
6334  ATMAUTOM
32  TAVERN
962  DELIVERY
468  AIRPORTP
619107  APARTMEN
24698  HOTELMOT
4  CHURCH
10376  ABANDONE
4377  SPORTSAR
451  CREDITUN
5380  AIRPORTT
15  HOTEL
5  WOODEDAR
2  CTAPROPE
13545  CHURCHSY
638  AIRPORTV
640  ANIMALHO
1  LIVERYAU
2  COUNTYJA
14  CLUB
4766  VEHICLEC
687  FEDERALB
         */
        std::ifstream infile;
        infile.open("crimes2.csv");
        std::string tmp;
        TC<T> testCase;
        int numOfLines = 6123275;
        testCase.N = numOfLines;
        testCase.K = 148;
        std::set<std::string> keywords;
        for (int i = 1; i <= numOfLines; i++) {
            getline(infile, tmp);
            testCase.filePairs[tmp].push_back(i);
            keywords.insert(tmp);
        }
        testCase.keywords.insert(testCase.keywords.end(), keywords.begin(), keywords.end());
        //        testCase.testKeywords.push_back("DOMESTIC");
        //        testCase.testKeywords.push_back("HUMANTRA");
        //        testCase.testKeywords.push_back("OTHERNAR");
        //        testCase.testKeywords.push_back("STALKING");
        //        testCase.testKeywords.push_back("LIQUORLA");
        //        testCase.testKeywords.push_back("ROBBERY");
        //
        //        testCase.Qs.push_back(1);
        //        testCase.Qs.push_back(22);
        //        testCase.Qs.push_back(111);
        //        testCase.Qs.push_back(2909);
        //        testCase.Qs.push_back(13546);
        //        testCase.Qs.push_back(229541);
        //
        //        testCase.delNumber.push_back(0);
        //        testCase.delNumber.push_back(2);
        //        testCase.delNumber.push_back(11);
        //        testCase.delNumber.push_back(290);
        //        testCase.delNumber.push_back(1354);
        //        testCase.delNumber.push_back(22954);


        //        testCase.testKeywords.push_back("CHURCH");
        //        testCase.testKeywords.push_back("HALLWAY");
        //        testCase.testKeywords.push_back("FIRESTAT");
        //        testCase.testKeywords.push_back("AIRPORTT");
        testCase.testKeywords.push_back("HOTELMOT");
        //        testCase.testKeywords.push_back("PARKINGL");

        //        testCase.Qs.push_back(4);
        //        testCase.Qs.push_back(78);
        //        testCase.Qs.push_back(907);
        //        testCase.Qs.push_back(5380);
        testCase.Qs.push_back(24698);
        //        testCase.Qs.push_back(175207);

        testCase.delNumber.push_back(4939);
        //        testCase.delNumber.push_back(0);
        //        testCase.delNumber.push_back(0);
        //        testCase.delNumber.push_back(0);
        //        testCase.delNumber.push_back(0);
        //        testCase.delNumber.push_back(0);


        infile.close();
        testCases.push_back(testCase);
    }

    template <typename T>
    static void readConfigFile(int argc, char** argv, std::string address, std::vector<TC<T> >& testCases, bool& inMemory, bool& overwrite) {
        /*
         * Config file structure (They should be sorted based on N)
         * 
         * Total Test Cases Number
         *      #for each test case
         *      N
         *      K
         *      query number
         *      #for each query 
         *          Q size
         *          delete number
         */
        std::ifstream infile;
        std::string tmp;

        //        if (argc > 1) {
        //            TC<T> testCase;
        //            testCase.N = std::stoi(argv[1]);
        //            testCase.K = std::stoi(argv[2]);
        //            testCase.Qs.push_back(std::stoi(argv[3]));
        //            testCase.delNumber.push_back(std::stoi(argv[4]));
        //            testCases.push_back(testCase);
        //        } else {
        infile.open(address);
        getline(infile, tmp);
        inMemory = (tmp == "true") ? true : false;
        getline(infile, tmp);
        overwrite = (tmp == "true") ? true : false;
        std::cout << "overWrite:" << overwrite << std::endl;
        getline(infile, tmp);
        int totalTests = stoi(tmp);
        for (int i = 0; i < totalTests; i++) {
            TC<T> testCase;
            getline(infile, tmp);
            testCase.N = stoi(tmp);
            getline(infile, tmp);
            testCase.K = stoi(tmp);
            getline(infile, tmp);
            int qNum = stoi(tmp);
            for (int i = 0; i < qNum; i++) {
                getline(infile, tmp);
                testCase.Qs.push_back(stoi(tmp));
                getline(infile, tmp);
                testCase.delNumber.push_back(stoi(tmp));
            }
            testCases.push_back(testCase);
        }
        infile.close();
        //        }
    };

    template <typename T>
    void static apply_permutation_in_place(std::vector<T>& vec, const std::vector<std::size_t>& p) {
        std::vector<bool> done(vec.size());
        for (std::size_t i = 0; i < vec.size(); ++i) {
            if (done[i]) {
                continue;
            }
            done[i] = true;
            std::size_t prev_j = i;
            std::size_t j = p[i];
            while (i != j) {
                std::swap(vec[prev_j], vec[j]);
                done[j] = true;
                prev_j = j;
                j = p[j];
            }
        }
    }

    template <typename T>
    static std::vector<T> apply_permutation(
            const std::vector<T>& vec,
            const std::vector<std::size_t>& p) {
        std::vector<T> sorted_vec(vec.size());
        std::transform(p.begin(), p.end(), sorted_vec.begin(), [&](std::size_t i) {
            return vec[i]; });
        return sorted_vec;
    }

    template <typename A, typename B>
    void static zip(
            const std::vector<A> &a,
            const std::vector<B> &b,
            std::vector<std::pair<A, B>> &zipped) {
        for (size_t i = 0; i < a.size(); ++i) {
            zipped.push_back(std::make_pair(a[i], b[i]));
        }
    }

    // Write the first and second element of the pairs in 
    // the given zipped vector into a and b. (This assumes 
    // that the vectors have equal length)

    template <typename A, typename B>
    void static unzip(
            const std::vector<std::pair<A, B>> &zipped,
            std::vector<A> &a,
            std::vector<B> &b) {
        for (size_t i = 0; i < a.size(); i++) {
            a[i] = zipped[i].first;
            b[i] = zipped[i].second;
        }
    }

    static std::vector<pair<string, int> > generateTestCases(std::vector<TC<int> >& testCases, uint keywordLength, unsigned int seed, string filename, std::vector<int>& ops) {
        char alphanum[] =
                "0123456789"
                "!@#$%^&*"
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                "abcdefghijklmnopqrstuvwxyz";

        srand(seed);
        uint totalKeywordSize = 0;
        uint totalPairNumber = 0;
        std::vector<pair<string, int> > allpairs;

        vector<int>resultSizes;


        for (uint i = 0; i < testCases.size(); i++) {
            std::ifstream infile;
            infile.open(filename.c_str());
            testCases[i].N = 0;
            testCases[i].K = 0;

            string line;
            while (std::getline(infile, line)) {
                int a = stoi(line);
                resultSizes.push_back(a);
                testCases[i].N += a;
                testCases[i].K++;
            }

            int queryCounter = 0;

            for (int j = 0; j < resultSizes.size(); j++) {
                string str = "";
                for (uint k = 0; k < keywordLength; ++k) {
                    str += alphanum[rand() % (sizeof (alphanum) - 1)];
                }
                testCases[i].keywords.push_back(str);
                testCases[i].filePairsKey.push_back(str);
                std::vector<int> files;
                for (int k = 0; k < resultSizes[j]; k++) {
                    files.push_back(k);
                    allpairs.push_back(pair<string, int>(str, k));
                    ops.push_back(0);
                }
                testCases[i].filePairsValue.push_back(files);
                if (queryCounter < testCases[i].Qs.size() && testCases[i].Qs[queryCounter] == resultSizes[j]) {
                    testCases[i].testKeywords.push_back(str);
                    queryCounter++;
                }

            }


            std::vector<int> shuffleids;
            vector<string> test;

            for (int z = 0; z < testCases[i].N; z++) {
                test.push_back(to_string(z));
                prf_type plain;
                memset(plain.data(), 0, AES_KEY_SIZE);
                memcpy(plain.data(), to_string(z).c_str(), 4);
                prf_type enc = encode(plain.data(), key);
                int id = *((int*) enc.data());
                shuffleids.push_back(id);
            }

            std::vector<std::pair < pair<string, int>, int> > zipped;
            zip(allpairs, shuffleids, zipped);

            std::sort(std::begin(zipped), std::end(zipped),
                    [&](const auto& a, const auto& b) {
                        return a.second > b.second;
                    });

            unzip(zipped, allpairs, shuffleids);


            return allpairs;
        }
    };

    //    template <typename T>

    static std::vector<pair<string, int> > generateTestCases(std::vector<TC<int> >& testCases, uint keywordLength, unsigned int seed, std::vector<int>& ops) {
        char alphanum[] =
                "0123456789"
                "!@#$%^&*"
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                "abcdefghijklmnopqrstuvwxyz";

        srand(seed);
        uint totalKeywordSize = 0;
        uint totalPairNumber = 0;
        std::vector<pair<string, int> > allpairs;
        for (uint i = 0; i < testCases.size(); i++) {

            for (uint j = 0; j < testCases[i].K - totalKeywordSize; j++) {
                std::string str;
                for (uint k = 0; k < keywordLength; ++k) {
                    str += alphanum[rand() % (sizeof (alphanum) - 1)];
                }
                //                str="salam";
                testCases[i].keywords.push_back(str);
            }
            totalKeywordSize += testCases[i].keywords.size();

            for (uint j = 0; j < testCases[i].Qs.size(); j++) {
                testCases[i].testKeywords.push_back(testCases[i].keywords[j]);
            }


            for (uint j = 0; j < testCases[i].Qs.size(); j++) {
                std::vector<int> files;
                for (uint k = 0; k < testCases[i].Qs[j]; k++) {
                    files.push_back(k);
                    totalPairNumber++;
                    allpairs.push_back(pair<string, int>(testCases[i].testKeywords[j], k));
                    ops.push_back(0);
                }
                for (uint k = 0; k < testCases[i].delNumber[j]; k++) {
                    totalPairNumber++;
                    allpairs.push_back(pair<string, int>(testCases[i].testKeywords[j], k));
                    ops.push_back(1);
                }
                testCases[i].filePairsKey.push_back(testCases[i].testKeywords[j]);
                testCases[i].filePairsValue.push_back(files);
                files.clear();
            }
            uint totalCounter = totalPairNumber;
            uint reminderKeywords = testCases[i].keywords.size() - testCases[i].testKeywords.size();
            for (uint j = testCases[i].testKeywords.size(); j < testCases[i].keywords.size(); j++) {
                std::vector<int> files;
                for (uint k = 0; k < ceil((double) (testCases[i].N - totalCounter) / (double) reminderKeywords) && totalPairNumber < testCases[i].N; k++) {
                    int fileName = ((rand() % 10000000)) + 10000000;
                    files.push_back(fileName);
                    totalPairNumber++;
                    allpairs.push_back(pair<string, int>(testCases[i].keywords[j], fileName));
                    ops.push_back(0);
                }
                testCases[i].filePairsKey.push_back(testCases[i].keywords[j]);
                testCases[i].filePairsValue.push_back(files);
                files.clear();
            }
            std::vector<int> shuffleids;
            std::vector<int> shuffleids2;
            vector<string> test;

            for (int z = 0; z < testCases[i].N; z++) {
                test.push_back(to_string(z));
                prf_type plain;
                memset(plain.data(), 0, AES_KEY_SIZE);
                memcpy(plain.data(), to_string(z).c_str(), 4);
                prf_type enc = encode(plain.data(), key);
                int id = *((int*) enc.data());
                shuffleids.push_back(id);
                shuffleids2.push_back(id);
            }

            std::vector<std::pair < pair<string, int>, int> > zipped;
            std::vector<std::pair < int, int> > zipped2;
            zip(allpairs, shuffleids, zipped);
            zip(ops, shuffleids2, zipped2);

            std::sort(std::begin(zipped), std::end(zipped),
                    [&](const auto& a, const auto& b) {
                        return a.second > b.second;
                    });

            std::sort(std::begin(zipped2), std::end(zipped2),
                    [&](const auto& a, const auto& b) {
                        return a.second > b.second;
                    });

            unzip(zipped, allpairs, shuffleids);
            unzip(zipped2, ops, shuffleids2);


            return allpairs;
        }
    };

    //-------------------------------------------------------------------------------

    //    template <typename T>

    static std::vector<pair<string, int> > generateTestCases(std::vector<TC<int> >& testCases, uint keywordLength, unsigned int seed, std::vector<std::string> testKeywords, std::vector<int>& ops) {
        char alphanum[] =
                "0123456789"
                "!@#$%^&*"
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                "abcdefghijklmnopqrstuvwxyz";

        srand(seed);
        uint totalKeywordSize = 0;
        uint totalPairNumber = 0;
        std::vector<pair<string, int> > allpairs;
        for (uint i = 0; i < testCases.size(); i++) {
            for (uint j = 0; j < testKeywords.size(); j++) {
                testCases[i].keywords.push_back(testKeywords[j]);
            }
            for (uint j = testKeywords.size(); j < testCases[i].K - totalKeywordSize; j++) {
                std::string str;
                for (uint k = 0; k < keywordLength; ++k) {
                    str += alphanum[rand() % (sizeof (alphanum) - 1)];
                }
                testCases[i].keywords.push_back(str);
            }
            totalKeywordSize += testCases[i].keywords.size();

            for (uint j = 0; j < testCases[i].Qs.size(); j++) {
                testCases[i].testKeywords.push_back(testCases[i].keywords[j]);
            }


            for (uint j = 0; j < testCases[i].Qs.size(); j++) {
                std::vector<int> files;
                for (uint k = 0; k < testCases[i].Qs[j]; k++) {
                    files.push_back(k);
                    totalPairNumber++;
                    allpairs.push_back(pair<string, int>(testCases[i].testKeywords[j], k));
                    ops.push_back(0);
                }
                for (uint k = 0; k < testCases[i].delNumber[j]; k++) {
                    totalPairNumber++;
                    allpairs.push_back(pair<string, int>(testCases[i].testKeywords[j], k));
                    ops.push_back(1);
                }
                testCases[i].filePairsKey.push_back(testCases[i].testKeywords[j]);
                testCases[i].filePairsValue.push_back(files);
                files.clear();
            }
            uint totalCounter = totalPairNumber;
            uint reminderKeywords = testCases[i].keywords.size() - testCases[i].testKeywords.size();
            for (uint j = testCases[i].testKeywords.size(); j < testCases[i].keywords.size(); j++) {
                std::vector<int> files;
                for (uint k = 0; k < ceil((double) (testCases[i].N - totalCounter) / (double) reminderKeywords) && totalPairNumber < testCases[i].N; k++) {
                    int fileName = ((rand() % 10000000)) + 10000000;
                    files.push_back(fileName);
                    totalPairNumber++;
                    allpairs.push_back(pair<string, int>(testCases[i].keywords[j], fileName));
                    ops.push_back(0);
                }
                testCases[i].filePairsKey.push_back(testCases[i].keywords[j]);
                testCases[i].filePairsValue.push_back(files);
                files.clear();
            }
            std::vector<int> shuffleids;
            std::vector<int> shuffleids2;
            vector<string> test;

            for (int z = 0; z < testCases[i].N; z++) {
                test.push_back(to_string(z));
                prf_type plain;
                memset(plain.data(), 0, AES_KEY_SIZE);
                memcpy(plain.data(), to_string(z).c_str(), 4);
                prf_type enc = encode(plain.data(), key);
                int id = *((int*) enc.data());
                shuffleids.push_back(id);
                shuffleids2.push_back(id);
            }

            std::vector<std::pair < pair<string, int>, int> > zipped;
            std::vector<std::pair < int, int> > zipped2;
            zip(allpairs, shuffleids, zipped);
            zip(ops, shuffleids2, zipped2);

            std::sort(std::begin(zipped), std::end(zipped),
                    [&](const auto& a, const auto& b) {
                        return a.second > b.second;
                    });

            std::sort(std::begin(zipped2), std::end(zipped2),
                    [&](const auto& a, const auto& b) {
                        return a.second > b.second;
                    });

            unzip(zipped, allpairs, shuffleids);
            unzip(zipped2, ops, shuffleids2);


            return allpairs;
        }
    };
    virtual ~Utilities();
};

#endif /* UTILITIES_H */

