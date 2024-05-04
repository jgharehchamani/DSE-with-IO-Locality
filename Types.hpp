#ifndef TYPES
#define TYPES

#include <array>
#include <vector>
#include <iostream>
#include<string>

#define USE_XXL 0
//#define DROP_CACHE  0
//#define HDD_CACHE  1
//#define KERNEL_CACHE  1

#define ID_SIZE 16
#define SPACE_OVERHEAD 4
#define LOCALITY 1
#define INF 9999999
//#define JUMP_SIZE 1
#define MAX_LEVEL 100

//#define CACHE_PERCENTAGE    0


using byte_t = uint8_t;
using block = std::vector<byte_t>;

#define AES_KEY_SIZE 32
#define TMP_AES_KEY_SIZE 16


#define NLOGN_LOCALITY 2
#define S 2

typedef std::array<uint8_t, AES_KEY_SIZE> prf_type;
typedef std::array<uint8_t, TMP_AES_KEY_SIZE> tmp_prf_type;

typedef unsigned char byte;

template <size_t N>
using bytes = std::array<byte_t, N>;

// A bucket contains a number of Blocks
constexpr int Z = 4;

enum Op {
    READ,
    WRITE
};

enum OP {
    INS, DEL
};

template< typename T >
std::array< byte_t, sizeof (T) > to_bytes(const T& object) {
    std::array< byte_t, sizeof (T) > bytes;

    const byte_t* begin = reinterpret_cast<const byte_t*> (std::addressof(object));
    const byte_t* end = begin + sizeof (T);
    std::copy(begin, end, std::begin(bytes));

    return bytes;
}

template< typename T >
T& from_bytes(const std::array< byte_t, sizeof (T) >& bytes, T& object) {
    byte_t* begin_object = reinterpret_cast<byte_t*> (std::addressof(object));
    std::copy(std::begin(bytes), std::end(bytes), begin_object);

    return object;
}

#endif
