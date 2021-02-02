/*  Program to run authentication on a file

    usage: authentic hashKeyFile padKeyFile inputFile messageNumber

    Written on 11 July 2020 by Jean-Daniel Bancal
    Last modified 17 Aug 2020
*/

#include <iostream>
#include <fstream>
#include <string>
#include <algorithm>
#include <cstring>
#include <cassert>
#include "uvmaclib.h"

using namespace std;

int main(int argc, char* argv[])
{
    // Check the number of parameters
    if (argc != 5) {
        // Tell the user how to run the program
#if (UVMAC_TAG_LEN == 64)
        cout << "This program creates a 64-bit tag for a file" << endl;
#else
        cout << "This program creates a 128-bit tag for a file" << endl;
#endif
        cout << endl;
        cout << "Usage: " << endl;
        cout << "    " << argv[0] << " hashKeyFile padKeyFile inputFile messageNumber" << endl;
        cout << endl;
        cout << "  Parameters:" << endl;
        cout << "    hashKeyFile: the key to be used to choose the hash function, in binary format" << endl;
#if (UVMAC_TAG_LEN == 64)
        cout << "      This file should contain 160 bytes" << endl;
#else
        cout << "      This file should contain 208 bytes" << endl;
#endif
        cout << "    padKeyFile: the key to be used for one-time pad, in binary format" << endl;
#if (UVMAC_TAG_LEN == 64)
        cout << "      This file should contain at least 8*messageNumber bytes" << endl;
#else
        cout << "      This file should contain at least 16*messageNumber bytes" << endl;
#endif
        cout << "    inputFile: file to be authenticated" << endl;
        cout << "    messageNumber: a number >=1, identifying the part of keyFile2 to be used" << endl;
        cout << "      Like a nonce: no number should be used twice" << endl;
        cout << endl;
        cout << "  Output format:" << endl;
        cout << endl;
        cout << "    A file containing the tag in hexadecimal format" << endl;
        return 1;
    }

    string filename1 = argv[1];
    string filename2 = argv[2];
    string filename3 = argv[3];
    string filename4 = filename3 + ".tag";


    // 1. Loading the hash key
#if (UVMAC_TAG_LEN == 64)
    uint64_t key_length = 20; // For 64-bits tags
#else
    uint64_t key_length = 26; // 128-bit tags require longer key
#endif
    alignas(4) unsigned char hash_key_data[key_length*8];
    ifstream file1;
    file1.open(filename1, ios::in | ios::binary);
    if (!file1)
    {
        cerr << "Opening hash key file " << filename1 << " failed" << endl;
        return 1;
    }
    file1.read((char*)hash_key_data, key_length*8);
    if (!file1) {
        cerr << "Error while reading from the hash key file " << filename1 << endl;
        return 1;
    }
    file1.close();


    // 2. Initializing the hash function
    alignas(16) uvmax_ctx_t ctx;
    uvmac_set_key(hash_key_data, key_length, &ctx);


    // 3. Decode the message number
    long long int messageNumber = atoll(argv[4]);
    if (messageNumber == 0)
    {
        cerr << "Message number should be an integer larger or equal to 1." << endl;
        return 1;
    }


    // 4. Loading the interesting part of the pad key
#if (UVMAC_TAG_LEN == 64)
    uint64_t running_key_length = 1; // For 64-bits tags
#else
    uint64_t running_key_length = 2; // 128-bit tags require longer key
#endif
    alignas(4) unsigned char running_key_data[running_key_length*8];
    uint64_t *running_key = (uint64_t*) &running_key_data;
    uint64_t running_key_position = 0;
    long int co = 0;
    ifstream file2;
    file2.open(filename2, ios::in | ios::binary);
    if (!file2)
    {
        cerr << "Opening pad key file " << filename2 << " failed" << endl;
        return 1;
    }
    while (co < messageNumber)
    {
        ++co;
        file2.read((char*) running_key_data, running_key_length*8);
        if (!file2) {
            cerr << "Error while reading from the pad key file " << filename1 << endl;
            return 1;
        }
    }
    file2.close();


    // 5. Load the input file and hash it
    /* Initialize 16-byte aligned message buffer */
    void *p;
    unsigned char *m;
    const unsigned int buf_len = 3 * (1 << 20);
    p = malloc(buf_len + 32);
    m = (unsigned char *)(((size_t)p + 16) & ~((size_t)15));
    memset(m, 0, buf_len + 16);
    uint64_t res, tagl;

    /* Load data from file */
    ifstream file3;
    file3.open(filename3, ios::in | ios::binary | ios::ate);
    if (!file3)
    {
        cerr << "Opening input file " << filename3 << " failed" << endl;
        return 1;
    }
    streampos fileSize = file3.tellg(); // get the file size
    file3.seekg (0, ios::beg); // Go back at the beginning of the file
    for (long int pos(0); pos < fileSize; )
    {
        unsigned int lengthToRead;
        if ((fileSize - pos) < buf_len)
            lengthToRead = fileSize - pos;
        else
            lengthToRead = buf_len;

        file3.read((char*) m, lengthToRead);
        if ((file3.gcount() != lengthToRead) || (!file3))
        {
            cerr << "File reading error. Read " << file3.gcount() << " bytes instead of " << lengthToRead << endl;
            return 1;
        }
        if (pos + lengthToRead < fileSize)
        {
            assert((lengthToRead % UVMAC_NHBYTES) == 0);
            vhash_update(m, lengthToRead, &ctx);
        }
        else
        {
            // We need to complete the message with zeros up to the next 16 bytes
            for (unsigned int j(lengthToRead-1); j < std::min(lengthToRead+16, buf_len+16); ++j)
                m[j] = 0;
            res = uvmac(m, lengthToRead-1, &tagl, &ctx, running_key, running_key_length, &running_key_position);
        }
        pos += lengthToRead;
    }
    file3.close();

    // If all is good we save the result in the output file
    ofstream file4;
    file4.open(filename4, ios::out);
    if (!file4)
    {
        cerr << "Opening output file " << filename4 << " failed" << endl;
        return 1;
    }
    file4 << hex << res;
    file4.close();

    return 0;
}

