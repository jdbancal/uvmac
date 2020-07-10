/*  This program computes an authentication tag for .

    usage: authenticate inputFile uHashKeyFile tagKeyFile

    parameters:

    inputFile: File containing the message to be authenticated. The file is
      read in binary.

    uHashKeyFile: File containing the secret key to be used to choose the hash
      function within a universal family. This file is read in binary
      It should typically contain 160 bytes (for a tag length of 64 bits).
      The same uHashKeyFile can be used to tag many different messages.

    tagKeyFile: File containing the key to be used to encrypt the tag with
      one-time-pad. This key should be used for ONLY ONE tag. This file should
      be of the length of the tag (8 bytes for a tag of length 64 bits).

    OUTPUT FORMAT:

    the tag is writen in a binary file

    Written on 11 July 2020 by Jean-Daniel Bancal
*/

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include "uvmac.h"

using namespace std;

int main(int argc, char* argv[])
{
    // NOTE: This file assumes that uvmac is set to create a 64-bit tag.

    // Check the number of parameters
    if (argc != 4) {
        // Tell the user how to run the program
        cerr << "Usage: " << argv[0] << " inputFilename uHashKeyFilename tagKeyFilename" << endl;
        return 1;
    }

    string filename1 = argv[1];
    string filename2 = argv[2];
    string filename3 = argv[3];
    string filename4 = filename1 + ".tag";

    ifstream file1;
    ifstream file2;
    ifstream file3;
    ofstream file4;
    file1.open(filename1, ios::binary);
    file2.open(filename2, ios::binary);
    file3.open(filename3, ios::binary);
    file4.open(filename4, ios::binary);
    if(!file1)
    {
        cerr << "Opening input file " << filename1 << " failed" << endl;
        file1.close();
        file2.close();
        file3.close();
        file4.close();
        return 1;
    }
    if(!file2)
    {
        cerr << "Opening input file " << filename2 << " failed" << endl;
        file1.close();
        file2.close();
        file3.close();
        file4.close();
        return 1;
    }
    if(!file3)
    {
        cerr << "Opening input file " << filename3 << " failed" << endl;
        file1.close();
        file2.close();
        file3.close();
        file4.close();
        return 1;
    }
    if(!file4)
    {
        cerr << "Opening output file " << filename4 << " failed" << endl;
        file1.close();
        file2.close();
        file3.close();
        file4.close();
        return 1;
    }

    // Load the first key
    char c1;
    vector < unsigned char > key1;
    int nbRead(0), minToRead(160), maxToRead(340);
    while (file2.get(c1) && (nbRead < maxToRead))
    {
        key1.push_back(c1);
        ++nbRead;
    }
    if (nbRead < minToRead)
    {
        cerr << "Only " << nbRead << " bytes could be read from " << filename2 << " but " << minToRead << " are needed." << endl;
        file1.close();
        file2.close();
        file3.close();
        file4.close();
        return 1;
    }

    // Initialize the hashing function with this key
    uvmax_ctx_t ctx __attribute__((aligned(16)));
    try
    {
        uvmac_set_key(key1.data(), nbRead/8, &ctx);
    }
    catch (const std::exception& e)
    {
        cerr << "Error while initializing the key. This is possible if some numbers in the key are too large." << endl
             << " Try with another random key or with a longer one." << endl;
        file1.close();
        file2.close();
        file3.close();
        file4.close();
        return 1;
    }

    // Load the second key
    vector < unsigned char > key2;
    nbRead = 0;
    minToRead = 8;
    maxToRead = 8;
    while (file3.get(c1) && (nbRead < maxToRead))
    {
        key2.push_back(c1);
        ++nbRead;
    }
    if (nbRead < minToRead)
    {
        cerr << "Only " << nbRead << " bytes could be read from " << filename3 << " but " << minToRead << " are needed." << endl;
        file1.close();
        file2.close();
        file3.close();
        file4.close();
        return 1;
    }

    // Read and process the data file
    const int bufferSize = 1024;
    vector < unsigned char > buffer (bufferSize+1, 0);
    streamsize s(0);
    while (file1)
    {
        file1.read((char*)buffer.data(), bufferSize);
        s = ((file1) ? bufferSize : file1.gcount());
        buffer[s] = 0;

        if (s == bufferSize)
        {
            vhash_update(buffer.data(), s, &ctx);
            s = 0;
        }
    }
    // Add zero paddings for the remaining part if needed
    if ((s > 0) && (s % 16 != 0))
    {
        for (int i(s); i < (s/16+1)*16; ++i)
        {
            buffer[i] = 0;
        }
    }

    // We finish processing and/or produce the tag
    uint64_t running_key_position(0);
    uint64_t tag = uvmac(buffer.data(), s, (uint64_t *)0, &ctx, (uint64_t*)key2.data(), key2.size()/8, &running_key_position);

    // Writing the tag in the output file
    file4.write((char*) &tag, 8);

    file1.close();
    file2.close();
    file3.close();
    file4.close();

    return 0;
}
