/*
 * =====================================================================================
 *
 *       Filename:  cpp_wrapper.cpp
 *
 *        Project:  7005-asn4-lossy
 *
 *    Description:  Wrappers around cpp source to allow for use of the cpp random stdlib
 *                  when computing losses
 *
 *      Functions:  uniform_set();
 *                  bit_pop();
 *                  damage_set();
 *
 *        Version:  1.0
 *        Created:  12/02/2017 03:33:57 PM
 *       Revision:  none
 *
 *         Author:  Isaac Morneau (im), isaacmorneau@gmail.com
 *
 * =====================================================================================
 */
#include <stdlib.h>

#include "cpp_wrapper.h"
#include <random>
#include <vector>


/*
 * ===  FUNCTION  ======================================================================
 *         Name:  uniform_set
 *  Description:  generate a uniform distribution of 1's in the loop size
 *   Parameters:  int * items - the items to set to 1
 *                int rate - the number per loop to set
 *                int loop - the size of the items list
 *       Return: void
 * =====================================================================================
 */
void uniform_set(int * items, int rate, int loop) {
    std::default_random_engine generator;
    std::uniform_int_distribution<int> distribution(0, loop-1);
    int pos;
    for (int i = 0; i < rate; ++i) {
randexists:
        pos = distribution(generator);
        if (items[pos]) {
            goto randexists;
        }
        items[pos] = 1;
    }
}

int bit_pop(unsigned char num) {
    int count = 0;
    while (num != 0) {
        if (num & 1) {
            ++count;
        }
        num >>= 1;
    }
    return count;
}

void damage_set(unsigned char * items, int size, int rate, int loop) {
    std::default_random_engine generator;
    std::uniform_int_distribution<int> int_dist(0, loop-1);
    std::uniform_int_distribution<unsigned char> uchar_dist(0, sizeof(unsigned char));

    int pos;
    unsigned char breaker;
    int bits = 0;
    int finishing_BER = rate * (size/(double)loop);
    int i = 0;
    while (i < finishing_BER) {
randexists:
        pos = int_dist(generator);
        if (items[pos]) {
            goto randexists;
        }
        //flipped bits for XOR
        breaker = uchar_dist(generator);
        //how many bits were broken
        bits = bit_pop(breaker);
        //do the breaking
        items[pos] ^= breaker;
        i += bits;
    }
}
