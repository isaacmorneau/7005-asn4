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

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  bit_pop
 *  Description:  count the number of 1s in bit mask for unamed char
 *   Parameters:  unsigned char num - the number to check
 *       Return:  int the number of 1s in the bit mask
 * =====================================================================================
 */
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

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  damage_set
 *  Description:  flip bits in the set at the given rate per loop
 *   Parameters:  unsigned char * items - the items to damage
 *                int size - how many items there are
 *                int rate - how often to damage them
 *                int loop - how big the loop is for the rate
 *       Return:  void
 * =====================================================================================
 */
void damage_set(unsigned char * items, int size, int rate, int loop) {
    std::default_random_engine generator;
    std::uniform_int_distribution<int> int_dist(0, size-1);
    std::uniform_int_distribution<unsigned char> uchar_dist(0, sizeof(unsigned char));

    unsigned char breaker;
    int bits = 0;
    int finishing_BER = rate * (size/(double)loop);
    int i = 0;
    while (i < finishing_BER) {
        //flipped bits for XOR
        breaker = uchar_dist(generator);
        //how many bits were broken
        bits = bit_pop(breaker);
        //do the breaking
        items[int_dist(generator)] ^= breaker;
        i += bits;
    }
}
