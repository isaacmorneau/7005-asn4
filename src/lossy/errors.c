/*
 * =====================================================================================
 *
 *       Filename:  errors.c
 *
 *        Project:  7005-asn4-lossy
 *
 *    Description:  The functions for cumputing and using the error rate in the lossy
 *                  middle man.
 *
 *      Functions:  ipow();
 *                  dec_to_frac();
 *                  errors_init();
 *                  errors_close();
 *                  errors_checkdrop();
 *                  errors_regen();
 *                  damage_packet();
 *
 *        Version:  1.0
 *        Created:  12/02/2017 03:36:50 PM
 *       Revision:  none
 *
 *         Author:  Isaac Morneau (im), isaacmorneau@gmail.com
 *
 * =====================================================================================
 */
#include <stdlib.h>

#include <math.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "errors.h"
#include "cpp_wrapper.h"

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  ipow
 *  Description:  interger pow
 *   Parameters:  int base - the numer to exponentiate
 *                int exp - the exponent to raise it to
 *       Return:  int - the result
 * =====================================================================================
 */
int ipow(int base, int exp) {
    assert(exp >= 0);
    int res = 1;
    while (exp) {
        if (exp & 1) {
            res *= base;
        }
        exp >>= 1;
        base *= base;
    }
    return res;
}


/*
 * ===  FUNCTION  ======================================================================
 *         Name:  dec_to_frac
 *  Description:  converts string percentages to improper fraction
 *   Parameters:  const char * dec_str - the percentage string
 *                int * restrict numerator - the numerator of the fraction
 *                int * restrict denominator - the denominator of the fraction
 *       Return:  void
 * =====================================================================================
 */
void dec_to_frac(const char * dec_str, int * restrict numerator, int * restrict denominator) {
    double dec = atof(dec_str);
    assert(dec > 0);
    char * dot = strchr(dec_str, '.');
    int denom = 100;//its in percent start at 100
    if (dot) { //theres a decimal part
        int multiplyer = ipow(10, strlen(dec_str) - strcspn(dec_str, ".") - ((int)(dot - dec_str)));
        denom *= multiplyer;
        dec *= multiplyer;
    }
    for(;denom < dec; denom*=10);//waste not want not
    for(*numerator = (int)dec, *denominator = denom; !(*numerator % 10 | *denominator % 10); *numerator /= 10, *denominator /= 10);
}


/*
 * ===  FUNCTION  ======================================================================
 *         Name:  errors_init
 *  Description:  initialize the error struct
 *   Parameters:  errors * restrict er - the structure to initialize
 *                const char * rate - the percentage error rate as a string
 *       Return:  void
 * =====================================================================================
 */
void errors_init(errors * restrict er, const char * rate) {
    double dec = atof(rate);
    if (dec > 100.0) {
        fprintf(stderr, "you cannot lose more than all packets don't be ridiculous\n");
        exit(1);
    } else if (dec < 0.0) {
        fprintf(stderr, "you cannot lose less than no packets don't be ridiculous\n");
        exit(1);
    }
    er->index = 0;
    dec_to_frac(rate, &er->rate, &er->loop);
    //should prolly check if this fails to allocate but really we should never be that low on memory
    er->drops = calloc(er->loop, sizeof(int));
    printf("loss: %d segment: %d\n", er->rate, er->loop);
    errors_regen(er);
}


/*
 * ===  FUNCTION  ======================================================================
 *         Name:  errors_close
 *  Description:  close the error structure
 *   Parameters:  errors * restrict er - the structure to close
 *       Return:  void
 * =====================================================================================
 */
void errors_close(errors * restrict er) {
    free(er->drops);
}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  errors_regen
 *  Description:  remake the internal error state
 *   Parameters:  errors * restrict er - the structure to close
 *       Return:  void
 * =====================================================================================
 */
void errors_regen(errors * restrict er) {
    memset(er->drops, 0, er->loop);
    uniform_set(er->drops, er->rate, er->loop);
}


/*
 * ===  FUNCTION  ======================================================================
 *         Name:  errors_checkdrop
 *  Description:  return 1 or 0 for if the error occured at the internal rate
 *   parameters:  errors * restrict er - the structure to check
 *       return:  void
 * =====================================================================================
 */
int errors_checkdrop(errors * restrict er) {
    if (er->loop == -1) {
        return 0;
    }
    int ret = 0;
    if (er->drops[er->index]) {
        ret = 1;
    }
    ++er->index;
    if (er->index >= er->loop) {
        errors_regen(er);
        er->index = 0;
    }
    return ret;
}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  damage_packet
 *  Description:  mutate the bits in the packet at the given rate
 *   Parameters:  raw_packet * restrict pkt - the packet to damage
 *                int rate - the rate at which bits are damaged
 *                int sample - the loop size for error rate
 *       Return:  void
 * =====================================================================================
 */
void damage_packet(raw_packet * restrict pkt, int rate, int sample) {
    for(int i = 0; i < (pkt->length-2) * 8; i += sample) {
        for(int j = rate;j--;) {
            pkt->data[rand() % (pkt->length - 2)] ^= rand() % (sizeof(unsigned char) * 8);
        }
    }
}
