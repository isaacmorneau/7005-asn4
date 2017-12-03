/*
 * =====================================================================================
 *
 *       Filename:  errors.h
 *
 *        Project:  7005-asn4-lossy
 *
 *    Description:  The functions for controlling error rate in the lossy middle man
 *
 *      Functions:  errors_init();
 *                  errors_close();
 *                  errors_checkdrop();
 *                  errors_regen();
 *                  damage_packet();
 *                  dec_to_frac();
 *
 *        Version:  1.0
 *        Created:  12/02/2017 03:38:39 PM
 *       Revision:  none
 *
 *         Author:  Isaac Morneau (im), isaacmorneau@gmail.com
 *
 * =====================================================================================
 */

#ifndef ERRORS_H
#define ERRORS_H

#include "../packet.h"

typedef struct errors {
    int index;//where we are
    int loop;//when to next regen drops
    int rate;//how many drops to make
    int * drops;//the positions to drop
} errors;

void errors_init(errors * er, const char * rate);
void errors_close(errors * er);
//remake the drops
void errors_regen(errors * er);
//see if we should drop
int errors_checkdrop(errors * er);
//corrupt it
void damage_packet(raw_packet * pkt, int rate, int sample);
//percent into usable ints
void dec_to_frac(const char * dec_str, int * numerator, int * denominator);

#endif
