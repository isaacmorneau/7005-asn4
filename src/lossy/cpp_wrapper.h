/*
 * =====================================================================================
 *
 *       Filename:  cpp_wrapper.h
 *
 *        Project:  7005-asn4-lossy
 *
 *    Description:  the exportable headers for the cpp wrapped in c random code
 *
 *      Functions:  uniform_set();
 *                  damage_set();
 *
 *        Version:  1.0
 *        Created:  12/02/2017 03:36:05 PM
 *       Revision:  none
 *
 *         Author:  Isaac Morneau (im), isaacmorneau@gmail.com
 *
 * =====================================================================================
 */

#ifndef CPP_WRAPPER
#define CPP_WRAPPER
#ifdef __cplusplus
extern "C" {
#endif

void uniform_set(int * items, int rate, int loop);
void damage_set(unsigned char * items, int size, int rate, int loop);

#ifdef __cplusplus
}
#endif
#endif
