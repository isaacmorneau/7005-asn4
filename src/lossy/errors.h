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

#endif
