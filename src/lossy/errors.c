#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <math.h>

#include "errors.h"

void errors_init(errors * er, const char * rate) {
    double loss = atof(rate);
    char * index = strchr(rate, '.');

    long segment = 100;
    long whole_loss;

    if (index) {//fractional loss
        int max_loops = strlen(index) - 1;

        double frac = loss - (long)loss;
        int multiplyer = 1;
        while (max_loops-- && frac) {
            frac *= 10;
            frac = frac - (long)frac;
            multiplyer *= 10;
        }

        segment *= multiplyer;
        whole_loss = loss * multiplyer;
    } else {//whole number loss
        whole_loss = (long)loss;
        if (whole_loss > 100) {
            fprintf(stderr, "you cannot lose more than all packets don't be ridiculous\n");
            abort();
        } else if (whole_loss < 0) {
            fprintf(stderr, "you cannot lose less than no packets don't be ridiculous\n");
            abort();
        }
    }
    er->index = 0;
    er->loop = (int)segment;
    er->rate = (int)whole_loss;
    //should prolly check if this fails to allocate but really we should never be that low on memory
    er->drops = calloc((int)segment, sizeof(int));
    printf("loss: %ld segment: %ld\n", whole_loss, segment);
    errors_regen(er);
}
void errors_close(errors * er) {
    free(er->drops);
}
void errors_regen(errors * er) {
    memset(er->drops, 0, er->loop);
    for (int i = er->rate; i--;) {
        er->drops[(int)(rand() % er->loop)] = 1;
    }
}
int errors_checkdrop(errors * er) {
    if (er->loop == -1 ) {
        return 0;
    }
    int ret = 0;
    if (er->drops[er->index]) {
        ret = 1;
    }
    ++(er->index);
    if (er->index >= er->loop) {
        errors_regen(er);
        er->index = 0;
    }
    return ret;
}
