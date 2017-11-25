#include "cpp_wrapper.h"
#include <random>

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
