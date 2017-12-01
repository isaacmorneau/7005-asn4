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
