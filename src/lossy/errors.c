#include "errors.h"

void errors_init(errors * er, const char * rate) {

}
void errors_close(errors * er) {
    free(er->drops);
}
void errors_regen(errors * er) {

}
int errors_checkdrop(errors * er) {
    return 0;
}
