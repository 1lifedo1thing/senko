#include "device_model.h"

#include <stdio.h>
#include <string.h>

int main(void) {
    static const struct { const char *code; const char *name; } cases[] = {
        {"iPhone4,1", "iPhone 4S"},
        {"iPhone3,3", "iPhone 4"},
        {"iPhone8,1", "iPhone 6s"},
        {"iPad2,5", "iPad mini"},
        {"iPad5,3", "iPad Air 2"},
        {"iPod5,1", "iPod touch (5th generation)"},
        {"iPhone17,5", "iPhone 16e"}
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        const char *name = senko_device_model_name(cases[i].code);
        if (!name || strcmp(name, cases[i].name) != 0) {
            fprintf(stderr, "wrong model for %s\n", cases[i].code);
            return 1;
        }
    }
    if (senko_device_model_name(NULL) || senko_device_model_name("") ||
        senko_device_model_name("iPhone4,11") || senko_device_model_name("iphone4,1") ||
        senko_device_model_name("x86_64")) {
        fprintf(stderr, "unknown model was recognized\n");
        return 1;
    }
    puts("device model checks passed");
    return 0;
}
