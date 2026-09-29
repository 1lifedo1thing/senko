#ifndef SENKOD_HELPER_H
#define SENKOD_HELPER_H

/* runs senkod --awg-probe <conf> or --update <deb> and returns the exit code;
   -1 when argv names neither */
int senkod_helper_main(int argc, char **argv);

/* the senkod binary on disk, for starting it in a helper mode */
const char *senkod_binary_path(void);

#endif
