
#if XWEB_TEST
static volatile sig_atomic_t sigINT;
#endif
static volatile sig_atomic_t sigTERM;
static volatile sig_atomic_t sigUSR1;
static volatile sig_atomic_t sigUSR2;

static void xweb_signal_handler (int signal) {

    switch (signal) {
        case SIGUSR1:
            sigUSR1 = 1;
            break;
        case SIGUSR2:
            sigUSR2 = 1;
            break;
#if XWEB_TEST
        case SIGINT:
            sigINT = 1;
            break;
#endif
        default: // SIGTERM / SIGINT
            sigTERM = 1;
    }
}
