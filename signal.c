
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

void xweb_signal_init2 (void) {

    // IGNORE ALL SIGNALS
    struct sigaction action = { 0 };

    action.sa_restorer = NULL;
    action.sa_flags = 0;
    action.sa_handler = SIG_IGN;

    for (int sig = 0; sig != NSIG; sig++)
        sigaction(sig, &action, NULL);

    // HANDLE ONLY THESE
    action.sa_handler = xweb_signal_handler;

    sigaction(SIGINT,  &action, NULL);
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGUSR1, &action, NULL);
    sigaction(SIGUSR2, &action, NULL);
}
