
void xweb_init1 (const u64 id) {

    dbg("RUNNING AS PROCESS ID %llu", (uintll)id);

    // SIGNALS
    // NO SIGNAL CAUGHT YET
    sigTERM = sigUSR1 = sigUSR2 = 0;
#if XWEB_TEST
    sigINT = 0;
#endif

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

    //
#if XWEB_TEST // DISABLE ECHO FOR PAUSE
    struct termios termios;
    tcgetattr(STDIN_FILENO, &termios);
    termios.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &termios);
#endif

    xweb_io_init2();

    // DNS
    // TODOS DEVEM SER SUBMETIDOS
    // DIVIDIDO ENTRE OS SERVIDORES
    DNSAnswer* answer = dnsAnswers;

    foreach (server, DNS_SERVERS_N)
        foreach (count, DNS_SERVER_ANSWERS_N) {
            answer->result = IO_ERR;
            answer->server = server;
            xweb_io_submit(&answer->result, IORING_OP_READ, dnsSockets[server], (u64)answer->pkt, 0, sizeof(answer->pkt));
            answer++;
        }

    // HOSTS
    xweb_host_ips_add_4(xweb_host_lookup_new("127.0.0.1", 9), IP4(127,0,0,1));
    xweb_host_lookup_new("127.0.0.1", 9)->pktSize = 0;

    // PROXIES
    foreach (i, XWEB_PROXIES_STATIC_N)
        xweb_proxy_add(
            proxiesStatic[i].ip,
            proxiesStatic[i].port,
            proxiesStatic[i].protocol);

    log("HAS %u PROXIES", proxiesN);
}
