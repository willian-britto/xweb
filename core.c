
static PyObject* xweb_PY_connect_start (const char* const restrict hostname, const uint hostnameSize, const uint port, void* const restrict ssl, const uint proxyTries) {

    xweb_connect_start(hostname, hostnameSize, port, ssl, proxyTries);

    return None;
}

static PyObject* xweb_PY_conn_send_bytes (PyObject* const bytes) {

    return xweb_conn_send_bytes(bytes);
}

// TODO: FIXME: CADA CONEXÃO COM UM BUFFER PRÓPRIO DE MSG? TERIA DE LIDAR COM O REFCOUNT; AO DELETAR A CONEXÃO *TENTAR* SE LIVRAR DO BUFFER, BASTANDO DESCONTAR O REF COUNT

// É DO TIPO CONSUME ONCE, ENTÃO LÊ DO FD TODA VEZ QUE FOR CHAMADA
// ESTÁ LENDO UMA MENSAGEM DE TAMANHO ESPECÍFICO
// NOTA: PARA TER CHEGADO AQUI, JA SABE QUE CHEGOU A CONECTAR E NAO CHEGOU A DESCONECTAR

static PyObject* xweb_conn_recv_sized_PY (void) {
#if 0
    ASSERT(conn->poll);                // POS ESSE TIPO DE FUNCAO LE DIRETO; NAO TEM BUFFERS
    ASSERT(!conn->in); // JA CONSUMIU TODOS NA FUNCAO START
    ASSERT(conn->msgSize);      // A FUNCAO ASSUME QUE AINDA TEM ALGO A LER

    dbg_conn("RECEIVE EXACT");

    if (conn->read) {

        const int size = xweb_conn_read(conn, MSGBUFF, conn->msgLmt);

        if (size == -1) {
            dbg_conn("RECEIVE EXACT - ERROR");
            return Err;
        }

        if (size) {

            MSGBUFF += size;
            conn->msgLmt  -= size;

            if (conn->msgLmt) {
                dbg_conn("RECEIVE EXACT - INCOMPLETE");
                return None;
            }

            dbg_conn("RECEIVE EXACT - COMPLETE");
            return xweb_conn_msg_finished(conn);
        }
    }

    if (conn->poll) {
        dbg_conn("RECEIVE EXACT - WAIT");
        return None;
    }

    dbg_conn("RECEIVE EXACT - CLOSED");
    return Err;
#endif
    return None;
}

static PyObject* xweb_PY_conn_recv_sized_start (const uint size) {
#if 0
    dbg_conn("RECEIVE EXACT - START - SIZE %u", size);

    ASSERT_CONN_NO_INPUT(conn);

    if (size == 0) {
        dbg_conn("RECEIVE EXACT - START - ZERO");
        return Err;
    }

    if (size > 128*1024*1024) {
        dbg_conn("RECEIVE EXACT - START - TOO BIG");
        return Err;
    }

    conn->msgType    = 0;
    conn->msgMore    = size;
    conn->msgSkip    = 0;
    conn->msgLmt     = size;
    MSGBUFF    = PyObject_Malloc(size);
    conn->msgIn      = NULL;
    conn->msgInStart = NULL;

    do {
        if (conn->in == NULL) { // CONSUMIU TUDO O QUE JÁ TINHA, E AINDA ASSIM NÃO COMPLETOU
            dbg_conn("RECEIVE EXACT - START - NOT IN CHUNKS");
            return xweb_conn_recv_sized(); // TENTA DAR UM READ E CONSUMIR O RESTANTE
        }

        uint size = conn->in->size;

        if (size == 0) {
            In* const next = conn->in->next;
            free(conn->in);
            if ((conn->in = next) == NULL)
                conn->in_ = NULL;
            continue;
        }

        if (size > conn->msgLmt)
            size = conn->msgLmt;

        memcpy(MSGBUFF, conn->in->start, size);

        conn->in->start += size;

        MSGBUFF += size;
        conn->msgLmt  -= size;

    } while (conn->msgLmt);

    dbg_conn("RECEIVE EXACT - START - DONE (ALREADY IN CHUNKS)");

    return xweb_conn_msg_finished(conn);
#endif
    (void)size; return None;
}

// INFORMA O TAMANHO E JÁ TENTA CONSUMIR
// VAI DESCONTANDO DO ->exactSize E COLOCANDO NO ->exactEnd
static PyObject* xweb_PY_conn_http_recv_body_eof (void) {

    return None;
}

static PyObject* xweb_PY_conn_http_recv_body_eof_start (void) {

    return xweb_PY_conn_http_recv_body_eof();
}

static PyObject* xweb_PY_conn_http_recv_body_sized (void) {

    return xweb_PY_conn_recv_sized();
}

static PyObject* xweb_PY_conn_http_recv_body_sized_start (const uint size) {

    return xweb_PY_conn_recv_sized_start(size);
}

static PyObject* xweb_PY_conn_http_recv_header (void) {

    Conn* const conn = thread->conn;

    while (conn->in) {

        const uint inSize = conn->in->end - conn->in->start;

        // SÓ VERIFICA SE JÁ FOR GRANDE, OU NO CAO DE SER PEQUENO MAS NÃO TER MAIS NADA
        if (inSize >= 128 || conn->in->next == NULL) {

            void* const end = memmem(conn->in->start, inSize, "\r\n\r\n", 4);

            if (end) { // FOUND
                if (memcmp(conn->in->start, "HTTP/1.0", 8) &&
                    memcmp(conn->in->start, "HTTP/1.1", 8)) {
                    conn->poll = CONN_POLL_CLOSE;
                    return Err; // BAD HEADER START
                }

                const uint size = end - conn->in->start;

                void* const buff = malloc(size);

                memcpy(buff, conn->in->start, size);
                conn->in->start += size + 4;

                thread->msg->ob_bytes = buff;
                thread->msg->ob_start = buff;
                thread->msg->ob_alloc = size;

                Py_REFCNT(thread->msg) = 2;
                return (PyObject*)thread->msg;
            }

            if (inSize >= 4096) {
                conn->poll = CONN_POLL_CLOSE;
                return Err; // THE HEADER IS TOO BIG
            }
        }

        if (conn->in->next == NULL)
            break;

        memcpy((conn->in->next->start -= inSize), conn->in->start, inSize);

        xweb_conn_in_consumed(conn);
    }

    if (conn->poll)
        return None;

    return Err;
}

// TODO: FIXME: NÃO É DO TIPO CONSUME, ENTÃO ELA MESMA DÁ O IN()
static PyObject* xweb_PY_conn_http_recv_header_start (void) {

    return xweb_PY_conn_http_recv_header();
}

// NOTE: NÃO ESTÁ SUPORTANDO O TRAILER
static PyObject* xweb_PY_conn_http_recv_body_chunked (void) {
#if 0
    ASSERT(conn->msgLmt >= 64);
    ASSERT(conn->msgLmt <= IN_SIZE_MAX);
    ASSERT(conn->msgSkip < conn->msgLmt);

    if (conn->msgIn == NULL) {
        if (conn->in == NULL) {
            if (conn->poll)
                return None;
            return Err;
        } // FINALMENTE INICIALIZA
        conn->msgIn = conn->in;
        conn->msgInStart = conn->in->start;
    }

    loop {

        ASSERT(conn->in);
        ASSERT(conn->in->start <= conn->in->end);
        ASSERT(conn->in->start >= ((char*)conn->in + sizeof(In)));
        ASSERT(conn->in->start <= ((char*)conn->in + sizeof(In) + IN_SIZE_MAX));
        ASSERT(conn->in_);
        ASSERT(conn->msgIn);
        ASSERT(conn->msgInStart >= conn->in->start);
        ASSERT(conn->msgInStart <= conn->in->end);

        if (conn->msgInStart == conn->msgIn->end) {
            // CHEGOU NO FIM DESTE IN
            if (conn->msgIn->next == NULL) {
                if (conn->poll)
                    return None;
                return Err;
            }
            conn->msgIn = conn->msgIn->next;
            conn->msgInStart = conn->msgIn->start;
            continue;
        }

        const uint TEM = conn->msgIn->end - conn->msgInStart;

        if (conn->msgSkip) {
            // AINDA ESTÁ SKIPPANDO UM CHUNK
            uint size = conn->msgSkip;
            if (size > TEM)
                size = TEM;
            conn->msgSkip -= size;
            conn->msgInStart += size;
            continue;
        }

        // ESTÁ NA HORA DE LER UM CHUNK SIZE
        if (TEM <= 8) {
            if (conn->msgIn->next) {
                *(u64*)(conn->msgIn->next->start - 8) =
                *(u64*)(conn->msgIn->end - 8);
                conn->msgIn->next->start -= TEM; // COLOCOU NO NEXT
                conn->msgIn->end -= TEM; // RETIROU DESTE
                continue; // PODE AINDA SER PEQUENO; ALÉM DISSO, PRECISA ATUALIZAR NOVAMENTE O TEM
            }
        }

        //
        char* ptr = conn->msgInStart; uint count = 0; uint chunkSize = 0; uint chr;

        while ((chr = *ptr++) != '\r') {
            if (count++ == 7)
                return Err;
            if ((chr -= ((chr <= '9') ? '0': (chr <= 'F') ? 'A' - 10: 'a' - 10)) > 0xFU)
                return Err;
            chunkSize <<= 4;
            chunkSize |= chr;
        }

        if (count == 0)
            return Err; // NÃO LEU NENHUM NIBBLE

        if (ptr > conn->msgIn->end) {
            if (conn->poll)
                return None;
            return Err;
        }

        // CONSEGUIU LER

        if (chunkSize == 0)  {
            // TERMINOU

            PyByteArrayObject* const body = (PyByteArrayObject*)PyByteArray_FromStringAndSize("", 1);

            PyObject_Free(body->ob_bytes);

            body->ob_bytes = PyObject_Malloc(conn->msgSkip);
            body->ob_start = body->ob_bytes;
            body->ob_alloc = conn->msgSkip;

            // AGORA COPIA TODOS
            // E VAI DANDO FREE NELES

            conn->msgLmt    = 0;
            conn->msgSkip   = 0;
            conn->msgIn     = NULL;
            conn->msgInStart = NULL;

            return (PyObject*)body;
        }

        // AINDA NÃO TERMINOU
        if (conn->msgLmt <= chunkSize)
            return Err; // É MUITO GRANDE

        conn->msgLmt -= chunkSize;
        conn->msgSkip = chunkSize + 1; // TAMBÉM IGNORA O \n
        conn->msgInStart = ptr;
    }
#endif
    return None;
}






















PyObject* xweb_PY_exit (void) {

    log("EXITING");

    foreach (i, DNS_SERVERS_N)
        close(dnsSockets[i]);

    const Conn* conn = conns;

    // TODO: FIXME: CANCELAR TUDO
    while (conn) {
        if (conn->fd)
            close(conn->fd);
        conn = conn->next;
    }

    //
    while (uConsumePending) {
        dbg("WAITING %u EVENTS", uConsumePending);
        sched_yield();
        uint head = *IOU_C_HEAD;
        loop {
            read_barrier();
            if (head == *IOU_C_TAIL)
                break;
            uConsumePending--;
            head++;
        }
        *IOU_C_HEAD = head;
        write_barrier(); // TODO: FIXME:
        break;
    }

    // TODO: FIXME: CUIDADO COM OS OBJETOS :S
    if (munmap(IOU_S_SQES, IOU_S_SQES_SIZE))
        fatal("FAILED TO UNMAP IOU_S_SQES");
    if (munmap(IOU_BASE, IOU_BASE_SIZE))
        fatal("FAILED TO UNMAP IOU_BASE");
    if (close(IOU_FD))
        fatal("FAILED TO CLOSE IOU_FD");

    // NOTE: WE CANNOT TOUCH ANYMORE:
        // IO_URING
        // dnsSockets[i]
        // EACH CONN->FD

#if XWEB_TEST // RESTORE THE ECHO
    struct termios termios;
    tcgetattr(STDIN_FILENO, &termios);
    termios.c_lflag |= ECHO;
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &termios);
#endif

    return 0;
}

#if XWEB_TEST
static void xweb_poll_pause (void) {

    if (sigINT) { u8 r[128]; // O SUFICIENTE PARA CONSUMIR TUDO
        sigINT = 0;
        write(1, "------------ PAUSE ------------\n", 32);
        const int readen = read(STDIN_FILENO, r, sizeof(r));
        if ((readen == -1 && errno == EINTR) || readen == 0)
            sigTERM = 1;
    }
}
#endif

PyObject* xweb_PY_poll (void) {

    do {
        xweb_conns_poll();
        xweb_dns_poll_send();
        xweb_log_poll();
        xweb_io_poll(); // TODO: FIXME: RECALCULAR OS SEGUNDOS/RTSC ANTES E DEPOIS DO YIELD
        xweb_dns_poll_receive();
        xweb_conns_poll_res();
#if XWEB_TEST
        xweb_poll_pause();
#endif
    } while (0); // TODO: FIXME: TEM QUE TER TIDO ALGUM EVENTO, OU ALCANCADO ALGUM TIMEOUT, OU PAUSADO, OU SIGTERM

    // TODO: FIXME: earliest = now + 15*1000
    // DAI NA THREAD_LEAVE:
    //  if (earliest > thread->timeout)
    //      earliest = thread->timeout;
    // E EM TODAS AS COISAS SENDO USADAS COMO TIMEOUT
    //      talvez na funcao TIMEOUT() ? :S
    //      não, nas comparações! if (SOMETIME <= now) em que SOMETIME for um timeout


    Py_REFCNT(None)        = 0xFFFFFFF;
    Py_REFCNT(Err)         = 0xFFFFFFF;
    Py_REFCNT(ErrClosed)   = 0xFFFFFFF;
    Py_REFCNT(ErrTimeout)  = 0xFFFFFFF;
    Py_REFCNT(ErrSession)  = 0xFFFFFFF;
    Py_REFCNT(ErrNotFound) = 0xFFFFFFF;

    if (sigTERM)
        return None;

    return UINTLL_TO_PY(xweb_now_update());
}

PyObject* xweb_PY_init1 (const u64 id) {

    dbg("RUNNING AS PROCESS ID %llu", (uintll)id);

    // SIGNALS
    // NO SIGNAL CAUGHT YET
    sigTERM = sigUSR1 = sigUSR2 = 0;
#if XWEB_TEST
    sigINT = 0;
#endif

    xweb_signal_init2();

    //
#if XWEB_TEST // DISABLE ECHO FOR PAUSE
    struct termios termios;
    tcgetattr(STDIN_FILENO, &termios);
    termios.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &termios);
#endif

    xweb_io_init2();
    xweb_dns_init2();

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

    return None;
}
