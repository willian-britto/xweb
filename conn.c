
static uint connsN;
static Conn* conns;


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
static PyObject* xweb_conn_http_recv_header_start_PY (void) {

    return xweb_PY_conn_http_recv_header();
}

// NOTE: NÃO ESTÁ SUPORTANDO O TRAILER
static PyObject* xweb_conn_http_recv_body_chunked_PY (void) {
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


void xweb_conn_out (Conn* const conn, Out* const out) {

    ASSERT(out);
    ASSERT(out->size);

    if (conn->out_) // SE TEM UM ÚLTIMO, APONTA ELE PARA ESTE
        (conn->out_)->next = out;
    else // SE NÃO TEM UM ÚLTIMO, ENTÃO TAMBÉM NÃO TEM UM PRIMEIRO
        conn->out = out;
    conn->out_ = out; // SEMPRE É O ÚLTIMO
}

static inline void xweb_conn_proxy_good (const Conn* const conn) {
    if (conn->proxy != PROXY_NONE)
        if (conn->pool->site->proxiesPoints[conn->proxy])
            conn->pool->site->proxiesPoints[conn->proxy]--;
}

static inline void xweb_conn_proxy_bad (const Conn* const conn) {
    if (conn->proxy != PROXY_NONE)
        if (conn->pool->site->proxiesPoints[conn->proxy] != PROXY_POINTS_MAX)
            conn->pool->site->proxiesPoints[conn->proxy]++;
}

// RETIRA ELE E PEGA O PRÓXIMO
static inline void xweb_conn_in_consumed (Conn* const conn) {

    In* const next = conn->in->next;

    free(conn->in);

    if (!(conn->in = next))
        conn->in_ = NULL;
}

static inline void xweb_out_free (Out* const out) {

    if (out->type == OUT_TYPE_DYNAMIC)
        free(*(void**)out->buff);
    elif (out->type == OUT_TYPE_PYTHON)
        Py_DECREF(*(PyObject**)out->buff);

    free(out);
}

static Out* xweb_out_sized (const uint size) {

    ASSERT(size);

    Out* const out = malloc(sizeof(Out) + size);

    out->next = NULL;
    out->type = OUT_TYPE_SIZED;
    out->size = size;
    out->start = out->buff;

    return out;
}

static Out* xweb_out_static (const void* const restrict buff, const uint size) {

    ASSERT(buff);
    ASSERT(size);

    Out* const out = malloc(sizeof(Out));

    out->next = NULL;
    out->type = OUT_TYPE_STATIC;
    out->size = size;
    out->start = (void*)(uintptr_t)buff;

    return out;
}

// CRIA E REGISTR UM OUT DE DADOS EMBUTIDOS DE TAL TAMANHO
static void* xweb_conn_out_sized (Conn* const conn, const uint size) {

    Out* const out = xweb_out_sized(size);

    xweb_conn_out(conn, out);

    return out->start;
}

static void xweb_conn_out_bytes (Conn* const conn, PyObject* const  obj) {

    Out* const out = malloc(sizeof(Out) + sizeof(PyObject*));

    out->next = NULL;
    out->type = OUT_TYPE_PYTHON;
    out->size = PY_BYTES_SIZE(obj);
    out->start = PY_BYTES_VALUE(obj);

    Py_INCREF((*(PyObject**)out->buff = obj));

    xweb_conn_out(conn, out);
}

static PyObject* xweb_conn_send_bytes (PyObject* const bytes) {

    if (!thread->conn->poll)
        return Err;

    xweb_conn_out_bytes(thread->conn, bytes);

    return None;
}

static inline u64 xweb_pool_hash (const Host* const host, const uint port) {

    // NOTE: SÓ PODE SER ASSIM ENQUANTO OS HOSTS FOREM ESTÁTICOS
    return (u64)(uintptr_t)host + port;
}

// LOOKUP/CREATE A CONNECTION POOL FOR THIS HOST:PORT, ON THE CURRENT SESSION
static Pool* xweb_pool_lookup_new (Host* const host, const uint port) {

    u64 hash = xweb_pool_hash(host, port);

    Pool** ptr = &thread->pools[hash & SESSION_POOLS_ROOTS_MASK]; hash >>= SESSION_POOLS_ROOTS_BITS;

    Pool* pool;

    while ((pool = *ptr)) {
        if (pool->host == host &&
            pool->port == port)
            return pool;
        ptr = &pool->childs[hash & POOL_CHILDS_MASK]; hash >>= POOL_CHILDS_BITS;
    }

    // THIS IS THE FIRST TIME WE REQUESTED A CONNECTION TO THIS HOST:PORT
    pool = (*ptr = malloc(sizeof(Pool)));
    pool->site     = thread->site; // TODO: FIXME: TEM QUE SER NA SESSÃO ATUAL, AQUELE DICT :S OU MELHOR NAO, SIMPLESMENTE VAI FORÇAR AO MUDAR -> VERIFICAR A SESSÃO ANTES DE CHAMAR A FUNCAO; E TALVEZ FECHAR TODAS AS CONEXÕES AO MUDAR?
    pool->host     = host;
    pool->port     = port;
    pool->connsNeeded = 0;
    pool->connsMax = 1024; //
    pool->connsN   = 0; // TODO: FIXME: TEM QUE CONTABILIZAR AQUI TODAS AS QUE ESTIVEREM ABERTAS, E NÃO SOMENTE AS FREES
    pool->conns    = NULL;

    foreach (i, POOL_CHILDS_N)
        pool->childs[i] = NULL;

    return pool;
}

// RETIRA A CONEXÃO DE SEU POOL
static inline void xweb_conn_pool_remove (Conn* const conn) {

    if (conn->poolPtr) {
        if ((*conn->poolPtr = conn->poolNext))
            (*conn->poolPtr)->poolPtr = conn->poolPtr;
        conn->poolPtr = NULL;
        conn->pool->connsN--; // TODA VEZ QUE RETIRAR, APAGAR FAZER ISSO AQUI
    }
}

// COLOCA A CONEXÃO EM SEU POOL
static inline void xweb_conn_pool_add (Conn* const conn) {

    if ((conn->poolNext = *(conn->poolPtr = &conn->pool->conns)))
        conn->poolNext->poolPtr = &conn->poolNext;
    conn->pool->conns = conn;
    conn->pool->connsN++;
}

static PyObject* xweb_PY_conn_release (void) {

    if (thread->conn &&
        thread->conn->poll) {
        xweb_conn_pool_add(thread->conn);
        thread->conn = NULL;
    }

    return None;
}

static PyObject* xweb_PY_conn_close (void) {

    if (thread->conn) {
        thread->conn->poll = CONN_POLL_CLOSE;
        thread->conn = NULL;
    }

    return None;
}

static PyObject* xweb_PY_connect (void) {

    dbg("SERA????");

    if (thread->pool->conns) {
        thread->conn = thread->pool->conns;
        thread->pool->connsNeeded--;
        thread->pool = NULL;
        xweb_conn_pool_remove(thread->conn);
        dbg("HAUHUAUAUAHUAAHUAHUAHAUUAHUAUAHHUAHAUAHUAUAHUAHAUHAUAHUAHUAHUAHUAHAUHAUAHUHAUAHUAHUAHAUHAUHAUAHU");
        return Err; // SUCCESS
    }

    if (thread->timeout <= now)
        return ErrTimeout;

    return None;
}

static void xweb_connect_start (const char* const restrict hostname, const uint hostnameSize, const uint port, void* const restrict ssl, const uint proxyTries) {

    Host* const host = xweb_host_lookup_new(hostname, hostnameSize);

    if (host == NULL)
        return Err; // BAD HOSTNAME

    if (port > 0xFFFF)
        return Err; // BAD PORT

    thread->timeout = now + 45*1000;

    Pool* const pool = xweb_pool_lookup_new(host, port
        //, ssl TODO: FIXME:
        );

    // TODO: FIXME: VAI PRECISAR DE OUTRA FUNCAO PARA O CASO DE PEGAR SO O HTTP1 PARA O WEBSOCKET
    if (pool->conns) {
        thread->conn = pool->conns;
        xweb_conn_pool_remove(thread->conn);
        return Err; // SUCCESS
    }

    // NO CONNECTION AVAILABLE IN HE POOL; CREATE A NEW ONE
    thread->pool = pool;
    thread->pool->connsNeeded++;

    Conn* const conn = malloc(sizeof(Conn));

    conn->pool        = pool;
    conn->poolPtr     = NULL;
    conn->proxy       = PROXY_NONE;
    conn->poll        = CONN_POLL_RESOLVE;
    conn->fd          = 0;
    conn->v6          = 0;
    conn->again       = 0;
    conn->try         = 0;
    conn->msgEnded    = 0;
    conn->msgStarted  = 0;
    conn->msgType     = 0;
    conn->msgSkip     = 0;
    conn->msgWait     = 0;
    conn->msgMore     = 0;
    conn->tmpEnd      = NULL;
    conn->in          = NULL;
    conn->in_         = NULL;
    conn->inTime      = 0;
    conn->out         = NULL;
    conn->out_        = NULL;
    conn->outTime     = 0;
    conn->sslIn     = NULL;
    conn->sslInRes    = 0;
    conn->sslOutRes   = 0;
    conn->sslOut      = NULL;
    conn->sslOut_     = NULL;
    conn->sslOutTime  = 0;
    conn->ssl         = ssl;
    conn->proxyTries  = proxyTries;
    conn->proxyTries_ = proxyTries;

    // COLOCA A CONEXÃO NA LISTA DE CONEXÕES
    if ((conn->next = *(conn->ptr = &conns)))
        conn->next->ptr = &conn->next;
    conns = conn;
    connsN++;

    return None;
}

static uint xweb_conn_poll_close (Conn* const conn) {

    dbg_conn("POLL - CLOSE");

    if (conn->ssl > CONN_SSL_USE) {
        wolfSSL_free(conn->ssl);
        conn->ssl = CONN_SSL_USE;
    }

    if (conn->sslInRes)
        xweb_io_submit(NULL, IORING_OP_ASYNC_CANCEL, conn->fd, (u64)&conn->sslInRes, 0, 0); // TODO: FIXME: TEM MESMO QUE PASSAR O FD?

    if (conn->sslOutRes) // lembrar o offset de onde salvou, e so precisa da syscall se for depois do start ->end, ou estiver sobrescrito
        xweb_io_submit(NULL, IORING_OP_ASYNC_CANCEL, conn->fd, (u64)&conn->sslOutRes, 0, 0);

    xweb_conn_pool_remove(conn);

    In* in = conn->in;

    while (in) { In* const next = in->next;
        free(in);
        in = next;
    }

    Out* out = conn->out;

    while (out) { Out* const next = out->next;
        xweb_out_free(out);
        out = next;
    }

    conn->v6         = 0; // TODO: FIXME: RESET REMAINING FIELDS
    conn->proxy      = PROXY_NONE;
    conn->msgEnded   = 0;
    conn->msgStarted = 0;
    conn->msgType    = 0;
    conn->msgSkip    = 0;
    conn->msgWait    = 0;
    conn->msgMore    = 0;
    conn->msgEnd     = 0;
    conn->in         = NULL;
    conn->in_        = NULL;
    conn->inTime     = 0;
    conn->out        = NULL;
    conn->out_       = NULL;
    conn->outTime    = 0;
    conn->sslInTime  = 0;
    conn->sslOut_    = NULL;
    conn->sslOutTime = 0;

    return CONN_POLL_CLOSING;
}

static uint xweb_conn_poll_closing (Conn* const conn) {

    if ((!conn->sslInRes) &&
        (!conn->sslOutRes)) {

        xweb_io_submit(NULL, IORING_OP_CLOSE, conn->fd, 0, 0, 0);

        free(conn->sslIn);

        Out* out = conn->sslOut;

        while (out) { Out* const next = out->next;
            xweb_out_free(out);
            out = next;
        }

        conn->fd         = 0;
        conn->sslIn      = NULL;
        conn->sslInRes   = 0;
        conn->sslOutRes  = 0;
        conn->sslOut     = NULL;

        dbg_conn("POLL - CLOSING - RETRY");
        return CONN_POLL_RESOLVE;
    }

    dbg_conn("POLL - CLOSING - NOT READY");
    return CONN_POLL_FLUSH;
}

static uint xweb_conn_poll_resolve (Conn* const conn) {

    //
    if (conn->pool->connsNeeded <= conn->pool->connsN) {
        if ((*conn->ptr = conn->next))
            (*conn->ptr)->ptr = conn->ptr;
        free(conn);
        connsN--;
        return CONN_POLL_STOP;
    }

    // DELAY BETWEEN RETRIES
    if (conn->again > now)
        return CONN_POLL_FLUSH;

    Site* const site = conn->pool->site;
    Host* const host = conn->pool->host;

    // MUST RESOLVE HOSTNAME FIRST
    if (host->ipsN == 0)
        return CONN_POLL_FLUSH;

    host->ip++;
    host->ip %= host->ipsN;

    ((u64*)conn->ip)[0] = ((u64*)(host->ips[host->ip]))[0];
    ((u64*)conn->ip)[1] = ((u64*)(host->ips[host->ip]))[1];

    if (!(conn->v6 = (host->v6 >> host->ip) & 1ULL)) {
        // SELECIONA UM PROXY
        if (conn->proxyTries) {
            conn->proxyTries--;
            ASSERT(proxiesN);
            if (site->proxiesCount++ % 10) {
                if (site->proxiesNext == proxiesN ||
                    site->proxiesNext == PROXIES_FIRSTS_N) {
                    site->proxiesNext = 0;
                    proxiesSortPoints = site->proxiesPoints;
                    qsort(site->proxies, proxiesN, sizeof(u16), (void*)xweb_proxy_cmp);
                    //
                    if (site->proxiesPoints[(PROXIES_FIRSTS_N <= proxiesN ? PROXIES_FIRSTS_N : proxiesN) - 1] >= (PROXY_POINTS_MAX - 10))
                        memset(site->proxiesPoints, PROXY_POINTS_ZERO, PROXIES_N);
                }
                conn->proxy = site->proxiesNext++;
                // TODO: FIXME: ESTÁ SEMPRE DESCONTANDO DO PROXY ENTÃO; ENTÃO COMPENSAR COM -1 AO CONSEGUIR CONECTAR
                if (site->proxiesPoints[conn->proxy] != PROXY_POINTS_MAX)
                    site->proxiesPoints[conn->proxy]++;
            }
        } else
            conn->proxyTries = conn->proxyTries_;
    }

    if (conn->proxy != PROXY_NONE) { Proxy* const proxy = &proxies[conn->proxy];
        conn->dAddr4.sin_family      = AF_INET;
        conn->dAddr4.sin_port        = _to_be16(proxy->port);
        conn->dAddr4.sin_addr.s_addr = proxy->ip;
        dbg_conn("RESOLVE - PROXY - IP %u.%u.%u.%u PORT %u", _IP4_ARGS(&conn->dAddr4.sin_addr.s_addr), proxy->port);
    } elif (conn->v6) {
        dbg_conn("RESOLVE - PROXY NONE - IP %02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X PORT %u", _IP6_ARGS(conn->ip), conn->pool->port);
        conn->dAddr6.sin6_family   = AF_INET6;
        conn->dAddr6.sin6_port     = _to_be16(conn->pool->port);
        conn->dAddr6.sin6_scope_id = 0;
        conn->dAddr6.sin6_flowinfo = 0;
 ((u64*)conn->dAddr6.sin6_addr.s6_addr)[0] = ((u64*)conn->ip)[0];
 ((u64*)conn->dAddr6.sin6_addr.s6_addr)[1] = ((u64*)conn->ip)[1];
    } else {
        dbg_conn("RESOLVE - PROXY NONE - IP %u.%u.%u.%u PORT %u", _IP4_ARGS(conn->ip), conn->pool->port);
        conn->dAddr4.sin_family      = AF_INET;
        conn->dAddr4.sin_port        = _to_be16(conn->pool->port);
        conn->dAddr4.sin_addr.s_addr = *(u32*)conn->ip;
    }

    // SELECIONA UM SOURCE
    // TODO: FIXME: SE UM SOURCE ADDRESS ESTIVER RUIM, ELE NÃO PODE DESCONTAR NO PROXY
    if (conn->v6) { site->ip6Next++;
        conn->sAddr6.sin6_family   = AF_INET6;
        conn->sAddr6.sin6_port     = 0;
        conn->sAddr6.sin6_scope_id = 0;
        conn->sAddr6.sin6_flowinfo = 0;
 ((u64*)conn->sAddr6.sin6_addr.s6_addr)[0] = ((u64*)ipv6Addresses[site->ip6Next % XWEB_IPV6_ADDRESSES_N])[0];
 ((u64*)conn->sAddr6.sin6_addr.s6_addr)[1] = ((u64*)ipv6Addresses[site->ip6Next % XWEB_IPV6_ADDRESSES_N])[1];
        dbg_conn("RESOLVE - LOCAL IP %02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X", _IP6_ARGS(conn->sAddr6.sin6_addr.s6_addr));
    } else { site->ip4Next++;
        conn->sAddr4.sin_family = AF_INET;
        conn->sAddr4.sin_port = 0;
        conn->sAddr4.sin_addr.s_addr = ipv4Addresses[site->ip4Next % XWEB_IPV4_ADDRESSES_N];
        dbg_conn("RESOLVE - LOCAL - IP %u.%u.%u.%u", _IP4_ARGS(&conn->sAddr4.sin_addr.s_addr));
    }

    dbg_conn("RESOLVE - CONNECT");

    const int sock = socket(conn->v6 ? AF_INET6 : AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);

    if (sock == -1)
        return CONN_POLL_FLUSH;

    // NOTE: ASSUMING IT WON'T FAIL
    if (bind(sock, &conn->sAddr, conn->v6 ? sizeof(SockAddrIP6) : sizeof(SockAddrIP4)))
        fatal("RESOLVE - BIND TO LOCAL ADDRESS FAILED");

    conn->fd = sock; // NOTE: ASSUMINDO QUE 1 <= SOCK <= 0xFFFF
    conn->timeout = now + 4*1000; // TCP CONNECT TIMEOUT
    conn->again = now + conn->try*1000;
    conn->try++; // WILL OVERFLOW AND RESET
    conn->sslInRes = IO_WAIT;

    xweb_io_submit(&conn->sslInRes, IORING_OP_CONNECT, conn->fd, (u64)&conn->dAddr, conn->v6 ? sizeof(SockAddrIP6) : sizeof(SockAddrIP4), 0);

    return CONN_POLL_CONNECT;
}

static uint xweb_conn_poll_connect (Conn* const conn) {

    if (conn->sslInRes) {
        if (conn->timeout <= now)
            return CONN_POLL_CLOSE;
        return CONN_POLL_FLUSH;
    }

    dbg_conn("CONNECT - CONNECTED");

    if (conn->proxy == PROXY_NONE)
        return CONN_POLL_SSL;

    // SEND PROXY CONNECT COMMAND
    char cmd[1024]; uint cmdSize;

    if (proxies[conn->proxy].protocol) { // SOCKS
        *(u16*)(cmd)     = 0x0104; // VERSION 4, COMMAND: CONNECT
        *(u16*)(cmd + 2) = _to_be16(conn->pool->port); // DESTINATION PORT
        *(u64*)(cmd + 4) = *(u32*)conn->ip; // DESTINATION ADDRESS, USER NAME
        cmdSize = 9;
    } else // HTTP
        cmdSize = snprintf(cmd, sizeof(cmd), "CONNECT %u.%u.%u.%u:%u HTTP/1.0\r\nUser-Agent: %s\r\nConnection: close\r\n\r\n", _IP4_ARGS(conn->ip), conn->pool->port, userAgents[random64(USER_AGENTS_N) % USER_AGENTS_N]);

    //
    memcpy(xweb_conn_out_sized(conn, cmdSize), cmd, cmdSize);

    conn->msgType = cmdSize == 9;
    conn->msgMore = 2048;
    conn->tmpEnd  = NULL;
    conn->timeout = now + 4*1000; // WAIT THE PROXY TO CONNECT TO THE DESTINATION AND CONFIRM IT TO US

    return CONN_POLL_PROXY_WAIT;
}

// WAITING THE PROXY TO CONNECT TO THE DESTINATION AND CONFIRM IT TO US
static uint xweb_conn_poll_proxy_wait (Conn* const conn) {

    dbg_conn("PROXY WAIT");

    // COPIA TUDO PARA O SCRATCH PAD
    // CONSUMINDO OS INS

    const void* const response = conn->tmp;
    const uint size = conn->tmpEnd - conn->tmp;

    // [b'HTTP/1.0 501 Tor is not an HTTP Proxy\r\nContent-Type: text/html; charset=iso-8859-1\r\n\r\n<html>\n<head>\n<title>This is a SOCKS Proxy, Not An HTTP Proxy</title>\n</head>\n<body>\n<h1>This is a SOCKs proxy, not an HTTP proxy.</h1>\n<p>\nIt appears you have configured your web browser to use this Tor port as\nan HTTP proxy.\n</p><p>\nThis is not correct: This port is configured as a SOCKS proxy, not\nan HTTP proxy. If you need an HTTP proxy tunnel, use the HTTPTunnelPort\nconfiguration option in place of, or in addition to, SOCKSPort.\nPlease configure your client accordingly.\n</p>\n<p>\nSee <a href="https://www.torproject.org/documentation.html">https://www.torproject.org/documentation.html</a> for more information.\n</p>\n</body>\n</html>\n\x00']
    // TODO: FIXME: THIS CODE DOES NOT SUPPORT PROTOCOLS WHICH RECEIVE DATA BEFORE SENDING THE FIRST MESSAGE
    if (conn->msgType) {
        // VERSION | GRANTED | REMOTE PORT | REMOTE ADDR
        //  0x00   |  0x90   |   0x0000    | 0x00000000
        if (size == 8 && *(u16*)response == 0x5A00U)
            goto OK;
        //if (size == 9 && memcmp(response, "\x04\x01\x01\xbb\xd9o\x0b%\x00", 9) == 0)
            //goto OK;
        if (size >= 8)
            return CONN_POLL_CLOSE;
    } elif (size >= 8) {
        if (*(u64*)response != 0x302E312F50545448ULL &&
            *(u64*)response != 0x312E312F50545448ULL)
            return CONN_POLL_CLOSE; // IT IS NOT HTTP/1.0 / HTTP/1.1
        if (*(u32*)(response + size - 4) == 0x0A0D0A0DU) {
            if (memcmp(response + 8, " 200 ", 5) == 0)
                goto OK;
            return CONN_POLL_CLOSE; // STATUS IS NOT 200
        }
        if (size >= 1024) // INCOMPLETE, AND TOO BIG ALREADY
            return CONN_POLL_CLOSE;
    }

    if (conn->timeout <= now)
        return CONN_POLL_CLOSE;

    return CONN_POLL_FLUSH;

OK:
    conn->msgType = 0;
    conn->tmpEnd  = NULL;

    return CONN_POLL_SSL;
}

static uint xweb_conn_poll_ssl (Conn* const conn) {

    if (conn->ssl) {
        conn->timeout = now + 2*1000;
        conn->ssl = wolfSSL_new(sslCtx);

        wolfSSL_UseSNI(conn->ssl, WOLFSSL_SNI_HOST_NAME, conn->pool->host->name, conn->pool->host->nameSize);
        //wolfSSL_SetIOReadCtx(conn->ssl, conn);
        wolfSSL_SetIOWriteCtx(conn->ssl, conn);

        return CONN_POLL_SSL_CONNECT;
    }

    dbg_conn("NO SSL - ESTABLISHED");

    xweb_conn_proxy_good(conn);
    xweb_conn_pool_add(conn);

    return CONN_POLL_POOL;
}

static uint xweb_conn_poll_ssl_connect (Conn* const conn) {

    Host* const host = conn->pool->host;

    const int connected = wolfSSL_connect(conn->ssl);

    if (connected != 1) {
        const int error = wolfSSL_get_error(conn->ssl, connected);
        if (error == WOLFSSL_ERROR_WANT_READ ||
            error == WOLFSSL_ERROR_WANT_WRITE) {
            if (conn->timeout >= now)
                return CONN_POLL_FLUSH;
            dbg_conn("SSL CONNECT - TIMED OUT");
            return CONN_POLL_CLOSE;
        }
        dbg_conn("SSL CONNECT - FAILED");
        return CONN_POLL_CLOSE;
    }

    WOLFSSL_X509* const certificate = wolfSSL_get_peer_certificate(conn->ssl);

    int size = 0; u64* const certificateDER = (u64*)wolfSSL_X509_get_der(certificate, &size);

    u64 hash0 = (u64)size <<  0;
    u64 hash1 = (u64)size << 16;
    u64 hash2 = (u64)size << 32;
    u64 hash3 = (u64)size << 48;

    size /= 32;

    const u64* certificateDER_ = certificateDER;

    do { // NOTE: ASSUMINDO QUE O HASH NÃO SEJA TUDO 0, SENÃO VAI BATER COM OS HASHES INICIALIZADOS
        u64 hashA = *certificateDER_++;
        u64 hashB = *certificateDER_++;
        u64 hashC = *certificateDER_++;
        u64 hashD = *certificateDER_++;

        hash0 += hashA & 0xFFFFFFFFU;
        hash1 += hashB & 0xFFFFFFFFU;
        hash2 += hashC & 0xFFFFFFFFU;
        hash3 += hashD & 0xFFFFFFFFU;

        hash0 += hashD >> 32;
        hash1 += hashC >> 32;
        hash2 += hashB >> 32;
        hash3 += hashA >> 32;

        hashA += hash0 >> (hashD & 0b11111111111111111111U);
        hashB += hash1 >> (hashC & 0b11111111111111111111U);
        hashC += hash2 >> (hashB & 0b11111111111111111111U);
        hashD += hash3 >> (hashA & 0b11111111111111111111U);

        hash0 += hashD;
        hash1 += hashC;
        hash2 += hashB;
        hash3 += hashA;

    } while (--size);

    // PRECISA?
    //OPENSSL_free(certificateDER);

    wolfSSL_X509_free(certificate);

    dbg_conn("SSL CONNECT - CERTIFICATE HASH %016llX %016llX %016llX %016llX",
        (uintll)hash0,
        (uintll)hash1,
        (uintll)hash2,
        (uintll)hash3
        );

    HostCert* cert = host->certs;

    loop { // IDENTIFICA ESTE CERTIFICADO
        if (cert == &host->certs[HOST_CERTIFICATES_N]) { // SEM MAIS CERTIFICADOS; CERTIFICADO AINDA NÃO CONHECIDO
            cert = &host->certs[host->certsCtr++ % HOST_CERTIFICATES_N]; // TODO: FIXME: AO INVÉS DISSO, CADASTRAR EM CIMA DO QUE TIVER COM MENOS HITS, MAS AINDA ASSIM ALTERNAR
            cert->hash   [0]  = hash0;
            cert->hash   [1]  = hash1;
            cert->hash   [2]  = hash2;
            cert->hash   [3]  = hash3;
            cert->proxiesNeed = HOST_CERTIFICATE_PROXIES_N;
            for (uint i = 0; i != HOST_CERTIFICATE_PROXIES_N; i++)
                cert->proxies[i] = PROXY_NONE;
            break;
        } // TEM MAIS UM CERTIFICADO
        if (cert->hash[0] == hash0 &&
            cert->hash[1] == hash1 &&
            cert->hash[2] == hash2 &&
            cert->hash[3] == hash3)
            break; // CERTIFICADO CONHECIDO
        cert++; // PRÓXIMO CERTIFICADO
    }

    if (cert->proxiesNeed) { // ESTE CERTIFICADO AINDA NÃO É CONFIÁVEL

        if (conn->proxy != PROXY_NONE) { // ESTÁ USANDO PROXY
            for (uint i = 0; i != HOST_CERTIFICATE_PROXIES_N; i++) { // TODO: FIXME: MAS ENTÃO ESTÁ FAZENDO REFERENCIA AO PROXY; VAI TER QUE USAR UMM PROXY CODE U64 :S
                if (cert->proxies[i] == conn->proxy)
                    break;
                if (cert->proxies[i] == PROXY_NONE) {
                    cert->proxies[i] = conn->proxy;
                    cert->proxiesNeed--;
                    break; // ESTE PROXY AINDA NÃO FOI CONTABILIZADO; ENTÃO CONTABILIZOU ELE
                }
            }
        } else // ESTÁ CONECTANDO DIRETAMENTE; ENTÃO CONFIA NO CERTIFICADO
            cert->proxiesNeed = 0;

        if (cert->proxiesNeed) { // O CERTIFICADO CONTINUA NÃO CONFIÁVEL
            dbg_conn("SSL CONNECT - CERTIFICATE HASH NOT TRUSTED");
            return CONN_POLL_CLOSE;
        }
    }

    dbg_conn("SSL CONNECT - DONE");

    // TODO: FIXME: VERIFICAR O ALPN, E SETAR EM ALGUM LUGAR
    xweb_conn_proxy_good(conn);
    xweb_conn_pool_add(conn);

    return CONN_POLL_POOL;
}

// TODO: FIXME: TESTAR DE TEMPOS EM TEMPOS AO INVÉS DE SÓ VERIFICAR ESTE INPUT
static uint xweb_conn_poll_pool (Conn* const conn) {

    if (conn->in) {
        dbg_conn("INPUT UNEXPECTED ON IDLE CONNECTION");
        return CONN_POLL_CLOSE;
    }

    return CONN_POLL_FLUSH;
}

static uint xweb_conn_poll_flush (Conn* const conn) {

    if (!conn->sslOutRes) {

        // CONSOME TODOS OS OUTS POSSIVEIS, COLOCANDO-OS NO SSLOUT
        if (conn->ssl > CONN_SSL_USE) {
            sslOutFree = 0;
            sslInSize = 0;
            while (conn->out) {
                if (conn->out->size) {
                    const int size = wolfSSL_write(conn->ssl, conn->out->start, conn->out->size);
                    if (size <= 0) {
                        const int error = wolfSSL_get_error(conn->ssl, size);
                        if (error == WOLFSSL_ERROR_WANT_READ ||
                            error == WOLFSSL_ERROR_WANT_WRITE)
                            break; // BUFFER FULL / NEED READ
                        // ERROR
                        if (0) // TODO: FIXME: SE A CONEXÃO NÃO ESTIVER NA THREAD, RETORNAR ISSO DE UMA VEZ
                            return CONN_POLL_CLOSE;
                        conn->poll = CONN_POLL_CLOSE;
                        // NESTE CASO, CONN->SSLOUT_ PODE SER GRANDE, MAS NAO DEVE SER, POIS SO NA THREAD ISSO É USADO
                        //      SO ALOCAR GRANDES BASEADOS NO TAMANHO TOTAL DA SOMA DOS CONN->OUTS
                        return CONN_POLL_STOP;
                    }
                    conn->out->start += size;
                    conn->out->size -= size;
                } else { // TERMINOU ESTE OUT
                    Out* const next = conn->out->next;
                    xweb_out_free(conn->out);
                    if ((conn->out = next) == NULL)
                        conn->out_ = NULL;
                }
            }
            // TODO: FIXME: REALLOCA O conn->sslOut_, POIS ALOCOU AQUELE 1MB
            // REALLOC TO A SMALLER SIZE NEVER FAILS, NEVER CHANGES BASE; NEVER COPIES
            // NOTE: AO CHEGAR AQUI, É DO TIPO SIZED
            if (conn->sslOut_)
                conn->sslOut_ = realloc(conn->sslOut_, sizeof(Out) + conn->sslOut_->size);
        } elif (conn->out) { // NÃO PRECISA ENCRIPTOGRAFAR; SIMPLESMENTE MOVE OS CHUNKS
            if (conn->sslOut_)
                conn->sslOut_->next = conn->out;
            else
                conn->sslOut = conn->out;
            conn->sslOut_ = conn->out_;
            conn->out = NULL;
            conn->out_ = NULL; // NOTE: ASSUMINDO QUE TODOS OS conn->out QUE CHEGAM AQUI TEM SIZE > 0
        }

        // CONSTROI O IOV[] E MANDA O WRITEV()
        uint c = 0; Out* out = conn->sslOut;

        while (c != 1024 && out) {
            conn->sslOutIOVs[c].iov_base = out->start;
            conn->sslOutIOVs[c].iov_len  = out->size;
            out = out->next;
            c++;
        }

        if (c) {
            xweb_io_submit(&conn->sslOutRes, IORING_OP_WRITEV, conn->fd, (u64)conn->sslOutIOVs, 0, c);
            conn->sslOutTime = now;
            conn->sslOutRes = IO_WAIT;
        }
    }

    if (conn->sslInRes == 0 &&
        conn->poll >= ) {

        uint size = conn->msgMore;

        // TODO: FIXME: conn->msgSkip?

        if (size == 0)
            size = 128;

        if (conn->ssl > CONN_SSL_USE) {
            size *= 2;
            size += 1024;
            conn->sslIn = malloc(size);
            conn->sslInRes = IO_WAIT;
            xweb_io_submit(&conn->sslInRes, IORING_OP_READ, conn->fd, (u64)conn->sslIn, 0, size);
        } else {
            size += 2*4096;
            In* const in = malloc(sizeof(In) + size);
            in->start = (void*)in + sizeof(In) + 4096;
            in->end   = (void*)in + sizeof(In) + 4096;
            in->lmt   = (void*)in + sizeof(In) + size;
            conn->sslInRes = IO_WAIT;
            conn->sslIn = in;
            xweb_io_submit(&conn->sslInRes, IORING_OP_READ, conn->fd, (u64)in + sizeof(In) + 4096, 0, size - 4096);
        }
    }

    return CONN_POLL_STOP;
}

static void xweb_conn_poll (Conn* const conn) {

    uint poll = conn->poll;

    while ((poll = (
        poll == CONN_POLL_CLOSE       ? xweb_conn_poll_close :
        poll == CONN_POLL_CLOSING     ? xweb_conn_poll_closing :
        poll == CONN_POLL_RESOLVE     ? xweb_conn_poll_resolve :
        poll == CONN_POLL_CONNECT     ? xweb_conn_poll_connect :
        poll == CONN_POLL_PROXY_WAIT  ? xweb_conn_poll_proxy_wait :
        poll == CONN_POLL_SSL         ? xweb_conn_poll_ssl :
        poll == CONN_POLL_SSL_CONNECT ? xweb_conn_poll_ssl_connect :
        poll == CONN_POLL_POOL        ? xweb_conn_poll_pool :
             /* CONN_POLL_FLUSH */      xweb_conn_poll_flush
        )(conn)) != CONN_POLL_STOP)
        if (poll != CONN_POLL_FLUSH)
            conn->poll = poll;
}

// EXECUTA AS AÇÕES DE ACORDO COM O STATUS DE CADA CONEXÃO
// ATÉ PORQUE NEM TODAS AS CONEXÕES ESTÃO EM UMA THREAD, ENTÃO TEM DE EXECUTR NO BACKGROUND
static void xweb_conns_poll (void) {

    Conn* conn = conns;

    while (conn) {
        Conn* const next = conn->next; // ELAS PODEM SER DELETADAS
        xweb_conn_poll(conn);
        conn = next;
    }
}

static void xweb_conns_poll_res (void) {

    for (Conn* conn = conns; conn; conn = conn->next) {

        uint sent     = conn->sslOutRes;
        uint received = conn->sslInRes;

        if (sent != IO_WAIT) {
            if (sent >= IO_ERR)
                conn->poll = CONN_POLL_CLOSE;
            else // SE LIVRA DE TUDO O QUE JÁ FOI ENVIADO
                while (sent) {
                    if (conn->sslOut->size > sent) {
                        conn->sslOut->size -= sent;
                        break; // ENVIOU SÓ UM PEDAÇO DESTE OUT
                    } // ENVIOU TODO ESTE OUT
                    sent -= conn->sslOut->size;
                    Out* const next = conn->sslOut->next;
                    xweb_out_free(conn->sslOut);
                    if ((conn->sslOut = next) == NULL)
                        conn->sslOut_ = NULL;
                }
            conn->sslOutRes = 0;
        }

        if (received != IO_WAIT) {
            if (received >= IO_ERR)
                conn->poll = CONN_POLL_CLOSE;
            elif (received) {
                if (conn->ssl > CONN_SSL_USE) { // SSLIN É UM BUFFER
                    sslInSize = received;
                    sslInStart = conn->sslIn;
                    sslOutFree = 0;
                    // CRIA UM conn->in_ BEEEM GRANDÃO
                    // TODO: FIXME: O conn->in_ CONSIDERA O 2*4096
                    // TODO: FIXME: O SSL NAO PODE TER NENHUM TIPO DE COMPRESSAO, OU SEJA, DO ENCRIPTOGRAFADO NAO PODE SE GERAR ALGO MAIOR
                    int size;
                    while ((size = wolfSSL_read(conn->ssl, conn->in_->end, conn->in_->lmt - conn->in_->end)) <= 0)
                        conn->in_->end += size;
                    if (wolfSSL_get_error(conn->ssl, size) != WOLFSSL_ERROR_WANT_READ)
                        conn->poll = CONN_POLL_CLOSE;
                    ASSERT(sslInSize == 0 || conn->poll == CONN_POLL_CLOSE);
                    // REALOCA O conn->in_ <==== !!!!
                    // TODO: FIXME: REALLOCA O conn->sslOut_, POIS ALOCOU AQUELE 1MB
                    free(conn->sslIn);
                    conn->sslIn = NULL;
                } else { // SSLIN É UM In
                    if (conn->in)
                        conn->in->next = conn->sslIn
                    else
                        conn->in = conn->sslIn;
                    conn->in_ = conn->sslIn;
                    conn->in_->end += received;
                    conn->sslIn = NULL;
                }
            } elif (conn->poll > CONN_POLL_CONNECT)
                conn->poll = CONN_POLL_CLOSE;
            conn->sslInRes = 0;
        }
    }
}

void xweb_conns_init (void) {

    connsN = 0;
    conns = NULL;
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

static PyObject* xweb_PY_conn_recv_sized (void) {
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
PyObject* xweb_conn_http_recv_header_start_PY (void) {

    return xweb_PY_conn_http_recv_header();
}
