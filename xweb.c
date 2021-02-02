/*

*/

#if XWEB_DEBUG
#define dbg(fmt, ...) ({ fprintf(stderr, "DEBUG: " fmt "\n", ##__VA_ARGS__); fflush(stderr); })
#else
#define dbg(fmt, ...) ({ })
#endif

#if 1
#define log(fmt, ...) ({ fprintf(stderr, fmt "\n", ##__VA_ARGS__); fflush(stderr); })
#else
#define log(fmt, ...) ({ })
#endif

#define dbg_conn(fmt, ...) dbg("CONNECTION %p %s: " fmt, conn, conn->pool->host->name, ##__VA_ARGS__)

#define err(fmt, ...) ({ fprintf(stderr, "ERROR: " fmt "\n", ##__VA_ARGS__); fflush(stderr); })

#define fatal(fmt, ...) ({ fprintf(stderr, "FATAL: " fmt "\n", ##__VA_ARGS__); fflush(stderr); abort(); })

typedef struct Pool Pool;

#define POOL_CHILDS_N 8
#define POOL_CHILDS_MASK 0b111ULL
#define POOL_CHILDS_BITS 3

// TO WALK UNTIL WE LOCATE THE HOST:PORT LIST
struct Pool {
    Host* host;
    u16 port;
    u16 connsMax;
    u16 connsNeeded; // HOW MANY THREADS ARE CURRENTLY WAITING FOR A CONNECTION FROM THIS POOL
    u16 connsN;
    Conn* conns;
    Site* site; // PARA QUE POSSA ACESSAR A LISTA DE PROXIES
    Pool* childs[POOL_CHILDS_N];
};

#define IN_SIZE_MAX (64*1024*1024)

static PyObject* Err;
static PyObject* ErrClosed;
static PyObject* ErrTimeout;
static PyObject* ErrSession;
static PyObject* ErrNotFound;

static Site* sites;
static Class* classes;
static Thread* threads;

static Site* site;
static Class* class;
static Thread* thread;


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

static PyObject* xweb_conn_http_recv_body_chunked_start_PY (const uint max) {
#if 0
    conn->msgLmt     = max;
    conn->msgSkip    = 0;
    conn->msgIn      = NULL;
    conn->msgInStart = NULL;

    return xweb_PY_conn_http_recv_body_chunked();
#endif
    (void)max; return None;
}

static PyObject* xweb_timeout_PY (const u64 timeout) {

    ASSERT(timeout >= now0);
    ASSERT(timeout <= 0xFFFFFFFFFFFULL);

    thread->timeout = timeout;

    return None;
}

static PyObject* xweb_sleep_PY (const u64 timeout) {

    ASSERT(timeout >= now0);
    ASSERT(timeout <= 0xFFFFFFFFFFFULL);

    thread->timeout = timeout;

    Py_REFCNT(thread->obj) = 0xFFFFFFFFU;

    return thread->obj;
}

static PyObject* xweb_PY_sleeping (Thread* const thread) {

    if (thread->timeout <= now)
        return ErrTimeout;

    return None;
}

static PyObject* xweb_PY_class_enter (Class* const class_) {

    thread = NULL;
    class  = class_;
    site   = class_->site;

    return None;
}

static PyObject* xweb_PY_main_enter (void) {

    thread = NULL;
    class  = NULL;
    site   = NULL;

    return None;
}

static PyObject* xweb_PY_class_leave (void) {

    class = NULL;
    site  = NULL;

    return None;
}

#define PY_FUNCTION_NAME_REAL(prefix, name) prefix ## name
#define PY_FUNCTION_NAME_PY(prefix, name, suffix) prefix ## name ## suffix

#define PY_FUNCTION_MAKE(name, _args_n, ...) \
    static PyObject* PY_FUNCTION_NAME_PY(xweb_PY_, name, _) (const PyObject* const restrict self __unused, PyObject* const args[_args_n] __unused, const Py_ssize_t argsN __unused) { \
        ASSERT(argsN == _args_n); \
        return PY_FUNCTION_NAME_REAL(xweb_PY_, name) (__VA_ARGS__); \
    };

#define PY_FUNCTION_DEF(name) { #name, (void*)PY_FUNCTION_NAME_PY(xweb_PY_, name, _), METH_FASTCALL, "" }

PY_FUNCTION_MAKE(init1,                             1, PY_TO_U64(args[0]));
PY_FUNCTION_MAKE(exit,                              0);
PY_FUNCTION_MAKE(log_,                              2, PY_BYTES_VALUE(args[0]), PY_BYTES_SIZE(args[0]), PY_BYTES_VALUE(args[1]), PY_BYTES_SIZE(args[1]));
PY_FUNCTION_MAKE(main_enter,                        0);
PY_FUNCTION_MAKE(class_new,                         2, PY_TO_PTR_NULL(args[0]), PY_BYTES_VALUE(args[1]), PY_BYTES_SIZE(args[1]));
PY_FUNCTION_MAKE(class_enter,                       1, PY_TO_PTR(args[0]));
PY_FUNCTION_MAKE(class_leave,                       0);
PY_FUNCTION_MAKE(thread_new,                        1, PY_TO_PTR_NULL(args[0]));
PY_FUNCTION_MAKE(thread_enter,                      1, PY_TO_PTR(args[0]));
PY_FUNCTION_MAKE(thread_leave,                      0);
PY_FUNCTION_MAKE(timeout,                           1, PY_TO_U64(args[0]));
PY_FUNCTION_MAKE(sleep,                             1, PY_TO_U64(args[0]));
PY_FUNCTION_MAKE(sleeping,                          1, PY_TO_PTR(args[0]));
PY_FUNCTION_MAKE(connect_start,                     4, PY_BYTES_VALUE(args[0]),  PY_BYTES_SIZE(args[0]), PY_TO_UINT(args[1]), (args[2] == None ? NULL : (void*)1ULL), PY_TO_UINT(args[3]));
PY_FUNCTION_MAKE(connect,                           0);
PY_FUNCTION_MAKE(conn_send_bytes,                   1,  args[0]);
PY_FUNCTION_MAKE(conn_recv_sized,                   0);
PY_FUNCTION_MAKE(conn_recv_sized_start,             1,  PY_TO_UINT(args[0]));
PY_FUNCTION_MAKE(conn_http_recv_body_chunked,       0);
PY_FUNCTION_MAKE(conn_http_recv_body_chunked_start, 1,  PY_TO_UINT(args[0]));
PY_FUNCTION_MAKE(conn_http_recv_body_eof,           0);
PY_FUNCTION_MAKE(conn_http_recv_body_eof_start,     0);
PY_FUNCTION_MAKE(conn_http_recv_body_sized,         0);
PY_FUNCTION_MAKE(conn_http_recv_body_sized_start,   1,  PY_TO_UINT(args[0]));
PY_FUNCTION_MAKE(conn_http_recv_header,             0);
PY_FUNCTION_MAKE(conn_http_recv_header_start,       0);
PY_FUNCTION_MAKE(conn_ws_recv,                      0);
PY_FUNCTION_MAKE(conn_ws_send_bytes_str,            1,  args[0]);
PY_FUNCTION_MAKE(conn_release,                      0);
PY_FUNCTION_MAKE(conn_close,                        0);
PY_FUNCTION_MAKE(poll,                              0);
PY_FUNCTION_MAKE(proxy_add,                         3, PY_BYTES_VALUE(args[0]), PY_TO_UINT(args[1]), PY_TO_UINT(args[2]));

static PyMethodDef xwebMethods[] = {
    PY_FUNCTION_DEF(init1),
    PY_FUNCTION_DEF(exit),
    PY_FUNCTION_DEF(log_),
    PY_FUNCTION_DEF(proxy_add),
    PY_FUNCTION_DEF(main_enter),
    PY_FUNCTION_DEF(class_new),
    PY_FUNCTION_DEF(class_enter),
    PY_FUNCTION_DEF(class_leave),
    PY_FUNCTION_DEF(thread_new),
    PY_FUNCTION_DEF(thread_enter),
    PY_FUNCTION_DEF(thread_leave),
    PY_FUNCTION_DEF(timeout),
    PY_FUNCTION_DEF(sleep),
    PY_FUNCTION_DEF(sleeping),
    PY_FUNCTION_DEF(connect_start),
    PY_FUNCTION_DEF(connect),
    PY_FUNCTION_DEF(conn_send_bytes),
    PY_FUNCTION_DEF(conn_recv_sized),
    PY_FUNCTION_DEF(conn_recv_sized_start),
    PY_FUNCTION_DEF(conn_http_recv_body_chunked),
    PY_FUNCTION_DEF(conn_http_recv_body_chunked_start),
    PY_FUNCTION_DEF(conn_http_recv_body_eof),
    PY_FUNCTION_DEF(conn_http_recv_body_eof_start),
    PY_FUNCTION_DEF(conn_http_recv_body_sized),
    PY_FUNCTION_DEF(conn_http_recv_body_sized_start),
    PY_FUNCTION_DEF(conn_http_recv_header),
    PY_FUNCTION_DEF(conn_http_recv_header_start),
    PY_FUNCTION_DEF(conn_ws_recv),
    PY_FUNCTION_DEF(conn_ws_send_bytes_str),
    PY_FUNCTION_DEF(conn_release),
    PY_FUNCTION_DEF(conn_close),
    PY_FUNCTION_DEF(poll),
    { NULL, NULL, 0, NULL }
};

static struct PyModuleDef xwebModule = {
    .m_base = PyModuleDef_HEAD_INIT,
    .m_name = "xweb",
    .m_doc = "XWeb",
    .m_size = -1,
    .m_methods = xwebMethods,
};

PyMODINIT_FUNC PyInit_xweb (void) {

    xweb_log_init();

    // TIME
    now0 = xweb_now_update();

    xweb_io_init();
    xweb_dns_init();
    xweb_proxies_init();
    xweb_hosts_init();
    xweb_ssl_init();
    xweb_conns_init();

    // THE LISTS
    sites    = NULL;
    classes  = NULL;
    threads  = NULL;

    // THE CURRENT
    site    = NULL;
    class   = NULL;
    thread  = NULL;

    //
    PyObject* const mod = PyModule_Create(&xwebModule);

    None = Py_None;

    PyModule_AddObject(mod, "TIME0",      UINTLL_TO_PY(now0));

    PyModule_AddObject(mod, "Err",         (Err         = PyErr_NewException("xweb.Err",         NULL, NULL)));
    PyModule_AddObject(mod, "ErrSession",  (ErrSession  = PyErr_NewException("xweb.ErrSession",  NULL, NULL)));
    PyModule_AddObject(mod, "ErrClosed",   (ErrClosed   = PyErr_NewException("xweb.ErrClosed",   NULL, NULL)));
    PyModule_AddObject(mod, "ErrTimeout",  (ErrTimeout  = PyErr_NewException("xweb.ErrTimeout",  NULL, NULL)));
    PyModule_AddObject(mod, "ErrNotFound", (ErrNotFound = PyErr_NewException("xweb.ErrNotFound", NULL, NULL)));

    Py_REFCNT(None)        = 0xFFFFFF;
    Py_REFCNT(Err)         = 0xFFFFFF;
    Py_REFCNT(ErrClosed)   = 0xFFFFFF;
    Py_REFCNT(ErrTimeout)  = 0xFFFFFF;
    Py_REFCNT(ErrSession)  = 0xFFFFFF;
    Py_REFCNT(ErrNotFound) = 0xFFFFFF;

    return mod;
}

// OLHAR TODOS OS ???*60*60*1000 , *60*60, 60*1000
// OLHAR TODOS OS SOMEETHING is CONSTANTE_INT

// kill/send signal to a process requires acquiring lock of the memory
// eixiting requires unlocking of the memory

// FILTER DNS RESULT IPs


// AS FUNCOES START DEVEM CHECAR  conn->poll == CLOSE
// OUTRAS FUNCOES DEVEM CHECAR O CLOSE?

// QUANDO UMA THREAD PEGAR UMA CONEXÃO, SETAR ELA COMO CONN_POLL_FLUSH
// AO DEVOLVER, SETAR ELA COMO CONN_POLL_POOL

// TODO: FIXME: SE RECEBEU ALGO, REMARCAR UM TIMEOUT? ATÉ PORQUE O TIMEOUT PODE SER POR CONEXÃO, E NÃO POR TASK








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
