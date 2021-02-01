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

//#define XWEB_WEBSOCKET_MASK 0xE1E1E1E1E1E1E1E1ULL
#define XWEB_WEBSOCKET_MASK 0ULL

#define WS_MSG_SIZE_MAX (128*1024*1024)

#define MS_MAX (32ULL*24*64*64*1024ULL)

typedef struct IOSubmission IOSubmission;
typedef struct Site Site;
typedef struct Class Class;
typedef struct Thread Thread;
typedef struct Pool Pool;
typedef struct StaticProxy StaticProxy;
typedef struct Proxy Proxy;
typedef struct DNSAnswer DNSAnswer;
typedef struct Host Host;
typedef struct HostServer HostServer;
typedef struct HostCert HostCert;
typedef struct HostDep HostDep;
typedef struct Conn Conn;
typedef struct In In;
typedef struct Out Out;

struct Class {
    Class* next;
    Class* parentNext; // PRÓXIMA CHILD DO PARENT
    Class* siteNext; // PRÓXIMA CLASSE DO MESMO SITE
    Class* parent;
    Class* childs;
    Site* site; // CLASSE ROOT DESTA CLASSE
    Thread* threads; // INSTANCIAS DESTA CLASSE
    u32 n;
    u32 nMax;
    u16 nameSize;
    u16 reserved;
    u32 reserved2;
    char name[];
};

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

#define SESSION_POOLS_ROOTS_N 64
#define SESSION_POOLS_ROOTS_MASK 0b111111ULL
#define SESSION_POOLS_ROOTS_BITS 6

struct Thread {
    Thread* next;
    Thread* parent;
    Thread* parentNext;
    Class* class; // CLASSE DA QUAL ELA É INSTÂNCIA
    Thread* classNext;
    Site* site; // SITE DA QUAL ELA É INSTÂNCIA
    Thread* childs;
    PyObject* obj;
    PyByteArrayObject* msg;
    Pool** pools; // [SESSION_POOLS_ROOTS_N]  OPEN FREE HTTP CONNECTIONS
    void* userAgent; // TODO: FIXME:
    void* cookies;
    u64 started;
    u64 timeout;
    u32 id;
    u16 nameSize;
    u16 reserved;
    Pool* pool;
    Conn* conn;
    Conn* streamConn; // PARA LEMBRAR ENQUANTO FAZ UMA REQUEST
    // u8 retry; // REMAINING RETRIES
    char name[];
};

struct Site {
    Site* next;
    Class* class; // CLASSE ROOT, A QUAL GEROU ESTE SITE
    Class* classes; // TODAS AS CLASSES DESTE SITE, INCLUINDO FILHAS DAS FILHAS ETC
    u16 ip4Next;
    u16 ip6Next;
    u16 proxiesCount;
    u16 proxiesNext;
    u8  proxiesPoints[PROXIES_N];
    u16 proxies[PROXIES_N];
};

#define IN_SIZE_MAX (64*1024*1024)

static u64 now0;
static u64 now;

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

static uint connsN;
static Conn* conns;

#define LOG_BUFFER_SIZE (2*1024*1024)

static char* logBuffer;
static char* logBufferReady;
static char* logBufferFlushing;
static char* logEnd;
static uint logFree;

#define PROXIES_ROOTS_N 512
#define PROXIES_ROOTS_BITS 9
#define PROXIES_ROOTS_MASK 0b111111111ULL

static uint  proxiesN;
static u16   proxiesRoots[PROXIES_ROOTS_N];
static Proxy proxies[PROXIES_N];

#define HOST_NONE     0xFFFF // TEM QUE SER TODOS OS BITS 1 NO hostsRoots[]
#define HOSTS_N       0xFFFF
#define HOSTS_ROOTS_N 512

static uint  hostsN;
static u16   hostsRoots[HOSTS_ROOTS_N];
static Host* hosts[HOSTS_N];

#define USER_AGENTS_N 4

static char* userAgents[] = {
    "Mozilla/5.0 (X11; Linux x86_64; rv:64.0) Gecko/20100101 Firefox/64.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:65.0) Gecko/20100101 Firefox/65.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:72.0) Gecko/20100101 Firefox/72.0",
};

//static const struct u64 ipv6AddressesBlocks[] = { XWEB_IPV6_ADDRESSES_BLOCKS };
static const u32 ipv4Addresses[]     = { XWEB_IPV4_ADDRESSES };
static const u8  ipv6Addresses[][16] = { XWEB_IPV6_ADDRESSES };

static const StaticProxy proxiesStatic[] = { XWEB_PROXIES_STATIC };

static WOLFSSL_CTX* sslCtx;

static uint sslInSize;
static void* sslInStart;
static uint sslOutFree;
static void* sslOutEnd;

static u8* proxiesSortPoints;

static inline u64 rdtsc (void) {
    uint lo;
    uint hi;
    __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
    return ((u64)hi << 32) | lo;
}

static inline u64 random64 (const u64 seed) {
    return seed + rdtsc() + random();
}

static u64 xweb_now_update (void) {

    struct timespec now_;

    clock_gettime(CLOCK_BOOTTIME, &now_);

    now = 3*MS_MAX + (u64)now_.tv_sec * 1000 + (u64)now_.tv_nsec / 1000000;

    return now;
}

static void xweb_poll_io (void) {

    u64 q = uSubmissionsEnd - uSubmissionsStart;

    // MAS LIMITADO A QUANTOS TEM FREE
    if (q > (65536 - uSubmissionsNew))
        q = (65536 - uSubmissionsNew);

    //
    uSubmissionsNew += q;

    q += uSubmissionsStart;

    //
    uint tail = *IOU_S_TAIL; // TODO: FIXME: uSubmissionTail

    read_barrier();

    // COPIA DO START AO Q-ESIMO, PARA O KERNEL
    while (uSubmissionsStart != q) { // ADD OUR SQ ENTRY TO THE TAIL OF THE SQE RING BUFFER

        const IOSubmission* const uSubmission = &uSubmissions[uSubmissionsStart++ & 0xFFFFU];

        if (uSubmission->fd) { const uint index = tail++ & IOU_S_MASK_CONST;

            IOU_S_ARRAY[index] = index;

            IOU_S_SQES[index].flags     = 0; // TODO: KEEP ALL MEMBERS OF THE STRUCTURE UP-TO-DATE
            IOU_S_SQES[index].ioprio    = 0;
            IOU_S_SQES[index].rw_flags  = 0;
            IOU_S_SQES[index].opcode    = uSubmission->opcode;
            IOU_S_SQES[index].fd        = uSubmission->fd;
            IOU_S_SQES[index].off       = uSubmission->off;
            IOU_S_SQES[index].addr      = uSubmission->addr;
            IOU_S_SQES[index].len       = uSubmission->len;
            IOU_S_SQES[index].user_data = uSubmission->data;

        } else // SE ESTE TIVER SIDO CANCELADO, IGNORA E DESCONSIDERA
            uSubmissionsNew--;
    }

    // UPDATE THE TAIL SO THE KERNEL CAN SEE IT
    *IOU_S_TAIL = tail;

    write_barrier();

    // MANDA O KERNEL CONSUMIR O QUE JÁ FOI COLOCADO - TODO: FIXME: É PARA COLOCAR SÓ OS NOVOS OU TODOS MESMO?
    // NOTE: ASSUMINDO QUE O JAMAIS TERA ERROS
    uSubmissionsNew -= io_uring_enter(IOU_FD, uSubmissionsNew, 0, 0);

    //ASSERT(uSubmissionsNew <= 65536);

    //
    sched_yield();
#if XWEB_TEST
    sleep(1);
#endif

    // LÊ TODO O CQ E SETA OS RESULTADOS
    const uint uConsumeTail = *IOU_C_TAIL;

    read_barrier();

    while (uConsumeHead != uConsumeTail) {

        const IOURingCQE* const cqe = &IOU_C_CQES[uConsumeHead++ & IOU_C_MASK_CONST];

        u32* const result = (u32*)cqe->user_data;

        // result = NULL -> É UM close(conn->fd), OU UM write(DNS)
        if (result == (u32*)&logBufferFlushing) {
            logBufferReady = logBufferFlushing;
            logBufferFlushing = NULL;
        } elif (result) { *result = cqe->res;
            // NOTE: EXPECTING AN OVERFLOW HERE IF RESULT < dnsAnswers
            const uint id = ((void*)result - (void*)dnsAnswers) / sizeof(DNSAnswer);

            if (id < DNS_ANSWERS_N)
                dnsAnswersReady[dnsAnswersReadyN++] = id;
        }
    }

    *IOU_C_HEAD = uConsumeHead;

    write_barrier();
}

static inline void xweb_io_submit (u32* const data, const uint opcode, const uint fd, const u64 addr, const u64 off, const uint len) {

    uSubmissions[uSubmissionsEnd].data   = (u64)data;
    uSubmissions[uSubmissionsEnd].opcode = opcode;
    uSubmissions[uSubmissionsEnd].fd     = fd;
    uSubmissions[uSubmissionsEnd].addr   = addr;
    uSubmissions[uSubmissionsEnd].off    = off;
    uSubmissions[uSubmissionsEnd].len    = len;

    // TODO: FIXME: SETAR O ->result como IO_WAIT SOMENTE QUANDO ELE FOR SUBMETIDO?
    //ou entao o if()else e so colocar no enqueued quando lotar o principal

    //se tiverr algo enqueued ou nao couber mais->enqueuea

    uSubmissionsEnd++;
}

// AO TENTAR CANCELAR ALGO:
//primeiro procurar ele na lista dos queueds
    // se o sslInRes || sslOutRes for IO_WAIT
        // cancelar todos os queueds pelo FD
    //cancela o &conn->sslInRes
    //cancela o &conn->sslOutRes
//se não achar, aí sim cancela no io_uring

// PUXA O ENCRIPTADO DO sslIn, E PASSA PARA O WOLFSSL
static int xweb_ssl_read (void* const restrict ign __unused, void* const restrict buff, uint size, void* const restrict ign2 __unused) {

    if (size > sslInSize)
        size = sslInSize;

    if (size == 0)
        return WOLFSSL_CBIO_ERR_WANT_READ;

    memcpy(buff, sslInStart, size);

    sslInStart += size;
    sslInSize -= size;

    return size;
}

// RECEBE O ENCRIPTADO DO WOLFSSL, E POE NO BUFFER DE SAÍDA
static int xweb_ssl_write (void* const restrict ign __unused, const void* restrict buff, const uint size, Conn* const restrict conn) {

    uint remaining = size;

    while (remaining) {
        if (sslOutFree) {

            uint consume = remaining;

            if (consume > sslOutFree)
                consume = sslOutFree;

            memcpy(sslOutEnd, buff, consume); // TODO: FIXME: PODE SER ALINHADO

            sslOutEnd  += consume;
            buff       += consume;
            remaining  -= consume;
            sslOutFree -= consume;

        } else {

            uint alloced = 1*1024*1024;

            if (alloced < remaining)
                alloced = remaining + 1024;

            Out* const out = malloc(sizeof(Out) + alloced);

            out->type = OUT_TYPE_SIZED;
            out->size = alloced;
            out->start = out->buff;
            out->next = NULL;

            if (conn->sslOut_)
                conn->sslOut_->next = out;
            else
                conn->sslOut = out;
            conn->sslOut_ = out;

            sslOutEnd = out->buff;
            sslOutFree = alloced;
        }
    }

    return size;
}

#if 0
static int flush_in (Conn* const conn) {

    void* sslBuff = malloc(16*1024*1024);

    sslEnd = sslBuff;
    sslRemaining = 16*1024*1024;

    // readrecebido peloio uring
    sslRemaining = tamanhodisto;

    // REALLOCA O SSLBUFFF
    const uint sslSize = sslEnd - sslBuff;

    sslBuff = realloc(sslBuff, sslSize);

    // o buff é algum lugar no buffer que será usado para colocar no conn->in
    // TRANSFORMA ESTE sslBuff EM UM NOVO conn->in

    return 0;
}
#endif

static PyObject* xweb_PY_class_new (Class* const parent, const char* const name, const uint nameSize) {

    Class* const new = malloc(sizeof(Class) + (parent ? parent->nameSize + 1 : 0) + nameSize);

    if (parent) {
        memcpy(new->name, parent->name, parent->nameSize);
        new->name[parent->nameSize] = '.';
        memcpy(new->name + parent->nameSize + 1, name, nameSize);
        new->nameSize = parent->nameSize + 1 + nameSize;
    } else {
        memcpy(new->name, name, nameSize);
        new->nameSize = nameSize;
    }

    new->childs = NULL;
    new->threads = NULL;
    new->n = 0;
    new->nMax = 0;
    new->reserved = 0;
    new->reserved2 = 0;
    new->next = classes;

    if ((new->parent = parent)) {
        new->parentNext = parent->childs;
        new->parent->childs = new;
        new->site = parent->site;
    } else { // É UMA CLASSE ROOT, ENTÃO CRIA UM SITE

        Site* const site = malloc(sizeof(Site));

        site->classes = NULL;
        site->ip4Next = 0;
        site->ip6Next = 0;
        site->proxiesCount = 0;
        site->proxiesNext = 0;
        site->class = new;
        site->next = sites;

        sites = site;

        foreach (i, PROXIES_N)
            site->proxies[i] = i;

        memset(site->proxiesPoints, PROXY_POINTS_ZERO, PROXIES_N);

        new->parentNext = NULL;
        new->site = site;
    }

    // CADASTRA ESTA CLASSE EM SEU SITE
    new->siteNext = new->site->classes;
    new->site->classes = new;

    // ESTAMOS NELA
    site = new->site;

    return PTR_TO_PY((classes = (class = new)));
}

static PyObject* xweb_PY_thread_new (Thread* const parent) {

    const uint id = class->n++;

    char name[512];
    uint nameSize;

    if (parent)
        nameSize = snprintf(name, sizeof(name), "%.*s%.*s[%u]", parent->nameSize, parent->name, class->nameSize - parent->class->nameSize, class->name + parent->class->nameSize, id);
    else
        nameSize = snprintf(name, sizeof(name), "%.*s[%u]", class->nameSize, class->name, id);

    Thread* const new = malloc(sizeof(Thread) + nameSize);

    memcpy(new->name, name, (new->nameSize = nameSize));

    new->next = threads;
    new->class = class;
    new->classNext = class->threads;
    new->class->threads = new;
    new->site = class->site;
    new->id = id;
    new->started = 0;
    new->userAgent = NULL;
    new->cookies = NULL;
    new->msg = (PyByteArrayObject*)PyByteArray_FromStringAndSize("", 1);
    new->pool = NULL;
    new->conn = NULL;
    new->streamConn = NULL;
    PyObject_Free(new->msg->ob_bytes);
    new->msg->ob_bytes = NULL;

    if ((new->parent = parent)) {
        new->parentNext = parent->childs;
        new->parent->childs = new;
        new->pools = parent->pools;
    } else {
        new->parentNext = NULL;
        new->pools = malloc(SESSION_POOLS_ROOTS_N*sizeof(Pool*));
        clear(new->pools, SESSION_POOLS_ROOTS_N * sizeof(Pool*));
    }

    // ESTAMOS NELA
    site = new->site;
    class = new->class;

    return (new->obj = PTR_TO_PY((thread = (threads = new))));
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

static PyObject* xweb_PY_proxy_add (const char* const ip_, const uint port, const uint protocol) {

    xweb_proxy_add(ip_, port, protocol);

    return None;
}

// CLEANUP BEFORE EXITING
static inline void xweb_exit (void) {

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

static void xweb_poll_log (void) {

    if (logEnd != logBuffer && logBufferReady) {
        logBufferFlushing = logBuffer;
        xweb_io_submit((u32*)&logBufferFlushing, IORING_OP_WRITE, STDOUT_FILENO, (u64)logBuffer, 0, logEnd - logBuffer);
        logBuffer = logBufferReady;
        logEnd = logBuffer;
        logFree = LOG_BUFFER_SIZE;
        logBufferReady = NULL;
    }
}

static void xweb_poll (void) {

    do {
        xweb_poll_conns();
        xweb_poll_dns_send();
        xweb_poll_log();
        xweb_poll_io(); // TODO: FIXME: RECALCULAR OS SEGUNDOS/RTSC ANTES E DEPOIS DO YIELD
        xweb_poll_dns_receive();
        xweb_poll_conns_res();
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
}

static PyObject* xweb_PY_poll (void) {

    xweb_poll();

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

// TODO: FIXME: SE RECEBEU ALGO, REMARCAR UM TIMEOUT?
// ATÉ PORQUE O TIMEOUT PODE SER POR CONEXÃO, E NÃO POR TASK
//conn->timeout = now + 30*1000;

static PyObject* xweb_PY_conn_send_bytes (PyObject* const bytes) {

    if (!thread->conn->poll)
        return Err;

    xweb_conn_out_bytes(thread->conn, bytes);

    return None;
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

static PyObject* xweb_PY_conn_http_recv_body_chunked_start (const uint max) {
#if 0
    conn->msgLmt     = max;
    conn->msgSkip    = 0;
    conn->msgIn      = NULL;
    conn->msgInStart = NULL;

    return xweb_PY_conn_http_recv_body_chunked();
#endif
    (void)max; return None;
}

// TODO: FIXME: TIMEOUT SE NENHUMA MENSAGEM COMPLETA EM 50 SEGUNDOS - PELO MENOS UM PING, PONG ETC
// TODO: FIXME: SUPPORT FRAGMENTATION
static PyObject* xweb_PY_conn_ws_recv (void) {

    Conn* const conn = thread->conn;

    while (conn->in) { // TEM QUE SER LOOP, POIS ALGUMAS MENSAGENS COMO PING E PONG NAO SERAO CONSUMIDAS

        if (conn->in->start == conn->in->end) {
            xweb_conn_in_consumed(conn);
            continue;
        }

        if (conn->msgType == 0) { // OPCODE
            const uint opcode = *(u8*)conn->in->start++;
            if (opcode == CONN_MSG_TYPE_WS_CLOSE) {
                conn->poll = CONN_POLL_CLOSE;
                break; // NOTE: TEM QUE ESQUECER DO INPUT BUFFER A PARTIR DAQUI. RESPONSABILIDADE DO CALLER DE NAO CONSUMIR MAIS.
            }
            conn->msgType = opcode;
            conn->msgStarted = now;
        }

        if (conn->msgMore == 0) { // SIZE

            uint size; void* in = conn->in->start;

            if ((size = *(u8*)in++) == 126)
                { size = _to_be16(*(u16*)in); in += sizeof(u16); }
            elif (size == 127)
                { size = _to_be64(*(u64*)in); in += sizeof(u64); }

            if (in > conn->in->end) { // NAO DEU PARA LER O SIZE
                if (!conn->in->next)
                    break;
                *(u64*)(conn->in->next->start - 8) = *(u64*)(conn->in->end - 8);
                conn->in->next->start -= (conn->in->end - conn->in->start);
                conn->in->end = conn->in->start;
                continue;
            }

            conn->in->start = in;
            conn->msgMore = size;

            if (size == 0 || size > 128*1024*1024) {
                conn->poll = CONN_POLL_CLOSE;
                break; // BAD SIZE
            }

            if (conn->msgType == CONN_MSG_TYPE_WS_PONG) {
                dbg_conn("WEBSOCKET RECEIVE - PONG");
                continue;
            }

            if (conn->msgType == CONN_MSG_TYPE_WS_PING) {
                // NOTE: ASSUMINDO QUE O PING É PEQUENO
                // NOTE: ASSUMINDO QUE NÃO TEREMOS OUTRO PING ANTES DE ESVAZIAR ESTE
                dbg_conn("WEBSOCKET RECEIVE - PING");
                conn->tmpEnd = conn->tmp;
                *( u8*)conn->tmpEnd = 0x8A;               conn->tmpEnd += 1;
                *( u8*)conn->tmpEnd = 0b10000000U | size; conn->tmpEnd += 1;
                *(u32*)conn->tmpEnd = 0x00000000U;        conn->tmpEnd += 4;
                continue;
            }

            THREADMSGBUFF = malloc(size);
            THREADMSGSTART = THREADMSGBUFF;
            THREADMSGEND = THREADMSGBUFF;

            continue;
        }

        // PAYLOAD

        // VAI TENTAR LER TUDO O QUE DER
        uint size = conn->in->end - conn->in->start;

        // MAS SOMENTE O QUE FALTA
        if (size > conn->msgMore)
            size = conn->msgMore;

        conn->msgMore -= size;

        if (conn->msgType == CONN_MSG_TYPE_WS_PONG) {
            if (conn->msgMore == 0)
                conn->msgType = 0;
            conn->in->start += size;
            continue;
        }

        memcpy(THREADMSGEND, conn->in->start, size);

        conn->in->start += size;
        THREADMSGEND += size;

        if (conn->msgMore == 0) {
            if (conn->msgType != CONN_MSG_TYPE_WS_PING) {
                // BINARY | STRING | INVALID MESSAGE TYPE
                thread->msg->ob_bytes = THREADMSGEND;
                thread->msg->ob_start = THREADMSGSTART;
                thread->msg->ob_alloc = THREADMSGEND;

                Py_REFCNT(thread->msg) = 2;

                conn->msgType  = 0;
                conn->msgSkip  = 0;
                conn->msgWait  = 0;
                conn->msgMore  = 0;

                return (PyObject*)thread->msg;
            }
            // PING
            // NOW REGISTER THE PONG
            xweb_conn_out(conn, xweb_out_static(conn->tmp, conn->tmpEnd - conn->tmp));

            conn->msgType  = 0;
            conn->msgSkip  = 0;
            conn->msgWait  = 0;
            conn->msgMore  = 0;
        }
    }

    if (conn->poll)
        return None;

    return Err;
}

// TODO: FIXME: UMA VERSÃO DISSO PARA INSERIR  UMA JÁ CONSTRUÍDA
// SE ESTIVER FECHADA, NEM TENTA
static PyObject* xweb_PY_conn_ws_send_bytes_str (PyObject* const bytes) {

    Conn* const conn = thread->conn;

    char* payload = PY_BYTES_VALUE(bytes);
    uint size = PY_BYTES_SIZE(bytes);

    if (size > (WS_MSG_SIZE_MAX - 32)) {
        return Err; // INVALID SIZE / TRYING TO SEND A MESSAGE TOO BIG
    }

    if (conn->poll == CONN_POLL_CLOSE) {
        return Err;
    }

    // NOTE: TEM QUE SER U64 E TODOS COM O MESMO BYTE
    const u64 mask = XWEB_WEBSOCKET_MASK;

    char* encoded = xweb_conn_out_sized(conn, ((size > 0xFFFFU) ? 14 : (size >= 126) ? 8 : 6) + size*!!mask);

    if (size > 0xFFFFU) {
        *(u16*)encoded = 0xFF81U;                         encoded += sizeof(u16);
        *(u64*)encoded = __builtin_bswap64(((u64)size));  encoded += sizeof(u64);
        *(u32*)encoded = mask;                            encoded += sizeof(u32);
    } elif (size >= 126) { // TODO: FIXME: ASSUMING WE ARE IN LITTLE ENDIAN
        *(u16*)encoded = 0xFE81U;                         encoded += sizeof(u16); // deixa marcado como 126
        *(u16*)encoded = __builtin_bswap16(((u16)size));  encoded += sizeof(u16);
        *(u32*)encoded = mask;                            encoded += sizeof(u32);
    } else { // <= 125
        *( u8*)encoded = 0x81;                            encoded += sizeof(u8);
        *( u8*)encoded = 0b10000000U | size;              encoded += sizeof(u8);
        *(u32*)encoded = mask;                            encoded += sizeof(u32);
    }

    if (mask) { // COPY IT, MASKING
        while (size >= sizeof(u64)) {
     *(u64*)encoded = *(u64*)payload ^ mask;
            encoded += sizeof(u64);
            payload += sizeof(u64);
            size    -= sizeof(u64);
        }
        while (size--)
           *encoded++ = *payload++ ^ mask;
    } else // ACIMA SÓ COLOCOU O HEADER
        xweb_conn_out_bytes(conn, bytes);

    return None;
}


static PyObject* xweb_PY_timeout (const u64 timeout) {

    ASSERT(timeout >= now0);
    ASSERT(timeout <= 0xFFFFFFFFFFFULL);

    thread->timeout = timeout;

    return None;
}

static PyObject* xweb_PY_sleep (const u64 timeout) {

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

static PyObject* xweb_PY_thread_enter (Thread* const thread_) {

    thread = thread_;
    site   = thread_->site;
    class  = thread_->class;

    return None;
}

static PyObject* xweb_PY_thread_leave (void) {

    ASSERT(Py_REFCNT(thread->msg) == 1);

    if (thread->msg->ob_bytes) {
        free(thread->msg->ob_bytes);
        thread->msg->ob_bytes = NULL;
    }

    //
    if (thread->conn &&
        thread->conn->poll == CONN_POLL_CLOSE)
        thread->conn = NULL;

    // O MESMO COM A STREAM
    //if (thread->conn &&
        //thread->conn->poll == CONN_POLL_CLOSE)
        //thread->conn = NULL;

    if (thread->streamConn) {
        Conn* const conn = thread->streamConn;

        // TODO: FIXME: SE A STREAM FOR RAW-SSL, TEM QUE PERIODICAMENTE EXECUTAR O RECV/SEND POIS PODE ESTAR QUERENDO RENEGOCIAR ETC :S
        // TODO: FIXME: SE O WRITE ESTIVER TRAVADO POR CAUSA DO SSLWANT READ, VAI FICAR MANDANDO MAIS PINGS POIS O OUTTIME NAO ESTÁ AJUSTADO
        if (1) {
            // WEBSOCKET
            if (conn->out == NULL && (conn->outTime + 30*1000) < now && (conn->inTime + 45*1000) < now) {
                // MUITO TEMPO SEM ENVIAR NADA E NÃO VAI ENVIAR NADA AGORA / MUITO TEMPO SEM RECEBER NADA
                //  -> ENVIA UM PING, PARA FORÇAR UM ENVIO E/OU RECEBER ALGO
                dbg("POLL() - SENDING PING");
                // ESTE TIME TEM QUE SER O DO SOCKET E NAO O SSL
                //conn->again = now + 30*1000;
                *(u16*)xweb_conn_out_sized(conn, 2) = 0x8009U;
            }
        }
    }

    //s[o deixa colocar outs quando xweb.connect() for True

    PyObject* const threadObj = thread->obj;

    thread = NULL;
    site   = NULL;
    class  = NULL;

    Py_REFCNT(threadObj) = 0xFFFFFFFFU;

    return threadObj;
}

static PyObject* xweb_PY_exit (void) {
    xweb_exit();
    return None;
}

// PROCESS_ID
static PyObject* xweb_PY_init1 (const u64 id) {

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
    
    //
    connsN = 0;
    conns = NULL;

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
