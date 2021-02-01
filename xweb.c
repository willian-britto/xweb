/*

    ❤️ will & LoveLyn ❤️
        - all cuteness reserved

    # --disable-rng --disable-coding  -DCUSTOM_RAND_GENERATE_SEED=my_GenerateSeed -DCUSTOM_RAND_GENERATE_BLOCK=my_rand_generate_block -Dmy_rand_generate_block=min
    ./configure \
     --disable-staticmemory --disable-jobserver --disable-hashdrbg

    NO SERVIDOR, TEM RDSEED
    //HAVE_INTEL_RDSEED

    CFLAGS="-DNO_DEV_URANDOM -DHAVE_INTEL_RDRAND -DUSE_INTEL_SPEEDUP -DNO_SHA -DKEEP_PEER_CERT -DNO_SESSION_CACHE -DNO_WOLFSSL_SERVER -DNO_ERROR_STRINGS -DNO_FILESYSTEM -DNO_MD4 -DNO_MD5" \
        ./configure \
            --prefix=/usr  --disable-base64encode \
            --disable-crypttests --disable-examples \
            --disable-harden --enable-singlethreaded \
            --disable-filesystem --disable-asynccrypt --disable-ocsp \
            --disable-md4 --disable-md5 --disable-sha --disable-sha224 --enable-sha256 --enable-sha512 \
            --disable-sslv3 --disable-tlsv10 --enable-tls13 --enable-sni --enable-alpn \
            --enable-fastmath --enable-intelasm --enable-aesni --enable-intelrand \
            --enable-renegotiation-indication

    # TODO: FIXME: PRECISA DISSO?
    # --enable-psk

    TODO: FIXME: DEIXAR O BUFFER INPUT COMO RAW*2.05+65536, E DEIXAR ESTE ENCRYPTED NO FINAL
        SEMPRE QUE POSSÍVEL, MOVê-LO, RETORNÁ-LO, A RAW+RAW_SIZE

    OS DEMAIS PROTOCOLOS SIMPLESMENTE CONSOMEM DO BUFFER RAW, A CADA ETAPA
    -> SEM NECESSIDADE DE COPY?

    TODO: FIXME: TEM QUE SEMPRE LER TUDO O QUE TIVER RECEBIDO, ANTES DE EFETUAR O CLOSE()
    TODO: FIXME: AO ENVIAR PARA UM COM BUFFER DE SAÍDA JÁ FULL, CLOSE THE CONNECTION, AND RETURN FAILED
    NOTE: USAR NULL DEREFERENCE E DEIXAR QUE DÊ SEGMENTATION FAULT AO INVÉS DE LIDAR COM ERROS
    TODO: TCP dns per proxies - usar contagem de resolved IPs; usar o proxy id, usando um bitmask para contar os certificados
    TODO: A CADA 10 MINUTOS, RECARREGAR TODOS OS HOSTNAMES VIA TCP, A PARTIR DE DIFERENTES PROXIES
    TODO: FIXME: USAR SOMENTE OS IPS VISTOS EM MAIS DE 3 SERVIDORES DNS
    TODO: FIXME: FATAL IF TOO MANY HOSTS
    TODO: FIXME: SE TIVER MAIS DO QUE (PROXIES_N - PROXIES_QUEUE_N) PROXIES COM PONTUAÇÃO NO MÁXIMO, RESETAR TODAS PARA (pontuacao -= 5)
                OU SEJA, SE APÓS O SORT, proxies[PROXIES_QUEUE_N-1] >= POINTS_MAX
    TODO: FIXME: SER CAPAZ DE LIMITAR O NUMERO DE CONEXÕES DENTRO DE UM SERVICE
            -> CRINDO ELE COM UM DEFAULT
    TODO: FIXME: SER CAPAZ DE LIMITAR O NUMERO DE CONEXÕES DENTRO DE UM HOST
            -> CRINDO ELE COM UM DEFAULT
    TODO: SER CAPAZ DE LIMITAR O NUMERO DE CONEXÕES DENTRO DE UM HOST:PORT (GLOBAL)
    TODO: SE TIVER ALCANCADO O LIMITE DE CONEXOES, IR RETORNANDO NULL ATÉ CONSEGUIR CRIAR, OU REUTILIZAR UMA
    TODO: LIMITAR A QUANTIDADE DE SERVICOS POR SESSION/GLOBAL?
    TODO: FIXME: SE O ERRRO DA REQUEST É PQ A CONEXÃO FECHOU, ENTÃO NEM SEQUER TENTOU; TEM QUE DAR UM RETRY
    TODO: TEM QUE RESPEITAR O SESSIONCHANGED() NO CONNECT(), OU ACABARÁ CONECTANDO ATOA; NÃO PRECISA, BASTA MOVER A CONEXÃO PARA O NOVO SERVICES
            SE A CONEXÃO AINDA NÃO FEZ NENHUMA REQUEST/STREAM, ENTÃO ELA PODE SER COLOCADA NO NOVO POOL DA NOVA SESSÃO
    TODO: FIXME: vai ter que puxar a conexão da lista IDLE com frequencia, fazer o teste, e colocar ela de novo
            fazer isso após o epoll() e antes de retornar ao Python,
                para que conexẽos que estiveram paradas não sejam reutilizadas antes de testar

    TEM QUE USAR O POOL DA THREAD E NÃO DA SESSÃO
        A THREAD APONTA PARA O USER-AGENT/POOL/COOKIES DA SESSÃO

    -> VAI TER QUE SUPORTAR CRIAR/DELETAR POOLS :S

    ALERTAR PARA AS COISAS QUE FIZEREM REQUESTS/STREAMS E/OU SE MANTEREM COM O USER-AGENT/POOL/COOKIES DA SESSÃO != DO PARENT

    A CONEXÃO É RAW SE NAO VIER NADA NO ALPN, ATÉ QUE SEJA USADA COMO SOCKET, HTTP REQUEST, OU WEBSOCKET
        SE HTTP 1.1 REQUEST, MANTÉM ELA COMO TAL ATÉ QUE SEJA PEDIDO UM WEBSOCKET

    TODO: BIND ADDRESSES RUINS PODEM CAUSAR BAD PROXIES

    A IDÉIA É TER 2*CONNECTIONS_N + 2*DNS_REQUESTS_N DE TAMANHO NO SQE
    - AS CONEXÕES VÃO USAR readv/writev
        NÃO ENVIA NADA ENQUANTOO ULTIMO WRITEV() NAO RETORNAR
        DAI ATUALIZA O QUE AINDA FALTA, E MANDA UM NOVO WRITEV() COM TUDO

    TODO: FIXME: SÓ RESOVLER HOSTNAMES QUE FORAM USADOS E/OU ESTIVERAM CONECTADOS NAS ÚLTIMAS 2 HORAS
        É MELHOR MANTER UMA LISTA E IR PUXANDO PRA FRENTE CONFORME FOREM SENDO USADOS
        MAS SÓ SOBRESCREVE OS QUE ESTIVEREM COM REF 0
    -> FAZER O MESMO COM OS PROXIES

    TODO: FIXME: AQUELE MODELO EM QUE SUBMETE A REQUEST AO POOL, MANTEM UM MINIM DE CONEXOES, ETC

    QUANDO xweb.connect() for True
        conn->retry = 0;
*/

#define WC_NO_HARDEN 1

#include <wolfssl/ssl.h>

#define WOLFSSL_SNI_HOST_NAME 0

extern int wolfSSL_UseSNI(void*, int, char*, unsigned short);

typedef WOLFSSL WOLFSSL;
typedef WOLFSSL_CTX WOLFSSL_CTX;

#include <Python.h>

typedef PyByteArrayObject PyByteArrayObject;
typedef PyObject PyObject;

static PyObject* None;

static inline void* PY_BYTES_VALUE (const PyObject* const obj) {
    ASSERT(obj);
    ASSERT(PyBytes_CheckExact(obj));
    return PyBytes_AS_STRING(obj);
}

static inline uint PY_BYTES_SIZE (const PyObject* const obj) {
    ASSERT(obj);
    ASSERT(PyBytes_CheckExact(obj));
    return PyBytes_GET_SIZE(obj);
}

static inline PyObject* UINTLL_TO_PY (const uintll value) {
    return PyLong_FromUnsignedLongLong(value);
}

static inline PyObject* PTR_TO_PY (void* const ptr) {
    ASSERT(ptr != NULL);
    return PyLong_FromVoidPtr(ptr);
}

static inline u64 PY_TO_U64 (PyObject* const obj) {
    ASSERT(PyLong_CheckExact(obj));
    return PyLong_AsUnsignedLongLong(obj);
}

static inline uint PY_TO_UINT (PyObject* const obj) {
    ASSERT(PyLong_CheckExact(obj));
    return PyLong_AsUnsignedLong(obj);
}

static inline void* PY_TO_PTR (PyObject* const obj) {
    ASSERT(PyLong_CheckExact(obj));
    return PyLong_AsVoidPtr(obj);
}

static inline void* PY_TO_PTR_NULL (PyObject* const obj) {
    ASSERT(obj == None || PyLong_CheckExact(obj));
    return (obj == None) ? NULL : PyLong_AsVoidPtr(obj);
}

#define _IP6_ARGS(a) ((u8*)(a))[0], ((u8*)(a))[1], ((u8*)(a))[2], ((u8*)(a))[3], ((u8*)(a))[4], ((u8*)(a))[5], ((u8*)(a))[6], ((u8*)(a))[7], ((u8*)(a))[8], ((u8*)(a))[9], ((u8*)(a))[10], ((u8*)(a))[11], ((u8*)(a))[12], ((u8*)(a))[13], ((u8*)(a))[14], ((u8*)(a))[15]
#define _IP4_ARGS(a) ((u8*)(a))[0], ((u8*)(a))[1], ((u8*)(a))[2], ((u8*)(a))[3]

#define IP6_ADDR_(p0, a0, p1, a1, p2, a2, p3, a3, p4, a4, p5, a5, p6, a6, p7, a7, p8, a8, p9, a9, pA, aA, pB, aB, pC, aC, pD, aD, pE, aE, pF, aF) \
    { p0 ## a0, p1 ## a1, p2 ## a2, p3 ## a3, p4 ## a4, p5 ## a5, p6 ## a6, p7 ## a7, p8 ## a8, p9 ## a9, pA ## aA, pB ## aB, pC ## aC, pD ## aD, pE ## aE, pF ## aF }

#define IP6_ADDR(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, aA, aB, aC, aD, aE, aF) \
    IP6_ADDR_(0x, a0, 0x, a1, 0x, a2, 0x, a3, 0x, a4, 0x, a5, 0x, a6, 0x, a7, 0x, a8, 0x, a9, 0x, aA, 0x, aB, 0x, aC, 0x, aD, 0x, aE, 0x, aF)

#define IP4(a, b, c, d) (((uint)(d) << 24) | ((uint)(c) << 16) | ((uint)(b) << 8) | ((uint)a))

#if DNS_RESOLVE_RETRY_INTERVAL_MIN >= DNS_RESOLVE_RETRY_INTERVAL_MAX
#error
#endif

#if DNS_RESOLVE_SUCCESS_INTERVAL_MIN >= DNS_RESOLVE_SUCCESS_INTERVAL_MAX
#error
#endif

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

#define clear(addr, size) memset(addr, 0, size)
#define clear1(addr, size) memset(addr, 0xFF, size)

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

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

struct IOSubmission {
    u64 data;
    u64 addr;
    u64 off;
    u16 opcode;
    u16 fd;
    u32 len;
};

#define PROXY_NONE 0xFFFF
#define PROXIES_N 65536

#define PROXY_POINTS_MAX   255U
#define PROXY_POINTS_ZERO  127U

struct StaticProxy {
    u32 ip;
    u16 port;
    u16 protocol;
};

#define PROXIES_CHILDS_N    4
#define PROXIES_CHILDS_BITS 2
#define PROXIES_CHILDS_MASK 0b11ULL

#define PROXIES_FIRSTS_N 1024 //

// AO DAR UM FREE NO PROXY, SE ELE AINDA ESTIVER EM USO, APENAS O RETIRE DO HASH TABLE
// NO CONNECTION_CLOSE(), SE O REF COUNT DER 0, AÍ SIM TERMINAR, LIMPANDO OS POINTS DE TODAS AS CLASSES, E O COLOQUE NUMA LINKED LIST
struct Proxy {
    u32 ip;
    u16 port;
    u16 protocol;
    u16 childs[PROXIES_CHILDS_N];
}; // TODO: FIXME: FAZER POR SITE, LIMITADO A 32.000, E NUNCA SOBRESCREVER OS QUE TIVER < 0xFF/2

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

struct HostDep {
    HostDep** aPtr;
    HostDep** bPtr;
    HostDep* aNext;
    HostDep* bNext;
    Host* a;
    Host* b;
    u64 expires; // TODO: FIXME: EXPIRAR ISSO
};

#define HOST_CERTIFICATE_PROXIES_N 5 // TEM QUE SER BASTANTE, PARA O CASO DE MUITOS PROXIES ATACAREM JUNTOS

struct HostCert {
    u64 proxiesNeed:8;
    u64 reserved:56;
    u64 hash[4];
    u64 proxies[HOST_CERTIFICATE_PROXIES_N];
};

#define HOST_CERTIFICATES_N 8 // TEM QUE TER BASTANTE, PARA O CASO DE MUITOS PROXIES TENTAREM NOS ATACAR
#define HOST_NAME_SIZE_MAX 127
#define HOST_IPS_N 64

#define DNS_SERVERS_N 5

struct Host {
    u64 hash;
    u16 childs[4];
    HostDep* a;
    HostDep* b;
    u64 v6; // BIT MASK INDICATING WHICH IPS ARE V6
    u16 id; // DNS TRANSACTION ID
    u8 nameSize; // SEM CONSIDERAR O \0
    u8 pktSize;
    u8 ip; // ITERATOR - LAST USED
    u8 ipsNew;
    u8 ipsN;
    u8 certsCtr; // na verdade é um counter, usar um %
    u64 lasts[DNS_SERVERS_N][2]; // LAST TIME SENT
    u64 agains[DNS_SERVERS_N][2]; // WHEN TO SEND AGAIN
    HostCert certs[HOST_CERTIFICATES_N];
    char name[HOST_NAME_SIZE_MAX + 1]; // POSSUI O \0
    u8 ips[HOST_IPS_N][16];
    u8 pkts[2][256]; // THE ONE TO BE SENT
};

// TODO: FIXME: ALOCAR SEMPRE COM 8 BYTES A MAIS, E NAO DEIXAR DAR READ() NELES
// APOS DAR O RECEIVE, COLOCAR UM \0\r\n\r\n\0\1 APÓS
// ISTO FICARÁ ONDE FICA O LMT; pos > lmt -> overflow
struct In { // PODERÁ SIMPLESMENTE SER TRANSFORMADO EM UM MSG, SE NÃO FOR SSL, OU DECODIFICAR NO SSL DENTRO DELE MESMO
    In* next; // ENQUANTO ESTIVER NO INBUFF, NAO PRCEISA PREENCHER NADA DISSO?
    void* start;
    void* end;
    void* lmt; // AS ALLOCATED
    char buff[]; // DEVERÁ COMEÇAR A RECEBER APÓS UM ESPAÇO PARA UM HEADER
}; // TODO: FIXME: FICAR DE OLHO PAR QUE NUNCA CHEGUE A < in->buff

#define OUT_TYPE_SIZED   0 // BUFF IS ALREADY AFTER IT, ALLOCED WITH THE STRUCTURE
#define OUT_TYPE_STATIC  1 // BUFF IS A POINTER TO STATIC
#define OUT_TYPE_DYNAMIC 2 // BUFF IS A POINTER TO DYNAMIC (MUST FREE)
#define OUT_TYPE_PYTHON  3 // BUFF IS A POINTER TO A PYTHON OBJECT (MUST DEREFERENCE)

struct Out {
    Out* next;
    u32 type;
    u32 size;
    void* start;
    char buff[];
};

// TODO: FIXME: ENFORCE CONNS_MAX POR CAUSA DO FD
// ao chegar em certo limite, aguarda no pool
//      se nao tiver conexoes suficientes, deixa para criar ela depois

#define CONN_POLL_CLOSE            0
#define CONN_POLL_CLOSING          1
#define CONN_POLL_RESOLVE          2
#define CONN_POLL_CONNECT          3 // DAQUI PARA CIMA, O conn->sslInRes == 0 NAO TEM EFEITO; OS DEMAIS CONSIDERAM QUE FOI ALGO RECEBIDO
#define CONN_POLL_PROXY_WAIT       4
#define CONN_POLL_SSL              5
#define CONN_POLL_SSL_CONNECT      6
#define CONN_POLL_POOL             8
#define CONN_POLL_FLUSH            9
#define CONN_POLL_STOP            10

#define CONN_MSG_TYPE_WS_NONE  0
#define CONN_MSG_TYPE_WS_BIN   0x82
#define CONN_MSG_TYPE_WS_STR   0x81
#define CONN_MSG_TYPE_WS_PING  0x89
#define CONN_MSG_TYPE_WS_PONG  0x0A
#define CONN_MSG_TYPE_WS_CLOSE 0x88

#define CONN_SSL_USE ((WOLFSSL*)1ULL)

// TODO: FIXME: BUFFER SIZE DINAMICO POR BANDWIDTH, COM UM MINIMAL?
// NOTE: conn->threads É NECESSÁRIO PARA QUE A REQUEST JÁ LIBERE A CONEXÃO PARA SER REUSADA, MAS DEIXAR A THREAD SE REFERIR A ELA E À SEU PROXY
struct Conn {
    Conn** ptr; // IN THE ACTIVES LIST
    Conn* next;
    Pool* pool;
    Conn** poolPtr;
    Conn* poolNext; // IN THE HTTP FREE CONNECTIONS
    u64 again; // QUANDO TENTAR CONECTAR DE NOVO
    u8 proxyTries_;
    u8 proxyTries;
    u8 try:5;
    u8 v6:3;
    u8 poll;
    u16 proxy;
    u16 fd;
    u64 timeout; // DA OPERAÇÃO ATUAL SENDO FEITA: CONECTANDO, HANDSHAKING, RECEBENDO HEADER, RECEBENDO QUALQUER MENSAGEM/PING
    u64 msgEnded; // QUANDO QUE COMPLETOU A ÚLTIMA MENSAGEM, A FIM DE TIMEOUT EM CONEXÕES LENTAS/TRAVADAS
    u64 msgStarted; // QUANDO QUE COMEÇOU A RECEBER ESTA MENSAGEM
    u8 msgType;
    u8 msgSkip; // ESTES N BYTES NO IN NÃO FAZEM PARTE DA MENSAGEM
    u16 msgWait; // SÓ PROCESSAR NOVAMENTE APÓS RECEBER N BYTES
    u32 msgMore;
    u32 msgEnd; // ONDE ESTÁ NO MOMENTO
    char* tmpEnd;
    In* in;
    In* in_;
    u64 inTime;
    Out* out;
    Out* out_;
    u64 outTime;
    void* sslIn;
    void* sslInStart;
    u64 sslInTime;
    u32 sslInRes;
    u32 sslOutRes;
    Out* sslOut;
    Out* sslOut_;
    u64 sslOutTime;
    WOLFSSL* ssl;
    union {
        struct {
            u8 ip[16];
            union {
                SockAddrAny sAddr;
                SockAddrIP4 sAddr4;
                SockAddrIP6 sAddr6;
            };
            union {
                SockAddrAny dAddr;
                SockAddrIP4 dAddr4;
                SockAddrIP6 dAddr6;
            };
        };
        IOV sslOutIOVs[1024];
    };
    char tmp[1024];
};

#define IN_SIZE_MAX (64*1024*1024)

#if XWEB_TEST
static volatile sig_atomic_t sigINT;
#endif
static volatile sig_atomic_t sigTERM;
static volatile sig_atomic_t sigUSR1;
static volatile sig_atomic_t sigUSR2;

static u64 now0;
static u64 now;

static IOSubmission uSubmissions[65536];
static uint uSubmissionsNew;
static u64 uSubmissionsStart;
static u64 uSubmissionsEnd;
static uint uConsumePending;
static uint uConsumeHead;

#define IOU_FD 3

#define IOU_S_SQES ((IOURingSQE*)0x0002E00000000ULL)
#define IOU_S_SQES_SIZE 1048576

#define IOU_BASE ((void*)0x0002F00000000ULL)
#define IOU_BASE_SIZE 590144

#define IOU_S_HEAD    ((uint*)0x0000002F00000000ULL)
#define IOU_S_TAIL    ((uint*)0x0000002F00000040ULL)
#define IOU_S_MASK    ((uint*)0x0000002F00000100ULL)
#define IOU_S_ENTRIES ((uint*)0x0000002F00000108ULL)
#define IOU_S_FLAGS   ((uint*)0x0000002F00000114ULL)
#define IOU_S_ARRAY   ((uint*)0x0000002F00080140ULL)

#define IOU_C_HEAD    ((uint*)0x0000002F00000080ULL)
#define IOU_C_TAIL    ((uint*)0x0000002F000000C0ULL)
#define IOU_C_MASK    ((uint*)0x0000002F00000104ULL)
#define IOU_C_ENTRIES ((uint*)0x0000002F0000010CULL)
#define IOU_C_CQES    ((IOURingCQE*)0x0000002F00000140ULL)

#define IOU_S_MASK_CONST 0x3FFFU
#define IOU_C_MASK_CONST 0x7FFFU

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

// TODO: FIXME: USAR OS SERVIDORES DNS IPV6
static const SockAddrIP4 dnsBindAddr = { .sin_family = AF_INET, .sin_port = 0, .sin_addr = { .s_addr = XWEB_RESOLVE_BIND_IP } };

#define DNS_SERVER_0 IP4(8,8,8,8)
#define DNS_SERVER_1 IP4(8,8,4,4)
#define DNS_SERVER_2 IP4(1,1,1,1)
#define DNS_SERVER_3 IP4(208,67,222,222)
#define DNS_SERVER_4 IP4(208,67,220,220)

// NOTE: TEM QUE CONSIDERAR O TEMPO QUE PODE TER PASSADO EM CPU BLOCK ETC
#define DNS_RESOLVE_EXPIRES (30*1000ULL)

#define DNS_RESOLVE_RETRY_INTERVAL TIME_RANDOM_INTERVAL((DNS_RESOLVE_RETRY_INTERVAL_MIN), (DNS_RESOLVE_RETRY_INTERVAL_MAX))
#define DNS_RESOLVE_SUCCESS_INTERVAL TIME_RANDOM_INTERVAL((DNS_RESOLVE_SUCCESS_INTERVAL_MIN), (DNS_RESOLVE_SUCCESS_INTERVAL_MAX))

#define DNS_ANSWERS_N (DNS_SERVERS_N * DNS_SERVER_ANSWERS_N)

#define DNS_ANSWER_PKT_SIZE 1024

static const SockAddrIP4 dnsServers[] =  {
   { .sin_family = AF_INET, .sin_port = 0x3500, .sin_addr = { .s_addr = DNS_SERVER_0 } },
   { .sin_family = AF_INET, .sin_port = 0x3500, .sin_addr = { .s_addr = DNS_SERVER_1 } },
   { .sin_family = AF_INET, .sin_port = 0x3500, .sin_addr = { .s_addr = DNS_SERVER_2 } },
   { .sin_family = AF_INET, .sin_port = 0x3500, .sin_addr = { .s_addr = DNS_SERVER_3 } },
   { .sin_family = AF_INET, .sin_port = 0x3500, .sin_addr = { .s_addr = DNS_SERVER_4 } },
};

struct DNSAnswer {
    u32 result; // TEM QUE TER OFFSET 0 NA ESTRUTURA
    u32 server;
    u8 pkt[DNS_ANSWER_PKT_SIZE];
};

static int dnsSockets[DNS_SERVERS_N];
static uint dnsAnswersReadyN;
static u16 dnsAnswersReady[DNS_ANSWERS_N];
static DNSAnswer dnsAnswers[DNS_ANSWERS_N];

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

static inline void xweb_conn_out (Conn* const conn, Out* const out) {

    ASSERT(out && out->size);

    if (conn->out_) // SE TEM UM ÚLTIMO, APONTA ELE PARA ESTE
        (conn->out_)->next = out;
    else // SE NÃO TEM UM ÚLTIMO, ENTÃO TAMBÉM NÃO TEM UM PRIMEIRO
        conn->out = out;
    conn->out_ = out; // SEMPRE É O ÚLTIMO
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

// TODO: FIXME: VALID IPV6 ADDRESSES
static inline int xweb_is_ip_valid_6 (const u64* const ip) {

    return ip[0];
}

static inline int xweb_is_ip_valid_4 (const uint ip) {

    return (
        ip != 0x00000000U &&
        ip != 0xFFFFFFFFU && // TODO: FIXME: FILTER SPECIAL ADDRESSES
        (ip & IP4(255,0,0,0)) != IP4(0,0,0,0) &&
        (ip & IP4(255,0,0,0)) != IP4(10,0,0,0) &&
        (ip & IP4(255,0,0,0)) != IP4(127,0,0,0) &&
        (ip & IP4(255,255,0,0)) != IP4(192,168,0,0) &&
        (ip & IP4(255,240,0,0)) != IP4(172,16,0,0) && // 172.16.0.0/12
        (ip & IP4(240,0,0,0)) != IP4(224,0,0,0)
    );
}

static int xweb_proxy_cmp (const u16* const a, const u16* const b) {
    return (int)proxiesSortPoints[*a] -
           (int)proxiesSortPoints[*b];
}

static void xweb_proxy_add (const uint ip, const uint port, const uint protocol) {

    u64 hash = ((u64)ip << 32) + ((u64)port << 16) + ip + port + protocol;

    u16* ptr = &proxiesRoots[hash & PROXIES_ROOTS_MASK]; hash >>= PROXIES_ROOTS_BITS;

    while (*ptr != PROXY_NONE) { Proxy* const proxy = &proxies[*ptr];
        if (proxy->ip == ip &&
            proxy->port == port &&
            proxy->protocol == protocol)
            return;
        ptr = &proxy->childs[hash & PROXIES_CHILDS_MASK]; hash >>= PROXIES_CHILDS_BITS;
    }

    dbg("ADDING PROXY %u.%u.%u.%u PORT %u PROTOCOL %u", _IP4_ARGS(&ip), port, protocol);

    if (proxiesN != PROXIES_N) { Proxy* const proxy = &proxies[proxiesN];

        proxy->ip        = ip;
        proxy->port      = port;
        proxy->protocol  = protocol;
        proxy->childs[0] = PROXY_NONE;
        proxy->childs[1] = PROXY_NONE;
        proxy->childs[2] = PROXY_NONE;
        proxy->childs[3] = PROXY_NONE;

        for (Site* site = sites; site; site = site->next)
            site->proxiesPoints[proxiesN] = PROXY_POINTS_ZERO;

        proxiesN++;
    }
}

static PyObject* xweb_PY_proxy_add (const char* const ip_, const uint port, const uint protocol) {

    uint a = 0, b = 0, c = 0, d = 0;

    if (sscanf(ip_, "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {

        const uint ip = IP4(a, b, c, d);

        if (xweb_is_ip_valid_4(ip) && 1 <= port && port <= 0xFFFF && protocol <= 2)
            xweb_proxy_add(ip, port, protocol);
    }

    return None;
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

static Host* xweb_host_new (const uint id, const u64 hash, const char* const name, const uint nameSize) {

    Host* const host = malloc(sizeof(Host));

    host->hash      = hash;
    host->childs[0] = HOST_NONE;
    host->childs[1] = HOST_NONE;
    host->childs[2] = HOST_NONE;
    host->childs[3] = HOST_NONE;
    host->a         = NULL;
    host->b         = NULL;
    host->v6        = 0;
    host->ip        = 0;
    host->ipsNew    = 0;
    host->ipsN      = 0;
    host->certsCtr  = 0;
    host->id        = id;
    host->nameSize  = nameSize;
    host->pktSize   = nameSize + 18;

    foreach (i, DNS_SERVERS_N) {
        host->agains[i][0] = 0;
        host->agains[i][1] = 0;
        host->lasts [i][0] = 0;
        host->lasts [i][1] = 0;
    }

    clear(host->certs, sizeof(host->certs));

    memcpy(host->name, name, sizeof(host->name)); host->name[nameSize] = 0;

    //
    u8 pkt[1024];

    memcpy(pkt, "\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16);

    *(u16*)pkt = _to_be16(host->id);

    u8* start = pkt + 12; u8* end = start; const uint size = nameSize + 1;

    memcpy(end + 1, name, size);

    end[size] = '.';

    do {
        u8* size = end;
        while (*++end != '.');
        *size = (end - size) - 1;
    } while (end != &start[size]);

    *end++ = 0;

    *(u32*)end = 0x01000100U; memcpy(host->pkts[0], pkt, host->pktSize); // TYPE A;  CLASS IN
    *(u16*)end =      0x1C00; memcpy(host->pkts[1], pkt, host->pktSize); // TYPE AAAA

    dbg("CREATED HOST %p ID %u NAME %s NAME SIZE %u", host, host->id, host->name, host->nameSize);

    return host;
}

static Host* xweb_host_lookup_new (const char* const name, const uint nameSize) {

    if (nameSize < 4)
        return NULL;

    if (nameSize > HOST_NAME_SIZE_MAX)
        return NULL;

    // TODO: FIXME: VALIDAR HOSTNAME
    // TODO: FIXME: NÃO PERMITIR QUE O HOSTNAME SEJAINVALIDO, UPPERCASE, ETC

    u64 hash  = nameSize;
    u64 hash2 = nameSize;

    uint size2 = nameSize;

    while (size2 > sizeof(u64)) {
        hash2 ^= size2;
        hash2 += hash << 1;
        hash  += hash2;
        hash  += *(u64*)name;
        size2 -= sizeof(u64);
    }

    while (size2) {
        hash2 ^= size2;
        hash2 += hash << 1;
        hash  += hash2;
        hash  += *(u8*)name;
        size2 -= sizeof(u8);
    }

    hash2 += hash2 >> 32;
    hash2 += hash2 >> 32;

    u16* ptr = &hostsRoots[hash2 % HOSTS_ROOTS_N];

    loop {
        const uint hostID = *ptr;

        if (hostID == HOST_NONE) {
            const uint hostID = hostsN++;
            if (hostID == HOSTS_N)
                fatal("TOO MANY HOSTS");
            return (hosts[(*ptr = hostID)] = xweb_host_new(hostID, hash, name, nameSize));
        }

        Host* const host = hosts[hostID];

        if (host->hash == hash &&
            host->nameSize == nameSize && !memcmp(
            host->name, name, nameSize))
            return host;

        ptr = &host->childs[hash & 0b11U]; hash >>= 2;
    }
}

// TODO: FIXME: MAS VAI TER DE SER MAIS INTELIGENTE DO QUE ISSO, CRIANDO UMA VERDADEIRA LISTA DE IPS, PARA QUE NÃO FIQUEM REPETIDOS @_@
//          MAS COMO UMA DAS ENTRADAS DE UM HOST PODE SER UM OUTRO HOST, ENTÃO SE ATUALIZAR UM, VAI TER DE ATUALIZAR TODOS OS QUE DEPENDEM DELE
// TODO: FIXME: LIMIT THE NUMBER OF RESOLVED ENTRIES PER HOST
// TODO: FIXME: LIMIT THE NUMBER OF RESOLVED LEVELS PER HOST (HOSTNAME/CNAME/CNAME/CNAME)

static inline void xweb_host_a_add (Host* const host, HostDep* const dep) {

    if ((dep->aNext = *(dep->aPtr = &host->a)))
         dep->aNext->aPtr = &dep->aNext;
    *dep->aPtr = dep;
}

static inline void xweb_host_b_add (Host* const host, HostDep* const dep) {

    if ((dep->bNext = *(dep->bPtr = &host->b)))
         dep->bNext->bPtr = &dep->bNext;
    *dep->bPtr = dep;
}

static inline void xweb_host_dep_remove_a (HostDep* const dep) {

    if ((*dep->aPtr = dep->aNext))
        (*dep->aPtr)->aPtr = dep->aPtr;
}

static inline void xweb_host_dep_remove_b (HostDep* const dep) {

    if ((*dep->bPtr = dep->bNext))
        (*dep->bPtr)->bPtr = dep->bPtr;
}

// AO EXPIRAR
static inline void xweb_host_dep_del (HostDep* const dep) {

    xweb_host_dep_remove_a(dep);
    xweb_host_dep_remove_b(dep);
    free(dep);
}

// TODO: FIXME: MAS SE ESTIVER ADICIONANDO MANUALMENTE, SETAR MANUALMENTE O TAL EXPIRATION
static void xweb_host_ips_add_6 (Host* const host, const u64* ip_) {

    u64* ip = (u64*)host->ips;
    u64 mask = host->v6;

    while (mask) {
        if ((mask & 1ULL) &&
            ip[0] == ip_[0] &&
            ip[1] == ip_[1]
            ) return;
        ip += 2;
        mask >>= 1;
    }

    if (host->ipsN != HOST_IPS_N)
        host->ipsN++;

    if (host->ipsNew == HOST_IPS_N)
        host->ipsNew = 0;

    host->v6 |= 1ULL << host->ipsNew;

    ip = (u64*)(host->ips[host->ipsNew++]);

    ip[0] = ip_[0];
    ip[1] = ip_[1];

    dbg("ADDED IP V6 %02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X ON HOST %s", _IP6_ARGS(((u8*)ip)), host->name);

    // REGISTRA ESTE MESMO IP EM TODOS OS SEUS DEPENDENTES
    HostDep* dep = host->a;

    while (dep) { ASSERT(dep->b == host);
        xweb_host_ips_add_6(dep->a, ip_);
        dep = dep->aNext;
    }
}

static void xweb_host_ips_add_4 (Host* const host, const uint ip_) {

    u64 mask = host->v6;
    u32* ip = (u32*)host->ips;
    uint i = HOST_IPS_N;

    while (i--) {
        if (!(mask & 1ULL) && *(u32*)ip == ip_)
            return;
        mask >>= 1;
        ip += 4;
    }

    if (host->ipsN != HOST_IPS_N)
        host->ipsN++;

    if (host->ipsNew == HOST_IPS_N)
        host->ipsNew = 0;

    host->v6 &= ~(1ULL << host->ipsNew);

    ip = (u32*)(host->ips[host->ipsNew++]);
    ip[0] = ip_;

    dbg("ADDED IP V4 %u.%u.%u.%u ON HOST %s", _IP4_ARGS(ip), host->name);

    // REGISTRA ESTE MESMO IP EM TODOS OS SEUS DEPENDENTES
    HostDep* dep = host->a;

    while (dep) { ASSERT(dep->b == host);
        xweb_host_ips_add_4(dep->a, ip_);
        dep = dep->aNext;
    }
}

static void xweb_host_depend (Host* const a, Host* const b) {

    dbg("HOST %s DEPENDS ON HOST %s", a->name, b->name);

    // COPIA OS IPS DELE
    for (int i = 0; i != b->ipsN; i++) {
        if (b->v6 & (1ULL << i))
            xweb_host_ips_add_6(a,  (u64*)(b->ips[i]));
        else
            xweb_host_ips_add_4(a, *(u32*)(b->ips[i]));
    }

    HostDep* dep = b->b;

    while (dep) { ASSERT(dep->a == b);
        xweb_host_depend(a, dep->b);
        dep = dep->bNext;
    }

    // MANDAR ELE RESOLVER ENTÃO
    // OS QUE ENTRAREM VÃO ENTRAR NELE
    //xweb_host_resolve(b);
}

static void xweb_host_names_add (Host* const restrict host, const char* restrict const name, const uint nameSize) {

    dbg("HOST %s RESOLVED AS CNAME %s SIZE %u", host->name, name, nameSize);

    // IDENTIFICAR O HOST
    Host* const b = xweb_host_lookup_new(name, nameSize);

    // CADASTRAR ELE COMO DEPENDENTE; CASO JÁ NÃO SEJA
    HostDep* dep = host->b;

    while (dep) { ASSERT(dep->a == host);
        if (dep->b == b) {
            dep->expires = now + 4*60*60*1000;
            return;
        } dep = dep->bNext;
    }

    dep = malloc(sizeof(HostDep));
    dep->expires = now + 4*60*60*1000;
    dep->a = host;
    dep->b = b;

    xweb_host_b_add(host, dep);
    xweb_host_a_add(b, dep); // NOTE: SE FOR PARA REMOVER ALGO, TAMBÉM TEM QUE REMOVER NESTE SENTIDO INVERSO
    xweb_host_depend(host, b);

    // QUANDO FOR RESOLVER UM HOST, TEM QUE MANDAR RESOLVER TODAS AS SUAS DEPENDENCIAS, E DE FORMA RECURSIVA
}

//
static inline u64 xweb_pool_hash (const Host* const host, const uint port) {

    // NOTA: SÓ PODE SER ASSIM ENQUANTO OS HOSTS FOREM ESTÁTICOS
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

static PyObject* xweb_PY_connect_start (const char* const restrict hostname, const uint hostnameSize, const uint port, void* const restrict ssl, const uint proxyTries) {

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
static void xweb_poll_conns (void) {

    Conn* conn = conns;

    while (conn) {
        Conn* const next = conn->next; // ELAS PODEM SER DELETADAS
        xweb_conn_poll(conn);
        conn = next;
    }
}

static void xweb_poll_conns_res (void) {

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

static PyObject* xweb_PY_log_ (const char* const pre, uint preSize, const char* const msg, uint msgSize) {

    if (logFree < (msgSize + 8192)) {
        logFree = LOG_BUFFER_SIZE;
        logEnd = logBuffer;
    }

    memcpy(logEnd, pre, preSize);
    logEnd += preSize;
    logFree -= preSize;

    if (thread) {
        memcpy(logEnd, thread->name, thread->nameSize);
        logEnd += thread->nameSize;
        logFree -= thread->nameSize + 1; // JA DESCONTA O \n
    } elif (class) {
        memcpy(logEnd, class->name, class->nameSize);
        logEnd += class->nameSize;
        logFree -= class->nameSize + 1;
    } else {
        memcpy(logEnd, "[main]", 6);
        logEnd += 6;
        logFree -= 7;
    }

    if (msgSize > logFree)
        msgSize = logFree;

    memcpy(logEnd, msg, msgSize);

    logEnd += msgSize;
    logFree -= msgSize;

    memcpy(logEnd, "\n", 1);

    logEnd += 1;

#if 1
    write(STDOUT_FILENO, logBuffer, logEnd - logBuffer);
    logEnd = logBuffer;
    logFree = LOG_BUFFER_SIZE;
#endif
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

// TODO: FIXME: salvar este novo NOW absoluto, e calcular o calendar atual
static inline void xweb_poll_dns_receive_cname (Host* const restrict host, const u8* pkt, const u8* data, uint dataSize) {

    dbg("GOT CNAME FOR HOST %s", host->name);

    char str[2048]; // HOST_NAME_SIZE_MAX + 1
    char* str_ = str;

    const u8* lmt = data + dataSize;

    while ((dataSize = *(u8*)data)) {
        if (dataSize >= 0b11000000) { // NOTE: ESTE U16 ENTÃO TEM QUE TERMINAR ESSE DATA SIZE
            const u8* const new = pkt + (_from_be16(*(u16*)data) & 0b0011111111111111U);
            if (new >= data)
                return; // POINTED FORWARD
            lmt = data;
            data = new;
            continue;  // PODERIA SALVAR O DATA INICIAL, E IR SUBINDO NO PACOTE; NÃO PODE FAZER REFERENCIA A OFFSETS DEPOIS DO COMEÇO DO ÚLTIMO QUE JÁ FOI VISTO
        } data += 1;
        if ((data + dataSize) > lmt)
            return; // TERMINA DEPOIS DO PACOTE
        if ((str_ + dataSize) > &str[sizeof(str) - 4])
            return; // NAME IS TOO BIG
        memcpy(str_, data, dataSize); str_ += dataSize;
        *str_++ = '.';
        data += dataSize;
    }

    if (str_ == str)
        return; // EMPTY NAME

    *--str_ = 0;

    xweb_host_names_add(host, str, str_ - str);
}

// ORIGINAL ENCODED
// TODO: FIXME: SIMPLESMENTE COMPARAR COM UM HASH
static inline int xweb_poll_dns_receive_handle_is_encoded_mismatch (const u8* restrict a, const u8* restrict b) {
    b++; // TODO: FIXME: PODERIA VERIFICAR ISTO SOMANDO ESTE COMEÇO COM TODOS OS OUTROS '.', E A CADA PONTO ADICIONAR +1
    loop { //
        const uint A = *a++;
        const uint B = *b++;
        if (!(A == B || (A == '.' && B <= 0b111111)))
            return 1;
        if (!A)
            return 0;
    }
}

// TODO: FIXME: NXDOMAIN WITH A SPECIFIC RETRY INTERVAL
static inline void xweb_poll_dns_receive_handle (const uint server, const u8* pkt, const u8* const end) {

    uint v6;
    const uint hostID = _from_be16(*(u16*)pkt);
    const u8* pos = pkt + 2;

    if (hostID >= hostsN)
        return; // BAD HOST ID

    Host* const host = hosts[hostID];

    dbg("HANDLE DNS ANSWER - PKT - HOST %s NAME SIZE %u", host->name, host->nameSize);

    // FLAGS AND QUESTIONS
    // STANDARD QUERY ANSWER; 1 QUESTION
    if (*(u32*)pos == 0x01008381U) {
        dbg("HANDLE DNS ANSWER - PKT - NO SUCH NAME");
        // TEM QUE FAER ISSO DEPOIS DE VER A VERSÃO
        //host->agains[server][v6] = host->lasts[server][v6] + DNS_RESOLVE_SUCCESS_INTERVAL;
        return;
    }

    if (*(u32*)pos != 0x01008081U) {
        dbg("HANDLE DNS ANSWER - PKT - BAD FLAGS AND QUESTION 0x%08X", *(u32*)pos);
        return;
    }

    pos += 10; // FLAGS, QUESTIONS, ANSWERSRRS, AUTHORITYRRS, ADITIONALRRS

    // TODO: FIXME: SE SÓ TEM UM JEITO DE ENCODAR, ENTÃO JÁ DEIXAR ENCODADO :S
    if (xweb_poll_dns_receive_handle_is_encoded_mismatch((u8*)host->name, pos)) {
        dbg("HANDLE DNS ANSWER - PKT - NAME MISMATCH");
        return; // NAME MISMATCH
    }

    pos += host->nameSize + 2;

    // TYPE AND CLASS
    if (*(u32*)pos == 0x01000100U)
        v6 = 0;
    elif (*(u32*)pos == 0x01001C00U)
        v6 = 1;
    else // BAD TYPE / CLASS
        return;

    if ((host->lasts[server][v6] + DNS_RESOLVE_EXPIRES) < now)
        return; // REQUEST EXPIRED

    pos += 4;

    while ((pos + 8) < end) {
        loop { // PULA O NOME
            const uint size = *(u8*)pos++;
            if (size == 0)
                break;
            if (size >= 0b11000000) {
                pos++;
                break;
            } pos += size;
        }
        if ((pos + 10) > end)
            break; // INCOMPLETE
        const uint type = *(u16*)pos;        // LE O TYPE
        pos += 8;                            // PULA O TYPE, CLASSE E TTL
        const uint size = _from_be16(*(u16*)pos); // LE O DATA SIZE
        pos += 2;                            // PULA O DATA SIZE
        if ((pos + size) > end)
            break; // INCOMPLETE
        if (type == 0x0100 && size == 4) { // A
            if (xweb_is_ip_valid_4(*(u32*)pos))
                xweb_host_ips_add_4(host, *(u32*)pos);
        } elif (type == 0x1C00 && size == 16) { // AAAA
            if (xweb_is_ip_valid_6((u64*)pos))
                xweb_host_ips_add_6(host, (u64*)pos);
        } elif (type == 0x0500 && 4 <= size && size <= HOST_NAME_SIZE_MAX) // CNAME
            xweb_poll_dns_receive_cname(host, pkt, pos, size);
        pos += size; // PULA O DATA
    }

    host->agains[server][v6] = host->lasts[server][v6] + DNS_RESOLVE_SUCCESS_INTERVAL;

    dbg("HANDLE DNS ANSWER - PKT - RESOLVE SUCCESS HOST %s V%c AGAIN IN %lld", host->name, v6?'6':'4', (intll)host->agains[server][v6] - (intll)now);
}

static void xweb_poll_dns_receive (void) {

    while (dnsAnswersReadyN) {

        DNSAnswer* const answer = &dnsAnswers[dnsAnswersReady[--dnsAnswersReadyN]];

        if (answer->result >= 24 &&
            answer->result <= 2048)
            xweb_poll_dns_receive_handle(answer->server, answer->pkt, answer->pkt + answer->result);

        answer->result = IO_WAIT;

        xweb_io_submit(&answer->result, IORING_OP_READ, dnsSockets[answer->server], (u64)answer->pkt, 0, sizeof(answer->pkt));
    }
}

static void xweb_poll_dns_send (void) {

    // LIMITAR QUANTOS SÃO ENVIADOS DE CADA VEZ
    // NÃO MANDA O V4 E V6 AO MESMO TEMPO, PARA O CASO DE TER PROBLEMAS NA REDE ETC
    foreach (h, hostsN) { Host* const host = hosts[h];
        foreach (i, DNS_SERVERS_N) {
            if (host->pktSize){
                if (host->agains[i][0] <= now) {
                    host->agains[i][0] = now + DNS_RESOLVE_RETRY_INTERVAL;
                    host->lasts [i][0] = now;
                    xweb_io_submit(NULL, IORING_OP_WRITE, dnsSockets[i], (u64)host->pkts[0], 0, host->pktSize);
                    dbg("SERVER %u RESOLVE HOST %s V4; AGAIN IN %lld MS", i, host->name, (intll)host->agains[i][0] - (intll)now);
                } elif (host->agains[i][1] <= now) {
                    host->agains[i][1] = now + DNS_RESOLVE_RETRY_INTERVAL;
                    host->lasts [i][1] = now;
                    xweb_io_submit(NULL, IORING_OP_WRITE, dnsSockets[i], (u64)host->pkts[1], 0, host->pktSize);
                    dbg("SERVER %u RESOLVE HOST %s V6; AGAIN IN %lld MS", i, host->name, (intll)host->agains[i][1] - (intll)now);
                }
            }
        }
    }
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

    if (mmap(IOU_S_SQES, IOU_S_SQES_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, IOU_FD, IORING_OFF_SQES) != IOU_S_SQES)
        fatal("FAILED TO MAP IOU_S_SQES");

    if (mmap(IOU_BASE, IOU_BASE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, IOU_FD, IORING_OFF_SQ_RING) != IOU_BASE)
        fatal("FAILED TO MAP IOU_BASE");

    dbg("#define IOU_S_MASK_CONST 0x%llXU", (uintll)*IOU_S_MASK);
    dbg("#define IOU_C_MASK_CONST 0x%llXU", (uintll)*IOU_C_MASK);

    ASSERT(IOU_S_MASK_CONST == *IOU_S_MASK);
    ASSERT(IOU_C_MASK_CONST == *IOU_C_MASK);

    uConsumeHead = *IOU_C_HEAD;

    read_barrier();

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

    logBuffer = malloc(LOG_BUFFER_SIZE);
    logBufferReady = malloc(LOG_BUFFER_SIZE);
    logBufferFlushing = NULL;
    logEnd = logBuffer;
    logFree = LOG_BUFFER_SIZE;

    // TIME
    now0 = xweb_now_update();

    // IO_URING
    IOURingParams params; memset(&params, 0, sizeof(params));

    const int fd = io_uring_setup(16384, &params);

    if (fd <= 0)
        fatal("FAILED TO OPEN IO_URING");

    if (params.sq_entries != 16384)
        fatal("TOO FEW SQ ENTRIES");

    uSubmissionsNew = 0;
    uSubmissionsStart = 0;
    uSubmissionsEnd = 0;

    uConsumePending = 0;

    // ASSUMING (params.features & IORING_FEAT_SINGLE_MMAP)
    uint sSize = params.sq_off.array + params.sq_entries * sizeof(uint);
    uint cSize = params.cq_off.cqes  + params.cq_entries * sizeof(IOURingCQE);

    if (sSize < cSize)
        sSize = cSize;

    dbg("IO_URING FD %d", fd);

    dbg("params.sq_entries = %llu", (uintll)params.sq_entries);

    dbg("#define IOU_BASE_SIZE %u", sSize);

    dbg("#define IOU_S_SQES_SIZE %llu", (uintll)params.sq_entries * sizeof(IOURingSQE));

    dbg("#define IOU_S_HEAD    ((uint*)0x%016llXULL)", (uintll)(IOU_BASE + params.sq_off.head));
    dbg("#define IOU_S_TAIL    ((uint*)0x%016llXULL)", (uintll)(IOU_BASE + params.sq_off.tail));
    dbg("#define IOU_S_MASK    ((uint*)0x%016llXULL)", (uintll)(IOU_BASE + params.sq_off.ring_mask));
    dbg("#define IOU_S_ENTRIES ((uint*)0x%016llXULL)", (uintll)(IOU_BASE + params.sq_off.ring_entries));
    dbg("#define IOU_S_FLAGS   ((uint*)0x%016llXULL)", (uintll)(IOU_BASE + params.sq_off.flags));
    dbg("#define IOU_S_ARRAY   ((uint*)0x%016llXULL)", (uintll)(IOU_BASE + params.sq_off.array));

    dbg("#define IOU_C_HEAD    ((uint*)0x%016llXULL)", (uintll)(IOU_BASE + params.cq_off.head));
    dbg("#define IOU_C_TAIL    ((uint*)0x%016llXULL)", (uintll)(IOU_BASE + params.cq_off.tail));
    dbg("#define IOU_C_MASK    ((uint*)0x%016llXULL)", (uintll)(IOU_BASE + params.cq_off.ring_mask));
    dbg("#define IOU_C_ENTRIES ((uint*)0x%016llXULL)", (uintll)(IOU_BASE + params.cq_off.ring_entries));
    dbg("#define IOU_C_CQES    ((IOURingCQE*)0x%016llXULL)", (uintll)(IOU_BASE + params.cq_off.cqes));

    ASSERT(fd == IOU_FD);

    // CONNS_N*(in e out) + DNS PACKETS + 1024
    ASSERT(params.sq_entries == 16384);

    ASSERT((IOU_BASE + params.sq_off.head)         == (void*)IOU_S_HEAD);
    ASSERT((IOU_BASE + params.sq_off.tail)         == (void*)IOU_S_TAIL);
    ASSERT((IOU_BASE + params.sq_off.ring_mask)    == (void*)IOU_S_MASK);
    ASSERT((IOU_BASE + params.sq_off.ring_entries) == (void*)IOU_S_ENTRIES);
    ASSERT((IOU_BASE + params.sq_off.flags)        == (void*)IOU_S_FLAGS);
    ASSERT((IOU_BASE + params.sq_off.array)        == (void*)IOU_S_ARRAY);

    ASSERT((IOU_BASE + params.cq_off.head)         == (void*)IOU_C_HEAD);
    ASSERT((IOU_BASE + params.cq_off.tail)         == (void*)IOU_C_TAIL);
    ASSERT((IOU_BASE + params.cq_off.ring_mask)    == (void*)IOU_C_MASK);
    ASSERT((IOU_BASE + params.cq_off.ring_entries) == (void*)IOU_C_ENTRIES);
    ASSERT((IOU_BASE + params.cq_off.cqes)         == (void*)IOU_C_CQES);

    ASSERT(IOU_BASE_SIZE == sSize);

    // DNS
    dnsAnswersReadyN = 0;

    foreach (i, DNS_SERVERS_N) {
        const int sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);
        if (sock <= 0)
            fatal("FAILED TO OPEN DNS SOCKET");
        if (bind(sock, (SockAddrAny*)&dnsBindAddr, sizeof(SockAddrIP4)))
            fatal("FAILED TO BIND DNS SOCKET");
        if (connect(sock, (SockAddrAny*)&dnsServers[i], sizeof(SockAddrIP4)))
            fatal("FAILED TO CONNECT DNS SOCKET");
        dnsSockets[i] = sock;
    }

    // PROXIES
    proxiesN = 0;

    foreach (i, PROXIES_ROOTS_N)
        proxiesRoots[i] = PROXY_NONE;

    foreach (i, PROXIES_N) {
        proxies[i].ip        = 0;
        proxies[i].port      = 0;
        proxies[i].protocol  = 0;
        proxies[i].childs[0] = PROXY_NONE;
        proxies[i].childs[1] = PROXY_NONE;
        proxies[i].childs[2] = PROXY_NONE;
        proxies[i].childs[3] = PROXY_NONE;
    }

    // HOSTS
    hostsN = 0;

    clear(hosts, sizeof(hosts));
    clear1(hostsRoots, sizeof(hostsRoots));

    // INITIALIZE THE SSL LIBRARY
    wolfSSL_Init();

    // CREATE THE SSL CONTEXT
    sslCtx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
    wolfSSL_CTX_set_verify(sslCtx, SSL_VERIFY_NONE, NULL);
    wolfSSL_SetIORecv(sslCtx, (CallbackIORecv)xweb_ssl_read);
    wolfSSL_SetIOSend(sslCtx, (CallbackIOSend)xweb_ssl_write);

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
