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
