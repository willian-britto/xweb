
#define SESSION_POOLS_ROOTS_N 64
#define SESSION_POOLS_ROOTS_MASK 0b111111ULL
#define SESSION_POOLS_ROOTS_BITS 6

typedef struct Thread Thread;

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
