
typedef struct Thread Thread;

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

