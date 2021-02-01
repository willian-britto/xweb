
typedef struct Site Site;

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
