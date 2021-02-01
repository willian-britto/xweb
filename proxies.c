typedef struct StaticProxy StaticProxy;
typedef struct Proxy Proxy;

#define PROXIES_ROOTS_N 512
#define PROXIES_ROOTS_BITS 9
#define PROXIES_ROOTS_MASK 0b111111111ULL

static const StaticProxy proxiesStatic[] = { XWEB_PROXIES_STATIC };

static u8* proxiesSortPoints;

static uint  proxiesN;
static u16   proxiesRoots[PROXIES_ROOTS_N];
static Proxy proxies[PROXIES_N];

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

void xweb_proxy_add (const char* const ip_, const uint port, const uint protocol) {

    uint a = 0, b = 0, c = 0, d = 0;

    if (sscanf(ip_, "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {

        const uint ip = IP4(a, b, c, d);

        if (xweb_is_ip_valid_4(ip) && 1 <= port && port <= 0xFFFF && protocol <= 2)
            xweb_proxy_add(ip, port, protocol);
    }
}

void xweb_proxies_init (void) {
    
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
}
