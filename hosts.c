
Host* xweb_host_new (const uint id, const u64 hash, const char* const name, const uint nameSize) {

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
