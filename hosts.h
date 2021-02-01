typedef struct Host Host;
typedef struct HostServer HostServer;
typedef struct HostCert HostCert;
typedef struct HostDep HostDep;

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
