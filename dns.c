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
