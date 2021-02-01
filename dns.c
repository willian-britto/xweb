#if DNS_RESOLVE_RETRY_INTERVAL_MIN >= DNS_RESOLVE_RETRY_INTERVAL_MAX
#error
#endif

#if DNS_RESOLVE_SUCCESS_INTERVAL_MIN >= DNS_RESOLVE_SUCCESS_INTERVAL_MAX
#error
#endif

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

void xweb_dns_init (void) {
   
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
}
