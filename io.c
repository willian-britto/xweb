
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

static IOSubmission uSubmissions[65536];
static uint uSubmissionsNew;
static u64 uSubmissionsStart;
static u64 uSubmissionsEnd;
static uint uConsumePending;
static uint uConsumeHead;

// AO TENTAR CANCELAR ALGO:
//primeiro procurar ele na lista dos queueds
    // se o sslInRes || sslOutRes for IO_WAIT
        // cancelar todos os queueds pelo FD
    //cancela o &conn->sslInRes
    //cancela o &conn->sslOutRes
//se não achar, aí sim cancela no io_uring

void xweb_io_submit (u32* const data, const uint opcode, const uint fd, const u64 addr, const u64 off, const uint len) {

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

void xweb_io_init2 (void) {

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
}

static void xweb_io_poll (void) {

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

void xweb_io_init (void) {

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
}
