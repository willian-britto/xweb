
struct IOSubmission {
    u64 data;
    u64 addr;
    u64 off;
    u16 opcode;
    u16 fd;
    u32 len;
};
