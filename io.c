static IOSubmission uSubmissions[65536];
static uint uSubmissionsNew;
static u64 uSubmissionsStart;
static u64 uSubmissionsEnd;
static uint uConsumePending;
static uint uConsumeHead;

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
