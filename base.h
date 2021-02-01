#define _GNU_SOURCE  1

#if XWEB_ASSERT
#define STRINGIFY_(x) #x
#define STRINGIFY(x) STRINGIFY_(x)
#define ASSERT(condition) ({ if (!(condition)) { write(STDOUT_FILENO, STRINGIFY(__LINE__) " " #condition "\n", sizeof(STRINGIFY(__LINE__) " " #condition "\n")); abort(); } })
#else
#define ASSERT(condition) ({})
#endif

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#if XWEB_TEST
#include <termios.h>
#endif
#include <sys/time.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <sched.h>
#include <fcntl.h>
#include <linux/io_uring.h>

#define foreach(_i, _n) for (uint _i = 0; _i != (_n); _i++)

#define TIME_RANDOM_INTERVAL(min, max) ((min) + random64(1) % ((max) - (min)))

// -1 -> 0xFFFFFFFFU
// -2 -> 0xFFFFFFFEU
#define IO_WAIT          0xFFFFF000U
#define IO_ERR           0xFFFFF001U
#define IO_EINTR         (0xFFFFFFFFU - EINTR        + 1U)
#define IO_EAGAIN        (0xFFFFFFFFU - EAGAIN       + 1U)
#define IO_ECONNREFUSED  (0xFFFFFFFFU - ECONNREFUSED + 1U)
#define IO_ENETUNREACH   (0xFFFFFFFFU - ENETUNREACH  + 1U)
#define IO_ECANCELED     (0xFFFFFFFFU - ECANCELED    + 1U)

typedef struct io_uring_params IOURingParams;
typedef struct io_uring_sqe IOURingSQE;
typedef struct io_uring_cqe IOURingCQE;

#define read_barrier()  __asm__ __volatile__("":::"memory")
#define write_barrier() __asm__ __volatile__("":::"memory")

static inline int io_uring_setup(uint entries, IOURingParams* p) {
    return syscall(__NR_io_uring_setup, entries, p);
}

static inline int io_uring_enter(int fd, uint to_submit, uint min_complete, uint flags) {
    return syscall(__NR_io_uring_enter, fd, to_submit, min_complete, flags, NULL, 0);
}

#define __unused __attribute__((unused))

#define _to_be16(x) __builtin_bswap16(x)
#define _to_be32(x) __builtin_bswap32(x)
#define _to_be64(x) __builtin_bswap64(x)

#define _from_be16(x) __builtin_bswap16(x)
#define _from_be32(x) __builtin_bswap32(x)
#define _from_be64(x) __builtin_bswap64(x)

typedef long long intll;

typedef unsigned int uint;
typedef unsigned long long int uintll;

typedef uint8_t byte;

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef int32_t i32;

#define loop while(1)
#define elif else if

typedef union SockAddr SockAddr;
typedef struct sockaddr SockAddrAny;
typedef struct sockaddr_in SockAddrIP4;
typedef struct sockaddr_in6 SockAddrIP6;

typedef struct mmsghdr MMsgHdr;
typedef struct msghdr MsgHdr;

typedef struct iovec IOV;

union SockAddr {
    SockAddrAny any;
    SockAddrIP4 ip4;
    SockAddrIP6 ip6;
};
