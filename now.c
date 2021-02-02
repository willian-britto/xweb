#define MS_MAX (32ULL*24*64*64*1024ULL)

static u64 now0;
static u64 now;

u64 xweb_now_update (void) {

    struct timespec now_;

    clock_gettime(CLOCK_BOOTTIME, &now_);

    now = 3*MS_MAX + (u64)now_.tv_sec * 1000 + (u64)now_.tv_nsec / 1000000;

    return now;
}
