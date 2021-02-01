
// TODO: FIXME: VALID IPV6 ADDRESSES
int xweb_is_ip_valid_6 (const u64* const ip) {

    return ip[0];
}

int xweb_is_ip_valid_4 (const uint ip) {

    return (
        ip != 0x00000000U &&
        ip != 0xFFFFFFFFU && // TODO: FIXME: FILTER SPECIAL ADDRESSES
        (ip & IP4(255,0,0,0)) != IP4(0,0,0,0) &&
        (ip & IP4(255,0,0,0)) != IP4(10,0,0,0) &&
        (ip & IP4(255,0,0,0)) != IP4(127,0,0,0) &&
        (ip & IP4(255,255,0,0)) != IP4(192,168,0,0) &&
        (ip & IP4(255,240,0,0)) != IP4(172,16,0,0) && // 172.16.0.0/12
        (ip & IP4(240,0,0,0)) != IP4(224,0,0,0)
    );
}
