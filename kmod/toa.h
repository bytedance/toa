#ifndef BYTEDANCE_TOA
#define BYTEDANCE_TOA

/* toa socket options, make sure doesn't overlap with uoa! */
enum {
    TOA_SO_BASE          = 2064,
    /* set */
    TOA_SO_SET_MAX       = TOA_SO_BASE,
    /* get */
    TOA_SO_GET_VNI       = TOA_SO_BASE,
    TOA_SO_GET_MAX       = TOA_SO_GET_VNI,
};
enum {
    TOA_BASE_CTL            = 4096,
    /* set */
    TOA_SO_SET_MAX_CTL          = TOA_BASE_CTL,
    /* get */
    TOA_SO_GET_LOOKUP       = TOA_BASE_CTL,
    TOA_SO_GET_MAX_CTL          = TOA_SO_GET_LOOKUP,
};

struct toa_nat64_peer {
    struct in6_addr saddr;
    uint16_t sport;
};
#endif