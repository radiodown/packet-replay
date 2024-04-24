#ifndef PCAP_H
#define PCAP_H

#include "syshead.h"
#include "options.h"

struct pcap_hdr
{
    uint32_t magic_number;  /* magic number */
    uint16_t version_major; /* major version number */
    uint16_t version_minor; /* minor version number */
    int32_t thiszone;       /* GMT to local correction */
    uint32_t sigfigs;       /* accuracy of timestamps */
    uint32_t snaplen;       /* max length of captured packets */
    uint32_t network;       /* data link type */
} typedef PCAP_HDR;

struct pcaprec_hdr
{
    uint32_t ts_sec;    /* timestamp seconds */
    uint32_t ts_subsec; /* timestamp subseconds */
    uint32_t incl_len;  /* number of octets of packet saved in file */
    uint32_t orig_len;  /* actual length of packet */
} typedef PCAPREC_HDR;

typedef struct tcphdr TCP;
typedef struct iphdr IP;
typedef struct ethhdr ETH;

// struct tcp_options {
//     uint8_t kind;
//     uint8_t len;
//     unsigned char data[18];
// } typedef TCP_OP;

struct __tcp_session
{
    unsigned char *raw; /* raw packet frame */

    int session_id; /* number of session  */
    int packet_id;  /* packet number in session */
    int segmented;  /* is packet segmented ? 1 :0 */

    struct pcaprec_hdr *pcap; /* packet hdr */
    struct ethhdr *eth;       /* ethernet frame */
    struct iphdr *ip;         /* ip header */
    struct tcphdr *tcp;       /* tcp header */
    
    // struct tcp_options *tcp_op;

    int payload_size;       /* tcp payload size*/
    unsigned char *payload; /* tcp payload */

    struct __tcp_session *head; /* the first packet of session list */
    struct __tcp_session *next; /* before packet of session list */
    struct __tcp_session *prev; /* later packet of session list */

} typedef TCP_SESSION;

int parse_pcap(options *o);
int send_pcap(options *o);
void print_pcap();

#endif
