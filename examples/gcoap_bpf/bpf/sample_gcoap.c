#include <stdint.h>
#include "bpf/bpfapi/helpers.h"

#define BPF_SAMPLE_STORAGE_KEY_EXECUTION    1
#define COAP_OPT_FINISH_PAYLOAD  (0x0001)

typedef struct {
    uint32_t hdr_p;                                  /**< pointer to raw packet   */
    uint32_t token_p;                                   /**< pointer to token        */
    uint32_t payload_p;                                 /**< pointer to payload      */
    uint16_t payload_len;                             /**< length of payload       */
    uint16_t options_len;                             /**< length of options array */
} bpf_coap_pkt_t;

int coap_resp(bpf_coap_ctx_t *gcoap)
{
    bpf_coap_pkt_t *pkt = gcoap->pkt;
    /* Track executions */
    uint32_t i;
    bpf_fetch_local(BPF_SAMPLE_STORAGE_KEY_EXECUTION, &i);
    bpf_store_local(BPF_SAMPLE_STORAGE_KEY_EXECUTION, i + 1);

    bpf_gcoap_resp_init(gcoap, (2 << 5) | 5);
    ssize_t pdu_len = bpf_coap_opt_finish(gcoap, COAP_OPT_FINISH_PAYLOAD);

    uint8_t *payload = (uint8_t*)(intptr_t)(pkt->payload_p);

    payload[0] = 'h';
    payload[1] = 'e';
    payload[2] = 'l';
    payload[3] = 'l';
    payload[4] = 'o';

    pdu_len += 5;
    return pdu_len;
}
