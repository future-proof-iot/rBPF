#include <stdint.h>
#include "bpf/bpfapi/helpers.h"

#define COAP_OPT_FINISH_PAYLOAD  (0x0001)
#define COAP_CODE_CONTENT      ((2 << 5) | 5)

int coap_resp(bpf_coap_ctx_t *gcoap)
{
    bpf_saul_reg_t *sensor;
    phydat_t measurement;

    /* Find first sensor */
    sensor = bpf_saul_reg_find_nth(1);

    if (!sensor ||
        (bpf_saul_reg_read(sensor,
                           &measurement) < 0)) {
        return -(5 << 5);
    }

    /* Coap Packet */
    bpf_gcoap_resp_init(gcoap,
            COAP_CODE_CONTENT);
    bpf_coap_add_format(gcoap, 0);
    ssize_t pdu_len = bpf_coap_opt_finish(gcoap,
            COAP_OPT_FINISH_PAYLOAD);
    uint8_t *payload = bpf_coap_get_pdu(gcoap);

    pdu_len += bpf_fmt_s16_dfp((char*)payload,
                               measurement.val[0],
                               measurement.scale);
    return pdu_len;
}
