/*
 *
 * Copyright (c) 2016 Cisco Systems, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 *   Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following
 *   disclaimer in the documentation and/or other materials provided
 *   with the distribution.
 *
 *   Neither the name of the Cisco Systems, Inc. nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/*
 * ike.c
 *
 * Internet Key Exchange (IKE) awareness for joy
 *
 */
#include <stdio.h>      /* for fprintf()           */
#include <stdlib.h>     /* for malloc, realloc, free */
#include <stdint.h>     /* for uint32_t            */

#ifdef WIN32
# include "Ws2tcpip.h"
# define strtok_r strtok_s
#else
# include <arpa/inet.h>  /* for ntohl()             */
#endif

#include "ike.h"
#include "utils.h"      /* for enum role */
#include "p2f.h"        /* for zprintf_ ...        */
#include "err.h"        /* for logging             */


//      IKEv2 Payload Types
#define NO_NEXT_PAYLOAD 0
//      RESERVED                                1 - 32
#define SECURITY_ASSOCIATION_V2                 33
#define KEY_EXCHANGE_V2                         34
#define IDENTIFICATION_INITIATOR_V2             35
#define IDENTIFICATION_RESPONDER_V2             36
#define CERTIFICATE_V2                          37
#define CERTIFICATE_REQUEST_V2                  38
#define AUTHENTICATION_V2                       39
#define NONCE_V2                                40
#define NOTIFY_V2                               41
#define DELETE_V2                               42
#define VENDOR_ID_V2                            43
#define TRAFFIC_SELECTOR_INITIATOR_V2           44
#define TRAFFIC_SELECTOR_RESPONDER_V2           45
#define ENCRYPTED_V2                            46
#define CONFIGURATION_V2                        47
#define EXTENSIBLE_AUTHENTICATION_V2            48
#define GENERIC_SECURE_PASSWORD_METHOD_V2       49
#define GROUP_IDENTIFICATION_V2                 50
#define GROUP_SECURITY_ASSOCIATION_V2           51
#define KEY_DOWNLOAD_V2                         52
#define ENCRYPTED_AND_AUTHENTICATED_FRAGMENT_V2 53
//      RESERVED TO IANA                        54 - 127
//      PRIVATE USE                             128 - 255

/*
 * A vector is contains a pointer to a string of bytes of a specified length.
 */
struct vector {
    unsigned int len;
    char *bytes;
};

/*
 *
 * \brief Initialize the memory of vector struct.
 *
 * \param vector_handle Contains vector structure to initialize.
 *
 */
static void vector_init(struct vector **vector_handle) {
    *vector_handle = malloc(sizeof(struct vector));
    if (*vector_handle == NULL) {
        /* Allocation failed */
        joy_log_err("malloc failed");
        return;
    }
    memset(*vector_handle, 0, sizeof(struct vector));
}

/*
 *
 * \brief Delete the memory of vector struct.
 *
 * \param vector_handle Contains vector structure to delete.
 *
 */
static void vector_delete(struct vector **vector_handle) {
    struct vector *vector = *vector_handle;

    if (vector->bytes != NULL) {
        free(vector->bytes);
    }

    free(vector_handle);
}

/*
 *
 * \brief Set the vector contents to the specified data, freeing the previous
 * vector contents. If the previous vector contents overlap in memory with the
 * new vector contents, the behavior is still defined since the free occurs
 * after the copy.
 *
 * \param vector Pointer to the vector to be set.
 * \param data Pointer to byte array to be copied.
 * \param len Length of the byte array to be copied.
 *
 */
static void vector_set(struct vector *vector,
                       const char *data,
                       unsigned int len) {
    char *tmpptr = NULL;

    tmpptr = malloc(len);
    if (tmpptr == NULL) {
        joy_log_err("malloc failed");
        return;
    }
    memcpy(tmpptr, data, len);
    if (vector->bytes != NULL) {
        free(vector->bytes);
    }
    vector->bytes = tmpptr;
    vector->len = len;
}

/*
 *
 * \brief Append the specified data to the current vector contents, even if the
 * vector is currently empty.
 *
 * \param vector Pointer to the vector to be appended to.
 * \param data Pointer to byte array to be appended.
 * \param len Length of the byte array to be appended.
 *
 */
static void vector_append(struct vector *vector,
                          const char *data,
                          unsigned int len) {

    vector->bytes = realloc(vector->bytes, vector->len + len);
    if (vector->bytes == NULL) {
        return;
    }
    memcpy(vector->bytes + vector->len, data, len);
    vector->len += len;
}

struct ike_attribute {
    uint16_t type;
    struct vector *value;
};

static unsigned int ike_attribute_unmarshal(struct ike_attribute *s, const char *x, unsigned int len) {
    unsigned int offset = 0;
    unsigned int length;

	if (len < 4) {
		return 0;
	}

    s->type = (uint16_t)x[offset] << 8 | (uint16_t)x[offset+1]; offset+=2;
    vector_init(&s->value);

    if (s->type >> 15 == 0) {
        // TLV format
        length = (uint16_t)x[offset] << 8 | (uint16_t)x[offset+1]; offset+=2;
        if (length > len-offset) {
            return 0;
        }
        vector_set(s->value, x+offset, length); offset+=length;
    } else {
        // TV format
        if (2 > len-offset) {
            return 0;
        }
        vector_set(s->value, x+offset, 2); offset+=2;
    }

    return offset;
}

struct ike_transform {
    uint8_t num;
    uint8_t last; // 3 if more, 0 if last
    uint8_t reserved1;
    uint16_t length;
    uint8_t type;
    uint8_t reserved2;
    uint16_t id;
    uint8_t id_v1; // IKEv1 only
    struct ike_attribute *attributes[IKE_MAX_ATTRIBUTES];
    unsigned int num_attributes;
};

static unsigned int ike_v1_transform_unmarshal(struct ike_transform *s, const char *x, unsigned int len) {
    return 0; // TODO
}

static unsigned int ike_transform_unmarshal(struct ike_transform *s, const char *x, unsigned int len) {
    unsigned int offset = 0;
    unsigned int length;

    if (len < 8) {
        return 0;
    }

    s->last = x[offset]; offset++;
    s->reserved1 = x[offset]; offset++;
    s->length = (uint16_t)x[offset] << 8 | (uint16_t)x[offset+1]; offset+=2;
    s->type = x[offset]; offset++;
    s->reserved2 = x[offset]; offset++;
    s->id = (uint16_t)x[offset] << 8 | (uint16_t)x[offset+1]; offset+=2;

    if (s->length > len) {
        return 0;
    }

    /* parse attributes */
    s->num_attributes = 0;
    while(offset < s->length && s->num_attributes < IKE_MAX_ATTRIBUTES) {
        s->attributes[s->num_attributes] = malloc(sizeof(struct ike_attribute));
        if (s->attributes[s->num_attributes] == NULL) {
            return 0;
        }

        length = ike_attribute_unmarshal(s->attributes[s->num_attributes], x+offset, len-offset);
        if (length == 0) {
            return 0;
        }

        offset += length;
        s->num_attributes++;
    }

    /* check that the length matches exactly */
    if (offset != s->length) {
        return 0;
    }

    return offset;
}

struct ike_proposal {
    uint8_t last;
    uint8_t reserved;
    uint16_t length;
    uint8_t num;
    uint8_t protocol_id;
    struct vector *spi;
    uint8_t num_transforms;
    struct ike_transform *transforms[IKE_MAX_TRANSFORMS];
};

static unsigned int ike_proposal_unmarshal(struct ike_proposal *s, const char *x, unsigned int len) {
    unsigned int offset = 0;
    unsigned int length;
    unsigned int spi_size;
    unsigned int num_transforms;
    unsigned int last_transform;

    if (len < 8) {
        return 0;
    }

    s->last = x[offset]; offset++;
    s->reserved = x[offset]; offset++;
    s->length = (uint16_t)x[offset] << 8 | (uint16_t)x[offset+1]; offset+=2;
    s->num = x[offset]; offset++;
    s->protocol_id = x[offset]; offset++;
    spi_size = x[offset]; offset++;
    num_transforms = x[offset]; offset++;

    if (s->length > len) {
        return 0;
    }

    /* parse spi */
    if (spi_size > len-offset) {
        return 0;
    }
    vector_init(&s->spi);
    vector_set(s->spi, x+offset, spi_size);
    offset += spi_size;

    if (num_transforms > IKE_MAX_TRANSFORMS) {
        return 0;
    }
    
    /* parse transforms */
    s->num_transforms = 0;
    last_transform = 3;
    while(offset < len && s->num_transforms < num_transforms && last_transform == 3) {
        s->transforms[s->num_transforms] = malloc(sizeof(struct ike_transform));
        if (s->transforms[s->num_transforms] == NULL) {
            joy_log_err("malloc failed");
            return 0;
        }

        length = ike_transform_unmarshal(s->transforms[s->num_transforms], x+offset, len-offset);
        if (length == 0) {
            return 0;
        }

        offset += length;
        s->num_transforms++;
        last_transform = s->transforms[s->num_transforms]->last;
    }

    if (s->num_transforms != num_transforms || offset != s->length) {
        return 0;
    }
    
    return offset;
}

struct ike_sa {
    uint32_t doi_v1;
    struct vector *situation_v1;
    unsigned int num_proposals;
	struct ike_proposal *proposals[IKE_MAX_PROPOSALS];
};

static unsigned int ike_sa_unmarshal(struct ike_sa *s, const char *x, unsigned int len) {
    unsigned int offset = 0;
    unsigned int length;
    unsigned int last_proposal;

    /* parse proposals */
    s->num_proposals = 0;
    last_proposal = 2;
    while(offset < len && s->num_proposals < IKE_MAX_PROPOSALS && last_proposal == 2) {
        s->proposals[s->num_proposals] = malloc(sizeof(struct ike_proposal));
        if (s->proposals[s->num_proposals] == NULL) {
            joy_log_err("malloc failed");
            return 0;
        }

        length = ike_proposal_unmarshal(s->proposals[s->num_proposals], x+offset, len-offset);
        if (length == 0) {
            return 0;
        }

        offset += length;
        s->num_proposals++;
        last_proposal = s->proposals[s->num_proposals]->last;

        /* the proposal num starts at one and increments for each proposal */
        if (s->proposals[s->num_proposals]->num != s->num_proposals) {
            return 0;
        }
    }

    return offset;
}

static unsigned int ike_payload_unmarshal(struct ike_payload *s, const char *x, unsigned int len) {
    unsigned int offset = 0;

    if (s == NULL || x == NULL) {
        return 0;
    }

    /* parse generic payload header */
    s->next_payload = x[offset]; offset++;
    s->reserved = x[offset]; offset++;
    s->length = (uint16_t)x[offset] << 8 | (uint16_t)x[offset+1]; offset+=2;

    if (s->length >= len) {
        return 0;
    }

    /* parse payload body */
    // TODO: use a union for the payload body (?)
    switch(s->type) {
        case SECURITY_ASSOCIATION_V2:
            break;
        default:
            break;
    }
    offset += s->length;

    return offset;

}

static unsigned int ike_hdr_unmarshal(struct ike_hdr *s, const char *x, unsigned int len) {
    unsigned int offset = 0;

    if (s == NULL || x == NULL) {
        return 0;
    }

    if (len < sizeof(struct ike_hdr)) {
        return 0;
    }
    memcpy(s->init_spi, x+offset, 8); offset += 8;
    memcpy(s->resp_spi, x+offset, 8); offset += 8;
    s->next_payload = x[offset]; offset++;
    s->major = x[offset]; offset++;
    s->minor = x[offset]; offset++;
    s->exchange_type = x[offset]; offset++;
    s->flags = x[offset]; offset++;
    s->message_id = (uint32_t)x[offset] << 24 |
        (uint32_t)x[offset+1] << 16 |
        (uint32_t)x[offset+2] << 8 |
        (uint32_t)x[offset+3]; offset += 4;
    s->length = (uint32_t)x[offset] << 24 |
        (uint32_t)x[offset+1] << 16 |
        (uint32_t)x[offset+2] << 8 |
        (uint32_t)x[offset+3]; offset += 4;

    return offset;
}


static unsigned int ike_msg_unmarshal(struct ike_msg *s, const char *x, unsigned int len) {
    unsigned int offset = 0;
    unsigned int length;
    uint8_t next_payload;

    if (s == NULL || x == NULL) {
        return 0;
    }

    /* parse header */
    s->hdr = malloc(sizeof(struct ike_hdr));
    if (s->hdr == NULL) {
        return 0;
    }

    length = ike_hdr_unmarshal(s->hdr, x+offset, len-offset);
    if (length == 0) {
        return 0;
    }

    if (s->hdr->length >= IKE_MAX_MESSAGE_LEN) {
        return 0;
    }

    offset += length;

    /* parse payloads */
    next_payload = s->hdr->next_payload;
    s->num_payloads = 0;
    while(offset < s->hdr->length && s->num_payloads < IKE_MAX_PAYLOADS && next_payload != NO_NEXT_PAYLOAD) {
        s->payloads[s->num_payloads] = malloc(sizeof(struct ike_payload));
        if (s->payloads[s->num_payloads] == NULL) {
            return 0;
        }

        s->payloads[s->num_payloads]->type = next_payload;
        length = ike_payload_unmarshal(s->payloads[s->num_payloads], x+offset, len-offset);
        if (length == 0) {
            return 0;
        }

        offset += length;
        next_payload = s->payloads[s->num_payloads]->next_payload;
        s->num_payloads++;
    }

    /* check that the length matches exactly */
    if (offset != s->hdr->length) {
        return 0;
    }

    return offset;
}

/*
 * start of ike feature functions
 */

inline void ike_init(struct ike **ike_handle) {

    if (*ike_handle != NULL) {
        ike_delete(ike_handle);
    }

    *ike_handle = malloc(sizeof(struct ike));
    if (*ike_handle == NULL) {
        /* Allocation failed */
        joy_log_err("malloc failed");
        return;
    }
    memset(*ike_handle, 0, sizeof(struct ike));
}

void ike_update(struct ike *ike,
        const struct pcap_pkthdr *header,
        const void *data,
        unsigned int len,
        unsigned int report_ike) {
    unsigned int length;
    const char *data_ptr = (const char *)data;

    // TODO: check if this is port 4500, and if so check that the first four bytes are zero and skip them (non-ESP indication).

    if (len == 0) {
    return;        /* skip zero-length messages */
    }


    if (report_ike) {

    while (len > 0 && ike->num_ike_msgs < IKE_MAX_MESSAGES) { /* parse all messages in the buffer */
        ike->ike_msgs[ike->num_ike_msgs] = malloc(sizeof(struct ike_msg));
        if (ike->ike_msgs[ike->num_ike_msgs] == NULL) {
            return;
        }

        length = ike_msg_unmarshal(ike->ike_msgs[ike->num_ike_msgs], data_ptr, len);
        if (length == 0) {
            /* unable to parse message */
            break;
        }

        /* skip to the next message in the buffer */
        len -= length;
        data_ptr += length;
        ike->num_ike_msgs++;
    }

    } /* report_ike */
}

void ike_print_json(const struct ike *x1,
                    const struct ike *x2,
                    zfile f) {
}

void ike_delete(struct ike **ike_handle) {
}

void ike_unit_test() {
    int num_fails = 0;

    fprintf(info, "\n******************************\n");
    fprintf(info, "IKE Unit Test starting...\n");

    if (num_fails) {
        fprintf(info, "Finished - # of failures: %d\n", num_fails);
    } else {
        fprintf(info, "Finished - success\n");
    }
    fprintf(info, "******************************\n\n");
}
