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

// IKEv1 Payload Types
#define SECURITY_ASSOCIATION_V1             1
#define PROPOSAL_V1                         2
#define TRANSFORM_V1                        3
#define KEY_EXCHANGE_V1                     4
#define IDENTIFICATION_V1                   5
#define CERTIFICATE_V1                      6
#define CERTIFICATE_REQUEST_V1              7
#define HASH_V1                             8
#define SIGNATURE_V1                        9
#define NONCE_V1                            10
#define NOTIFICATION_V1                     11
#define DELETE_V1                           12
#define VENDOR_ID_V1                        13
//  RESERVED                                           14
#define SA_KEK_PAYLOAD_V1                   15
#define SA_TEK_PAYLOAD_V1                   16
#define KEY_DOWNLOAD_V1                     17
#define SEQUENCE_NUMBER_V1                  18
#define PROOF_OF_POSSESSION_V1              19
#define NAT_DISCOVERY_V1                    20
#define NAT_ORIGINAL_ADDRESS_V1             21
#define GROUP_ASSOCIATED_POLICY_V1          22
//  UNASSIGNED                              23 - 127
//  RESERVED FOR PRIVATE USE                128 - 255

// IKEv2 Payload Types
#define NO_NEXT_PAYLOAD 0
// RESERVED                             1 - 32
#define SECURITY_ASSOCIATION                 33
#define KEY_EXCHANGE                         34
#define IDENTIFICATION_INITIATOR             35
#define IDENTIFICATION_RESPONDER             36
#define CERTIFICATE                          37
#define CERTIFICATE_REQUEST                  38
#define AUTHENTICATION                       39
#define NONCE                                40
#define NOTIFY                               41
#define DELETE                               42
#define VENDOR_ID                            43
#define TRAFFIC_SELECTOR_INITIATOR           44
#define TRAFFIC_SELECTOR_RESPONDER           45
#define ENCRYPTED                            46
#define CONFIGURATION                        47
#define EXTENSIBLE_AUTHENTICATION            48
#define GENERIC_SECURE_PASSWORD_METHOD       49
#define GROUP_IDENTIFICATION                 50
#define GROUP_SECURITY_ASSOCIATION           51
#define KEY_DOWNLOAD                         52
#define ENCRYPTED_AND_AUTHENTICATED_FRAGMENT 53
// RESERVED TO IANA                     54 - 127
// PRIVATE USE                          128 - 255

// ISAKMP Domain of Interpretation (DOI)
#define ISAKMP_V1  0
#define IPSEC_V1   1
#define GDOI_V1    2

/*
 * A vector is contains a pointer to a string of bytes of a specified length.
 */
struct vector {
    unsigned int len;
    unsigned char *bytes;
};

/*
 *
 * \brief Delete the memory of vector struct.
 *
 * \param vector_handle Contains vector structure to delete.
 *
 */
static void vector_delete(struct vector **vector_handle) {
    struct vector *vector = *vector_handle;

    if (vector == NULL) {
        return;
    }
    if (vector->bytes != NULL) {
        free(vector->bytes);
    }

    free(vector);
    *vector_handle = NULL;
}

/*
 *
 * \brief Initialize the memory of vector struct.
 *
 * \param vector_handle Contains vector structure to initialize.
 *
 */
static void vector_init(struct vector **vector_handle) {

    if (*vector_handle != NULL) {
        vector_delete(vector_handle);
    }

    *vector_handle = calloc(1, sizeof(struct vector));
    if (*vector_handle == NULL) {
        /* Allocation failed */
        joy_log_err("malloc failed");
        return;
    }
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
    unsigned char *tmpptr = NULL;

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

struct ike_attribute {
    uint16_t type;
    struct vector *value;
};

static void ike_attribute_print_json(struct ike_attribute *s, zfile f) {
    zprintf(f, "{");
    zprintf(f, "\"%u\":", s->type);
    zprintf_raw_as_hex(f, s->value->bytes, s->value->len);
    zprintf(f, "}");
}

static void ike_attribute_delete(struct ike_attribute **s_handle) {
    struct ike_attribute *s = *s_handle;

    if (s == NULL) {
        return;
    }
    vector_delete(&s->value);

    free(s);
    *s_handle = NULL;
}

static void ike_attribute_init(struct ike_attribute **s_handle) {
    
    if (*s_handle != NULL) {
        ike_attribute_delete(s_handle);
    }

    *s_handle = calloc(1, sizeof(struct ike_attribute));
    if (*s_handle == NULL) {
        joy_log_err("malloc failed");
        return;
    }
}

static unsigned int ike_attribute_unmarshal(struct ike_attribute *s, const char *x, unsigned int len) {
    unsigned int offset = 0;
    unsigned int length;

	if (len < 4) {
        joy_log_err("len %u < 4", len);
		return 0;
	}

    s->type = (uint16_t)(x[offset]&0xff) << 8 | (uint16_t)(x[offset+1]&0xff); offset+=2;
    vector_init(&s->value);

    if (s->type >> 15 == 0) {
        // TLV format
        length = (uint16_t)(x[offset]&0xff) << 8 | (uint16_t)(x[offset+1]&0xff); offset+=2;
        if (length > len-offset) {
            joy_log_err("length %u > len-offset %u", length, len-offset)
            return 0;
        }
        vector_set(s->value, x+offset, length); offset+=length;
    } else {
        // TV format
        if (len-offset < 2) {
            joy_log_err("len-offset %u < 2", len-offset);
            return 0;
        }
        vector_set(s->value, x+offset, 2); offset+=2;
    }

    return offset;
}

struct ike_transform {
    uint8_t last; // 3 if more, 0 if last
    uint16_t length;
    uint8_t type;
    uint16_t id;
    uint8_t id_v1;
    uint8_t num_v1;
    unsigned int num_attributes;
    struct ike_attribute *attributes[IKE_MAX_ATTRIBUTES];
};

static void ike_transform_print_json(struct ike_transform *s, zfile f) {
    int i;

    zprintf(f, "{");
    zprintf(f, "\"type\":\"%u\",", s->type);
    zprintf(f, "\"id\":\"%u\"", s->id);
    for (i = 0; i < s->num_attributes; i++) {
        if (i == 0) {
            zprintf(f, ",\"attributes\":[");
        } else {
            zprintf(f, ",");
        }
        ike_attribute_print_json(s->attributes[i], f);
        if (i == s->num_attributes-1) {
            zprintf(f, "]");
        }
    }
    zprintf(f, "}");
}

static void ike_transform_v1_print_json(struct ike_transform *s, zfile f) {
    int i;

    zprintf(f, "{");
    zprintf(f, "\"id\":\"%u\"", s->id_v1);
    zprintf(f, ",\"num\":\"%u\"", s->num_v1);
    for (i = 0; i < s->num_attributes; i++) {
        if (i == 0) {
            zprintf(f, ",\"attributes\":[");
        } else {
            zprintf(f, ",");
        }
        ike_attribute_print_json(s->attributes[i], f);
        if (i == s->num_attributes-1) {
            zprintf(f, "]");
        }
    }
    zprintf(f, "}");
}

static void ike_transform_delete(struct ike_transform **s_handle) {
    struct ike_transform *s = *s_handle;
    int i;

    if (s == NULL) {
        return;
    }
    for (i = 0; i < s->num_attributes; i++) {
        ike_attribute_delete(&s->attributes[i]);
    }

    free(s);
    *s_handle = NULL;
}

static void ike_transform_init(struct ike_transform **s_handle) {

    if (*s_handle != NULL) {
        ike_transform_delete(s_handle);
    }

    *s_handle = calloc(1, sizeof(struct ike_transform));
    if (*s_handle == NULL) {
        joy_log_err("malloc failed");
        return;
    }
}

static unsigned int ike_transform_unmarshal(struct ike_transform *s, const char *x, unsigned int len) {
    unsigned int offset = 0;
    unsigned int length;

    if (len < 8) {
        joy_log_err("len %u < 8", len);
        return 0;
    }

    s->last = x[offset]; offset++;
    offset++; /* reserved */
    s->length = (uint16_t)(x[offset]&0xff) << 8 | (uint16_t)(x[offset+1]&0xff); offset+=2;
    s->type = x[offset]; offset++;
    offset++; /* reserved */
    s->id = (uint16_t)(x[offset]&0xff) << 8 | (uint16_t)(x[offset+1]&0xff); offset+=2;

    if (s->length > len) {
        joy_log_err("s->length %u > len %u", s->length, len);
        return 0;
    }

    /* parse attributes */
    s->num_attributes = 0;
    while(offset < s->length && s->num_attributes < IKE_MAX_ATTRIBUTES) {
        ike_attribute_init(&s->attributes[s->num_attributes]);
        length = ike_attribute_unmarshal(s->attributes[s->num_attributes], x+offset, len-offset);
        if (length == 0) {
            joy_log_err("unable to unmarshal attribute");
            return 0;
        }

        offset += length;
        s->num_attributes++;
    }

    /* check that the length matches exactly */
    if (offset != s->length) {
        joy_log_err("offset %u != s->length %u", offset, s->length)
        return 0;
    }

    return offset;
}

static unsigned int ike_transform_v1_unmarshal(struct ike_transform *s, const char *x, unsigned int len) {
    unsigned int offset = 0;
    unsigned int length;

    if (len < 8) {
        joy_log_err("len %u < 8", len);
        return 0;
    }

    s->last = x[offset]; offset++;
    offset++; /* reserved */
    s->length = (uint16_t)(x[offset]&0xff) << 8 | (uint16_t)(x[offset+1]&0xff); offset+=2;
    s->num_v1 = x[offset]; offset++;
    s->id_v1 = x[offset]; offset++;
    offset+=2; /* reserved */

    if (s->length > len) {
        joy_log_err("s->length %u > len %u", s->length, len);
        return 0;
    }

    /* parse attributes */
    s->num_attributes = 0;
    while(offset < s->length && s->num_attributes < IKE_MAX_ATTRIBUTES) {
        ike_attribute_init(&s->attributes[s->num_attributes]);
        length = ike_attribute_unmarshal(s->attributes[s->num_attributes], x+offset, len-offset);
        if (length == 0) {
            joy_log_err("unable to unmarshal attribute");
            return 0;
        }

        offset += length;
        s->num_attributes++;
    }

    /* check that the length matches exactly */
    if (offset != s->length) {
        joy_log_err("offset %u != s->length %u", offset, s->length)
        return 0;
    }

    return offset;
}

struct ike_proposal {
    uint8_t last;
    uint16_t length;
    uint8_t num;
    uint8_t protocol_id;
    struct vector *spi;
    uint8_t num_transforms;
    struct ike_transform *transforms[IKE_MAX_TRANSFORMS];
};

static void ike_proposal_print_json(struct ike_proposal *s, zfile f) {
    int i;

    zprintf(f, "{");
    zprintf(f, "\"num\":%u", s->num);
    zprintf(f, ",\"protocol_id\":%u", s->protocol_id);
    zprintf(f, ",\"spi\":");
    zprintf_raw_as_hex(f, s->spi->bytes, s->spi->len);
    if (s->num_transforms > 0) {
        zprintf(f, ",\"transforms\":[");
        for (i = 0; i < s->num_transforms; i++) {
            if (i > 0) {
                zprintf(f, ",");
            }
            ike_transform_print_json(s->transforms[i], f);
        }
        zprintf(f, "]");
    }
    zprintf(f, "}");
}

static void ike_proposal_v1_print_json(struct ike_proposal *s, zfile f) {
    int i;

    zprintf(f, "{");
    zprintf(f, "\"num\":%u", s->num);
    zprintf(f, ",\"protocol_id\":%u", s->protocol_id);
    zprintf(f, ",\"spi\":");
    zprintf_raw_as_hex(f, s->spi->bytes, s->spi->len);
    if (s->num_transforms > 0) {
        zprintf(f, ",\"transforms\":[");
        for (i = 0; i < s->num_transforms; i++) {
            if (i > 0) {
                zprintf(f, ",");
            }
            ike_transform_v1_print_json(s->transforms[i], f);
        }
        zprintf(f, "]");
    }
    zprintf(f, "}");
}

static void ike_proposal_delete(struct ike_proposal **s_handle) {
    struct ike_proposal *s = *s_handle;
    int i;

    if (s == NULL) {
        return;
    }
    vector_delete(&s->spi);
    for (i = 0; i < s->num_transforms; i++) {
        ike_transform_delete(&s->transforms[i]);
    }
    
    free(s);
    *s_handle = NULL;
}

static void ike_proposal_init(struct ike_proposal **s_handle) {

    if (*s_handle != NULL) {
        ike_proposal_delete(s_handle);
    }

    *s_handle = calloc(1, sizeof(struct ike_proposal));
    if (*s_handle == NULL) {
        joy_log_err("malloc failed");
        return;
    }
}

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
    offset++; /* reserved */
    s->length = (uint16_t)(x[offset]&0xff) << 8 | (uint16_t)(x[offset+1]&0xff); offset+=2;
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
        ike_transform_init(&s->transforms[s->num_transforms]);
        length = ike_transform_unmarshal(s->transforms[s->num_transforms], x+offset, len-offset);
        if (length == 0) {
            return 0;
        }

        offset += length;
        last_transform = s->transforms[s->num_transforms]->last;
        s->num_transforms++;
    }

    if (s->num_transforms != num_transforms || offset != s->length) {
        return 0;
    }
    
    return offset;
}

static unsigned int ike_proposal_v1_unmarshal(struct ike_proposal *s, const char *x, unsigned int len) {
    unsigned int offset = 0;
    unsigned int length;
    unsigned int spi_size;
    unsigned int num_transforms;
    unsigned int last_transform;

    if (len < 8) {
        joy_log_err("len %u < 8", len);
        return 0;
    }

    s->last = x[offset]; offset++;
    offset++; /* reserved */
    s->length = (uint16_t)(x[offset]&0xff) << 8 | (uint16_t)(x[offset+1]&0xff); offset+=2;
    s->num = x[offset]; offset++;
    s->protocol_id = x[offset]; offset++;
    spi_size = x[offset]; offset++;
    num_transforms = x[offset]; offset++;

    if (s->length > len) {
        joy_log_err("s->length %u > len %u", s->length, len);
        return 0;
    }

    /* parse spi */
    if (spi_size > len-offset) {
        joy_log_err("spi_size %u > len-offset %u", spi_size, len-offset);
        return 0;
    }
    vector_init(&s->spi);
    vector_set(s->spi, x+offset, spi_size);
    offset += spi_size;

    if (num_transforms > IKE_MAX_TRANSFORMS) {
        joy_log_err("num_transforms %u > IKE_MAX_TRANSFORMS %u", num_transforms, IKE_MAX_TRANSFORMS);
        return 0;
    }
    
    /* parse transforms */
    s->num_transforms = 0;
    last_transform = 3;
    while(offset < len && s->num_transforms < num_transforms && last_transform == 3) {
        ike_transform_init(&s->transforms[s->num_transforms]);
        length = ike_transform_v1_unmarshal(s->transforms[s->num_transforms], x+offset, len-offset);
        if (length == 0) {
            joy_log_err("unable to unmarshal transform");
            return 0;
        }

        offset += length;
        last_transform = s->transforms[s->num_transforms]->last;
        s->num_transforms++;
    }

    if (s->num_transforms != num_transforms) {
        joy_log_err("s->num_transforms %u != num_transforms %u", s->num_transforms, num_transforms);
        return 0;
    }
    if (offset != s->length) {
        joy_log_err("offset %u != s->length %u", offset, s->length);
        return 0;
    }
    
    return offset;
}

struct ike_sa {
    uint32_t doi_v1;
    uint32_t situation_v1;
    uint32_t ldi_v1;
    struct vector *secrecy_level_v1;
    struct vector *secrecy_category_v1;
    struct vector *integrity_level_v1;
    struct vector *integrity_category_v1;
    unsigned int num_proposals;
	struct ike_proposal *proposals[IKE_MAX_PROPOSALS];
};

static void ike_sa_print_json(struct ike_sa *s, zfile f) {
    int i;

    zprintf(f, "{");
    for(i = 0; i < s->num_proposals; i++) {
        if (i == 0) {
            zprintf(f, "\"proposals\":[");
        } else {
            zprintf(f, ",");
        }
        ike_proposal_print_json(s->proposals[i], f);
        if (i == s->num_proposals-1) {
            zprintf(f, "]");
        }
    }
    zprintf(f, "}");
}

static void ike_sa_v1_print_json(struct ike_sa *s, zfile f) {
    int i;

    zprintf(f, "{");
    zprintf(f, "\"doi\":%u", s->doi_v1);
    zprintf(f, ",\"situation\":%u", s->situation_v1);
    if (s->situation_v1 & (0x02 | 0x04)) {
        zprintf(f, ",\"ldi\":%u", s->ldi_v1);
    }
    if (s->situation_v1 & 0x02) {
        zprintf(f, ",\"secrecy_level\":");
        zprintf_raw_as_hex(f, s->secrecy_level_v1->bytes, s->secrecy_level_v1->len);
        zprintf(f, ",\"secrecy_category\":");
        zprintf_raw_as_hex(f, s->secrecy_category_v1->bytes, s->secrecy_category_v1->len);
    }
    if (s->situation_v1 & 0x04) {
        zprintf(f, ",\"integrity_level\":");
        zprintf_raw_as_hex(f, s->integrity_level_v1->bytes, s->integrity_level_v1->len);
        zprintf(f, ",\"integrity_category\":");
        zprintf_raw_as_hex(f, s->integrity_category_v1->bytes, s->integrity_category_v1->len);
    }

    for(i = 0; i < s->num_proposals; i++) {
        if (i == 0) {
            zprintf(f, ",\"proposals\":[");
        } else {
            zprintf(f, ",");
        }
        ike_proposal_v1_print_json(s->proposals[i], f);
        if (i == s->num_proposals-1) {
            zprintf(f, "]");
        }
    }
    zprintf(f, "}");
}

static void ike_sa_delete(struct ike_sa **s_handle) {
    struct ike_sa *s = *s_handle;
    int i;

    if (s == NULL) {
        return;
    }
    vector_delete(&s->secrecy_level_v1);
    vector_delete(&s->secrecy_category_v1);
    vector_delete(&s->integrity_level_v1);
    vector_delete(&s->integrity_category_v1);
    for (i = 0; i < s->num_proposals; i++) {
        ike_proposal_delete(&s->proposals[i]);
    }

    free(s);
    *s_handle = NULL;
}

static void ike_sa_init(struct ike_sa **s_handle) {

    if (*s_handle != NULL) {
        ike_sa_delete(s_handle);
    }

    *s_handle = calloc(1, sizeof(struct ike_sa));
    if (*s_handle == NULL) {
        joy_log_err("malloc failed");
        return;
    }
}

static unsigned int ike_sa_unmarshal(struct ike_sa *s, const char *x, unsigned int len) {
    unsigned int offset = 0;
    unsigned int length;
    unsigned int last_proposal;

    /* parse proposals */
    s->num_proposals = 0;
    last_proposal = 2;
    while(offset < len && s->num_proposals < IKE_MAX_PROPOSALS && last_proposal == 2) {
        ike_proposal_init(&s->proposals[s->num_proposals]);
        length = ike_proposal_unmarshal(s->proposals[s->num_proposals], x+offset, len-offset);
        if (length == 0) {
            return 0;
        }

        offset += length;
        last_proposal = s->proposals[s->num_proposals]->last;
        s->num_proposals++;
    }

    return offset;
}

static unsigned int ike_sa_v1_unmarshal(struct ike_sa *s, const char *x, unsigned int len) {
    unsigned int offset = 0;
    unsigned int length;
    unsigned int last_proposal;

    s->doi_v1 = (uint32_t)(x[offset]&0xff) << 24 |
        (uint32_t)(x[offset+1]&0xff) << 16 |
        (uint32_t)(x[offset+2]&0xff) << 8 |
        (uint32_t)(x[offset+3]&0xff); offset+=4;

    if (s->doi_v1 != IPSEC_V1) {
        joy_log_err("doi %u != IPSEC_V1 %u", s->doi_v1, IPSEC_V1);
        return 0;
    }

    s->situation_v1 = (uint32_t)(x[offset]&0xff) << 24 |
        (uint32_t)(x[offset+1]&0xff) << 16 |
        (uint32_t)(x[offset+2]&0xff) << 8 |
        (uint32_t)(x[offset+3]&0xff); offset+=4;

    /* SIT_IDENTITY_ONLY is required for IPSEC DOI implementations */ 
    if ( ! (s->situation_v1 & 0x01)) {
        joy_log_err("SIT_IDENTITY_ONLY bit not set");
        return 0;
    }

    /* Labeled Domain Information */
    if (s->situation_v1 & (0x02 | 0x04)) {
        s->ldi_v1 = (uint32_t)(x[offset]&0xff) << 24 |
            (uint32_t)(x[offset+1]&0xff) << 16 |
            (uint32_t)(x[offset+2]&0xff) << 8 |
            (uint32_t)(x[offset+3]&0xff); offset+=4;
    }
    
    /* SIT_SECRECY */
    if (s->situation_v1 & 0x02) {
        length = (uint16_t)(x[offset]&0xff) << 8 | (uint16_t)(x[offset+1]&0xff); offset+=2;
        offset += 2; /* reserved */
        vector_init(&s->secrecy_level_v1);
        vector_set(s->secrecy_level_v1, x+offset, length);
        offset += length;

        length = (uint16_t)(x[offset]&0xff) << 8 | (uint16_t)(x[offset+1]&0xff); offset+=2;
        offset += 2; /* reserved */
        vector_init(&s->secrecy_category_v1);
        vector_set(s->secrecy_category_v1, x+offset, (length+7)/8); /* length is in bits for bitmap */
    }

    /* SIT_INTEGRITY */
    if (s->situation_v1 & 0x04) {
        length = (uint16_t)(x[offset]&0xff) << 8 | (uint16_t)(x[offset+1]&0xff); offset+=2;
        offset += 2; /* reserved */
        vector_init(&s->integrity_level_v1);
        vector_set(s->integrity_level_v1, x+offset, length);
        offset += length;

        length = (uint16_t)(x[offset]&0xff) << 8 | (uint16_t)(x[offset+1]&0xff); offset+=2;
        offset += 2; /* reserved */
        vector_init(&s->integrity_category_v1);
        vector_set(s->integrity_category_v1, x+offset, (length+7)/8); /* length is in bits for bitmap */
    }

    /* parse proposals */
    s->num_proposals = 0;
    last_proposal = 2;
    while(offset < len && s->num_proposals < IKE_MAX_PROPOSALS && last_proposal == 2) {
        ike_proposal_init(&s->proposals[s->num_proposals]);
        length = ike_proposal_v1_unmarshal(s->proposals[s->num_proposals], x+offset, len-offset);
        if (length == 0) {
            joy_log_err("unable to parse proposal");
            return 0;
        }

        offset += length;
        last_proposal = s->proposals[s->num_proposals]->last;
        s->num_proposals++;
    }

    return offset;
}

struct ike_ke {
    uint16_t group;
    struct vector *data;
};

static void ike_ke_print_json(struct ike_ke *s, zfile f) {
    zprintf(f, "{");
    zprintf(f, "\"group\":%u", s->group);
    zprintf(f, ",\"data\":");
    zprintf_raw_as_hex(f, s->data->bytes, s->data->len);
    zprintf(f, "}");
}

static void ike_ke_v1_print_json(struct ike_ke *s, zfile f) {
    zprintf(f, "{");
    zprintf(f, "\"data\":");
    zprintf_raw_as_hex(f, s->data->bytes, s->data->len);
    zprintf(f, "}");
}

static void ike_ke_delete(struct ike_ke **s_handle) {
    struct ike_ke *s = *s_handle;

    if (s == NULL) {
        return;
    }
    vector_delete(&s->data);

    free(s);
    *s_handle = NULL;
}

static void ike_ke_init(struct ike_ke **s_handle) {

    if (*s_handle != NULL) {
        ike_ke_delete(s_handle);
    }

    *s_handle = calloc(1, sizeof(struct ike_ke));
    if (*s_handle == NULL) {
        joy_log_err("malloc failed");
        return;
    }
}

static unsigned int ike_ke_unmarshal(struct ike_ke *s, const char *x, unsigned int len) {
    unsigned int offset = 0;

    if (len < 4) {
        return 0;
    }

    s->group = (uint16_t)(x[offset]&0xff) << 8 | (uint16_t)(x[offset+1]&0xff); offset+=2;
    offset+=2; /* reserved */

    vector_init(&s->data);
    vector_set(s->data, x+offset, len-offset);
    offset += len-offset;

	return offset;
}

static unsigned int ike_ke_v1_unmarshal(struct ike_ke *s, const char *x, unsigned int len) {
    unsigned int offset = 0;

    vector_init(&s->data);
    vector_set(s->data, x+offset, len-offset);
    offset += len-offset;

	return offset;
}

struct ike_id {
    uint8_t type;
    struct vector *data;
};

static void ike_id_print_json(struct ike_id *s, zfile f) {

    zprintf(f, "{");
    zprintf(f, "\"type\":%u", s->type);
    zprintf(f, ",\"data\":");
    zprintf_raw_as_hex(f, s->data->bytes, s->data->len);
    zprintf(f, "}");
}

static void ike_id_delete(struct ike_id **s_handle) {
    struct ike_id *s = *s_handle;

    if (s == NULL) {
        return;
    }
    vector_delete(&s->data);

    free(s);
    *s_handle = NULL;
}

static void ike_id_init(struct ike_id **s_handle) {

    if (*s_handle != NULL) {
        ike_id_delete(s_handle);
    }

    *s_handle = calloc(1, sizeof(struct ike_id));
    if (*s_handle == NULL) {
        joy_log_err("malloc failed");
        return;
    }
}

static unsigned int ike_id_unmarshal(struct ike_id *s, const char *x, unsigned int len) {
    unsigned int offset = 0;

    if (len < 4) {
        return 0;
    }

    s->type = x[offset]; offset++;
    offset+=3; /* reserved */

    vector_init(&s->data);
    vector_set(s->data, x+offset, len-offset);
    offset += len-offset;

	return offset;
}

struct ike_cert {
    uint8_t encoding;
    struct vector *data;
};

static void ike_cert_print_json(struct ike_cert *s, zfile f) {

    zprintf(f, "{");
    zprintf(f, "\"encoding\":%u", s->encoding);
    zprintf(f, ",\"data\":");
    zprintf_raw_as_hex(f, s->data->bytes, s->data->len);
    zprintf(f, "}");
}

static void ike_cert_delete(struct ike_cert **s_handle) {
    struct ike_cert *s = *s_handle;

    if (s == NULL) {
        return;
    }
    vector_delete(&s->data);

    free(s);
    *s_handle = NULL;
}

static void ike_cert_init(struct ike_cert **s_handle) {

    if (*s_handle != NULL) {
        ike_cert_delete(s_handle);
    }

    *s_handle = calloc(1, sizeof(struct ike_cert));
    if (*s_handle == NULL) {
        joy_log_err("malloc failed");
        return;
    }
}

static unsigned int ike_cert_unmarshal(struct ike_cert *s, const char *x, unsigned int len) {
    unsigned int offset = 0;

    if (len < 1) {
        return 0;
    }

    s->encoding = x[offset]; offset++;

    vector_init(&s->data);
    vector_set(s->data, x+offset, len-offset);
    offset += len-offset;

	return offset;
}

struct ike_cr {
    uint8_t encoding;
    struct vector *data;
};

static void ike_cr_print_json(struct ike_cr *s, zfile f) {

    zprintf(f, "{");
    zprintf(f, "\"encoding\":%u", s->encoding);
    zprintf(f, ",\"data\":");
    zprintf_raw_as_hex(f, s->data->bytes, s->data->len);
    zprintf(f, "}");
}

static void ike_cr_delete(struct ike_cr **s_handle) {
    struct ike_cr *s = *s_handle;

    if (s == NULL) {
        return;
    }
    vector_delete(&s->data);

    free(s);
    *s_handle = NULL;
}

static void ike_cr_init(struct ike_cr **s_handle) {

    if (*s_handle != NULL) {
        ike_cr_delete(s_handle);
    }

    *s_handle = calloc(1, sizeof(struct ike_cr));
    if (*s_handle == NULL) {
        joy_log_err("malloc failed");
        return;
    }
}

static unsigned int ike_cr_unmarshal(struct ike_cr *s, const char *x, unsigned int len) {
    unsigned int offset = 0;

    if (len < 1) {
        return 0;
    }

    s->encoding = x[offset]; offset++;

    vector_init(&s->data);
    vector_set(s->data, x+offset, len-offset);
    offset += len-offset;

	return offset;
}

struct ike_auth {
    uint8_t method;
    struct vector *data;
};

static void ike_auth_print_json(struct ike_auth *s, zfile f) {

    zprintf(f, "{");
    zprintf(f, "\"method\":%u", s->method);
    zprintf(f, ",\"data\":");
    zprintf_raw_as_hex(f, s->data->bytes, s->data->len);
    zprintf(f, "}");
}

static void ike_auth_delete(struct ike_auth **s_handle) {
    struct ike_auth *s = *s_handle;

    if (s == NULL) {
        return;
    }
    vector_delete(&s->data);

    free(s);
    *s_handle = NULL;
}

static void ike_auth_init(struct ike_auth **s_handle) {

    if (*s_handle != NULL) {
        ike_auth_delete(s_handle);
    }

    *s_handle = calloc(1, sizeof(struct ike_auth));
    if (*s_handle == NULL) {
        joy_log_err("malloc failed");
        return;
    }
}

static unsigned int ike_auth_unmarshal(struct ike_auth *s, const char *x, unsigned int len) {
    unsigned int offset = 0;

    if (len < 4) {
        return 0;
    }

    s->method = x[offset]; offset++;
    offset+=3; /* reserved */

    vector_init(&s->data);
    vector_set(s->data, x+offset, len-offset);
    offset += len-offset;

	return offset;
}

struct ike_hash_v1 {
    struct vector *data;
};

static void ike_hash_v1_print_json(struct ike_hash_v1 *s, zfile f) {

    zprintf(f, "{");
    zprintf(f, "\"data\":");
    zprintf_raw_as_hex(f, s->data->bytes, s->data->len);
    zprintf(f, "}");
}

static void ike_hash_v1_delete(struct ike_hash_v1 **s_handle) {
    struct ike_hash_v1 *s = *s_handle;

    if (s == NULL) {
        return;
    }
    vector_delete(&s->data);

    free(s);
    *s_handle = NULL;
}

static void ike_hash_v1_init(struct ike_hash_v1 **s_handle) {

    if (*s_handle != NULL) {
        ike_hash_v1_delete(s_handle);
    }

    *s_handle = calloc(1, sizeof(struct ike_hash_v1));
    if (*s_handle == NULL) {
        joy_log_err("malloc failed");
        return;
    }
}

static unsigned int ike_hash_v1_unmarshal(struct ike_hash_v1 *s, const char *x, unsigned int len) {
    unsigned int offset = 0;

    vector_init(&s->data);
    vector_set(s->data, x+offset, len-offset);
    offset += len-offset;

	return offset;
}

struct ike_notify {
    uint32_t doi_v1;
    uint8_t protocol_id;
    uint16_t type;
    struct vector *spi;
    struct vector *data;
};

static void ike_notify_print_json(struct ike_notify *s, zfile f) {

    zprintf(f, "{");
    zprintf(f, "\"protocol_id\":%u", s->protocol_id);
    zprintf(f, ",\"type\":%u", s->type);
    zprintf(f, ",\"spi\":");
    zprintf_raw_as_hex(f, s->spi->bytes, s->spi->len);
    zprintf(f, ",\"data\":");
    zprintf_raw_as_hex(f, s->data->bytes, s->data->len);
    zprintf(f, "}");
}

static void ike_notify_v1_print_json(struct ike_notify *s, zfile f) {

    zprintf(f, "{");
    zprintf(f, "\"doi\":%u", s->doi_v1);
    zprintf(f, ",\"protocol_id\":%u", s->protocol_id);
    zprintf(f, ",\"type\":%u", s->type);
    zprintf(f, ",\"spi\":");
    zprintf_raw_as_hex(f, s->spi->bytes, s->spi->len);
    zprintf(f, ",\"data\":");
    zprintf_raw_as_hex(f, s->data->bytes, s->data->len);
    zprintf(f, "}");
}

static void ike_notify_delete(struct ike_notify **s_handle) {
    struct ike_notify *s = *s_handle;

    if (s == NULL) {
        return;
    }
    vector_delete(&s->spi);
    vector_delete(&s->data);

    free(s);
    *s_handle = NULL;
}

static void ike_notify_init(struct ike_notify **s_handle) {

    if (*s_handle != NULL) {
        ike_notify_delete(s_handle);
    }

    *s_handle = calloc(1, sizeof(struct ike_notify));
    if (*s_handle == NULL) {
        joy_log_err("malloc failed");
        return;
    }
}

static unsigned int ike_notify_unmarshal(struct ike_notify *s, const char *x, unsigned int len) {
    unsigned int offset = 0;
    unsigned int spi_size;

    if (len < 4) {
        return 0;
    }

    s->protocol_id = x[offset]; offset++;
    spi_size = x[offset]; offset++;
    s->type = (uint16_t)x[offset] << 8 | (uint16_t)x[offset+1]; offset+=2;

    if (spi_size > len-offset) {
        return 0;
    }

    vector_init(&s->spi);
    vector_set(s->spi, x+offset, spi_size);
    offset += spi_size;

    vector_init(&s->data);
    vector_set(s->data, x+offset, len-offset);
    offset += len-offset;

	return offset;
}

static unsigned int ike_notify_v1_unmarshal(struct ike_notify *s, const char *x, unsigned int len) {
    unsigned int offset = 0;
    unsigned int spi_size;

    if (len < 8) {
        joy_log_err("len %u < 8", len);
        return 0;
    }

    s->doi_v1 = (uint32_t)(x[offset]&0xff) << 24 |
        (uint32_t)(x[offset+1]&0xff) << 16 |
        (uint32_t)(x[offset+2]&0xff) << 8 |
        (uint32_t)(x[offset+3]&0xff); offset += 4;
    s->protocol_id = x[offset]; offset++;
    spi_size = x[offset]; offset++;
    s->type = (uint16_t)(x[offset]&0xff) << 8 | (uint16_t)(x[offset+1]&0xff); offset+=2;

    if (spi_size > len-offset) {
        joy_log_err("spi_size %u > len-offset %u", spi_size, len-offset);
        return 0;
    }

    vector_init(&s->spi);
    vector_set(s->spi, x+offset, spi_size);
    offset += spi_size;

    vector_init(&s->data);
    vector_set(s->data, x+offset, len-offset);
    offset += len-offset;

	return offset;
}

struct ike_nonce {
    struct vector *data;
};

static void ike_nonce_print_json(struct ike_nonce *s, zfile f) {

    zprintf(f, "{");
    zprintf(f, "\"data\":");
    zprintf_raw_as_hex(f, s->data->bytes, s->data->len);
    zprintf(f, "}");
}

static void ike_nonce_delete(struct ike_nonce **s_handle) {
    struct ike_nonce *s = *s_handle;

    if (s == NULL) {
        return;
    }
    vector_delete(&s->data);

    free(s);
    *s_handle = NULL;
}

static void ike_nonce_init(struct ike_nonce **s_handle) {

    if (*s_handle != NULL) {
        ike_nonce_delete(s_handle);
    }

    *s_handle = calloc(1, sizeof(struct ike_nonce));
    if (*s_handle == NULL) {
        joy_log_err("malloc failed");
        return;
    }
}

static unsigned int ike_nonce_unmarshal(struct ike_nonce *s, const char *x, unsigned int len) {
    unsigned int offset = 0;

    vector_init(&s->data);
    vector_set(s->data, x+offset, len-offset);
    offset += len-offset;

	return offset;
}

struct ike_vid {
    struct vector *data;
};

static void ike_vid_print_json(struct ike_vid *s, zfile f) {

    zprintf(f, "{");
    zprintf(f, "\"data\":");
    zprintf_raw_as_hex(f, s->data->bytes, s->data->len);
    zprintf(f, "}");
}

static void ike_vid_delete(struct ike_vid **s_handle) {
    struct ike_vid *s = *s_handle;

    if (s == NULL) {
        return;
    }
    vector_delete(&s->data);

    free(s);
    *s_handle = NULL;
}

static void ike_vid_init(struct ike_vid **s_handle) {

    if (*s_handle != NULL) {
        ike_vid_delete(s_handle);
    }

    *s_handle = calloc(1, sizeof(struct ike_vid));
    if (*s_handle == NULL) {
        joy_log_err("malloc failed");
        return;
    }
}

static unsigned int ike_vid_unmarshal(struct ike_vid *s, const char *x, unsigned int len) {
    unsigned int offset = 0;

    vector_init(&s->data);
    vector_set(s->data, x+offset, len-offset);
    offset += len-offset;

	return offset;
}

union ike_payload_body {
    struct ike_sa *sa;
    struct ike_ke *ke;
    struct ike_id *id;
    struct ike_cert *cert;
    struct ike_cr *cr;
    struct ike_auth *auth;
    struct ike_hash_v1 *hash_v1;
    struct ike_nonce *nonce;
    struct ike_notify *notify;
    struct ike_vid *vid;
};

struct ike_payload {
    uint8_t type;
    uint8_t next_payload;
    uint8_t reserved;
    uint16_t length;
    union ike_payload_body *body;
};

static void ike_payload_print_json(struct ike_payload *s, zfile f) {

    zprintf(f, "{");
    zprintf(f, "\"type\":%d", s->type);

    /* print payload body */
    zprintf(f, ",\"body\":[");
    switch(s->type) {
        case SECURITY_ASSOCIATION:
            ike_sa_print_json(s->body->sa, f);
            break;
        case SECURITY_ASSOCIATION_V1:
            ike_sa_v1_print_json(s->body->sa, f);
            break;
        case KEY_EXCHANGE:
            ike_ke_print_json(s->body->ke, f);
            break;
        case KEY_EXCHANGE_V1:
            ike_ke_v1_print_json(s->body->ke, f);
            break;
        case IDENTIFICATION_INITIATOR:
        case IDENTIFICATION_RESPONDER:
        case IDENTIFICATION_V1:
            ike_id_print_json(s->body->id, f);
            break;
        case CERTIFICATE:
        case CERTIFICATE_V1:
            ike_cert_print_json(s->body->cert, f);
            break;
        case CERTIFICATE_REQUEST:
        case CERTIFICATE_REQUEST_V1:
            ike_cr_print_json(s->body->cr, f);
            break;
        case AUTHENTICATION:
            ike_auth_print_json(s->body->auth, f);
            break;
        case HASH_V1:
            ike_hash_v1_print_json(s->body->hash_v1, f);
            break;
        case NONCE:
        case NONCE_V1:
            ike_nonce_print_json(s->body->nonce, f);
            break;
        case NOTIFY:
            ike_notify_print_json(s->body->notify, f);
            break;
        case NOTIFICATION_V1:
            ike_notify_v1_print_json(s->body->notify, f);
            break;
        case VENDOR_ID:
        case VENDOR_ID_V1:
            ike_vid_print_json(s->body->vid, f);
            break;
        default:
            break;
    }
    zprintf(f, "]");
    zprintf(f, "}");
}

static void ike_payload_delete(struct ike_payload **s_handle) {
    struct ike_payload *s = *s_handle;

    if (s == NULL) {
        return;
    }

    /* delete payload body */
    switch(s->type) {
        case SECURITY_ASSOCIATION:
        case SECURITY_ASSOCIATION_V1:
            ike_sa_delete(&s->body->sa);
            break;
        case KEY_EXCHANGE:
        case KEY_EXCHANGE_V1:
            ike_ke_delete(&s->body->ke);
            break;
        case IDENTIFICATION_INITIATOR:
        case IDENTIFICATION_RESPONDER:
        case IDENTIFICATION_V1:
            ike_id_delete(&s->body->id);
            break;
        case CERTIFICATE:
        case CERTIFICATE_V1:
            ike_cert_delete(&s->body->cert);
            break;
        case CERTIFICATE_REQUEST:
        case CERTIFICATE_REQUEST_V1:
            ike_cr_delete(&s->body->cr);
            break;
        case AUTHENTICATION:
            ike_auth_delete(&s->body->auth);
            break;
        case HASH_V1:
            ike_hash_v1_delete(&s->body->hash_v1);
            break;
        case NONCE:
        case NONCE_V1:
            ike_nonce_delete(&s->body->nonce);
            break;
        case NOTIFY:
        case NOTIFICATION_V1:
            ike_notify_delete(&s->body->notify);
            break;
        case VENDOR_ID:
        case VENDOR_ID_V1:
            ike_vid_delete(&s->body->vid);
            break;
        default:
            break;
    }

    free(s->body);
    free(s);
    *s_handle = NULL;
}

static void ike_payload_init(struct ike_payload **s_handle) {

    if (*s_handle != NULL) {
        ike_payload_delete(s_handle);
    }

    *s_handle = calloc(1, sizeof(struct ike_payload));
    if (*s_handle == NULL) {
        joy_log_err("malloc failed");
        return;
    }
    (*s_handle)->body = calloc(1, sizeof(union ike_payload_body));
    if ((*s_handle)->body == NULL) {
        joy_log_err("malloc failed");
        return;
    }
}


static unsigned int ike_payload_unmarshal(struct ike_payload *s, const char *x, unsigned int len) {
    unsigned int offset = 0;
    unsigned int length;

    /* parse generic payload header */
    s->next_payload = x[offset]; offset++;
    offset++; /* reserved */
    s->length = (uint16_t)(x[offset]&0xff) << 8 | (uint16_t)(x[offset+1]&0xff); offset+=2;

    if (s->length > len) {
        joy_log_err("s->length %u > len %u", s->length, len);
        return 0;
    }


    length = s->length-offset;

    /* parse payload body */
    switch(s->type) {
        case SECURITY_ASSOCIATION:
            ike_sa_init(&s->body->sa);
            length = ike_sa_unmarshal(s->body->sa, x+offset, length);
            break;
        case SECURITY_ASSOCIATION_V1:
            ike_sa_init(&s->body->sa);
            length = ike_sa_v1_unmarshal(s->body->sa, x+offset, length);
            break;
        case KEY_EXCHANGE:
            ike_ke_init(&s->body->ke);
            length = ike_ke_unmarshal(s->body->ke, x+offset, length);
            break;
        case KEY_EXCHANGE_V1:
            ike_ke_init(&s->body->ke);
            length = ike_ke_v1_unmarshal(s->body->ke, x+offset, length);
            break;
        case IDENTIFICATION_INITIATOR:
        case IDENTIFICATION_RESPONDER:
        case IDENTIFICATION_V1:
            ike_id_init(&s->body->id);
            length = ike_id_unmarshal(s->body->id, x+offset, length);
            break;
        case CERTIFICATE:
        case CERTIFICATE_V1:
            ike_cert_init(&s->body->cert);
            length = ike_cert_unmarshal(s->body->cert, x+offset, length);
            break;
        case CERTIFICATE_REQUEST:
        case CERTIFICATE_REQUEST_V1:
            ike_cr_init(&s->body->cr);
            length = ike_cr_unmarshal(s->body->cr, x+offset, length);
            break;
        case AUTHENTICATION:
            ike_auth_init(&s->body->auth);
            length = ike_auth_unmarshal(s->body->auth, x+offset, length);
            break;
        case HASH_V1:
            ike_hash_v1_init(&s->body->hash_v1);
            length = ike_hash_v1_unmarshal(s->body->hash_v1, x+offset, length);
            break;
        case NONCE:
        case NONCE_V1:
            ike_nonce_init(&s->body->nonce);
            length = ike_nonce_unmarshal(s->body->nonce, x+offset, length);
            break;
        case NOTIFY:
            ike_notify_init(&s->body->notify);
            length = ike_notify_unmarshal(s->body->notify, x+offset, length);
            break;
        case NOTIFICATION_V1:
            ike_notify_init(&s->body->notify);
            length = ike_notify_v1_unmarshal(s->body->notify, x+offset, length);
            break;
        case VENDOR_ID:
        case VENDOR_ID_V1:
            ike_vid_init(&s->body->vid);
            length = ike_vid_unmarshal(s->body->vid, x+offset, length);
            break;
        default:
            break;
    }

    /* the lengths must match exacctly */
    if (length != s->length-offset) {
        joy_log_err("length %u != length-offset %u", s->length, length-offset);
        return 0;
    }
    offset += length;

    return offset;
}

struct ike_header {
    uint8_t init_spi[8];
    uint8_t resp_spi[8];
    uint8_t next_payload;
    uint8_t major;
    uint8_t minor;
    uint8_t exchange_type;
    uint8_t flags;
    uint32_t message_id;
    uint32_t length;
};

static void ike_header_print_json(struct ike_header *s, zfile f) {

    zprintf(f, "{");
    zprintf(f, "\"init_spi\":");
    zprintf_raw_as_hex(f, s->init_spi, sizeof(s->init_spi));
    zprintf(f, ",\"resp_spi\":");
    zprintf_raw_as_hex(f, s->resp_spi, sizeof(s->resp_spi));
    zprintf(f, ",\"major\":%u", s->major);
    zprintf(f, ",\"minor\":%u", s->minor);
    zprintf(f, ",\"exchange_type\":%u", s->exchange_type);
    zprintf(f, ",\"flags\":%u", s->flags);
    zprintf(f, ",\"message_id\":%u", s->message_id);
    zprintf(f, "}");
}

static void ike_header_delete(struct ike_header **s_handle) {
    struct ike_header *s = *s_handle;

    if (s == NULL) {
        return;
    }

    free(s);
    *s_handle = NULL;
}

static void ike_header_init(struct ike_header **s_handle) {

    if (*s_handle != NULL) {
        ike_header_delete(s_handle);
    }

    *s_handle = calloc(1, sizeof(struct ike_header));
    if (*s_handle == NULL) {
        joy_log_err("malloc failed");
        return;
    }
}

static unsigned int ike_header_unmarshal(struct ike_header *s, const char *x, unsigned int len) {
    unsigned int offset = 0;

    if (s == NULL || x == NULL) {
        return 0;
    }

    if (len < sizeof(struct ike_header)) {
        return 0;
    }
    memcpy(s->init_spi, x+offset, 8); offset+=8;
    memcpy(s->resp_spi, x+offset, 8); offset+=8;
    s->next_payload = x[offset]; offset++;
    s->major = (x[offset] & 0xf0) >> 4; 
    s->minor = (x[offset] & 0x0f); offset++;
    s->exchange_type = x[offset]; offset++;
    s->flags = x[offset]; offset++;
    s->message_id = (uint32_t)(x[offset]&0xff) << 24 |
        (uint32_t)(x[offset+1]&0xff) << 16 |
        (uint32_t)(x[offset+2]&0xff) << 8 |
        (uint32_t)(x[offset+3]&0xff); offset += 4;
    s->length = (uint32_t)(x[offset]&0xff) << 24 |
        (uint32_t)(x[offset+1]&0xff) << 16 |
        (uint32_t)(x[offset+2]&0xff) << 8 |
        (uint32_t)(x[offset+3]&0xff); offset += 4;

    return offset;
}

struct ike_message {
    struct ike_header *header;
    unsigned int num_payloads;
    struct ike_payload *payloads[IKE_MAX_PAYLOADS];
};

static void ike_message_print_json(struct ike_message *s, zfile f) {
    int i;

    zprintf(f, "{");
    zprintf(f, "\"header\":");
    ike_header_print_json(s->header, f);
    for (i = 0; i < s->num_payloads; i++) {
        if (i == 0) {
            zprintf(f, ",\"payloads\":[");
        } else {
            zprintf(f, ",");
        }
        ike_payload_print_json(s->payloads[i], f);
        if (i == s->num_payloads-1) {
            zprintf(f, "]");
        }
    }
    zprintf(f, "}");
}

static void ike_message_delete(struct ike_message **s_handle) {
    struct ike_message *s = *s_handle;
    int i;

    if (s == NULL) {
        return;
    }
    ike_header_delete(&s->header);
    for (i = 0; i < s->num_payloads; i++) {
        ike_payload_delete(&s->payloads[i]);
    }
    
    free(s);
    *s_handle = NULL;
}

static void ike_message_init(struct ike_message **s_handle) {

    if (*s_handle != NULL) {
        ike_message_delete(s_handle);
    }

    *s_handle = calloc(1, sizeof(struct ike_message));
    if (*s_handle == NULL) {
        joy_log_err("malloc failed");
        return;
    }
}

static unsigned int ike_message_unmarshal(struct ike_message *s, const char *x, unsigned int len) {
    unsigned int offset = 0;
    unsigned int length;
    uint8_t next_payload;

    /* parse header */
    ike_header_init(&s->header);
    length = ike_header_unmarshal(s->header, x+offset, len-offset);
    if (length == 0) {
        joy_log_err("unable to unmarshal header");
        return 0;
    }
    if (s->header->length > IKE_MAX_MESSAGE_LEN) {
        joy_log_err("header length %u > IKE_MAX_MESSAGE_LEN %u", s->header->length, IKE_MAX_MESSAGE_LEN);
        return 0;
    }
    offset += length;

    /* parse payloads */
    next_payload = s->header->next_payload;
    s->num_payloads = 0;
    while(offset < s->header->length && s->num_payloads < IKE_MAX_PAYLOADS && next_payload != NO_NEXT_PAYLOAD) {
        ike_payload_init(&s->payloads[s->num_payloads]);
        s->payloads[s->num_payloads]->type = next_payload;
        length = ike_payload_unmarshal(s->payloads[s->num_payloads], x+offset, len-offset);
        if (length == 0) {
            joy_log_err("unable to unmarshal payload");
            return 0;
        }

        offset += length;
        next_payload = s->payloads[s->num_payloads]->next_payload;
        s->num_payloads++;
    }

    /* check that the length matches exactly */
    if (offset != s->header->length) {
        joy_log_err("offset %u != header length %u", offset, s->header->length);
        return 0;
    }

    return offset;
}

static void ike_process(struct ike *init,
                        struct ike *resp) {
    if (init == NULL || resp == NULL) {
        return;
    }
}

/*
 * start of ike feature functions
 */

inline void ike_init(struct ike **ike_handle) {

    if (*ike_handle != NULL) {
        ike_delete(ike_handle);
    }

    *ike_handle = calloc(1, sizeof(struct ike));
    if (*ike_handle == NULL) {
        joy_log_err("malloc failed");
        return;
    }
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

    while (len > 0 && ike->num_messages < IKE_MAX_MESSAGES) { /* parse all messages in the buffer */
        ike_message_init(&ike->messages[ike->num_messages]);
        length = ike_message_unmarshal(ike->messages[ike->num_messages], data_ptr, len);
        if (length == 0) {
            /* unable to parse message */
            joy_log_err("unable to parse message");
            break;
        }

        /* skip to the next message in the buffer */
        len -= length;
        data_ptr += length;
        ike->num_messages++;
    }

    } /* report_ike */
}

void ike_print_json(const struct ike *x1,
                    const struct ike *x2,
                    zfile f) {
    struct ike *init = NULL, *resp = NULL;
    int i;

    init = (struct ike*)x1;
    resp = (struct ike*)x2;

    ike_process(init, resp);

    zprintf(f, ",\"ike\":{");
    if (init != NULL) {
        zprintf(f, "\"init\":{");
        for (i = 0; i < init->num_messages; i++) {
            if (i == 0) {
                zprintf(f, "\"messages\":[");
            } else {
                zprintf(f, ",");
            }
            ike_message_print_json(init->messages[i], f);
            if (i == init->num_messages-1) {
                zprintf(f, "]");
            }
        }
        zprintf(f, "}");
    }
    if (resp != NULL) {
        if (init != NULL) {
            zprintf(f, ",");
        }
        zprintf(f, "\"resp\":{");
        for (i = 0; i < resp->num_messages; i++) {
            if (i == 0) {
                zprintf(f, "\"messages\":[");
            } else {
                zprintf(f, ",");
            }
            ike_message_print_json(resp->messages[i], f);
            if (i == resp->num_messages-1) {
                zprintf(f, "]");
            }
        }
        zprintf(f, "}");
    }
    zprintf(f, "}");
}

void ike_delete(struct ike **ike_handle) {
    struct ike *ike= *ike_handle;
    int i;

    if (ike == NULL) {
        return;
    }
    for (i = 0; i < ike->num_messages; i++) {
        ike_message_delete(&ike->messages[i]);
    }

    free(ike);
    *ike_handle = NULL;
    
}

void ike_unit_test() {
    int num_fails = 0;

    fprintf(info, "\n******************************\n");
    fprintf(info, "IKE Unit Test starting...\n");

    if (num_fails) {
        fprintf(info, "Finished - # of failures: %u\n", num_fails);
    } else {
        fprintf(info, "Finished - success\n");
    }
    fprintf(info, "******************************\n\n");
}
