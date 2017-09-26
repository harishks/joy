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
 * ipsec.c
 *
 * IP Security (IPsec) awareness for joy
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

#include "ipsec.h"
#include "utils.h"      /* for enum role */
#include "p2f.h"        /* for zprintf_ ...        */
#include "err.h"        /* for logging             */

/*
 *
 * \brief Copy a json-printable string from the source buffer to the
 *        destination buffer.
 *
 * \param buf Destination buffer.
 * \param buflen Maximum length of the destination buffer.
 * \param data Source buffer.
 * \param datalen Length of the source buffer.
 *
 */
static void copy_printable_string(char *buf,
                                  unsigned int buflen,
                                  const char *data,
                                  unsigned int datalen) {
    while (buflen-- && datalen--) {
        /* json constraints */
	    if (!isprint(*data) || *data == '\"' || *data == '\\' || *data <= 0x1f) {
	        break;
	    }
	    *buf++ = *data++;
    }

    *buf = 0; /* null terminate buffer */
}

/*
 *
 * \brief Find a substring in a buffer of a given length, and return a pointer
 * to the first substring match. The substring search will terminate upon
 * encountering a null byte or reaching the end of the buffer.
 *
 * \param buf The buffer to be searched.
 * \param buflen The length of the buffer.
 * \param sub The substring to search for.
 * \param sublen The length of the substring.
 *
 * \return A pointer to the first substring match, or NULL if not found.
 *
 */
static const char * memsearch(const char *buf, const unsigned int buflen, const char *sub, const unsigned int sublen) {
    unsigned int bufidx;

    for (bufidx = 0; bufidx < buflen; bufidx++) {
        if ((bufidx + sublen > buflen) || buf[bufidx] == '\0') {
            break;
        }
        if (memcmp(buf+bufidx, sub, sublen) == 0) {
            return buf+bufidx;
        }
    }

    return NULL;
}


/*
 * A vector is contains a pointer to a string of bytes of a specified length.
 */
struct vector {
    unsigned int len;
    char *bytes;
};

/*
 *
 * \brief Initialize vector struct.
 *
 * \param vector Pointer to the vector to be initialized.
 *
 */
static void vector_init(struct vector *vector) {
    vector->len = 0;
    vector->bytes = NULL;
}

/*
 *
 * \brief Free a vector, setting it to the state just after a call to vector_init.
 *
 * \param vector Pointer to the vector to free.
 *
 */
static void vector_free(struct vector *vector) {
    if (vector->bytes != NULL) {
        free(vector->bytes);
    }
    vector_init(vector);
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
        return;
    }
    memcpy(tmpptr, data, len);
    vector_free(vector); /* does nothing if already empty */
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

/*
 *
 * \brief Allocate and return a pointer to a string representation of a vector.
 * This string must later be freed to avoid a memory leak.
 *
 * \param vector Pointer to the vector to stringify.
 *
 * \return A pointer to a string representation of the vector.
 */
static char *vector_string(struct vector *vector) {
    char *s;

    s = malloc(vector->len+1);
    if (s == NULL) {
        return NULL;
    }
    if (vector->len > 0) {
        copy_printable_string(s, vector->len+1, vector->bytes, vector->len);
    } else {
        s[0] = 0;
    }

    return s;
}

struct ipsec_msg {
    struct ipsec_hdr *hdr;
    struct ipsec_payload *payloads;
};

// IKEv1 and IKEv2 share the same message header format
struct ipsec_hdr {
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

struct ipsec_payload {
    uint8_t type;
    uint8_t next_payload;
    uint8_t reserved;
    uint16_t length;
    struct ipsec_payload_body *body;
};

enum ipsec_payload_type {
	//  IKEv2 Payload Types
	//  RESERVED                             1 - 32
	SECURITY_ASSOCIATION_V2                 = 33,
	KEY_EXCHANGE_V2                         = 34,
	IDENTIFICATION_INITIATOR_V2             = 35,
	IDENTIFICATION_RESPONDER_V2             = 36,
	CERTIFICATE_V2                          = 37,
	CERTIFICATE_REQUEST_V2                  = 38,
	AUTHENTICATION_V2                       = 39,
	NONCE_V2                                = 40,
	NOTIFY_V2                               = 41,
	DELETE_V2                               = 42,
	VENDOR_ID_V2                            = 43,
	TRAFFIC_SELECTOR_INITIATOR_V2           = 44,
	TRAFFIC_SELECTOR_RESPONDER_V2           = 45,
	ENCRYPTED_V2                            = 46,
	CONFIGURATION_V2                        = 47,
	EXTENSIBLE_AUTHENTICATION_V2            = 48,
	GENERIC_SECURE_PASSWORD_METHOD_V2       = 49,
	GROUP_IDENTIFICATION_V2                 = 50,
	GROUP_SECURITY_ASSOCIATION_V2           = 51,
	KEY_DOWNLOAD_V2                         = 52,
	ENCRYPTED_AND_AUTHENTICATED_FRAGMENT_V2 = 53
	//  RESERVED TO IANA                    54 - 127
	//  PRIVATE USE                         128 - 255
};

struct ipsec_payload_body {
    enum ipsec_payload_type type;
};

struct ipsec_proposal {
    uint8_t proposal_num;
    uint8_t protocol_id;
    struct vector *spi;
    struct ipsec_transform *transforms;
};

struct ipsec_transform {
    uint8_t num;
    uint8_t id_v1; // IKEv1 only
    uint8_t type; // IKEv2 only
    uint16_t id; // IKEv2 only
    struct ipsec_attribute *attributes;
};

struct ipsec_attribute {
    uint16_t type;
    struct vector *value;
};

/*
 * start of ipsec feature functions
 */

inline void ipsec_init(struct ipsec **ipsec_handle) {
}

void ipsec_update(struct ipsec *ipsec,
        const struct pcap_pkthdr *header,
        const void *data,
        unsigned int len,
        unsigned int report_ipsec) {

    if (len == 0) {
    return;        /* skip zero-length messages */
    }

    if (report_ipsec) {
    }

}

void ipsec_print_json(const struct ipsec *x1,
                    const struct ipsec *x2,
                    zfile f) {
}

void ipsec_delete(struct ipsec **ipsec_handle) {
}

void ipsec_unit_test() {
    int num_fails = 0;

    fprintf(info, "\n******************************\n");
    fprintf(info, "IPsec Unit Test starting...\n");

    if (num_fails) {
        fprintf(info, "Finished - # of failures: %d\n", num_fails);
    } else {
        fprintf(info, "Finished - success\n");
    }
    fprintf(info, "******************************\n\n");
}
