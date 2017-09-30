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
 * ike.h
 *
 * Internet Key Exchange (IKE) awareness for joy
 *
 */

#ifndef IKE_H
#define IKE_H

#include <stdio.h>      /* for FILE* */
#include <pcap.h>
#include "output.h"
#include "feature.h"
#include "utils.h"      /* for enum role */

#define ike_usage "  ike=1                      report IKE information\n"

#define ike_filter(key) ((key->prot == 17) && (key->dp == 500 || key->sp == 500 || key->dp == 4500 || key->sp == 4500))

#define IKE_MAX_MESSAGE_LEN 35000 // must be at least 1200, should be at least 3000 according to https://tools.ietf.org/html/rfc5996
#define IKE_MAX_MESSAGES 2 // TODO
#define IKE_MAX_PAYLOADS 10 // TODO
#define IKE_MAX_PROPOSALS 10 // TODO
#define IKE_MAX_TRANSFORMS 20 // TODO
#define IKE_MAX_ATTRIBUTES 10 // TODO

typedef struct ike {
    enum role role;
    unsigned int num_messages;
    struct ike_message *messages[IKE_MAX_MESSAGES];
} ike_t;

declare_feature(ike);

void ike_init(struct ike **ike_handle);

void ike_update(struct ike *ike,
                const struct pcap_pkthdr *header,
		const void *data,
		unsigned int len,
		unsigned int report_ike);

void ike_print_json(const struct ike *w1,
		    const struct ike *w2,
		    zfile f);

void ike_delete(struct ike **ike_handle);

void ike_unit_test();

#endif /* IKE_H */

