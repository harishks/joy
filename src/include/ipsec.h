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
 * ipsec.h
 *
 * IP Security (IPsec) awareness for joy
 *
 */

#ifndef IPSEC_H
#define IPSEC_H

#include <stdio.h>      /* for FILE* */
#include <pcap.h>
#include "output.h"
#include "feature.h"
#include "utils.h"      /* for enum role */

#define ipsec_usage "  ipsec=1                      report IPsec information\n"

#define ipsec_filter(key) ((key->prot == 17) && (key->dp == 500 || key->sp == 500))

typedef struct ipsec {
} ipsec_t;

declare_feature(ipsec);

void ipsec_init(struct ipsec **ipsec_handle);

void ipsec_update(struct ipsec *ipsec,
                const struct pcap_pkthdr *header,
		const void *data,
		unsigned int len,
		unsigned int report_ipsec);

void ipsec_print_json(const struct ipsec *w1,
		    const struct ipsec *w2,
		    zfile f);

void ipsec_delete(struct ipsec **ipsec_handle);

void ipsec_unit_test();

#endif /* IPSEC_H */

