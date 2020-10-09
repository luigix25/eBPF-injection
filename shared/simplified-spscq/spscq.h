/*
 * Copyright (C) 2018 Universita' di Pisa
 * Copyright (C) 2018 Vincenzo Maffione
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef __SPSCQ_H__
#define __SPSCQ_H__

#ifdef __cplusplus
extern "C" {
#endif

#ifndef ACCESS_ONCE
#ifdef __cplusplus
#define ACCESS_ONCE(x)                                                         \
    (*static_cast<std::remove_reference<decltype(x)>::type volatile *>(&(x)))
#else /* !__cplusplus */
#define ACCESS_ONCE(x) (*(volatile typeof(x) *)&(x))
#endif /* !__cplusplus */
#endif /* !ACCESS_ONCE */

#include <stdint.h>
#include <stdio.h>

#define compiler_barrier() asm volatile("" ::: "memory")

#define SPSCQ_CACHELINE_SIZE 64
#define SPSCQ_ALIGN_SIZE 128
#define SPSCQ_CACHELINE_ALIGNED __attribute__((aligned(SPSCQ_ALIGN_SIZE)))
#define SPSCQ_ALIGNED_SIZE(_sz)                                                \
    ((_sz + SPSCQ_ALIGN_SIZE - 1) & (~(SPSCQ_ALIGN_SIZE - 1)))

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif
#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif

/* Support for slot remapping. No slot remapping happens by default. */
#ifndef SMAP
#define SMAP(x) x
#endif

inline int
is_power_of_two(int x)
{
    return !x || !(x & (x - 1));
}

/*
 * Queues based on the Lamport concurrent lock-free queue.
 */
struct Blq {
    /* Producer private data. */
    SPSCQ_CACHELINE_ALIGNED
    unsigned int write_priv;
    unsigned int read_shadow;

    /* Producer write, consumer read. */
    SPSCQ_CACHELINE_ALIGNED
    unsigned int write;

    /* Consumer private data. */
    SPSCQ_CACHELINE_ALIGNED
    unsigned int read_priv;
    unsigned int write_shadow;

    /* Producer read, consumer write. */
    SPSCQ_CACHELINE_ALIGNED
    unsigned int read;

    /* Shared read only data. */
    SPSCQ_CACHELINE_ALIGNED
    unsigned int qlen;
    unsigned int qmask;

    /* The queue. */
    SPSCQ_CACHELINE_ALIGNED
    uintptr_t q[0];
};

inline size_t
blq_size(int qlen)
{
    struct Blq *blq;
    return SPSCQ_ALIGNED_SIZE(sizeof(*blq) + qlen * sizeof(blq->q[0]));
}

inline int
blq_init(struct Blq *blq, int qlen)
{
    if (qlen < 2 || !is_power_of_two(qlen)) {
        printf("Error: queue length %d is not a power of two\n", qlen);
        return -1;
    }

    blq->qlen  = qlen;
    blq->qmask = qlen - 1;

    return 0;
}

inline int
lq_write(struct Blq *q, uintptr_t m)
{
    unsigned write    = q->write;
    unsigned int next = (write + 1) & q->qmask;

    if (next == ACCESS_ONCE(q->read)) {
        return -1; /* no space */
    }
    ACCESS_ONCE(q->q[SMAP(write)]) = m;
    compiler_barrier();
    ACCESS_ONCE(q->write) = next;
    return 0;
}

inline uintptr_t
lq_read(struct Blq *q)
{
    unsigned read = q->read;
    uintptr_t m;

    if (read == ACCESS_ONCE(q->write)) {
        return 0; /* queue empty */
    }
    compiler_barrier();
    m                    = ACCESS_ONCE(q->q[SMAP(read)]);
    ACCESS_ONCE(q->read) = (read + 1) & q->qmask;
    return m;
}

#ifdef __cplusplus
}
#endif

#endif /* __SPSCQ_H__ */
