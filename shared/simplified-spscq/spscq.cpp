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
#include <stdio.h>
#include <cstdlib>
#include <fstream>
#include <cstring>
#include <string>
#include <unistd.h>
#include <ctime>
#include <cerrno>
#include <assert.h>
#include <cstring>
#include <thread>
#include <map>
#include <random>
#include <algorithm>
#include <iostream>
#include <functional>
#include <chrono>
#include <signal.h>
#include <sstream>
#include <sys/mman.h>

#include "mlib.h"

/* This must be defined before including spscq.h. */
static unsigned short *smap = nullptr;
#if 1
#define SMAP(x) smap[x]
#else
#define SMAP(x) x
#endif

#include "spscq.h"

//#define RATE_LIMITING_CONSUMER /* Enable support for rate limiting consumer */

#undef QDEBUG /* dump queue state at each operation */

#define ONEBILLION (1000LL * 1000000LL) /* 1 billion */

static int stop = 0;

static void
sigint_handler(int signum)
{
    ACCESS_ONCE(stop) = 1;
}

/* Alloc zeroed cacheline-aligned memory, aborting on failure. */
static void *
szalloc(size_t size, bool hugepages)
{
    void *p = NULL;
    if (hugepages) {
        p = mmap(NULL, size, PROT_WRITE | PROT_READ,
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
        if (p == MAP_FAILED) {
            printf("mmap allocation failure: %s\n", strerror(errno));
            exit(EXIT_FAILURE);
        }
        assert(reinterpret_cast<uint64_t>(p) % SPSCQ_ALIGN_SIZE == 0);
    } else {
        int ret = posix_memalign(&p, SPSCQ_ALIGN_SIZE, size);
        if (ret) {
            printf("allocation failure: %s\n", strerror(errno));
            exit(EXIT_FAILURE);
        }
        memset(p, 0, size);
    }
    return p;
}

static void
sfree(void *ptr, size_t size, bool hugepages)
{
    if (hugepages) {
        munmap(ptr, size);
    } else {
        free(ptr);
    }
}

unsigned int
ilog2(unsigned int x)
{
    unsigned int probe = 0x00000001U;
    unsigned int ret   = 0;
    unsigned int c;

    assert(x != 0);

    for (c = 0; probe != 0; probe <<= 1, c++) {
        if (x & probe) {
            ret = c;
        }
    }

    return ret;
}

struct RateLimitedStats {
    std::chrono::system_clock::time_point last;
    long long int step   = 30ULL * 1000000ULL;
    long long int thresh = 0;

    RateLimitedStats(long long int th)
        : last(std::chrono::system_clock::now()), thresh(th - step)
    {
    }

    inline void stat(long long int left)
    {
        if (unlikely(left < thresh)) {
            std::chrono::system_clock::time_point now =
                std::chrono::system_clock::now();
            long long unsigned int ndiff =
                std::chrono::duration_cast<std::chrono::nanoseconds>(now - last)
                    .count();
            double mpps;
            mpps = step * 1000.0 / ndiff;
            printf("%3.3f Mpps\n", mpps);
            if (ndiff < 2 * ONEBILLION) {
                step <<= 1;
            } else if (ndiff > 3 * ONEBILLION) {
                step >>= 1;
            }
            thresh -= step;
            last = now;
        }
    }
};

enum class MbufMode {
    NoAccess = 0,
    LinearAccess,
};

struct Mbuf {
    unsigned int len;
    unsigned int __padding[7];
#define MBUF_LEN_MAX (4096 + SPSCQ_CACHELINE_SIZE - 8 * sizeof(unsigned int))
    char buf[MBUF_LEN_MAX];
};

enum class RateLimitMode {
    None = 0,
    Limit,
};

enum class EmulatedOverhead {
    None = 0,
    SpinCycles,
};

struct Iffq;

struct Global {
    static constexpr int DFLT_BATCH        = 32;
    static constexpr int DFLT_QLEN         = 256;
    static constexpr int DFLT_LINE_ENTRIES = 32;
    static constexpr int DFLT_D            = 10;

    /* Test length as a number of packets. */
    long long unsigned int num_packets = 0; /* infinite */

    /* Length of the SPSC queue. */
    unsigned int qlen = DFLT_QLEN;

    /* How many entries for each line in iffq. */
    unsigned int line_entries = DFLT_LINE_ENTRIES;

    /* Max batch for producer and consumer operation. */
    unsigned int prod_batch = DFLT_BATCH;
    unsigned int cons_batch = DFLT_BATCH;

    /* Affinity for producer and consumer. */
    int p_core = 0, c_core = 1;

    /* Emulated per-packet load for the producer and consumer side,
     * in TSC ticks (initially in nanoseconds). */
    uint64_t prod_spin_ticks = 0, cons_spin_ticks = 0;
    uint64_t cons_rate_limit_cycles = 0;

    bool online_rate   = false;
    bool perf_counters = false;

    /* Test duration in seconds. */
    unsigned int duration = DFLT_D;

    /* Type of queue used. */
    std::string test_type = "lq";

    /* If true we do a latency test; if false we do a throughput test. */
    bool latency = false;

    /* Try to keep hardware prefetcher disabled for the accesses to the
     * queue slots. This should reduce the noise in the cache miss
     * behaviour. */
    bool deceive_hw_data_prefetcher = false;

    /* Allocate memory from hugepages. */
    bool hugepages = false;

    MbufMode mbuf_mode = MbufMode::NoAccess;

    /* Timestamp to compute experiment statistics. */
    std::chrono::system_clock::time_point begin, end;

    /* Checksum for when -M is used. */
    unsigned int csum;

    /* When -M is used, we need a variable to increment that depends on
     * something contained inside the mbuf; this is needed to make sure
     * that spin_for() has a data dependency on the mbuf_get() or
     * mbuf_put(), so that spin_for() does not run in the parallel
     * with mbuf_put() or mbuf_get().
     * To avoid the compiler optimizing out this variable, P and C
     * save it to the 'trash' global variable here. */
    unsigned int trash;

    /* Packet count written back by consumers. It's safer for it
     * to have its own cacheline. */
    SPSCQ_CACHELINE_ALIGNED
    volatile long long unsigned pkt_cnt = 0;

    /* Average batches as seen by producer and consumer. */
    SPSCQ_CACHELINE_ALIGNED
    long long int producer_batches = 0;
    long long int consumer_batches = 0;

    /* L1 dcache miss rates in M/sec. */
    float prod_read_miss_rate  = 0.0;
    float cons_read_miss_rate  = 0.0;
    float prod_write_miss_rate = 0.0;
    float cons_write_miss_rate = 0.0;

    /* CPU instruction rate in B/sec. */
    float prod_insn_rate = 0.0;
    float cons_insn_rate = 0.0;

    /* The lamport-like queue. */
    Blq *blq      = nullptr;
    Blq *blq_back = nullptr;

    /* The ff-like queue. */
    Iffq *ffq      = nullptr;
    Iffq *ffq_back = nullptr;

    /* A pool of preallocated mbufs (only accessed by P). */
    Mbuf *pool = nullptr;

    /* Index in the mbuf pool array (only accessed by P). */
    unsigned int pool_idx = 0;

    /* Maks for the mbuf pool array (only accessed by P). */
    unsigned int pool_mask;

    void producer_header();
    void producer_footer();
    void consumer_header();
    void consumer_footer();
    void print_results();
};

// static Mbuf gm[2];


static void
qslotmap_init(unsigned short *qslotmap, unsigned qlen, bool shuffle)
{
    if (!shuffle) {
        for (unsigned i = 0; i < qlen; i++) {
            qslotmap[i] = i;
        }
        return;
    }
    /* Prepare support for shuffled queue slots to disable the effect of hw
     * prefetching on the queue slots.
     * K is the number of entries per cacheline. */
    unsigned int K = SPSCQ_CACHELINE_SIZE / sizeof(uintptr_t);
    std::vector<unsigned short> v(qlen / K);
    std::random_device rd;
    std::mt19937 gen(rd());

    /* First create a vector of qlen/K elements (i.e. the number of cache
     * lines in the queue), containing a random permutation of
     * K*[0..qlen/K[. */
    for (size_t i = 0; i < v.size(); i++) {
        v[i] = K * i;
    }
    std::shuffle(v.begin(), v.end(), gen);

    for (unsigned j = 0; j < qlen / K; j++) {
        std::vector<unsigned short> u(K);

        /* Generate slot indices for the #j cacheline, as a random
         * permutation of [v[j]..v[j]+K[ */
        for (size_t i = 0; i < K; i++) {
            u[i] = v[j] + i;
        }
        std::shuffle(u.begin(), u.end(), gen);
        for (size_t i = 0; i < K; i++) {
            qslotmap[j * K + i] = u[i];
        }
    }
}

static inline Mbuf * mbuf_get(Global *const g, unsigned int trash){
    Mbuf *m = &g->pool[g->pool_idx & g->pool_mask];
    /* We want that m->len depends on trash but we
    * don't want to put trash inside m->len (to
    * preserve the checksum). */
    m->len = g->pool_idx++ + !!(trash == 0xdeadbeef);
    return m;
    
}


static inline void mbuf_put(Mbuf *const m, unsigned int *csum, unsigned int *trash){
    *trash += reinterpret_cast<uintptr_t>(m);
    *csum += m->len;
}


static Blq *
blq_create(int qlen, bool hugepages)
{
    Blq *blq = static_cast<Blq *>(szalloc(blq_size(qlen), hugepages));
    int ret;

    ret = blq_init(blq, qlen);
    if (ret) {
        return NULL;
    }

    assert(reinterpret_cast<uintptr_t>(blq) % SPSCQ_ALIGN_SIZE == 0);
    assert((reinterpret_cast<uintptr_t>(&blq->write)) -
               (reinterpret_cast<uintptr_t>(&blq->write_priv)) ==
           SPSCQ_ALIGN_SIZE);
    assert((reinterpret_cast<uintptr_t>(&blq->read_priv)) -
               (reinterpret_cast<uintptr_t>(&blq->write)) ==
           SPSCQ_ALIGN_SIZE);
    assert((reinterpret_cast<uintptr_t>(&blq->read)) -
               (reinterpret_cast<uintptr_t>(&blq->read_priv)) ==
           SPSCQ_ALIGN_SIZE);
    assert((reinterpret_cast<uintptr_t>(&blq->qlen)) -
               (reinterpret_cast<uintptr_t>(&blq->read)) ==
           SPSCQ_ALIGN_SIZE);
    assert((reinterpret_cast<uintptr_t>(&blq->q[0])) -
               (reinterpret_cast<uintptr_t>(&blq->qlen)) ==
           SPSCQ_ALIGN_SIZE);

    return blq;
}

static void
blq_free(Blq *blq, bool hugepages)
{
    memset(blq, 0, sizeof(*blq));
    sfree(blq, blq_size(blq->qlen), hugepages);
}

static inline void spin_for(uint64_t spin, unsigned int *trash)
{
    uint64_t when = rdtsc() + spin;

    while (rdtsc() < when) {
        (*trash)++;
        compiler_barrier();
    }
}


void * lq_producer(void *opaque){
    Global *g                  = (Global*) opaque;
    // const uint64_t spin        = g->prod_spin_ticks;
    Blq *blq                   = g->blq;    
    unsigned int trash         = 0;

    runon("P", g->p_core);
    
    g->begin    = std::chrono::system_clock::now();

    while (!ACCESS_ONCE(stop)) {
        // spin_for(spin, &trash);
        Mbuf *m = mbuf_get(g, trash);
        while (lq_write(blq, (uintptr_t)m)!=0) {}
    }

    return NULL;
}


void * lq_consumer(void *opaque){   
    Global *g                  = (Global*) opaque; 
    // const uint64_t spin        = g->cons_spin_ticks;    
    Blq *blq                   = g->blq;
    unsigned int csum          = 0;
    unsigned int trash         = 0;    
    Mbuf *m;

    runon("C", g->c_core);

    for (;;) {
        m = (Mbuf *)lq_read(blq);
        if (m) {
            ++g->pkt_cnt;
            mbuf_put(m, &csum, &trash);
            // spin_for(spin, &trash);
        }
        if (unlikely(ACCESS_ONCE(stop))) {
            break;
        }
    }

    g->end = std::chrono::system_clock::now();
    return NULL;
}


int main(int argc, char **argv){
    pthread_t producer, consumer;
    struct sigaction sa;
    int ret;
    Global _g;
    Global *g = &_g;


    //init pool???
    size_t pool_size = SPSCQ_ALIGNED_SIZE(2 * g->qlen * sizeof(g->pool[0]));
    size_t pool_and_smap_size = pool_size + (g->qlen * sizeof(SMAP(0)));
    /* Allocate mbuf pool and smap together. */
    void *pool_and_smap = szalloc(pool_and_smap_size, g->hugepages);

    /* Init the mbuf pool and the mask. */
    g->pool      = static_cast<Mbuf *>(pool_and_smap);
    g->pool_mask = (2 * g->qlen) - 1;

        /* Init the smap. */
    smap = reinterpret_cast<unsigned short *>(
        (static_cast<char *>(pool_and_smap) + pool_size));
    qslotmap_init(smap, g->qlen, g->deceive_hw_data_prefetcher);




    //mbuf access mode
    g->mbuf_mode = MbufMode::LinearAccess;

    //Use hugepages? default false
    // g->hugepages = true;

    //signal handler
    sa.sa_handler = sigint_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    ret         = sigaction(SIGINT, &sa, NULL);
    if (ret) {
        perror("sigaction(SIGINT)");
        exit(EXIT_FAILURE);
    }


    //SETUP QUEUE
    g->blq = blq_create(g->qlen, g->hugepages);
    // printf("Allocating lamport queue\n");
    
    //2thread P, C
    pthread_create(&producer, NULL, lq_producer, g);    
    pthread_create(&consumer, NULL, lq_consumer, g);


    pthread_join(producer, NULL);
    pthread_join(consumer, NULL);


    double mpps = g->pkt_cnt * 1000.0 /
        std::chrono::duration_cast<std::chrono::nanoseconds>(g->end - g->begin).count();

    printf("%3.3f", mpps);
    // printf("%3.3f Mpps [Mega packets per second]\n", mpps);

    //DEALLOC QUEUE
    blq_free(g->blq, g->hugepages);

    return 0;
}
