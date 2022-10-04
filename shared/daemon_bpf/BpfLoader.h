#include <iostream>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <bpf_injection_header.h>

using namespace std;

class BpfLoader
{
    private:
        bpf_object *obj;
        bpf_program *prog;
        bpf_link *links = nullptr;

    public:
        BpfLoader(bpf_injection_msg_t message);
        /* Loads the BPF Program inside the kernel */
        int load();
        /* Returns fd for a map */
        int getMap(const char *);
        ~BpfLoader();
};