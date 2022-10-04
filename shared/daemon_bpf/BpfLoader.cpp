#include "BpfLoader.h"

BpfLoader::BpfLoader(bpf_injection_msg_t message){
    this->obj = bpf_object__open_mem(message.payload,message.header.payload_len,NULL);
    if (libbpf_get_error(this->obj)) {
        cerr<<"ERROR: opening BPF object file failed"<<endl;
        throw -1;
    }

    delete[] (uint8_t*)message.payload;

    this->prog = bpf_object__find_program_by_name(this->obj, "bpf_prog1");
    if (!this->prog) {
        cerr<<"finding a prog in obj file failed"<<endl;
        throw -1;
    }
    
    cout<<"BPF Program Type"<<endl;
    cout<<bpf_program__section_name(prog)<<endl;

}

int BpfLoader::load(){

    /* load BPF program */
    if (bpf_object__load(this->obj)) {
        cout<<"ERROR: loading BPF object file failed"<<endl;
        return -1;
    }

    int err;

    //Loading all available progs
    bpf_object__for_each_program(prog, obj) {
        links = bpf_program__attach(prog);
        err = libbpf_get_error(links);
        if (err < 0) {
            cerr<<"ERROR: bpf_program__attach failed"<<endl;
            links = NULL;
            return err;
        }
    }

    cout<<"Bpf program successfully loaded."<<endl;
    return 0;
}

int BpfLoader::getMap(const char *name){

    bpf_map *map;

    //Debug: All Maps Available
    cout<<"Available Maps:\n";
    bpf_object__for_each_map(map, obj) {
		const char *name = bpf_map__name(map);
        cout<<"[LOG] map: "<<name<<endl;
    }

    int map_fd = bpf_object__find_map_fd_by_name(obj,name);
    if(map_fd < 0){
        cerr<<"Error map "<<name<<" not found"<<endl;
        return -1;
    }

    return map_fd;


}

BpfLoader::~BpfLoader(){

    bpf_link__destroy(this->links);
    bpf_object__close(this->obj);
}
