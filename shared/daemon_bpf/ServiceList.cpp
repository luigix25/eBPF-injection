#include "ServiceList.h"
using namespace std;

void Service::Service::print(){
    cout<<"Service ID: "<<(int)this->service_id<<" pid: "<<this->pid<<"\n";
}

void ServiceList::addService(Service s){

    Service tmp = findService(s.service_id);
    if(tmp.pid != -1){
        cout<<"Service already in the list"<<endl;
        return;
    }

    this->service_list.push_back(s);

}
    
void ServiceList::removeService(Service s){

    this->service_list.remove(s);

}


Service ServiceList::findService(uint8_t service_id){

    for(Service s : this->service_list){
        if(s.service_id == service_id)
            return s;
    }

    Service tmp(-1,-1);
    return tmp;


}
