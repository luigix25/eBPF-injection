#include <iostream>
#include <list>

class Service {
public:
    uint8_t service_id;
    pid_t pid;

    Service(uint8_t s_id, pid_t p){
        this->service_id = s_id;
        this->pid = p;
    }

    bool operator==(const Service& lhs) {
        return (lhs.service_id == this->service_id) && (lhs.pid == this->pid);

    }

    void print();

};


class ServiceList
{
private:
    std::list<Service> service_list;
public:
    ServiceList(){
        
    }

    /*Adds New Service to the list*/
    void addService(Service);
    
    /*Removes Service from the list*/
    void removeService(Service);
    /*Searches for a Service inside the List using the service_id*/
    Service findService(uint8_t);
};

