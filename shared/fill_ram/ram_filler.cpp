#include <iostream>
using namespace std;

#define KILO 1024
#define MEGA 1024 * KILO
#define GIGA 1024 * MEGA

void write_roba(char *p,long len){
    for(long i=0;i<len;i++){
        p[i] = 'a' + i;

    }
}

int main(){

    char c;
    char *p;
    long allocated = 0;

    while(true){
        cout<<"g: allocate 1G\nm: allocate 100M\nq: quit\n";
        cin>>c;

        switch (c)
        {
            case 'g':
                p = new char[GIGA];
                write_roba(p,GIGA);
                break;
            case 'm':
                p = new char[100 * MEGA];
                write_roba(p,100*MEGA);
                break;
            default:
                return 0;
            }
    }

}