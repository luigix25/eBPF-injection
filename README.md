Master's Thesis, Computer Engineering.


Abstract:

Virtual machines are increasingly important today because of their extensive use in cloud computing.
The performance of these systems is often limited by the fact that a lot of relevant information is only known to the guests running in the virtual machines and is opaque to the host. Paravirtualization, i.e., creating explicit communication interfaces between the guests and the host, is the mayor technique used today to overcome this limitation, but the evolution of these interfaces is limited by the need of keeping them compatible with legacy guests. The purpose of this thesis is to design and implement a mechanism to extend paravirtualization using eBPF in order to allow the host to inject arbitrary code into the guest kernel, as well as the application of this mechanism in order to improve the performance of virtual machines.