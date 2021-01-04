#include "mythread.h"
#include "mainwindow.h"
#include "pcap.h"

pcap_t *handle; //Handle of the device that shall be sniffed
char errbuf[PCAP_ERRBUF_SIZE];
struct bpf_program fp;
bpf_u_int32 pNet;

Mythread::Mythread()
{

}

void Mythread::setDev( char * d)
{
    this->my_dev = d;
}
void Mythread::run()
{
    //pcap_loop iig thread eer ajilluulah
        handle = pcap_open_live(this->my_dev , BUFSIZ , 0 , -1 , errbuf);
        if (handle == NULL)
        {
            printf("start: Интерфейс %s -д алдаа гарлаа : %s\n" , this->my_dev , errbuf);
            exit(1);
        }
        printf("Done\n");
        //Put the device in sniff loop
        pcap_loop(handle , -1, MainWindow::process_packet , NULL);
    }
void Mythread::stop()
{
    pcap_breakloop(handle);
}
