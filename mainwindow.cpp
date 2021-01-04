#include "mainwindow.h"
#include "ui_mainwindow.h"
#include<pcap.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<net/ethernet.h>
#include<netinet/ip_icmp.h>
#include<netinet/udp.h>
#include<netinet/tcp.h>
#include<netinet/ip.h>
#include<time.h>
#include<sys/time.h>
#include "mythread.h"
#include "QThread"
#include "QtCore"
#include "QtGui"
#include "qdebug.h"
#include"entity.h"
#include<QInputDialog>
#include <QByteArray>
#include<QLineEdit>
#include<QMessageBox>
#include"form.h"
#include "QPalette"
#include "QColor"
#include "nightcharts.h"
#include "nightchartswidget.h"
#include "entity.h"
FILE *logfile;
struct sockaddr_in source,dest;
int tcp=0,udp=0,icmp=0,others=0,igmp=0, ipv6=0, ipv4=0, total=0,i,j;
clock_t begin, end;
char *portstr;
QString ethcnt[65236];
QString ipcnt[65236];
QString packetData[65236];
QString datadumpcnt[65236];
QString protocol[65236];
QString searchString;
QString icmpcnt[65236];
QStringList lista;
QStringList size1, size2, size3, size4, size5, size6, size7, size8, size9, size10;
int packetDatacnt = 0;
int datadumpcnt1 = 0;
int ethcnt1 = 0;
int ipcnt1  = 0;
int protocolcnt = 0;
int maxp = 0;
int minp = 66;
int tcpcount = 0, udpcount = 0, icmpcount = 0, httpscount = 0, httpcount = 0, ftpcount = 0, sshcount = 0;
int telnetcount = 0, smtpcount = 0, dnscount = 0, popcount = 0, netbioscount = 0, ldapcount = 0, imapcount = 0, snmpcount = 0;
int bgpcount = 0, ldapscount = 0, dhcpcount = 0, tftpcount = 0, ntpcount = 0, ssdpcount = 0;
int sizesearch1 = 0, sizesearch2 = 0, sizesearch3 = 0, sizesearch4 = 0, sizesearch5 = 0, sizesearch6 = 0, sizesearch7 = 0, sizesearch8 = 0;
int sizesearch9 = 0, sizesearch10 = 0;
int otherscount = 0;
QString sizedef1 = "40-200";
QString sizedef2 = "201-361";
QString sizedef3 = "362-522";
QString sizedef4 = "523-683";
QString sizedef5 = "684-844";
QString sizedef6 = "845-1005";
QString sizedef7 = "1006-1166";
QString sizedef8 = "1167-1327";
QString sizedef9 = "1328-1488";
QString sizedef10 = "1488-15017";
QStringList listb = {"https", "http", "ftp", "telnet","dns", "pop", "netbios", "snmp","dhcp", "others"};
MainWindow* MainWindow::s_inst = NULL;

MainWindow *MainWindow::get_inst(){

    if (!s_inst)
        s_inst = new MainWindow();

    return s_inst;
}
MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    //MainWindow uusgeh
    ui->setupUi(this);

    Entity entity;
    entity.cnt=0;
    entity.data="";
    entity.minValue=0;
    entity.maxValue=0;
    datalist.append(entity);
    entity.minValue=40;
    entity.maxValue=200;
    datalist.append(entity);


    entity.minValue=201;
    entity.maxValue=361;
    datalist.append(entity);


    entity.minValue=362;
    entity.maxValue=522;
    datalist.append(entity);

    entity.minValue=523;
    entity.maxValue=683;
    datalist.append(entity);

    entity.minValue=684;
    entity.maxValue=844;
    datalist.append(entity);

    entity.minValue=845;
    entity.maxValue=1005;
    datalist.append(entity);

    entity.minValue=1006;
    entity.maxValue=1166;
    datalist.append(entity);

    entity.minValue=1167;
    entity.maxValue=1327;
    datalist.append(entity);

    entity.minValue=1328;
    entity.maxValue=1488;
    datalist.append(entity);

    entity.minValue=1489;
    entity.maxValue=15017;
    datalist.append(entity);

    for (int  i=0;i < datalist.size();i++)
    {
        if (i == 0)
            ui->comboBoxPNum->addItem(QString::fromUtf8("Бүгд"));
        else
            ui->comboBoxPNum->addItem(QString::number(datalist.value(i).minValue)+"-"+QString::number(datalist.value(i).maxValue));
    }

    pcap_if_t *alldevs, *d;
    char errbuf[PCAP_ERRBUF_SIZE];
    // interface gargah
    if (pcap_findalldevs(&alldevs, errbuf)== -1)
    {
          fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
          exit(1);
    }

       // interface iig combobox ruu hiih
        int i =0;
        for(d=alldevs; d; d=d->next)
        {
            ui->interfaceBox->addItem(d->name);
            inList[i]= d->name;
            i++;
          //  printf("%s\n", d->name);
        }
        ui->stopButton_3->setEnabled(false);

        //logfile uusgeh

        logfile=fopen("log.txt","w");
        if(logfile==NULL)
        {
            printf("Файл үүсгэх боломжгүй байна");
        }
        printf("logfile uuslee\n");
        begin=clock();
        s_inst=this;
        this->setWindowTitle(QString::fromUtf8("Пакет шинжлэгч"));
        ui->comboBox->addItem(QString::fromUtf8("Хистограм"));
        ui->comboBox->addItem(QString::fromUtf8("Протокол хистограм"));
        ui->comboBox->addItem(QString::fromUtf8("Хэмжээний хистограм"));
}
void MainWindow::process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
    //packet bolovsruulalt
    int size = header->len;
    end=clock();
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    ++total;
    double time = (double)(end-begin)/CLOCKS_PER_SEC;
    QString a;
    switch ( iph->protocol )
    {
        case 1:  //ICMP Protocol
            ++icmp;
            print_icmp_packet( buffer , size);
            a = "icmp";
            protocol[protocolcnt] = "icmp";
            break;

        case 6:  //TCP Protocol
            ++tcp;
            tcpcount ++;
            a = "tcp";
            print_tcp_packet(buffer , size);
            protocol[protocolcnt] = "tcp";
            break;
        case 17: //UDP Protocol
            ++udp;
            udpcount ++;
            a = "udp";
            print_udp_packet(buffer , size);
            protocol[protocolcnt] = "udp";
            break;
        default:
            ++others;
            a = "others";
            protocol[protocolcnt] = "others";
            otherscount ++;
            other_print(buffer , size);
            break;
    }
    MainWindow::get_inst()->dataAppend(a, total, header->len);
    protocolcnt ++;
    MainWindow::get_inst()->printProtocol(buffer, iph->saddr, iph->daddr, total, time, a, size, portstr);
    MainWindow::get_inst()->sizeFilter(buffer, iph->saddr, iph->daddr, total, time, a, size, portstr);
    MainWindow::get_inst()->graph.setUpGrap(total, time, size);
}
void MainWindow::dataAppend(QString a,int count,long long len)
{
    Entity entity;
    for (int  i=1;i < datalist.size();i++)
        {
            // hemjees shalgah
            if (len <= datalist.value(i).maxValue ){
                entity = datalist.value(i);
                entity.cnt++;
                entity.data.append(a);
                datalist[i]=entity;
                break;
            }
        }
}
void MainWindow::print_ethernet_header(const u_char *Buffer, int Size)
{
    //packet ethernet header zadargaa
    struct ethhdr *eth = (struct ethhdr *)Buffer;
    ethcnt[ethcnt1] = QString::fromUtf8("\nEthernet Header\n   |-Destination Address     : ") +
                QString::asprintf("%.2X-",eth->h_dest[0]) +
                QString::asprintf("%.2X-",eth->h_dest[1]) +
                QString::asprintf("%.2X-",eth->h_dest[2]) +
                QString::asprintf("%.2X-",eth->h_dest[3]) +
                QString::asprintf("%.2X-",eth->h_dest[4]) +
                QString::asprintf("%.2X-",eth->h_dest[5]) +
                QString::fromUtf8("\n   |-Source Address     : ") +
                QString::asprintf("%.2X-",eth->h_source[0]) +
                QString::asprintf("%.2X-",eth->h_source[1]) +
                QString::asprintf("%.2X-",eth->h_source[2]) +
                QString::asprintf("%.2X-",eth->h_source[3]) +
                QString::asprintf("%.2X-",eth->h_source[4]) +
                QString::asprintf("%.2X",eth->h_source[5]) +
                QString("\n   |-Protocol     : ") +
                QString::number((unsigned short)eth->h_proto);
    fprintf(logfile , "\n");
    fprintf(logfile , "Ethernet Header\n");
    fprintf(logfile , "   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
    fprintf(logfile , "   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
    fprintf(logfile , "   |-Protocol            : %u \n",(unsigned short)eth->h_proto);
    ethcnt1++;
}

void MainWindow::print_ip_header(const u_char * Buffer, int Size)
{
    //packet ip header zadargaa
    if (Size > maxp)
        maxp = Size;
    else if (Size < minp)
            minp = Size;
    print_ethernet_header(Buffer , Size);

    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
    iphdrlen =iph->ihl*4;

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
    ipcnt[ipcnt1] = QString::fromUtf8("\nIP Header\n   |-IP Version     : ") +
                    QString::number((unsigned int)iph->version) +
                    QString::fromUtf8("\n   |-IP Header Length    : ") +
                    QString::number((unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4) +
                    QString::fromUtf8("\n   |-Type Of Service     : ") +
                    QString::number((unsigned int)iph->tos) +
                    QString::fromUtf8("\n   |-IP Total Length     : ") +
                    QString::number(ntohs(iph->tot_len)) +
                    QString::fromUtf8("\n   |-Identification      : ") +
                    QString::number(ntohs(iph->id)) +
                    QString::fromUtf8("\n   |-TTL                 : ") +
                    QString::number((unsigned int)iph->ttl) +
                    QString::fromUtf8("\n   |-Protocol            : ") +
                    QString::number((unsigned int)iph->protocol) +
                    QString::fromUtf8("\n   |-Checksum            : ") +
                    QString::number(ntohs(iph->check)) +
                    QString::fromUtf8("\n   |-Source IP           : ") +
                    QString::fromUtf8(inet_ntoa(source.sin_addr)) +
                    QString::fromUtf8("\n   |-Destination IP      : ") +
                    QString::fromUtf8(inet_ntoa(dest.sin_addr));
    fprintf(logfile , "\n");
    fprintf(logfile , "IP Header\n");
    fprintf(logfile , "   |-IP Version        : %d\n",(unsigned int)iph->version);
    fprintf(logfile , "   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
    fprintf(logfile , "   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
    fprintf(logfile , "   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
    fprintf(logfile , "   |-Identification    : %d\n",ntohs(iph->id));
    //fprintf(logfile , "   |-Reserved ZERO Field   : %d\n",(unsigned int)iphdr->ip_reserved_zero);
    //fprintf(logfile , "   |-Dont Fragment Field   : %d\n",(unsigned int)iphdr->ip_dont_fragment);
    //fprintf(logfile , "   |-More Fragment Field   : %d\n",(unsigned int)iphdr->ip_more_fragment);
    fprintf(logfile , "   |-TTL      : %d\n",(unsigned int)iph->ttl);
    fprintf(logfile , "   |-Protocol : %d\n",(unsigned int)iph->protocol);
    fprintf(logfile , "   |-Checksum : %d\n",ntohs(iph->check));
    fprintf(logfile , "   |-Source IP        : %s\n" , inet_ntoa(source.sin_addr) );
    fprintf(logfile , "   |-Destination IP   : %s\n" , inet_ntoa(dest.sin_addr) );
    ipcnt1 ++;
}


void MainWindow::print_tcp_packet(const u_char * Buffer, int Size)
{
    //tcp packet zadargaa
    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
    iphdrlen = iph->ihl*4;

    struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));

    int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;

    long desport=(long)ntohs(tcph->dest);
    long sourceport=(long)ntohs(tcph->source);
    //protocol shuult
        if (desport==443 || sourceport==443)
        {
            portstr="HTTPS";
            httpscount ++;
        }
        else if(desport==80 || sourceport==80)
        {
            httpcount ++;
            portstr="HTTP";
        }
        else if(desport==20 || sourceport==20)
        {
            portstr="FTP";
            ftpcount ++;
        }
        else if(desport==21 || sourceport==21)
        {
            portstr="FTP";
            ftpcount ++;
        }
        else if(desport==22 || sourceport==22)
        {
            portstr="SSH";
            sshcount ++;
        }
        else if(desport==23 || sourceport==23)
        {
            portstr="TELNET";
            telnetcount ++;
        }
        else if(desport==25 || sourceport==25)
        {
            portstr="SMTP";
            smtpcount ++;
        }
        else if(desport==53 || sourceport==53)
        {
            portstr="DNS";
            dnscount ++;
        }
        else if(desport==110 || sourceport==110)
        {
            portstr="POP";
            popcount ++;
        }
        else if(desport==137 || sourceport==137)
        {
            portstr="NetBIOS";
            netbioscount ++;
        }
        else if(desport==138 || sourceport==138)
        {
            portstr="NetBIOS";
            netbioscount ++;
        }
        else if(desport==139 || sourceport==139)
        {
            portstr="NetBIOS";
            netbioscount ++;
        }
        else if(desport==389 || sourceport==389)
        {
            portstr="LDAP";
            ldapcount ++;
        }
        else if(desport==143 || sourceport==143)
        {
            portstr="IMAP";
            imapcount ++;
        }
        else if(desport==161 || sourceport==161)
        {
            portstr="SNMP";
            snmpcount ++;
        }
        else if(desport==162 || sourceport==162)
        {
            portstr="SNMP";
            snmpcount ++;
        }
        else if(desport==179 || sourceport==179)
        {
            portstr="BGP";
            bgpcount ++;
        }
        else if(desport==636 || sourceport==363)
        {
            portstr="LDAPS";
            ldapscount ++;
        }
        else if(desport==989 || sourceport==990)
        {
            portstr="FTP";
            ftpcount ++;
        }
        else
        {
            portstr="TCP";
        }

    fprintf(logfile , "\n\n***********************TCP Packet*************************\n");
    print_ip_header(Buffer,Size);
    packetData[packetDatacnt] = QString::fromUtf8("\nTCP Header\n   |-Source Port      : ") +
                QString::number(ntohs(tcph->source)) +
                QString::fromUtf8("\n   |-Destination Port     : ") +
                QString::number(ntohs(tcph->dest)) +
                QString::fromUtf8("\n   |-Sequence Number      : ") +
                QString::number(ntohl(tcph->seq)) +
                QString::fromUtf8("\n   |-Acknowledge Number   : ") +
                QString::number(ntohl(tcph->ack_seq)) +
                QString::fromUtf8("\n   |-Header Length        : ") +
                QString::number((unsigned int)tcph->doff) +
                QString::fromUtf8(" DWORDS or ") +
                QString::number((unsigned int)tcph->doff*4) +
                QString::fromUtf8("BYTES\n") +
                QString::fromUtf8("   |-Urgent Flag            : ") +
                QString::number((unsigned int)tcph->urg) +
                QString::fromUtf8("\n   |-Acknowledgement Flag : ") +
                QString::number((unsigned int)tcph->ack) +
                QString::fromUtf8("\n   |-Push Flag            : ") +
                QString::number((unsigned int)tcph->psh) +
                QString::fromUtf8("\n   |-Reset Flag           : ") +
                QString::number((unsigned int)tcph->rst) +
                QString::fromUtf8("\n   |-Synchronise Flag     :") +
                QString::number((unsigned int)tcph->syn) +
                QString::fromUtf8("\n   |-Finish Flag          : ") +
                QString::number((unsigned int)tcph->fin) +
                QString::fromUtf8("\n   |-Window               : ") +
                QString::number(ntohs(tcph->window)) +
                QString::fromUtf8("\n   |-Checksum             : ") +
                QString::number(ntohs(tcph->check)) +
                QString::fromUtf8("\n   |-Urgent Pointer       : ") +
                QString::number(tcph->urg_ptr) +
                QString::fromUtf8("\n");
    fprintf(logfile , "\n");
    fprintf(logfile , "TCP Header\n");
    fprintf(logfile , "   |-Source Port      : %u\n",ntohs(tcph->source));
    fprintf(logfile , "   |-Destination Port : %u\n",ntohs(tcph->dest));
    fprintf(logfile , "   |-Sequence Number    : %u\n",ntohl(tcph->seq));
    fprintf(logfile , "   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
    fprintf(logfile , "   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
    //fprintf(logfile , "   |-CWR Flag : %d\n",(unsigned int)tcph->cwr);
    //fprintf(logfile , "   |-ECN Flag : %d\n",(unsigned int)tcph->ece);
    fprintf(logfile , "   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
    fprintf(logfile , "   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
    fprintf(logfile , "   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
    fprintf(logfile , "   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
    fprintf(logfile , "   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
    fprintf(logfile , "   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
    fprintf(logfile , "   |-Window         : %d\n",ntohs(tcph->window));
    fprintf(logfile , "   |-Checksum       : %d\n",ntohs(tcph->check));
    fprintf(logfile , "   |-Urgent Pointer : %d\n",tcph->urg_ptr);
    if (  strcmp("HTTPS", portstr)==0 ){
            packetData[packetDatacnt].append(QString::fromUtf8(portstr) +
                                   QString::fromUtf8(" Header\n"));
            fprintf(logfile , "%s Header\n", portstr);
            if (0< Size - header_size  ){

                if(Buffer[66]==0X16){
                    packetData[packetDatacnt].append(QString::fromUtf8("   |-Handshake protocol type \n"));
                    fprintf(logfile , "   |-Handshake protocol type \n" );

                    if(Buffer[67]==0X03 && Buffer[68]==0X00)
                    {
                        packetData[packetDatacnt].append(QString::fromUtf8("   |-SSL version (SSL 3.0) \n"));
                        fprintf(logfile , "   |-SSL version (SSL 3.0) \n" );
                    }
                    else if(Buffer[67]==0X03 && Buffer[68]==0X01){
                        packetData[packetDatacnt].append(QString::fromUtf8("   |-SSL version (TLS 1.0) \n"));
                        fprintf(logfile , "   |-SSL version (TLS 1.0) \n" );
                    }
                    else if(Buffer[67]==0X03 && Buffer[68]==0X02){
                        packetData[packetDatacnt].append(QString::fromUtf8("   |-SSL version (TLS 1.1) \n"));
                        fprintf(logfile , "   |-SSL version (TLS 1.1) \n" );
                    }
                    else if(Buffer[67]==0X03 && Buffer[68]==0X03){
                        packetData[packetDatacnt].append(QString::fromUtf8("   |-SSL version (TLS 1.2) \n"));
                        fprintf(logfile , "   |-SSL version (TLS 1.2) \n" );
                    }
                    packetData[packetDatacnt].append(QString::fromUtf8("   |-Record length (") +
                                           QString::number(Buffer[70]) +
                                           QString::fromUtf8(" bytes)\n"));
                    fprintf(logfile , " 180 25 155  |-Record length (%d bytes) \n", Buffer[70] );


                    if(Buffer[71]==0X01){
                        packetData[packetDatacnt].append(QString::fromUtf8("   |-\n") +
                                               QString::fromUtf8("   |-ClientHello message type \n") +
                                               QString::fromUtf8("   |-Message length  ("));
                        fprintf(logfile , "   |-\n");
                        fprintf(logfile , "   |-ClientHello message type \n" );
                        fprintf(logfile , "   |-Message length  (");
                            if(Buffer[72]>0X00)
                            {
                                packetData[packetDatacnt].append(QString::number(Buffer[72]));
                                fprintf(logfile , "%d", Buffer[72]);
                            }
                            if(Buffer[74]>0X00)
                            {
                                packetData[packetDatacnt].append(QString::number(Buffer[73]));
                                fprintf(logfile , "%d", Buffer[73]);
                            }
                            if(Buffer[74]>0X00)
                            {
                                packetData[packetDatacnt].append(QString::number(Buffer[74]));
                                fprintf(logfile , "%d", Buffer[74]);
                            }
                        packetData[packetDatacnt].append(QString::fromUtf8("bytes)\n"));
                        fprintf(logfile , "bytes)\n");
                        /*if(Buffer[75]==0X03 && Buffer[76]==0X00)
                        {
                            tcpcnt[tcpcnt1].append(QString::fromUtf8("   |-SSL version (SSL 3.0) \n"));
                            fprintf(logfile , "   |-SSL version (SSL 3.0) \n" );
                        }
                        else if(Buffer[75]==0X03 && Buffer[76]==0X01){
                            tcpcnt[tcpcnt1].append(QString::fromUtf8("   |-SSL version (TLS 1.0) \n"));
                            fprintf(logfile , "   |-SSL version (TLS 1.0) \n" );
                        }
                        else if(Buffer[75]==0X03 && Buffer[76]==0X02){
                            tcpcnt[tcpcnt1].append(QString::fromUtf8("   |-SSL version (TLS 1.1) \n"));
                            fprintf(logfile , "   |-SSL version (TLS 1.1) \n" );
                        }
                        else if(Buffer[75]==0X03 && Buffer[76]==0X03){
                            tcpcnt[tcpcnt1].append(QString::fromUtf8("   |-SSL version (TLS 1.2) \n"));
                            fprintf(logfile , "   |-SSL version (TLS 1.2) \n" );
                        }*/


                    }
                    else if(Buffer[71]==0X02){
                        packetData[packetDatacnt].append(QString::fromUtf8("   |-\n") +
                                               QString::fromUtf8("   |-ServerHello message type \n") +
                                               QString::fromUtf8("   |-Message length  ("));
                        fprintf(logfile , "   |-\n");
                        fprintf(logfile , "   |-ServerHello message type \n" );
                        fprintf(logfile , "   |-Message length  (");
                            if(Buffer[72]>0X00)
                            {
                                packetData[packetDatacnt].append(QString::number(Buffer[72]));
                                fprintf(logfile , "%d", Buffer[72]);
                            }
                            if(Buffer[74]>0X00)
                            {
                                packetData[packetDatacnt].append(QString::number(Buffer[73]));
                                fprintf(logfile , "%d", Buffer[73]);
                            }
                            if(Buffer[74]>0X00)
                            {
                                packetData[packetDatacnt].append(QString::number(Buffer[74]));
                                fprintf(logfile , "%d", Buffer[74]);
                            }
                        packetData[packetDatacnt].append(QString::fromUtf8("bytes)\n"));
                        fprintf(logfile , "bytes)\n");
                        /*if(Buffer[75]==0X03 && Buffer[76]==0X00)
                        {
                            tcpcnt[tcpcnt1].append(QString::fromUtf8("   |-SSL version (SSL 3.0) \n"));
                            fprintf(logfile , "   |-SSL version (SSL 3.0) \n" );
                        }
                        else if(Buffer[75]==0X03 && Buffer[76]==0X01){
                            tcpcnt[tcpcnt1].append(QString::fromUtf8("   |-SSL version (TLS 1.0) \n"));
                            fprintf(logfile , "   |-SSL version (TLS 1.0) \n" );
                        }
                        else if(Buffer[75]==0X03 && Buffer[76]==0X02){
                            tcpcnt[tcpcnt1].append(QString::fromUtf8("   |-SSL version (TLS 1.1) \n"));
                            fprintf(logfile , "   |-SSL version (TLS 1.1) \n" );
                        }
                        else if(Buffer[75]==0X03 && Buffer[76]==0X03){
                            tcpcnt[tcpcnt1].append(QString::fromUtf8("   |-SSL version (TLS 1.2) \n"));
                            fprintf(logfile , "   |-SSL version (TLS 1.2) \n" );
                        }*/


                    }
                    else if(Buffer[71]==0X0b){
                        packetData[packetDatacnt].append(QString::fromUtf8("   |-\n") +
                                               QString::fromUtf8("   |-Certificate message type\n") +
                                               QString::fromUtf8("   |-Message length  ("));
                        fprintf(logfile , "   |-\n");
                        fprintf(logfile , "   |-Certificate message type\n" );
                        fprintf(logfile , "   |-Message length  (");
                            if(Buffer[72]>0X00)
                            {
                                packetData[packetDatacnt].append(QString::number(Buffer[72]));
                                fprintf(logfile , "%d", Buffer[72]);
                            }
                            if(Buffer[74]>0X00)
                            {
                                packetData[packetDatacnt].append(QString::number(Buffer[73]));
                                fprintf(logfile , "%d", Buffer[73]);
                            }
                            if(Buffer[74]>0X00)
                            {
                                packetData[packetDatacnt].append(QString::number(Buffer[74]));
                                fprintf(logfile , "%d", Buffer[74]);
                            }
                        packetData[packetDatacnt].append(QString::fromUtf8(" bytes)\n"));
                        fprintf(logfile , "bytes)\n");
                        packetData[packetDatacnt].append(QString::fromUtf8("   |-Certificates length ("));
                        fprintf(logfile , "   |-Certificates length (");
                            if(Buffer[75]>0X00)
                            {
                                packetData[packetDatacnt].append(QString::number(Buffer[75]));
                                fprintf(logfile , "%d", Buffer[75]);
                            }
                            if(Buffer[76]>0X00)
                            {
                                packetData[packetDatacnt].append(QString::number(Buffer[76]));
                                fprintf(logfile , "%d", Buffer[76]);
                            }
                            if(Buffer[77]>0X00)
                            {
                                packetData[packetDatacnt].append(QString::number(Buffer[77]));
                                fprintf(logfile , "%d", Buffer[77]);
                            }
                        packetData[packetDatacnt].append(QString::fromUtf8("bytes)\n"));
                        fprintf(logfile , "bytes)\n");

                    }
                    else if(Buffer[71]==0X0e){
                        packetData[packetDatacnt].append(QString::fromUtf8("\n") +
                                               QString::fromUtf8("   |-ServerHelloDone message\n") +
                                               QString::fromUtf8("   |-Message length  ("));
                        fprintf(logfile , "\n");
                        fprintf(logfile , "   |-ServerHelloDone message\n" );
                        fprintf(logfile , "   |-Message length  (");
                            if(Buffer[72]>0X00)
                            {
                                packetData[packetDatacnt].append(QString::number(Buffer[72]));
                                fprintf(logfile , "%d", Buffer[72]);
                            }
                            if(Buffer[74]>0X00)
                            {
                                packetData[packetDatacnt].append(QString::number(Buffer[73]));
                                fprintf(logfile , "%d", Buffer[73]);
                            }
                            if(Buffer[74]>0X00)
                            {
                                packetData[packetDatacnt].append(QString::number(Buffer[74]));
                                fprintf(logfile , "%d", Buffer[74]);
                            }
                        packetData[packetDatacnt].append(QString::fromUtf8("bytes)\n"));
                        fprintf(logfile , "bytes)\n");

                    }
                    else if(Buffer[71]==0X10){
                        packetData[packetDatacnt].append(QString::fromUtf8("\n") +
                                               QString::fromUtf8("   |-ClientKeyExchange message type\n") +
                                               QString::fromUtf8("   |-Message length  ("));
                        fprintf(logfile , "\n");
                        fprintf(logfile , "   |-ClientKeyExchange message type\n" );
                        fprintf(logfile , "   |-Message length  (");
                            if(Buffer[72]>0X00)
                            {
                                packetData[packetDatacnt].append(QString::number(Buffer[72]));
                                fprintf(logfile , "%d", Buffer[72]);
                            }
                            if(Buffer[74]>0X00)
                            {
                                packetData[packetDatacnt].append(QString::number(Buffer[73]));
                                fprintf(logfile , "%d", Buffer[73]);
                            }
                            if(Buffer[74]>0X00)
                            {
                                packetData[packetDatacnt].append(QString::number(Buffer[74]));
                                fprintf(logfile , "%d", Buffer[74]);
                            }
                        packetData[packetDatacnt].append(QString::fromUtf8(" bytes)\n") +
                                               QString::fromUtf8("RSA encrypted key data (premaster secret)\n"));
                        fprintf(logfile , "bytes)\nRSA encrypted key data (premaster secret)\n");

                    }
                    else if(Buffer[71]==0X04){
                        packetData[packetDatacnt].append(QString::fromUtf8("\n") +
                                               QString::fromUtf8("   |-New Session Ticket message type (extension)\n") +
                                               QString::fromUtf8("   |-Message length  ("));
                        fprintf(logfile , "\n");
                        fprintf(logfile , "   |-New Session Ticket message type (extension)\n" );
                        fprintf(logfile , "   |-Message length  (");
                            if(Buffer[72]>0X00)
                            {
                                packetData[packetDatacnt].append(QString::number(Buffer[72]));
                                fprintf(logfile , "%d", Buffer[72]);
                            }
                            if(Buffer[74]>0X00)
                            {
                                packetData[packetDatacnt].append(QString::number(Buffer[73]));
                                fprintf(logfile , "%d", Buffer[73]);
                            }
                            if(Buffer[74]>0X00)
                            {
                                packetData[packetDatacnt].append(QString::number(Buffer[74]));
                                fprintf(logfile , "%d", Buffer[74]);
                            }
                        packetData[packetDatacnt].append(QString::fromUtf8(" bytes)\n"));
                        fprintf(logfile , "bytes)\n");

                    }
                    else if(Buffer[71]==0X6d || Buffer[71]==0X0c){
                        packetData[packetDatacnt].append(QString::fromUtf8("\n   |-Encrypted Finished message\n"));
                        fprintf(logfile , "\n");
                        fprintf(logfile , "   |-Encrypted Finished message\n" );

                    }

            }
            else if(Buffer[71]==0X14){
                packetData[packetDatacnt].append(QString::fromUtf8("   |-ChangeCipherSpec protocol type 14\n"));
                fprintf(logfile , "   |-ChangeCipherSpec protocol type 14\n" );
            }
            else if(Buffer[71]==0X17){
                packetData[packetDatacnt].append(QString::fromUtf8("   |-ApplicationData protocol type\n"));
                fprintf(logfile , "   |-ApplicationData protocol type\n" );
            }
            else if(Buffer[71]==0X15){
                packetData[packetDatacnt].append(QString::fromUtf8("   |-ChangeCipherSpec protocol type 15\n"));
                fprintf(logfile , "   |-ChangeCipherSpec protocol type 15\n" );
            }
            else if(Buffer[71]==0X14){
                packetData[packetDatacnt].append(QString::fromUtf8("   |-Alert protocol typen"));
                fprintf(logfile , "   |-Alert protocol typen" );
            }

            }
            else{
                packetData[packetDatacnt].append(QString::fromUtf8("   |-Secure Sockets Layer"));
                fprintf(logfile ,"   |-Secure Sockets Layer");
            }
        }
      else if (strcmp("HTTP", portstr)==0   || strcmp("SSDP", portstr)==0)
      {
          int aa=0;
          packetData[packetDatacnt].append(QString::fromUtf8(portstr) +
                                 QString::fromUtf8(" Header\n"));
          fprintf(logfile , "%s Header\n", portstr);

         // if(Buffer[42]==0X48 || Buffer[42]==0X50 || Buffer[42]==0X47 ){
          if(1==1){
             packetData[packetDatacnt].append(QString::fromUtf8("   |-"));
             fprintf(logfile , "   |-");
             for (int i = 42; i < Size - header_size; i++)
             {
                if( (Buffer[i]>0X2C && Buffer[i]<0X3C) || (Buffer[i]>0X40 && Buffer[i]<0X7D) || Buffer[i]==0X0D || Buffer[i]==0X0A || Buffer[i]==0X200){
                // if(1==1){
                       if(Buffer[i]==0X0D ){
                          if (Buffer[i+1]==0X0A)
                          {
                              aa++;
                             packetData[packetDatacnt].append(QString::asprintf("\n   |-"));
                             fprintf(logfile , "\n   |-");
                             i++;
                          }
                      }
                      else{
                           packetData[packetDatacnt].append(QString::asprintf("%c",Buffer[i]));
                           fprintf(logfile , "%c", Buffer[i]);
                      }
                  }
                 if(aa>19)
                 {
                     break;
                 }
              }
          }

      }
      else if (strcmp("DNS", portstr)==0 )
          {
              packetData[packetDatacnt].append(QString::fromUtf8(portstr) +
                                     QString::fromUtf8(" Header\n") +
                                     QString::fromUtf8("   |-Transaction ID:   : Ox%02X", Buffer[42]) +
                                     QString::fromUtf8("%02X \n", Buffer[43]) +
                                     QString::fromUtf8("   |-Flags             : 0x%02X", Buffer[44]) +
                                     QString::fromUtf8("%02X Standard query    : \n", Buffer[45]) +
                                     QString::fromUtf8("   |-Questions         : 0x%d", Buffer[46]) +
                                     QString::fromUtf8("%d\n", Buffer[47]) +
                                     QString::fromUtf8("   |-Answer RRs        : 0x%d", Buffer[48]) +
                                     QString::fromUtf8("%d\n", Buffer[49]) +
                                     QString::fromUtf8("  |-Authority RRs: 0x%02", Buffer[50]) +
                                     QString::fromUtf8("%02X\n", Buffer[51]) +
                                     QString::fromUtf8("   |-Additional RRs    : 0x%02X", Buffer[52]) +
                                     QString::fromUtf8("%02X\n", Buffer[53]) +
                                     QString::fromUtf8("\n") +
                                     QString::fromUtf8("   |-Queries \n") +
                                     QString::fromUtf8("   |-Name              : \n") +
                                     QString::fromUtf8("\n"));
              fprintf(logfile , "%s Header\n", portstr);
              fprintf(logfile ,"   |-Transaction ID:   : Ox%02X%02X \n", Buffer[42], Buffer[43]);

              fprintf(logfile ,"   |-Flags             : 0x%02X%02X Standard query: \n", Buffer[44], Buffer[45]);
              fprintf(logfile ,"   |-Questions         : 0x%d%d\n", Buffer[46], Buffer[47]);
              fprintf(logfile ,"   |-Answer RRs        : 0x%d%d\n", Buffer[48], Buffer[49]);
              fprintf(logfile ,"   |-Authority RRs     : 0x%02X%02X\n", Buffer[50], Buffer[51]);
              fprintf(logfile ,"   |-Additional RRs    : 0x%02X%02X\n", Buffer[52], Buffer[53]);
              fprintf(logfile , "\n");
              fprintf(logfile ,"   |-Queries \n");
              fprintf(logfile ,"   |-Name              : ");
              fprintf(logfile , "\n");
              int wcount=0;
              while(1){
                  if (Buffer[wcount]==0X00 || wcount>Size)
                  {
                      break;
                  }
                  else{
                      if  (Buffer[wcount]>0X60 && Buffer[wcount]<0X7B)
                      {
                          packetData[packetDatacnt].append(QString::fromUtf8("%c", Buffer[wcount]));
                          fprintf(logfile, "%c", Buffer[wcount]);

                      }
                      else{
                          packetData[packetDatacnt].append(QString::fromUtf8("."));
                          fprintf(logfile, ".");
                      }


                      wcount++;
                  }
              }
      }
      else if (strcmp("DHCP", portstr)==0 )
      {
          packetData[packetDatacnt].append(QString::fromUtf8(portstr) +
                                 QString::fromUtf8(" Header\n") +
                                 QString::fromUtf8("   |-Message type            : Boot Reply : %d\n", Buffer[42]) +
                                 QString::fromUtf8("   |-Hardware type           : Ethernet (0x%02X) \n", Buffer[43]) +
                                 QString::fromUtf8("   |-Hardware address length : %d\n", Buffer[44]) +
                                 QString::fromUtf8("   |-Hops                    : %d\n", Buffer[45]) +
                                 QString::fromUtf8("   |-Transaction ID          : 0x%02X", Buffer[46]) +
                                 QString::fromUtf8("%02X", Buffer[47]) +
                                 QString::fromUtf8("%02X", Buffer[48]) +
                                 QString::fromUtf8("%02X\n", Buffer[49]) +
                                 QString::fromUtf8("   |-Seconds elapsed         : %d", Buffer[50]) +
                                 QString::fromUtf8("%d", Buffer[51]) +
                                 QString::fromUtf8("   |-Bootp flags             : 0x%02X", Buffer[52]) +
                                 QString::fromUtf8("%02X (Unicast)\n", Buffer[51]) +
                                 QString::fromUtf8("   |-Client IP address       : %d.", Buffer[54]) +
                                 QString::fromUtf8("%d.", Buffer[55]) +
                                 QString::fromUtf8("%d.", Buffer[56]) +
                                 QString::fromUtf8("%d\n", Buffer[57]) +
                                 QString::fromUtf8("   |-Your (client) IP address: %d.", Buffer[58]) +
                                 QString::fromUtf8("%d.", Buffer[59]) +
                                 QString::fromUtf8("%d.", Buffer[60]) +
                                 QString::fromUtf8("%d\n", Buffer[61]) +
                                 QString::fromUtf8("   |-Next server IP address  : %d.", Buffer[62]) +
                                 QString::fromUtf8("%d.", Buffer[63]) +
                                 QString::fromUtf8("%d.", Buffer[64]) +
                                 QString::fromUtf8("%d\n", Buffer[65]) +
                                 QString::fromUtf8("   |-Relay agent IP address  : %d.", Buffer[66]) +
                                 QString::fromUtf8("%d.", Buffer[67]) +
                                 QString::fromUtf8("%d.", Buffer[68]) +
                                 QString::fromUtf8("%d\n", Buffer[69]) +
                                 QString::fromUtf8("   |-Client MAC address: %02X:", Buffer[70]) +
                                 QString::fromUtf8("%02X:",Buffer[71]) +
                                 QString::fromUtf8("%02X:",Buffer[72]) +
                                 QString::fromUtf8("%02X\n",Buffer[73]) +
                                 QString::fromUtf8("\n"));
          fprintf(logfile , "%s Header\n", portstr);
          fprintf(logfile ,"   |-Message type            : Boot Reply : %d\n", Buffer[42]);
          fprintf(logfile ,"   |-Hardware type           : Ethernet (0x%02X) \n", Buffer[43]);
          fprintf(logfile ,"   |-Hardware address length : %d\n", Buffer[44]);
          fprintf(logfile ,"   |-Hops                    : %d\n", Buffer[45]);
          fprintf(logfile ,"   |-Transaction ID          : 0x%02X%02X%02X%02X\n", Buffer[46], Buffer[47], Buffer[48], Buffer[49]);
          fprintf(logfile ,"   |-Seconds elapsed         : %d%d\n", Buffer[50], Buffer[51]);
          fprintf(logfile ,"   |-Bootp flags             : 0x%02X%02X (Unicast)\n", Buffer[52], Buffer[53]);
          fprintf(logfile ,"   |-Client IP address       : %d.%d.%d.%d\n",Buffer[54], Buffer[55], Buffer[56], Buffer[57]);
          fprintf(logfile ,"   |-Your (client) IP address: %d.%d.%d.%d\n",Buffer[58], Buffer[59], Buffer[60], Buffer[61]);
          fprintf(logfile ,"   |-Next server IP address  : %d.%d.%d.%d\n",Buffer[62], Buffer[63], Buffer[64], Buffer[65]);
          fprintf(logfile ,"   |-Relay agent IP address  : %d.%d.%d.%d\n",Buffer[66], Buffer[67], Buffer[68], Buffer[69]);
          fprintf(logfile ,"   |-Client MAC address      : %02X:%02X:%02X:%02X\n", Buffer[70], Buffer[71], Buffer[72], Buffer[73]);

     }
    //packet iin zadargaag hevleh
    fprintf(logfile , "\n");
    datadumpcnt[datadumpcnt1].append(QString::fromUtf8("                        DATA Dump                         \n"));
    fprintf(logfile , "                        DATA Dump                         ");
    fprintf(logfile , "\n");

    fprintf(logfile , "IP Header\n");
    datadumpcnt[datadumpcnt1].append(QString::fromUtf8("IP Header\n"));
    PrintData(Buffer,iphdrlen);

    fprintf(logfile , "TCP Header\n");
    datadumpcnt[datadumpcnt1].append(QString::fromUtf8("TCP Header\n"));
    PrintData(Buffer+iphdrlen,tcph->doff*4);

    fprintf(logfile , "Data Payload\n");
    datadumpcnt[datadumpcnt1].append(QString::fromUtf8("Data Payload\n"));
    PrintData(Buffer + header_size , Size - header_size );

    fprintf(logfile , "\n###########################################################");
    packetDatacnt ++;
    datadumpcnt1 ++;
}

void MainWindow::print_udp_packet(const u_char *Buffer , int Size)
{
    //udp packet zadargaa
    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
    iphdrlen = iph->ihl*4;

    struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));

    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;

    fprintf(logfile , "\n\n***********************UDP Packet*************************\n");

    print_ip_header(Buffer,Size);
    //protocol shuult
    long desport=(long)ntohs(udph->dest);
        long sourceport=(long)ntohs(udph->source);

        if(desport==53 || sourceport==53)
        {
            portstr="DNS";
            dnscount ++;
        }
        else if(desport==67 || sourceport==67)
        {
            portstr="DHCP";
            dhcpcount ++;
        }
        else if(desport==68 || sourceport==68)
        {
            portstr="DHCP";
            dhcpcount ++;
        }
        else if(desport==69 || sourceport==69)
        {
            portstr="TFTP";
            tftpcount ++;
        }
        else if(desport==123 || sourceport==123)
        {
            portstr="NTP";
            ntpcount ++;
        }
        else if(desport==137 || sourceport==137)
        {
            portstr="NetBIOS";
            netbioscount ++;
        }
        else if(desport==138 || sourceport==138)
        {
            portstr="NetBIOS";
            netbioscount ++;
        }
        else if(desport==443 || sourceport==443)
        {
            portstr="HTTPS";
            httpscount ++;
        }
        else if(desport==139 || sourceport==139)
        {
            portstr="NetBIOS";
            netbioscount ++;
        }
        else if(desport==161 || sourceport==161)
        {
            portstr="SNMP";
            snmpcount ++;
        }
        else if(desport==162 || sourceport==162)
        {
            portstr="SNMP";
            snmpcount ++;
        }
        else if(desport==179 || sourceport==179)
        {
            portstr="BGP";
            bgpcount ++;
        }
        else if(desport==389 || sourceport==389)
        {
            portstr="LDAP";
            ldapcount ++;
        }
        else if(desport==636 || sourceport==363)
        {
            portstr="LDAPS";
            ldapscount ++;
        }
        else if(desport==989 || sourceport==990)
        {
            portstr="FTP";
            ftpcount ++;
        }
        else if(desport==636 || sourceport==363)
        {
            portstr="LDAPS";
            ldapscount ++;
        }
        else if(desport==1900 || sourceport==1900)
        {
            portstr="SSDP";
            ssdpcount ++;
        }
        else
        {
            portstr="UDP";
        }
      packetData[packetDatacnt] = QString::fromUtf8("\nUDP Header\n   |-Source Port      : ") +
                    QString::number(ntohs(udph->source)) +
                    QString::fromUtf8("\n   |-Destination Port                 : ") +
                    QString::number(ntohs(udph->dest)) +
                    QString::fromUtf8("\n   |-UDP Length                       : ") +
                    QString::number(ntohs(udph->len)) +
                    QString::fromUtf8("\n   |-UDP Checksum                     : ") +
                    QString::number(ntohs(udph->check)) +
                    QString::fromUtf8("\n");
    fprintf(logfile , "\nUDP Header\n");
    fprintf(logfile , "   |-Source Port      : %d\n" , ntohs(udph->source));
    fprintf(logfile , "   |-Destination Port : %d\n" , ntohs(udph->dest));
    fprintf(logfile , "   |-UDP Length       : %d\n" , ntohs(udph->len));
    fprintf(logfile , "   |-UDP Checksum     : %d\n" , ntohs(udph->check));
    if (  strcmp("HTTPS", portstr)==0 )
        {
            packetData[packetDatacnt].append(portstr +
                                   QString::fromUtf8("Header\n"));
            fprintf(logfile , "%s Header\n", portstr);
            if (0< Size - header_size  )
            {
                packetData[packetDatacnt].append(QString::fromUtf8("   |-Content Type: Application Data  (") +
                                       QString::number(Buffer[42]) +
                                       QString::fromUtf8(")\n") +
                                       QString::fromUtf8("   |-Version: TLS 1.2 (0x0303)\n") +
                                       QString::fromUtf8("   |-Length: ") +
                                       QString::number(Buffer[46]) +
                                       QString::fromUtf8("\n") +
                                       QString::fromUtf8("   |-Encrypted data :     "));
                fprintf(logfile ,"   |-Content Type: Application Data  (%d)\n", Buffer[42]);
                fprintf(logfile ,"   |-Version: TLS 1.2 (0x0303)\n");
                fprintf(logfile ,"   |-Length: %d\n", Buffer[46]);
                fprintf(logfile ,"   |-Encrypted data :     ");
                for (int i = 47; i < Size; i++)
                {
                    packetData[packetDatacnt].append(QString::fromUtf8("%02X", Buffer[i]));
                    fprintf(logfile ,"%02X ", Buffer[i]);
                    if (i%16==0)
                    {
                        packetData[packetDatacnt].append(QString::fromUtf8("\n                 "));
                        fprintf(logfile , "\n                 ");
                    }
                    else if (i%8==0)
                    {
                        packetData[packetDatacnt].append(QString::fromUtf8("    "));
                        fprintf(logfile , "    ");
                    }

                }
            }
            else{
                packetData[packetDatacnt].append(QString::fromUtf8("   |-Secure Sockets Layer"));
                fprintf(logfile ,"   |-Secure Sockets Layer");
            }
        }
        else if (strcmp("HTTP", portstr)==0   || strcmp("SSDP", portstr)==0)
        {
            int aa=0;
            packetData[packetDatacnt].append(portstr +
                                   QString::fromUtf8("Header\n"));
            fprintf(logfile , "%s Header\n", portstr);
            if(Buffer[42]==0X48 || Buffer[42]==0X50 || Buffer[42]==0X47 )
            {
               packetData[packetDatacnt].append(QString::fromUtf8("   |-"));
               fprintf(logfile , "   |-");
               for (int i = 42; i < Size - header_size; i++)
               {
                    if((Buffer[i]>0X2C && Buffer[i]<0X3C) || (Buffer[i]>0X40 && Buffer[i]<0X7D) || Buffer[i]==0X0D || Buffer[i]==0X0A || Buffer[i]==0X20 ){
                         if(Buffer[i]==0X0D ){
                            if (Buffer[i+1]==0X0A)
                            {
                                aa++;
                               packetData[packetDatacnt].append(QString::fromUtf8("\n   |-"));
                               fprintf(logfile , "\n   |-");
                               i++;
                            }
                        }
                        else{
                             packetData[packetDatacnt].append(QString::fromUtf8("%c", Buffer[i]));
                             fprintf(logfile , "%c", Buffer[i]);

                        }
                    }
                   if(aa>19)
                   {
                       break;
                   }
                }
            }

        }
        else if (strcmp("DNS", portstr)==0 )
            {
                packetData[packetDatacnt].append(QString::fromUtf8("\n"));
                packetData[packetDatacnt].append(QString(portstr) +
                                       QString::fromUtf8(" Header\n") +
                                       QString::fromUtf8("   |-Transaction ID: : 0x") +
                                       QString::number(Buffer[42]) +
                                       QString::number(Buffer[43]) +
                                       QString::fromUtf8("\n   |-Flags: 0x") +
                                       QString::number(Buffer[44]) +
                                       QString::number(Buffer[45]) +
                                       QString::fromUtf8("\n   |-Questions: 0x") +
                                       QString::number(Buffer[46]) +
                                       QString::number(Buffer[47]) +
                                       QString::fromUtf8("\n   |-Answer RRs: 0x") +
                                       QString::number(Buffer[48]) +
                                       QString::number(Buffer[49]) +
                                       QString::fromUtf8("   |-Authority RRs: 0x") +
                                       QString::number(Buffer[50]) +
                                       QString::number(Buffer[51]) +
                                       QString::fromUtf8("   |-Additional RRs: 0x") +
                                       QString::number(Buffer[52]) +
                                       QString::number(Buffer[53]) +
                                       QString::fromUtf8("\n") +
                                       QString::fromUtf8("   |-Queries \n") +
                                       QString::fromUtf8("\n"));
                fprintf(logfile , "%s Header\n", portstr);
                fprintf(logfile ,"   |-Transaction ID: : 0x%02X%02X\n", Buffer[42], Buffer[43]);

                fprintf(logfile ,"   |-Flags: 0x%02X%02X Standard query: \n", Buffer[44], Buffer[45]);
                fprintf(logfile ,"   |-Questions: 0x%d%d\n", Buffer[46], Buffer[47]);
                fprintf(logfile ,"   |-Answer RRs: 0x%d%d\n", Buffer[48], Buffer[49]);
                fprintf(logfile ,"   |-Authority RRs: 0x%02X%02X\n", Buffer[50], Buffer[51]);
                fprintf(logfile ,"   |-Additional RRs: 0x%02X%02X\n", Buffer[52], Buffer[53]);
                fprintf(logfile , "\n");
                fprintf(logfile ,"   |-Queries \n");
                fprintf(logfile ,"   |-Name: ");
                fprintf(logfile , "\n");
                int wcount=55;
                while(1){
                    if (Buffer[wcount]==0X00 || wcount>Size)
                    {
                        break;
                    }
                    else{
                        if  (Buffer[wcount]>0X60 && Buffer[wcount]<0X7B)
                        {
                            packetData[packetDatacnt].append(QString::asprintf("%c",Buffer[wcount]));
                            fprintf(logfile, "%c", Buffer[wcount]);
                        }
                        else{
                            packetData[packetDatacnt].append(QString::fromUtf8("."));
                            fprintf(logfile, ".");
                        }
                        wcount++;
                    }
                }

        }
        else if (strcmp("DHCP", portstr)==0 )
        {
        packetData[packetDatacnt].append(QString(portstr) +
                               QString::fromUtf8("\n   |-Message type: Boot Reply : ") +
                               QString::number(Buffer[42]) +
                               QString::fromUtf8("\n   |-Hardware type: Ethernet (0x") +
                               QString::number(Buffer[43]) +
                               QString::fromUtf8(") \n") +
                               QString::fromUtf8("   |-Hardware address length: ") +
                               QString::number(Buffer[44]) +
                               QString::fromUtf8("\n   |-Hops: ") +
                               QString::number(Buffer[45]) +
                               QString::fromUtf8("\n   |-Transaction ID: 0x") +
                               QString::number(Buffer[46]) +
                               QString::number(Buffer[47]) +
                QString::number(Buffer[48]) +
                QString::number(Buffer[49]) +
                QString::fromUtf8("\n   |-Seconds elapsed: ") +
                QString::number(Buffer[50]) +
                QString::number(Buffer[51]) +
                QString::fromUtf8("   |-Bootp flags: 0x") +
                QString::number(Buffer[52]) +
                QString::number(Buffer[53]) +
                QString::fromUtf8(" (Unicast)\n") +
                QString::fromUtf8("   |-Client IP address: ") +
                QString::number(Buffer[54]) +
                QString::fromUtf8(".") +
                QString::number(Buffer[55]) +
                QString::fromUtf8(".") +
                QString::number(Buffer[56]) +
                QString::fromUtf8(".") +
                QString::number(Buffer[57]) +
                QString::fromUtf8("\n") +
                QString::fromUtf8("   |-Your (client) IP address: ") +
                QString::number(Buffer[58]) +
                QString::fromUtf8(".") +
                QString::number(Buffer[59]) +
                QString::fromUtf8(".") +
                QString::number(Buffer[60]) +
                QString::fromUtf8(".") +
                QString::number(Buffer[61]) +
                QString::fromUtf8("\n   |-Next server IP address: ") +
                QString::number(Buffer[62]) +
                QString::fromUtf8(".") +
                QString::number(Buffer[63]) +
                QString::fromUtf8(".") +
                QString::number(Buffer[64]) +
                QString::fromUtf8(".") +
                QString::number(Buffer[65]) +
                QString::fromUtf8("\n   |-Relay agent IP address: ") +
                QString::number(Buffer[66]) +
                QString::fromUtf8(".") +
                QString::number(Buffer[67]) +
                QString::fromUtf8(".") +
                QString::number(Buffer[68]) +
                QString::fromUtf8(".") +
                QString::number(Buffer[69]) +
                QString::fromUtf8("\n   |-Client MAC address: ") +
                QString::number(Buffer[70]) +
                QString::fromUtf8(".") +
                QString::number(Buffer[71]) +
                QString::fromUtf8(".") +
                QString::number(Buffer[72]) +
                QString::fromUtf8(".") +
                QString::number(Buffer[73]) +
                QString::fromUtf8(".") +
                QString::fromUtf8("\n"));
            fprintf(logfile , "%s Header\n", portstr);
            fprintf(logfile ,"   |-Message type: Boot Reply : %d\n", Buffer[42]);
            fprintf(logfile ,"   |-Hardware type: Ethernet (0x%02X) \n", Buffer[43]);
            fprintf(logfile ,"   |-Hardware address length: %d\n", Buffer[44]);
            fprintf(logfile ,"   |-Hops: %d\n", Buffer[45]);
            fprintf(logfile ,"   |-Transaction ID: 0x%02X%02X%02X%02X\n", Buffer[46], Buffer[47], Buffer[48], Buffer[49]);
            fprintf(logfile ,"   |-Seconds elapsed: %d%d\n", Buffer[50], Buffer[51]);
            fprintf(logfile ,"   |-Bootp flags: 0x%02X%02X (Unicast)\n", Buffer[52], Buffer[53]);
            fprintf(logfile ,"   |-Client IP address: %d.%d.%d.%d\n",Buffer[54], Buffer[55], Buffer[56], Buffer[57]);
            fprintf(logfile ,"   |-Your (client) IP address: %d.%d.%d.%d\n",Buffer[58], Buffer[59], Buffer[60], Buffer[61]);
            fprintf(logfile ,"   |-Next server IP address: %d.%d.%d.%d\n",Buffer[62], Buffer[63], Buffer[64], Buffer[65]);
            fprintf(logfile ,"   |-Relay agent IP address: %d.%d.%d.%d\n",Buffer[66], Buffer[67], Buffer[68], Buffer[69]);
            fprintf(logfile ,"   |-Client MAC address: %02X:%02X:%02X:%02X\n", Buffer[70], Buffer[71], Buffer[72], Buffer[73]);
       }
    //packet zadargaag hevleh
    fprintf(logfile , "\n");
    datadumpcnt[datadumpcnt1] = QString::fromUtf8("\nIP Header\n");
    fprintf(logfile , "IP Header\n");
    PrintData(Buffer , iphdrlen);

    fprintf(logfile , "UDP Header\n");
    datadumpcnt[datadumpcnt1].append(QString::fromUtf8("\nUDP Header\n"));
    PrintData(Buffer+iphdrlen , sizeof udph);

    fprintf(logfile , "Data Payload\n");
    datadumpcnt[datadumpcnt1].append(QString::fromUtf8("Data Payload\n"));
    //Move the pointer ahead and reduce the size of string
    PrintData(Buffer + header_size , Size - header_size);

    fprintf(logfile , "\n###########################################################");
    packetDatacnt ++;
    datadumpcnt1 ++;
}

void MainWindow::print_icmp_packet(const u_char * Buffer , int Size)
{
    //icmp packet zadargaa
    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr));
    iphdrlen = iph->ihl * 4;

    struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen  + sizeof(struct ethhdr));

    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof icmph;

    fprintf(logfile , "\n\n***********************ICMP Packet*************************\n");

    print_ip_header(Buffer , Size);

    fprintf(logfile , "\n");
    packetData[packetDatacnt] = QString::fromUtf8("\nICMP Header\n") +
                        QString::fromUtf8("   |-Type : %d"),(unsigned int)(icmph->type);
    fprintf(logfile , "ICMP Header\n");
    fprintf(logfile , "   |-Type : %d",(unsigned int)(icmph->type));

    if((unsigned int)(icmph->type) == 11)
    {
        packetData[packetDatacnt].append(QString::fromUtf8("  (TTL Expired)\n"));
        fprintf(logfile , "  (TTL Expired)\n");
    }
    else if((unsigned int)(icmph->type) == ICMP_ECHOREPLY)
    {
        packetData[packetDatacnt].append(QString::fromUtf8("  (ICMP Echo Reply)\n"));
        fprintf(logfile , "  (ICMP Echo Reply)\n");
    }
    packetData[packetDatacnt].append(QString::fromUtf8("   |-Code : %d\n", (unsigned int)(icmph->code)) +
                             QString::fromUtf8("   |-Checksum : %d\n",ntohs(icmph->checksum)) +
                             QString::fromUtf8("\n"));
    fprintf(logfile , "   |-Code : %d\n",(unsigned int)(icmph->code));
    fprintf(logfile , "   |-Checksum : %d\n",ntohs(icmph->checksum));
    //fprintf(logfile , "   |-ID       : %d\n",ntohs(icmph->id));
    //fprintf(logfile , "   |-Sequence : %d\n",ntohs(icmph->sequence));
    fprintf(logfile , "\n");

    fprintf(logfile , "IP Header\n");
    datadumpcnt[datadumpcnt1] = QString::fromUtf8("IP Header\n");
    PrintData(Buffer,iphdrlen);

    fprintf(logfile , "UDP Header\n");
    datadumpcnt[datadumpcnt1].append(QString::fromUtf8("UDP Header\n"));
    PrintData(Buffer + iphdrlen , sizeof icmph);

    fprintf(logfile , "Data Payload\n");
    datadumpcnt[datadumpcnt1].append(QString::fromUtf8("Data Payload\n"));

    //Move the pointer ahead and reduce the size of string
    PrintData(Buffer + header_size , (Size - header_size) );

    fprintf(logfile , "\n###########################################################");
    packetDatacnt ++;
    datadumpcnt1 ++;
}
void MainWindow::PrintData (const u_char * data , int Size)
{//Data dump iig hevleh
    int i , j, k=0;
    for(i=0 ; i < Size ; i++)
    {
        for(i=0 ; i < Size ; i++)
            {
                k++;
                if( k==16)
                {
                    datadumpcnt[datadumpcnt1].append(QString::fromUtf8("         "));
                    fprintf(logfile , "         ");
                    for(j=i-16 ; j<i ; j++)
                    {
                        if(data[j]>=32 && data[j]<=128)
                        {
                            datadumpcnt[datadumpcnt1].append(QString::asprintf("%c", (unsigned char)data[j]));
                            fprintf(logfile , "%c",(unsigned char)data[j]);
                        }

                        else
                        {
                            datadumpcnt[datadumpcnt1].append(QString::fromUtf8("."));
                            fprintf(logfile , ".");
                        }
                    }
                    datadumpcnt[datadumpcnt1].append(QString::fromUtf8("\n"));
                    fprintf(logfile , "\n");
                    k=0;
                }

        if(k == 16) fprintf(logfile , "   ");
        {
            datadumpcnt[datadumpcnt1].append(QString::asprintf("%02X", (unsigned int)data[i]));
            fprintf(logfile , " %02X",(unsigned int)data[i]);
        }
        if( i==Size-1)
        {
            for(j=0;j<15-i%16;j++)
            {
              datadumpcnt[datadumpcnt1].append(QString::fromUtf8("   "));
              fprintf(logfile , "   ");
            }
            datadumpcnt[datadumpcnt1].append(QString::fromUtf8("         "));
            fprintf(logfile , "         ");

            for(j=i-i%16 ; j<=i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                {
                  datadumpcnt[datadumpcnt1].append(QString::asprintf("%c", (unsigned int) data[j]));
                  fprintf(logfile , "%c",(unsigned char)data[j]);
                }
                else
                {
                  datadumpcnt[datadumpcnt1].append(QString::fromUtf8("."));
                  fprintf(logfile , ".");
                }
            }
            datadumpcnt[datadumpcnt1].append(QString::fromUtf8("\n"));
            fprintf(logfile ,  "\n" );
            }
        }
    }
}
void MainWindow::other_print(const u_char * Buffer, int Size)
{
    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr));
    iphdrlen = iph->ihl * 4;

    struct othershdr *othersh = (struct othershdr *)(Buffer + iphdrlen  + sizeof(struct ethhdr));

    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof othersh;
    fprintf(logfile , "IP Header\n");
    datadumpcnt[datadumpcnt1] = QString::fromUtf8("IP Header\n");
    PrintData(Buffer,iphdrlen);

    fprintf(logfile , "Data Payload\n");
    datadumpcnt[datadumpcnt1].append(QString::fromUtf8("Data Payload\n"));

    //Move the pointer ahead and reduce the size of string
    PrintData(Buffer + header_size , (Size - header_size) );
    packetData[packetDatacnt] = QString::fromUtf8("Задлах боломжгүй");
    packetDatacnt ++;
    datadumpcnt1 ++;
}
MainWindow::~MainWindow()
{
    delete ui;

}

void MainWindow::on_startButton_3_clicked()
{
    //start tovch darhad
    this->mythread.setDev(this->inList[0]);
    this->mythread.start();
    ui->startButton_3->setDisabled(true);
    ui->stopButton_3->setEnabled(true);
    ui->statusBar->showMessage(QString::fromUtf8("Пакетийг бариж байна"),3000);
    for (int i =0;i<datalist.size();i++){
             Entity enti= datalist.value(i);
             enti.data="";
             enti.cnt=0;
             datalist[i]=enti;
         }
}

void MainWindow::on_stopButton_3_clicked()
{
    //stop tovch darhad
    ui->stopButton_3->setEnabled(false);
    ui->startButton_3->setEnabled(true);
    this->mythread.stop();
    ui->statusBar->showMessage(QString::fromUtf8("Пакетийг бариж дууслаа"),9000);
    ui->statusBar->showMessage(QString::fromUtf8("Хамгийн их хэмжээтэй пакет: ") +
                               QString::number(maxp) +
                               QString::fromUtf8("              Хамгийн бага хэмжээтэй пакет: ") +
                               QString::number(minp) +
                               QString::fromUtf8("              Нийт баригдсан пакет: ") +
                               QString::number(total));
}

void MainWindow::printProtocol(const u_char * Buffer, unsigned int sourcaddr, unsigned int destaddr, int total, double time, QString protocol, int Size, char *portNum)
{
    //GUI d gargah
    unsigned short iphdrlen;
    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
    iphdrlen =iph->ihl*4;
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
    QString s_addr = inet_ntoa(source.sin_addr);
    QString d_addr = inet_ntoa(dest.sin_addr);
    QTreeWidgetItem *itm = new QTreeWidgetItem(ui->treeWidget);
    if (protocol == "others")
    {
        itm->setText(0, QString::number(total));
        itm->setText(1,QString::number(time));
        itm->setText(2,s_addr);
        itm->setText(3,d_addr);
        itm->setText(4,protocol);
        itm->setText(5,QString::number(Size));
        itm->setText(6,"Задлах боломжгүй");
    }
    else {
        itm->setText(0, QString::number(total));
        itm->setText(1,QString::number(time));
        itm->setText(2,s_addr);
        itm->setText(3,d_addr);
        itm->setText(4,protocol);
        itm->setText(5,QString::number(Size));
        itm->setText(6,portNum);
        lista.append(QString::fromUtf8("Дугаар: ") + QString::number(total) +
                     QString::fromUtf8("\nХугацаа: ") + QString::number(time) +
                     QString::fromUtf8("\nИлгээгч хаяг: ") + s_addr +
                     QString::fromUtf8("\nХүлээн авах хаяг: ") + d_addr +
                     QString::fromUtf8("\nПротокол: ") + protocol +
                     QString::fromUtf8("\nХэмжээ: ") + QString::number(Size) +
                     QString::fromUtf8("\nТайлбар: ") + portNum + QString::fromUtf8("\n"));
        if (portNum == "HTTP")
            for (int i=0; i < 7; i++)
                itm->setBackgroundColor(i,QColor(74, 157, 153));
        else if (portNum == "HTTPS")
            for (int i=0; i < 7; i++)
                itm->setBackgroundColor(i,QColor(127, 72, 241));
        else if (portNum == "DNS")
            for (int i=0; i < 7; i++)
                itm->setBackgroundColor(i,QColor(229, 153, 96));
        else if (portNum == "NetBIOS")
            for (int i=0; i < 7; i++)
                itm->setBackgroundColor(i, QColor(104, 241, 6));
        else if (portNum == "icmp")
            for (int i = 0;i < 7; i++)
                itm->setBackgroundColor(i, QColor(31, 152, 98));
        else if (portNum == "FTP")
            for (int i=0; i < 7; i++)
                itm->setBackgroundColor(i, QColor(37, 133, 107));
        else if (portNum == "POP")
            for (int i=0; i < 7; i++)
                itm->setBackgroundColor(i, QColor(223, 211, 48));
        else if (portNum = "SNMP")
            for (int i=0; i < 7; i++)
                itm->setBackgroundColor(i, QColor(107, 206, 96));
        else if (portNum == "DHCP")
            for (int i=0; i < 7; i++)
                itm->setBackgroundColor(i, QColor(195, 122, 136));
        else if (protocol == "others")
        {
            itm->setText(6,QString::fromUtf8("Задлах боломжгүй"));
            for (int i=0; i < 7; i++)
                itm->setBackgroundColor(i,Qt::darkGray);
        }
    }
}

void MainWindow::on_treeWidget_clicked(const QModelIndex &index)
{
    //TreeWidget item der darhad hevleh uildel
    ui->textBrowser_2->clear();
    int a = index.row();
    ui->textBrowser->append(ethcnt[a]);
    ui->textBrowser->append(ipcnt[a]);
    if (protocol[a] == "icmp")
    {
        ui->textBrowser->append(QString::fromUtf8("ICMP пакет"));
    }
    else
        ui->textBrowser->append(packetData[a]);
    if (protocol[a] == "tcp")
    {
        ui->textBrowser_2->append(datadumpcnt[a]);
    }
    else if (protocol[a] == "udp")
    {
        ui->textBrowser_2->append(datadumpcnt[a]);
    }
    else if (protocol[a] == "icmp")
    {
        ui->textBrowser_2->append(datadumpcnt[a]);
    }
    else if (protocol[a] == "others")
    {
        ui->textBrowser_2->append(datadumpcnt[a]);
    }
}
void MainWindow::on_pushButton_clicked()
{
    //hailt hiih
    QString a = ui->textEdit->toPlainText();
    form.print(a, lista);
    if (a == "HTTP")
        form.statusChange(a, httpcount);
    else if (a == "HTTPS")
        form.statusChange(a, httpscount);
    else if (a == "DNS")
        form.statusChange(a, dnscount);
    else if (a == "udp")
        form.statusChange(a, udpcount);
    else if (a == "tcp")
        form.statusChange(a, tcpcount);
    else if (a == "DHCP")
        form.statusChange(a, dhcpcount);
    else if (a == "FTP")
        form.statusChange(a, ftpcount);
    else if (a == "NetBIOS")
        form.statusChange(a, netbioscount);
    else if (a == "LDAP")
        form.statusChange(a, ldapcount);
    else if (a == "IMAP")
        form.statusChange(a, imapcount);
    else if (a == "SNMP")
        form.statusChange(a, snmpcount);
    else if (a == "BGP")
        form.statusChange(a, bgpcount);
    else if (a == "LDAPS")
        form.statusChange(a, ldapscount);
    else
        form.ipsearch();
    form.show();
    form.setWindowTitle(QString::fromUtf8("Хайлт"));
    QRegExp regExp(a, Qt::CaseInsensitive, QRegExp::Wildcard);
}
void MainWindow::on_comboBoxPNum_currentIndexChanged(int index)
{
    if (index == 1)
        form.setWindowTitle("40-200");
    else if (index == 2)
        form.setWindowTitle("201-361");
    else if (index == 3)
        form.setWindowTitle("362-522");
    else if (index == 4)
        form.setWindowTitle("523-683");
    else if (index == 5)
        form.setWindowTitle("684-844");
    else if (index == 6)
        form.setWindowTitle("845-1005");
    else if (index == 7)
        form.setWindowTitle("1006-1166");
    else if (index == 8)
        form.setWindowTitle("1167-1327");
    else if (index == 9)
        form.setWindowTitle("1328-1488");
    else if (index == 10)
        form.setWindowTitle("1488-15017");
    //hemjeesiin angilal
    if (index == 1)
    {
        form.printSize(size1);
        form.show();
        form.searchChange(sizedef1, sizesearch1);
    }
    else if (index == 2)
    {
        form.printSize(size2);
        form.show();
        form.searchChange(sizedef2, sizesearch2);
    }
    else if (index == 3)
    {
        form.printSize(size3);
        form.show();
        form.searchChange(sizedef3, sizesearch3);
    }
    else if (index == 4)
    {
        form.printSize(size4);
        form.show();
        form.searchChange(sizedef4, sizesearch4);
    }
    else if (index == 5)
    {
        form.printSize(size5);
        form.show();
        form.searchChange(sizedef5, sizesearch5);
    }
    else if (index == 6)
    {
        form.printSize(size6);
        form.show();
        form.searchChange(sizedef6, sizesearch6);
    }
    else if (index == 7)
    {
        form.printSize(size7);
        form.show();
        form.searchChange(sizedef7, sizesearch7);
    }
    else if (index == 8)
    {
        form.printSize(size8);
        form.show();
        form.searchChange(sizedef8, sizesearch8);
    }
    else if (index == 9)
    {
        form.printSize(size9);
        form.show();
        form.searchChange(sizedef9, sizesearch9);
    }
    else if (index == 10)
    {
        form.printSize(size10);
        form.show();
        form.searchChange(sizedef10, sizesearch10);
    }
}
void MainWindow::sizeFilter(const u_char * Buffer, unsigned int sourcaddr, unsigned int destaddr, int total, double time, QString protocol, int Size, char *portCheck)
{
    //hemjeeger yalgah
    unsigned short iphdrlen;
    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
    iphdrlen =iph->ihl*4;
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
    QString s_addr = inet_ntoa(source.sin_addr);
    QString d_addr = inet_ntoa(dest.sin_addr);
    if (Size > 40 && Size < 200)
    {
        size1.append(QString::fromUtf8("Дугаар: ") + QString::number(total) +
                        QString::fromUtf8("\nХугацаа: ") + QString::number(time) +
                        QString::fromUtf8("\nИлгээгч хаяг: ") + s_addr +
                        QString::fromUtf8("\nХүлээн авах хаяг: ") + d_addr +
                        QString::fromUtf8("\nПротокол: ") + protocol +
                        QString::fromUtf8("\nХэмжээ: ") + QString::number(Size) +
                        QString::fromUtf8("\nТайлбар: ") + portCheck + QString::fromUtf8("\n"));
        sizesearch1 ++;
    }
    else if (Size > 201 && Size < 361)
    {
        size2.append(QString::fromUtf8("Дугаар: ") + QString::number(total) +
                        QString::fromUtf8("\nХугацаа: ") + QString::number(time) +
                        QString::fromUtf8("\nИлгээгч хаяг: ") + s_addr +
                        QString::fromUtf8("\nХүлээн авах хаяг: ") + d_addr +
                        QString::fromUtf8("\nПротокол: ") + protocol +
                        QString::fromUtf8("\nХэмжээ: ") + QString::number(Size) +
                        QString::fromUtf8("\nТайлбар: ") + portCheck + QString::fromUtf8("\n"));
        sizesearch2 ++;
    }
    else if (Size > 362 && Size < 522)
    {
        size3.append(QString::fromUtf8("Дугаар: ") + QString::number(total) +
                        QString::fromUtf8("\nХугацаа: ") + QString::number(time) +
                        QString::fromUtf8("\nИлгээгч хаяг: ") + s_addr +
                        QString::fromUtf8("\nХүлээн авах хаяг: ") + d_addr +
                        QString::fromUtf8("\nПротокол: ") + protocol +
                        QString::fromUtf8("\nХэмжээ: ") + QString::number(Size) +
                        QString::fromUtf8("\nТайлбар: ") + portCheck + QString::fromUtf8("\n"));
        sizesearch3 ++;
    }
    else if (Size > 523 && Size < 683)
    {
        size4.append(QString::fromUtf8("Дугаар: ") + QString::number(total) +
                        QString::fromUtf8("\nХугацаа: ") + QString::number(time) +
                        QString::fromUtf8("\nИлгээгч хаяг: ") + s_addr +
                        QString::fromUtf8("\nХүлээн авах хаяг: ") + d_addr +
                        QString::fromUtf8("\nПротокол: ") + protocol +
                        QString::fromUtf8("\nХэмжээ: ") + QString::number(Size) +
                        QString::fromUtf8("\nТайлбар: ") + portCheck + QString::fromUtf8("\n"));
        sizesearch4 ++;
    }
    else if (Size > 684 && Size < 844)
    {
        size5.append(QString::fromUtf8("Дугаар: ") + QString::number(total) +
                        QString::fromUtf8("\nХугацаа: ") + QString::number(time) +
                        QString::fromUtf8("\nИлгээгч хаяг: ") + s_addr +
                        QString::fromUtf8("\nХүлээн авах хаяг: ") + d_addr +
                        QString::fromUtf8("\nПротокол: ") + protocol +
                        QString::fromUtf8("\nХэмжээ: ") + QString::number(Size) +
                        QString::fromUtf8("\nТайлбар: ") + portCheck + QString::fromUtf8("\n"));
        sizesearch5 ++;
    }
    else if (Size > 845 && Size < 1005)
    {
        size6.append(QString::fromUtf8("Дугаар: ") + QString::number(total) +
                        QString::fromUtf8("\nХугацаа: ") + QString::number(time) +
                        QString::fromUtf8("\nИлгээгч хаяг: ") + s_addr +
                        QString::fromUtf8("\nХүлээн авах хаяг: ") + d_addr +
                        QString::fromUtf8("\nПротокол: ") + protocol +
                        QString::fromUtf8("\nХэмжээ: ") + QString::number(Size) +
                        QString::fromUtf8("\nТайлбар: ") + portCheck + QString::fromUtf8("\n"));
        sizesearch6 ++;
    }
    else if (Size > 1006 && Size < 1166)
    {
        size7.append(QString::fromUtf8("Дугаар: ") + QString::number(total) +
                        QString::fromUtf8("\nХугацаа: ") + QString::number(time) +
                        QString::fromUtf8("\nИлгээгч хаяг: ") + s_addr +
                        QString::fromUtf8("\nХүлээн авах хаяг: ") + d_addr +
                        QString::fromUtf8("\nПротокол: ") + protocol +
                        QString::fromUtf8("\nХэмжээ: ") + QString::number(Size) +
                        QString::fromUtf8("\nТайлбар: ") + portCheck + QString::fromUtf8("\n"));
        sizesearch7 ++;
    }
    else if (Size > 1167 && Size < 1327)
    {
        size8.append(QString::fromUtf8("Дугаар: ") + QString::number(total) +
                        QString::fromUtf8("\nХугацаа: ") + QString::number(time) +
                        QString::fromUtf8("\nИлгээгч хаяг: ") + s_addr +
                        QString::fromUtf8("\nХүлээн авах хаяг: ") + d_addr +
                        QString::fromUtf8("\nПротокол: ") + protocol +
                        QString::fromUtf8("\nХэмжээ: ") + QString::number(Size) +
                        QString::fromUtf8("\nТайлбар: ") + portCheck + QString::fromUtf8("\n"));
        sizesearch8 ++;
    }
    else if (Size > 1328 && Size < 1488)
    {
        size9.append(QString::fromUtf8("Дугаар: ") + QString::number(total) +
                        QString::fromUtf8("\nХугацаа: ") + QString::number(time) +
                        QString::fromUtf8("\nИлгээгч хаяг: ") + s_addr +
                        QString::fromUtf8("\nХүлээн авах хаяг: ") + d_addr +
                        QString::fromUtf8("\nПротокол: ") + protocol +
                        QString::fromUtf8("\nХэмжээ: ") + QString::number(Size) +
                        QString::fromUtf8("\nТайлбар: ") + portCheck + QString::fromUtf8("\n"));
        sizesearch9 ++;
    }
    else if (Size > 1489 && Size < 15017)
    {
        size10.append(QString::fromUtf8("Дугаар: ") + QString::number(total) +
                        QString::fromUtf8("\nХугацаа: ") + QString::number(time) +
                        QString::fromUtf8("\nИлгээгч хаяг: ") + s_addr +
                        QString::fromUtf8("\nХүлээн авах хаяг: ") + d_addr +
                        QString::fromUtf8("\nПротокол: ") + protocol +
                        QString::fromUtf8("\nХэмжээ: ") + QString::number(Size) +
                        QString::fromUtf8("\nТайлбар: ") + portCheck + QString::fromUtf8("\n"));
        sizesearch10 ++;
    }
}
void MainWindow::on_showGButton_clicked()
{
    graph.show();
    graph.setWindowTitle(QString::fromUtf8("График"));
}
void MainWindow::on_comboBox_currentIndexChanged(int index)
{
    if (index == 1)
    {
        NightchartsWidget *wid =new NightchartsWidget;
        wid->setWindowTitle(QString::fromUtf8("Хистограм"));
        wid->setFixedSize(900, 700);
        wid->setFixedSize(900, 700);
        double httpper = (httpcount * 100.0f)/total;
        double httpsper = (httpscount * 100.0f)/total;
        double ftpper = (ftpcount * 100.0f)/total;
        double telnetper = (telnetcount * 100.0f)/total;
        double snmpper = (smtpcount * 100.0f)/total;
        double dnsper = (dnscount * 100.0f)/total;
        double popper = (popcount * 100.0f)/total;
        double netbiosper = (netbioscount * 100.0f)/total;
        double dhcpper = (dhcpcount * 100.0f)/total;
        double othersper = (otherscount * 100.0f)/total;
        wid->addItem(listb[0], QColor(127, 72, 241), httpsper);
        wid->addItem(listb[1], QColor(74, 157, 153), httpper);
        wid->addItem(listb[2], QColor(37, 133, 107), ftpper);
        wid->addItem(listb[3], QColor(150, 39, 55), telnetper);
        wid->addItem(listb[4], QColor(229, 153, 96), dnsper);
        wid->addItem(listb[5], QColor(223, 211, 48), popper);
        wid->addItem(listb[6], QColor(104, 241, 6), netbiosper);
        wid->addItem(listb[7], QColor(107, 206, 96), snmpper);
        wid->addItem(listb[8], QColor(195, 122, 136), dhcpper);
        wid->addItem(listb[9], QColor(0, 0, 0), othersper);
        wid->show();
    }
    else if (index == 2)
    {
        NightchartsWidget *wid =new NightchartsWidget;
        wid->setWindowTitle(QString::fromUtf8("Хистограм"));
            wid->setFixedSize(900, 700);

            for (int i =1,k=0;i<datalist.size();i++,k+=25){
                double dd = 100.0f*(datalist.value(i).cnt/(double)total);
                double per= ((int)ceil(100.0*dd))/100.0;
                wid->addItem(QString::number(datalist.value(i).minValue)+"-"+QString::number(datalist.value(i).maxValue)+"    ",QColor(k,0,255-k),per);
            }

            wid->show();
    }
}

void MainWindow::on_saveButton_clicked()
{
    int ret;
    char oldname[] = "log.txt";
    char logfname[20];
    bool ok;
    QString name = QInputDialog::getText(0, QString::fromUtf8("Файлын мэдээлэл"), QString::fromUtf8("Та файлын нэрээ оруулна уу?"), QLineEdit::Normal, "", &ok);
    //logfname = QString(name).toLatin1();
    //QString(name) + ".txt";
    name += ".txt";
    ret = rename(oldname, QString(name).toLatin1());
    if (ret == 0)
        ui->statusBar->showMessage(QString::fromUtf8("Файлд амжилттай хадгалагдлаа"), 3000);
    else
        ui->statusBar->showMessage(QString::fromUtf8("Файлд хадгалах амжилтгүй боллоо"), 3000);
}
