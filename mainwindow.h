#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "myprint.h"
#include "pcap.h"
#include "mythread.h"
#include "QTreeWidgetItem"
#include<sys/socket.h>
#include<arpa/inet.h>
#include<net/ethernet.h>
#include<netinet/ip_icmp.h>   //Provides declarations for icmp header
#include<netinet/udp.h>   //Provides declarations for udp header
#include<netinet/tcp.h>   //Provides declarations for tcp header
#include<netinet/ip.h>    //Provides declarations for ip header
#include<time.h>
#include<sys/time.h>
#include "entity.h"
#include"QPaintEvent"
#include "QRegExp"
#include"QDebug"
#include "form.h"
#include "qcustomplot.h"
#include "graph.h"
#include "histogram.h"
namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    Graph graph;
    Histogram histogr;
    Form form;
     MainWindow(QWidget *parent = 0);
    ~MainWindow();
    char *inList[10];
    void dataAppend(QString a,int count,long long len);
    static void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer);
    static void print_ethernet_header(const u_char *Buffer, int Size);
    static void print_ip_header(const u_char * Buffer, int Size);
    static void print_tcp_packet(const u_char * Buffer, int Size);
    static void print_udp_packet(const u_char *Buffer , int Size);
    static void print_icmp_packet(const u_char * Buffer , int Size);
    static void PrintData (const u_char * data , int Size);
    static void other_print(const u_char * Buffer, int Size);
    void printProtocol(const u_char * Buffer, unsigned int sourcaddr, unsigned int destaddr, int total, double time, QString protocol, int Size, char *portstr);
    void setDev(char *d);
    void stop();
    void ui_print_ethernet_header(ethhdr *eth, int total);
    ethhdr return_ethernet_header(const u_char *Buffer, int Size);
    //void logPrint(QTreeWidgetItem *itm, int col);
    static MainWindow *get_inst();
    QList<Entity> datalist;
    void callGrap(int total, double time, int size);
    void sizeFilter(const u_char * Buffer, unsigned int sourcaddr, unsigned int destaddr, int total, double time, QString protocol, int Size, char *portstr);
private slots:
    void on_startButton_3_clicked();

    void on_stopButton_3_clicked();

    void on_treeWidget_clicked(const QModelIndex &index);

    void on_pushButton_clicked();

    void on_comboBoxPNum_currentIndexChanged(int index);

    void on_showGButton_clicked();

    void on_comboBox_currentIndexChanged(int index);

    void on_saveButton_clicked();

private:
    Ui::MainWindow *ui;
    static MainWindow* s_inst;
    Mythread mythread;
    QStringList myList;
signals:
    void newTextEntered(const QString &text);
};
#endif // MAINWINDOW_H
