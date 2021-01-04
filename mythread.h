#ifndef MYTHREAD_H
#define MYTHREAD_H
#include <QtCore>

class Mythread : public QThread
{
public:
    char *my_dev;
    Mythread();
    void run() Q_DECL_OVERRIDE;
    void setDev(char *d);
    void stop();
};


#endif // MYTHREAD_H
