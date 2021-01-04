#ifndef MYTHREAD1_H
#define MYTHREAD1_H
#include "QtCore"

class Mythread1 : public QThread
{
public:
    Mythread1();
    void run() Q_DECL_OVERRIDE;
};

#endif // MYTHREAD1_H
