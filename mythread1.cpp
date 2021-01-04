#include "mythread1.h"
#include "mainwindow.h"

Mythread1::Mythread1()
{

}

void Mythread1::run()
{
    MainWindow mw;
        while (1)
        {
            mw.getMyText();
        }
    }
