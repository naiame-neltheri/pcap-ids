#-------------------------------------------------
#
# Project created by QtCreator 2016-12-19T20:21:10
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets printsupport

TARGET = pcap
TEMPLATE = app
LIBS += -lpcap

SOURCES += main.cpp\
        mainwindow.cpp \
    mythread.cpp \
    form.cpp \
    entity.cpp \
    qcustomplot.cpp \
    graph.cpp \
    nightcharts.cpp \
    nightchartswidget.cpp \
    histogram.cpp

HEADERS  += mainwindow.h \
    mythread.h \
    form.h \
    entity.h \
    qcustomplot.h \
    graph.h \
    nightcharts.h \
    nightchartswidget.h \
    histogram.h

FORMS    += mainwindow.ui \
    form.ui \
    graph.ui \
    histogram.ui

DISTFILES +=
