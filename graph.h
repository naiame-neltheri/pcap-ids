#ifndef GRAPH_H
#define GRAPH_H

#include <QWidget>
#include "qcustomplot.h"
namespace Ui {
class Graph;
}

class Graph : public QWidget
{
    Q_OBJECT

public:
    QCustomPlot customPlot;
    explicit Graph(QWidget *parent = 0);
    ~Graph();
    void setUpGrap(int total, clock_t tot, int size);
    void realtimeDataSlot(int size, clock_t tot);
private:
    Ui::Graph *ui;
};

#endif // GRAPH_H
