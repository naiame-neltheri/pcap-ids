#include "graph.h"
#include "ui_graph.h"
#include "time.h"
#include "QTimer"
QTimer dataTimer;
clock_t start, stop;

Graph::Graph(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Graph)
{
    ui->setupUi(this);
}
void Graph::setUpGrap(int total, clock_t tot, int size)
{
    ui->plot->addGraph(); // blue line
    ui->plot->graph(0)->setPen(QPen(QColor(40, 110, 255)));

    QSharedPointer<QCPAxisTickerTime> timeTicker(new QCPAxisTickerTime);
    timeTicker->setTimeFormat("%h:%m:%s");
    ui->plot->xAxis->setTicker(timeTicker);
    ui->plot->axisRect()->setupFullAxesBox();
    ui->plot->yAxis->setRange(0, 3000);
    ui->plot->yAxis->setLabel(QString::fromUtf8("Пакетын урт(byte)"));
    ui->plot->xAxis->setLabel(QString::fromUtf8("Хугацаа (секунд)"));

    // make left and bottom axes transfer their ranges to right and top axes:
    connect(ui->plot->xAxis, SIGNAL(rangeChanged(QCPRange)), ui->plot->xAxis2, SLOT(setRange(QCPRange)));
    connect(ui->plot->yAxis, SIGNAL(rangeChanged(QCPRange)), ui->plot->yAxis2, SLOT(setRange(QCPRange)));

    // setup a timer that repeatedly calls MainWindow::realtimeDataSlot:
    connect(&dataTimer, SIGNAL(timeout()), this, SLOT(realtimeDataSlot()));
    dataTimer.start(0); // Interval 0 means to refresh as fast as possible
    Graph::realtimeDataSlot(size, tot);
}
void Graph::realtimeDataSlot(int size, clock_t tot)
{
    static QTime time(QTime::currentTime());
    // calculate two new data points:
    double key = time.elapsed()/1000.0; // time elapsed since start of demo, in seconds
    static double lastPointKey = 0;
    if (key-lastPointKey > 0.002) // at most add point every 2 ms
    {
      // add data to lines:
      ui->plot->graph(0)->addData(key, size);
      // rescale value (vertical) axis to fit the current data:
      //ui->plot->graph(0)->rescaleValueAxis();
      //ui->plot->graph(1)->rescaleValueAxis(true);
      lastPointKey = key;
    }
    // make key axis range scroll with the data (at a constant range size of 8):
    ui->plot->xAxis->setRange(key, 8, Qt::AlignRight);
    ui->plot->replot();

    // calculate frames per second:
    static double lastFpsKey;
    static int frameCount;
    ++frameCount;
}
Graph::~Graph()
{
    delete ui;
}
