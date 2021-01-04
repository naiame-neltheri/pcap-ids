#include "histogram.h"
#include "ui_histogram.h"
#include "qcustomplot.h"

Histogram::Histogram(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Histogram)
{
    ui->setupUi(this);
    //setGui();
}
void Histogram::setGui()
{
    QLinearGradient gradient(0, 0, 0, 400);
    gradient.setColorAt(0, QColor(90, 90, 90));
    gradient.setColorAt(0.38, QColor(105, 105, 105));
    gradient.setColorAt(1, QColor(70, 70, 70));
    ui->customPlot->setBackground(QBrush(gradient));

    // create empty bar chart objects:
    QCPBars *one = new QCPBars(ui->customPlot->xAxis, ui->customPlot->yAxis);
    QCPBars *two = new QCPBars(ui->customPlot->xAxis, ui->customPlot->yAxis);
    QCPBars *three = new QCPBars(ui->customPlot->xAxis, ui->customPlot->yAxis);
    QCPBars *four = new QCPBars(ui->customPlot->xAxis, ui->customPlot->yAxis);
    QCPBars *five = new QCPBars(ui->customPlot->xAxis, ui->customPlot->yAxis);
    QCPBars *six = new QCPBars(ui->customPlot->xAxis, ui->customPlot->yAxis);
    QCPBars *seven = new QCPBars(ui->customPlot->xAxis, ui->customPlot->yAxis);
    QCPBars *eight = new QCPBars(ui->customPlot->xAxis, ui->customPlot->yAxis);
    QCPBars *nine = new QCPBars(ui->customPlot->xAxis, ui->customPlot->yAxis);
    QCPBars *ten = new QCPBars(ui->customPlot->xAxis, ui->customPlot->yAxis);
    one->setAntialiased(false); // gives more crisp, pixel aligned bar borders
    two->setAntialiased(false);
    three->setAntialiased(false);
    four->setAntialiased(false);
    five->setAntialiased(false);
    six->setAntialiased(false);
    seven->setAntialiased(false);
    eight->setAntialiased(false);
    nine->setAntialiased(false);
    ten->setAntialiased(false);
    one->setStackingGap(1);
    two->setStackingGap(1);
    three->setStackingGap(1);
    four->setStackingGap(1);
    five->setStackingGap(1);
    six->setStackingGap(1);
    seven->setStackingGap(1);
    eight->setStackingGap(1);
    nine->setStackingGap(1);
    ten->setStackingGap(1);
    // set names and colors:
    ten->setName("three fuels");
    ten->setPen(QPen(QColor(50, 250, 250).lighter(170)));
    ten->setBrush(QColor(111, 9, 176));
    nine->setName("three fuels");
    nine->setPen(QPen(QColor(78, 251, 8).lighter(170)));
    nine->setBrush(QColor(111, 9, 176));
    eight->setName("three fuels");
    eight->setPen(QPen(QColor(111, 9, 176).lighter(170)));
    eight->setBrush(QColor(111, 9, 176));
    seven->setName("three fuels");
    seven->setPen(QPen(QColor(111, 9, 176).lighter(170)));
    seven->setBrush(QColor(111, 9, 176));
    six->setName("three fuels");
    six->setPen(QPen(QColor(111, 9, 176).lighter(170)));
    six->setBrush(QColor(111, 9, 176));
    five->setName("three fuels");
    five->setPen(QPen(QColor(111, 9, 176).lighter(170)));
    five->setBrush(QColor(111, 9, 176));
    four->setName("three fuels");
    four->setPen(QPen(QColor(111, 9, 176).lighter(170)));
    four->setBrush(QColor(111, 9, 176));
    three->setName("three fuels");
    three->setPen(QPen(QColor(111, 9, 176).lighter(170)));
    three->setBrush(QColor(111, 9, 176));
    two->setName("two");
    two->setPen(QPen(QColor(250, 170, 20).lighter(150)));
    two->setBrush(QColor(250, 170, 20));
    one->setName("oneerative");
    one->setPen(QPen(QColor(0, 168, 140).lighter(130)));
    one->setBrush(QColor(0, 168, 140));
    // stack bars on top of each other:

    // prepare x axis with country labels:
    QVector<double> ticks;
    QVector<QString> labels;
    ticks << 1 << 2 << 3 << 4 << 5 << 6 << 7 << 8 << 9 << 10;
    labels << "40-200" << "201-361" << "362-522" << "523-683" << "684-844" << "845-1005" << "1006-1166" << "1167-1327" << "1328-1488" << "1489-15017";
    QSharedPointer<QCPAxisTickerText> textTicker(new QCPAxisTickerText);
    textTicker->addTicks(ticks, labels);
    ui->customPlot->xAxis->setTicker(textTicker);
    ui->customPlot->xAxis->setTickLabelRotation(60);
    ui->customPlot->xAxis->setSubTicks(false);
    ui->customPlot->xAxis->setTickLength(0, 4);
    ui->customPlot->xAxis->setRange(0, 11);
    ui->customPlot->xAxis->setBasePen(QPen(Qt::white));
    ui->customPlot->xAxis->setTickPen(QPen(Qt::white));
    ui->customPlot->xAxis->grid()->setVisible(true);
    ui->customPlot->xAxis->grid()->setPen(QPen(QColor(130, 130, 130), 0, Qt::DotLine));
    ui->customPlot->xAxis->setTickLabelColor(Qt::white);
    ui->customPlot->xAxis->setLabelColor(Qt::white);

    // prepare y axis:
    ui->customPlot->yAxis->setRange(0, 12.1);
    ui->customPlot->yAxis->setPadding(5); // a bit more space to the left border
    ui->customPlot->yAxis->setLabel(QString::fromUtf8("Пакетийн хэмжээ"));
    ui->customPlot->yAxis->setBasePen(QPen(Qt::white));
    ui->customPlot->yAxis->setTickPen(QPen(Qt::white));
    ui->customPlot->yAxis->setSubTickPen(QPen(Qt::white));
    ui->customPlot->yAxis->grid()->setSubGridVisible(true);
    ui->customPlot->yAxis->setTickLabelColor(Qt::white);
    ui->customPlot->yAxis->setLabelColor(Qt::white);
    ui->customPlot->yAxis->grid()->setPen(QPen(QColor(130, 130, 130), 0, Qt::SolidLine));
    ui->customPlot->yAxis->grid()->setSubGridPen(QPen(QColor(130, 130, 130), 0, Qt::DotLine));

    // Add data:
    QVector<double> threeData, twoData, oneData, fourData, fiveData, sixData, sevenData, eightData, nineData, tenData;
    tenData << 0.86*10.5 << 0.83*5.5 << 0.84*5.5 << 0.52*5.8 << 0.89*5.2 << 0.90*4.2 << 0.67*11.2;
    nineData << 0.86*10.5 << 0.83*5.5 << 0.84*5.5 << 0.52*5.8 << 0.89*5.2 << 0.90*4.2 << 0.67*11.2;
    eightData << 0.86*10.5 << 0.83*5.5 << 0.84*5.5 << 0.52*5.8 << 0.89*5.2 << 0.90*4.2 << 0.67*11.2;
    sevenData << 0.86*10.5 << 0.83*5.5 << 0.84*5.5 << 0.52*5.8 << 0.89*5.2 << 0.90*4.2 << 0.67*11.2;
    sixData << 0.86*10.5 << 0.83*5.5 << 0.84*5.5 << 0.52*5.8 << 0.89*5.2 << 0.90*4.2 << 0.67*11.2;
    fiveData << 0.86*10.5 << 0.83*5.5 << 0.84*5.5 << 0.52*5.8 << 0.89*5.2 << 0.90*4.2 << 0.67*11.2;
    fourData << 0.86*10.5 << 0.83*5.5 << 0.84*5.5 << 0.52*5.8 << 0.89*5.2 << 0.90*4.2 << 0.67*11.2;
    threeData  << 0.86*10.5 << 0.83*5.5 << 0.84*5.5 << 0.52*5.8 << 0.89*5.2 << 0.90*4.2 << 0.67*11.2;
    twoData << 0.08*10.5 << 0.12*5.5 << 0.12*5.5 << 0.40*5.8 << 0.09*5.2 << 0.00*4.2 << 0.07*11.2;
    oneData   << 0.06*10.5 << 0.05*5.5 << 0.04*5.5 << 0.06*5.8 << 0.02*5.2 << 0.07*4.2 << 0.25*11.2;
    ten->setData(ticks, tenData);
    nine->setData(ticks, nineData);
    eight->setData(ticks, eightData);
    seven->setData(ticks, sevenData);
    six->setData(ticks, sixData);
    five->setData(ticks, fiveData);
    four->setData(ticks, fourData);
    three->setData(ticks, threeData);
    two->setData(ticks, twoData);
    one->setData(ticks, oneData);

    // setup legend:
    ui->customPlot->legend->setVisible(true);
    ui->customPlot->axisRect()->insetLayout()->setInsetAlignment(0, Qt::AlignTop|Qt::AlignHCenter);
    ui->customPlot->legend->setBrush(QColor(255, 255, 255, 100));
    ui->customPlot->legend->setBorderPen(Qt::NoPen);
    QFont legendFont = font();
    legendFont.setPointSize(10);
    ui->customPlot->legend->setFont(legendFont);
    ui->customPlot->setInteractions(QCP::iRangeDrag | QCP::iRangeZoom);
}
Histogram::~Histogram()
{
    delete ui;
}
