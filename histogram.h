#ifndef HISTOGRAM_H
#define HISTOGRAM_H

#include <QWidget>

namespace Ui {
class Histogram;
}

class Histogram : public QWidget
{
    Q_OBJECT

public:
    explicit Histogram(QWidget *parent = 0);
    ~Histogram();
    void setGui();

private:
    Ui::Histogram *ui;
};

#endif // HISTOGRAM_H
