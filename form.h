#ifndef FORM_H
#define FORM_H

#include <QWidget>
#include "entity.h"
namespace Ui {
class Form;
}

class Form : public QWidget
{
    Q_OBJECT

public:
    explicit Form(QWidget *parent = 0);
    ~Form();
    void print(QString a, QStringList lista);
    void printSize(QStringList lista);
    void statusChange(QString a, int protocolcount);
    void searchChange(QString a, int sizesearch);
    void ipsearch();
private slots:

private:
    Ui::Form *ui;
};

#endif // FORM_H
