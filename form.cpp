#include "form.h"
#include "ui_form.h"

Form::Form(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Form)
{
    ui->setupUi(this);
}

Form::~Form()
{
    delete ui;
}
void Form::print(QString a, QStringList lista)
{
    //hailtiin ur dung hevleh
    ui->listWidget->clear();
    QRegExp regExp(a, Qt::CaseInsensitive, QRegExp::Wildcard);
    ui->listWidget->addItems(lista.filter(regExp));
}
void Form::printSize(QStringList list)
{
    //hemjeeger haisan ur dung hevleh
    ui->listWidget->clear();
    ui->listWidget->addItems(list);
}
void Form::statusChange(QString a, int protocolcount)
{
    ui->label->setText(QString::fromUtf8("Нийт: ") +
                       QString::number(protocolcount) +
                       QString::fromUtf8(" ") +
                       a +
                       QString::fromUtf8(" пакет баригдсан"));
}
void Form::searchChange(QString a, int sizesearch)
{
    ui->label->setText(a + QString::fromUtf8(" Хэмжээтэй пакет: ") + QString::number(sizesearch));
}
void Form::ipsearch()
{
    ui->label->setText("");
}
