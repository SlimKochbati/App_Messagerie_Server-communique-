#ifndef SERVER_H
#define SERVER_H

#include <QDialog>
#include <QString>
#include <QVector>
#include <QTcpServer>
#include <QTcpSocket>
#include <QNetworkSession>
#include <QTextEdit>

QT_BEGIN_NAMESPACE
class QLabel;
class QLineEdit;
QT_END_NAMESPACE

class Server : public QDialog
{
    Q_OBJECT

public:
    explicit Server(QWidget *parent = nullptr);

private slots:
    void sessionOpened();
    void displayMessage(const QString &sender, const QString &message);
    void newClientConnection();
    void clientDisconnected();
    void sendMessageToClients();
    void sendMessageToAllClients(const QString &message, QTcpSocket *excludeSocket = nullptr);


private:
    QLabel *statusLabel = nullptr;
    QTcpServer *tcpServer = nullptr;
    QVector<QString> fortunes;
    QNetworkSession *networkSession = nullptr;
    QTextEdit *messageDisplay;
    QLineEdit *sendMessage;
    QPushButton *sendMessageButton;
    QList<QTcpSocket*> clientConnections;

};

#endif
