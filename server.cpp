#include <QtWidgets>
#include <QtNetwork>
#include <QtCore>
#include <QNetworkSession>
#include "server.h"

Server::Server(QWidget *parent)
    : QDialog(parent)
    , statusLabel(new QLabel)
    , messageDisplay(new QTextEdit)
    , sendMessage(new QLineEdit)
    , sendMessageButton(new QPushButton(tr("Envoyer")))
{
    setWindowTitle(tr("Server"));
    setStyleSheet("QWidget {"
                  "background-color: #2c2c2c;"   // Fond de la fenêtre en gris foncé
                  "color: #e0e0e0;"               // Texte en gris clair
                  "font-size: 12pt;"               // Taille de police ajustée
                  "font-family: Arial;"            // Police utilisée
                  "}"
                  "QPushButton {"
                  "background-color: #444444;"     // Fond des boutons gris foncé
                  "border: 1px solid #666666;"     // Bordure gris clair
                  "color: white;"                  // Texte du bouton en blanc
                  "padding: 10px 20px;"            // Espacement intérieur des boutons
                  "border-radius: 5px;"            // Coins arrondis des boutons
                  "}"
                  "QPushButton:hover {"
                  "background-color: #555555;"     // Changer le fond des boutons au survol
                  "}"
                  "QLineEdit, QTextEdit {"
                  "background-color: #333333;"     // Fond des champs de texte en gris foncé
                  "color: white;"                  // Texte des champs de texte en blanc
                  "border: 1px solid #66666;"     // Bordure des champs de texte
                  "padding: 5px;"                  // Espacement intérieur des champs de texte
                  "}"
                  "QLabel {"
                  "color: #e0e0e0;"                // Texte des labels en gris clair
                  "}"
                  "QComboBox {"
                  "background-color: #333333;"     // Fond des comboboxes en gris foncé
                  "color: white;"                  // Texte en blanc
                  "border: 1px solid #666666;"     // Bordure gris clair
                  "}"
                  "QComboBox:hover {"
                  "background-color: #444444;"     // Changer le fond de la combobox au survol
                  "}"
                  "QPushButton:pressed {"
                  "background-color: #666666;"     // Fond des boutons quand pressés
                  "}");
    setWindowFlags(windowFlags() & ~Qt::WindowContextHelpButtonHint);
    statusLabel->setTextInteractionFlags(Qt::TextBrowserInteraction);
    messageDisplay->setReadOnly(true);
    sendMessageButton->setStyleSheet("background-color: blue; color: white;");  // Ajout du fond bleu et du texte en blanc
    QNetworkConfigurationManager manager;
    if (manager.capabilities() & QNetworkConfigurationManager::NetworkSessionRequired) {
        QSettings settings(QSettings::UserScope, QLatin1String("QtProject"));
        settings.beginGroup(QLatin1String("QtNetwork"));
        const QString id = settings.value(QLatin1String("DefaultNetworkConfiguration")).toString();
        settings.endGroup();
        QNetworkConfiguration config = manager.configurationFromIdentifier(id);
        if ((config.state() & QNetworkConfiguration::Discovered) != QNetworkConfiguration::Discovered) {
            config = manager.defaultConfiguration();
        }
        networkSession = new QNetworkSession(config, this);
        connect(networkSession, &QNetworkSession::opened, this, &Server::sessionOpened);
        statusLabel->setText(tr("Ouverture de la session réseau."));
        networkSession->open();
    } else {
        sessionOpened();
    }

    tcpServer = new QTcpServer(this);
    if (!tcpServer->listen()) {
        QMessageBox::critical(this, tr("Serveur Fortune"),
                              tr("Impossible de démarrer le serveur : %1.")
                                  .arg(tcpServer->errorString()));
        close();
        return;
    }

    QString ipAddress;
    QList<QHostAddress> ipAddressesList = QNetworkInterface::allAddresses();
    for (const QHostAddress &address : ipAddressesList) {
        if (address != QHostAddress::LocalHost && address.toIPv4Address()) {
            ipAddress = address.toString();
            break;
        }
    }
    if (ipAddress.isEmpty())
        ipAddress = QHostAddress(QHostAddress::LocalHost).toString();

    statusLabel->setText(tr("%1\n%2\n")
                             .arg(ipAddress).arg(tcpServer->serverPort()));

    connect(tcpServer, &QTcpServer::newConnection, this, &Server::newClientConnection);
    connect(sendMessageButton, &QPushButton::clicked, this, &Server::sendMessageToClients);

    auto mainLayout = new QVBoxLayout(this);
     mainLayout->addWidget(statusLabel);
    mainLayout->addWidget(new QLabel(tr("Tapez un message :")));
    mainLayout->addWidget(sendMessage);
    mainLayout->addWidget(sendMessageButton);
    mainLayout->addWidget(new QLabel(tr("Chat :")));
    mainLayout->addWidget(messageDisplay);


    setLayout(mainLayout);

    // Augmenter la taille de la fenêtre
    resize(400, 400);
}

void Server::sessionOpened() {
    if (networkSession) {
        QNetworkConfiguration config = networkSession->configuration();
        QString id;
        if (config.type() == QNetworkConfiguration::UserChoice)
            id = networkSession->sessionProperty(QLatin1String("UserChoiceConfiguration")).toString();
        else
            id = config.identifier();
        QSettings settings(QSettings::UserScope, QLatin1String("QtProject"));
        settings.beginGroup(QLatin1String("QtNetwork"));
        settings.setValue(QLatin1String("DefaultNetworkConfiguration"), id);
        settings.endGroup();
    }
}

void Server::newClientConnection() {
    QTcpSocket *clientConnection = tcpServer->nextPendingConnection();
    clientConnections.append(clientConnection); // Ajouter le client à la liste des connexions
    QString clientIp = clientConnection->peerAddress().toString();
    // Enlever le préfixe "::ffff:" si présent
    if (clientIp.startsWith("::ffff:")) {
        clientIp = clientIp.mid(7);
    }
    displayMessage("<LOGS>", tr("Client connecté (%1)").arg(clientIp));
    connect(clientConnection, &QAbstractSocket::disconnected, this, &Server::clientDisconnected);
    connect(clientConnection, &QIODevice::readyRead, this, [=]() {
        QDataStream in(clientConnection);
        in.setVersion(QDataStream::Qt_5_0);
        QString message;
        in >> message;

        // Afficher le message sur l'interface du serveur
        displayMessage("Client", message);

        // Envoyer le message à tous les clients sauf l'expéditeur
        sendMessageToAllClients(message, clientConnection);
    });
}

void Server::clientDisconnected() {
    QTcpSocket *clientConnection = qobject_cast<QTcpSocket *>(sender());
    QString clientIp = clientConnection->peerAddress().toString();
    // Enlever le préfixe "::ffff:" si présent
    if (clientIp.startsWith("::ffff:")) {
        clientIp = clientIp.mid(7);
    }
    displayMessage("<LOGS>", tr("Client deconnecté (%1)").arg(clientIp));
    if (clientConnection) {
        clientConnections.removeAll(clientConnection);
        clientConnection->deleteLater();
    }
}

void Server::sendMessageToClients() {
    QString message = sendMessage->text();
    if (message.isEmpty()) {
        return;
    }
    displayMessage("Vous", message);

    // Envoyer le message à tous les clients
    sendMessageToAllClients(message);
    sendMessage->clear();
}

void Server::sendMessageToAllClients(const QString &message, QTcpSocket *excludeSocket) {
    QByteArray block;
    QDataStream out(&block, QIODevice::WriteOnly);
    out.setVersion(QDataStream::Qt_5_0);
    out << message;

    for (QTcpSocket *clientConnection : qAsConst(clientConnections)) {
        if (clientConnection != excludeSocket) {
            clientConnection->write(block);
            clientConnection->flush();
        }
    }
}

void Server::displayMessage(const QString &sender, const QString &message) {
    QString timeStamp = QDateTime::currentDateTime().toString("dd/MM/yyyy | hh:mm:ss");
    messageDisplay->append(QString("[%1] %2 : %3").arg(timeStamp, sender, message));
}
