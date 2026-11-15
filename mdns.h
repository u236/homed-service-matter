// NOT REWIEWED

#ifndef MDNS_H
#define MDNS_H

#define MDNS_ADDRESS_IPV4               "224.0.0.251"
#define MDNS_ADDRESS_IPV6               "ff02::fb"
#define MDNS_PORT                       5353
#define MDNS_BROWSE_INTERVAL            5000

#define MDNS_FLAG_RESPONSE              0x8000
#define MDNS_CLASS_MASK                 0x7FFF

#define MATTER_COMMISSIONABLE_SERVICE   "_matterc._udp.local"
#define MATTER_OPERATIONAL_SERVICE      "_matter._tcp.local"

#include <QHostAddress>
#include <QTimer>
#include <QUdpSocket>

#pragma pack(push, 1)

struct dnsHeaderStruct
{
    quint16 id;
    quint16 flags;
    quint16 questions;
    quint16 answers;
    quint16 authority;
    quint16 additional;
};

struct dnsQuestionStruct
{
    quint16 type;
    quint16 recordClass;
};

struct dnsRecordStruct
{
    quint16 type;
    quint16 recordClass;
    quint32 ttl;
    quint16 length;
};

struct dnsServiceStruct
{
    quint16 priority;
    quint16 weight;
    quint16 port;
};

#pragma pack(pop)

namespace DNS
{
    enum class Type : quint16
    {
        A       = 1,
        PTR     = 12,
        TXT     = 16,
        AAAA    = 28,
        SRV     = 33,
        ANY     = 255
    };

    enum class Class : quint16
    {
        IN      = 1
    };

    struct Record
    {
        QString                 name;
        Type                    type;
        quint16                 recordClass;
        quint32                 ttl;
        QByteArray              data;

        QString                 pointer;
        QString                 target;
        quint16                 port;
        quint16                 priority;
        quint16                 weight;
        QHostAddress            address;
        QMap <QString, QString> text;

        Record(void) : type(Type::A), recordClass(0), ttl(0), port(0), priority(0), weight(0) {}
    };

    struct Message
    {
        quint16                 id;
        quint16                 flags;
        QList <Record>          questions;
        QList <Record>          answers;
        QList <Record>          authority;
        QList <Record>          additional;

        Message(void) : id(0), flags(0) {}
    };
}

struct MatterService
{
    QString      instanceName;
    QString      hostName;
    QHostAddress address;
    quint16      port;
    quint16      discriminator;
    quint16      vendorId;
    quint16      productId;
    quint8       commissioningMode;
    QString      deviceName;
    bool         operational;

    MatterService(void) : port(0), discriminator(0), vendorId(0), productId(0), commissioningMode(0), operational(false) {}
};

class MDNS : public QObject
{
    Q_OBJECT

public:

    MDNS(QObject *parent);

    void browse(void);
    void stop(void);
    void purgeOperational(const QHostAddress &address);

private:

    QUdpSocket *m_socket4, *m_socket6;
    QTimer *m_timer;

    QMap <QString, MatterService> m_services;

    QByteArray encodeName(const QString &name);
    QString decodeName(const QByteArray &data, quint32 &offset);

    QByteArray encodeQuery(const QString &name, DNS::Type type);
    DNS::Message decodeMessage(const QByteArray &data);

    void parseRecord(const QByteArray &data, quint32 &offset, DNS::Record &record, bool question = false);
    void parseText(const DNS::Record &record, MatterService &service);
    void parseResponse(const DNS::Message &message);

private slots:

    void readyRead(void);

signals:

    void serviceFound(const MatterService &service);
    void serviceResolved(const MatterService &service);

};

#endif
