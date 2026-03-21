#ifndef MDNS_H
#define MDNS_H

#include <QObject>
#include <QUdpSocket>
#include <QHostAddress>
#include <QTimer>
#include <QMap>

/*
    mDNS/DNS-SD for Matter device discovery — spec section 4.3

    Matter devices advertise via mDNS:
    - Commissionable: _matterc._udp.local (with discriminator, vendor/product)
    - Commissioned:   _matter._tcp.local (operational discovery)

    DNS-SD TXT records for commissionable devices:
    - D=<discriminator>     (12-bit long discriminator)
    - VP=<vendor>+<product> (vendor and product ID)
    - CM=<mode>             (commissioning mode: 0=not, 1=basic, 2=enhanced)
    - DT=<device type>      (optional)
    - DN=<device name>      (optional)

    mDNS uses multicast:
    - IPv4: 224.0.0.251:5353
    - IPv6: ff02::fb:5353
*/

#define MDNS_MULTICAST_ADDR     "224.0.0.251"
#define MDNS_PORT               5353

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
        QString name;
        Type type;
        quint16 rrclass;
        quint32 ttl;
        QByteArray rdata;

        QString ptrName;
        QString srvTarget;
        quint16 srvPort;
        quint16 srvPriority;
        quint16 srvWeight;
        QHostAddress address;
        QMap <QString, QString> txt;

        Record(void) : type(Type::A), rrclass(0), ttl(0), srvPort(0), srvPriority(0), srvWeight(0) {}
    };

    struct Message
    {
        quint16 id;
        quint16 flags;
        QList <Record> questions;
        QList <Record> answers;
        QList <Record> authority;
        QList <Record> additional;

        bool isResponse(void) { return flags & 0x8000; }

        Message(void) : id(0), flags(0) {}
    };
}

struct MatterService
{
    QString instanceName;
    QString hostName;
    QHostAddress address;
    quint16 port;
    quint16 discriminator;
    quint16 vendorId;
    quint16 productId;
    quint8 commissioningMode;
    QString deviceName;

    MatterService(void) : port(0), discriminator(0), vendorId(0), productId(0), commissioningMode(0) {}
};

class MDNS : public QObject
{
    Q_OBJECT

public:

    MDNS(QObject *parent);

    void browse(void);
    void stop(void);
    void resolve(const QString &instanceName);

private:

    QUdpSocket *m_socket;
    QTimer *m_browseTimer;

    QMap <QString, MatterService> m_services;

    QByteArray encodeName(const QString &name);
    QString decodeName(const QByteArray &data, quint32 &offset);

    QByteArray encodeQuery(const QString &name, DNS::Type type);
    DNS::Message decodeMessage(const QByteArray &data);
    void parseRecord(const QByteArray &data, quint32 &offset, DNS::Record &record, bool question = false);

    void parseTxtRecord(const DNS::Record &record, MatterService &service);
    void processMdnsResponse(const DNS::Message &message);

private slots:

    void readyRead(void);
    void browseTimeout(void);

signals:

    void serviceFound(const MatterService &service);
    void serviceResolved(const MatterService &service);

};

#endif
