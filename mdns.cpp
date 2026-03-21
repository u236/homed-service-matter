#include "mdns.h"
#include "logger.h"
#include <QNetworkInterface>
#include <QtEndian>

#define MATTER_COMMISSION_SERVICE   "_matterc._udp.local"
#define MATTER_OPERATIVE_SERVICE    "_matter._tcp.local"

MDNS::MDNS(QObject *parent) : QObject(parent), m_socket(new QUdpSocket(this)), m_browseTimer(new QTimer(this))
{
    connect(m_socket, &QUdpSocket::readyRead, this, &MDNS::readyRead);
    connect(m_browseTimer, &QTimer::timeout, this, &MDNS::browseTimeout);

    m_browseTimer->setSingleShot(true);

    if (m_socket->bind(QHostAddress::AnyIPv4, MDNS_PORT, QAbstractSocket::ShareAddress | QAbstractSocket::ReuseAddressHint))
    {
        m_socket->joinMulticastGroup(QHostAddress(MDNS_MULTICAST_ADDR));
        logInfo << "mDNS listening on" << MDNS_MULTICAST_ADDR << ":" << MDNS_PORT;
    }
    else
        logWarning << "Failed to bind mDNS socket";
}

QByteArray MDNS::encodeName(const QString &name)
{
    QByteArray result;
    QList <QString> labels = name.split('.');

    for (const QString &label : labels)
    {
        QByteArray utf8 = label.toUtf8();
        result.append(static_cast <char> (utf8.length()));
        result.append(utf8);
    }

    result.append('\0');
    return result;
}

QString MDNS::decodeName(const QByteArray &data, quint32 &offset)
{
    QList <QString> labels;
    quint32 saved = 0;
    bool jumped = false;

    while (offset < static_cast <quint32> (data.length()))
    {
        quint8 length = static_cast <quint8> (data.at(offset));

        if (length == 0)
        {
            offset++;
            break;
        }

        if ((length & 0xC0) == 0xC0)
        {
            if (!jumped)
                saved = offset + 2;

            quint16 pointer = (static_cast <quint16> (length & 0x3F) << 8) | static_cast <quint8> (data.at(offset + 1));
            offset = pointer;
            jumped = true;
            continue;
        }

        offset++;

        if (offset + length > static_cast <quint32> (data.length()))
            break;

        labels.append(QString::fromUtf8(data.mid(offset, length)));
        offset += length;
    }

    if (jumped)
        offset = saved;

    return labels.join('.');
}

QByteArray MDNS::encodeQuery(const QString &name, DNS::Type type)
{
    QByteArray data;
    quint16 value;

    value = 0; data.append(reinterpret_cast <const char*> (&value), 2);
    value = 0; data.append(reinterpret_cast <const char*> (&value), 2);
    value = qToBigEndian <quint16> (1); data.append(reinterpret_cast <const char*> (&value), 2);
    value = 0; data.append(reinterpret_cast <const char*> (&value), 2);
    value = 0; data.append(reinterpret_cast <const char*> (&value), 2);
    value = 0; data.append(reinterpret_cast <const char*> (&value), 2);

    data.append(encodeName(name));

    value = qToBigEndian(static_cast <quint16> (type));
    data.append(reinterpret_cast <const char*> (&value), 2);

    value = qToBigEndian(static_cast <quint16> (DNS::Class::IN));
    data.append(reinterpret_cast <const char*> (&value), 2);

    return data;
}

void MDNS::parseRecord(const QByteArray &data, quint32 &offset, DNS::Record &record, bool question)
{
    record.name = decodeName(data, offset);

    if (offset + 4 > static_cast <quint32> (data.length()))
        return;

    record.type = static_cast <DNS::Type> (qFromBigEndian <quint16> (data.constData() + offset));
    offset += 2;

    record.rrclass = qFromBigEndian <quint16> (data.constData() + offset) & 0x7FFF;
    offset += 2;

    if (question)
        return;

    if (offset + 6 > static_cast <quint32> (data.length()))
        return;

    record.ttl = qFromBigEndian <quint32> (data.constData() + offset);
    offset += 4;

    quint16 rdlength = qFromBigEndian <quint16> (data.constData() + offset);
    offset += 2;

    if (offset + rdlength > static_cast <quint32> (data.length()))
        return;

    record.rdata = data.mid(offset, rdlength);
    quint32 rdataEnd = offset + rdlength;

    switch (record.type)
    {
        case DNS::Type::PTR:
            record.ptrName = decodeName(data, offset);
            break;

        case DNS::Type::SRV:

            if (rdlength >= 6)
            {
                record.srvPriority = qFromBigEndian <quint16> (data.constData() + offset);
                offset += 2;
                record.srvWeight = qFromBigEndian <quint16> (data.constData() + offset);
                offset += 2;
                record.srvPort = qFromBigEndian <quint16> (data.constData() + offset);
                offset += 2;
                record.srvTarget = decodeName(data, offset);
            }

            break;

        case DNS::Type::A:

            if (rdlength == 4)
                record.address = QHostAddress(qFromBigEndian <quint32> (reinterpret_cast <const uchar*> (record.rdata.constData())));

            break;

        case DNS::Type::AAAA:

            if (rdlength == 16)
                record.address = QHostAddress(reinterpret_cast <const quint8*> (record.rdata.constData()));

            break;

        case DNS::Type::TXT:
        {
            quint32 pos = 0;

            while (pos < static_cast <quint32> (record.rdata.length()))
            {
                quint8 len = static_cast <quint8> (record.rdata.at(pos++));

                if (pos + len > static_cast <quint32> (record.rdata.length()))
                    break;

                QString entry = QString::fromUtf8(record.rdata.mid(pos, len));
                int eq = entry.indexOf('=');

                if (eq > 0)
                    record.txt.insert(entry.left(eq), entry.mid(eq + 1));

                pos += len;
            }

            break;
        }

        default:
            break;
    }

    offset = rdataEnd;
}

DNS::Message MDNS::decodeMessage(const QByteArray &data)
{
    DNS::Message msg;

    if (data.length() < 12)
        return msg;

    quint32 offset = 0;

    msg.id = qFromBigEndian <quint16> (data.constData() + offset); offset += 2;
    msg.flags = qFromBigEndian <quint16> (data.constData() + offset); offset += 2;

    quint16 qdcount = qFromBigEndian <quint16> (data.constData() + offset); offset += 2;
    quint16 ancount = qFromBigEndian <quint16> (data.constData() + offset); offset += 2;
    quint16 nscount = qFromBigEndian <quint16> (data.constData() + offset); offset += 2;
    quint16 arcount = qFromBigEndian <quint16> (data.constData() + offset); offset += 2;

    for (quint16 i = 0; i < qdcount && offset < static_cast <quint32> (data.length()); i++)
    {
        DNS::Record record;
        parseRecord(data, offset, record, true);
        msg.questions.append(record);
    }

    for (quint16 i = 0; i < ancount && offset < static_cast <quint32> (data.length()); i++)
    {
        DNS::Record record;
        parseRecord(data, offset, record);
        msg.answers.append(record);
    }

    for (quint16 i = 0; i < nscount && offset < static_cast <quint32> (data.length()); i++)
    {
        DNS::Record record;
        parseRecord(data, offset, record);
        msg.authority.append(record);
    }

    for (quint16 i = 0; i < arcount && offset < static_cast <quint32> (data.length()); i++)
    {
        DNS::Record record;
        parseRecord(data, offset, record);
        msg.additional.append(record);
    }

    return msg;
}

void MDNS::parseTxtRecord(const DNS::Record &record, MatterService &service)
{
    for (auto it = record.txt.begin(); it != record.txt.end(); it++)
    {
        if (it.key() == "D")
            service.discriminator = it.value().toUShort();
        else if (it.key() == "VP")
        {
            QList <QString> parts = it.value().split('+');
            service.vendorId = parts.value(0).toUShort();
            service.productId = parts.value(1).toUShort();
        }
        else if (it.key() == "CM")
            service.commissioningMode = static_cast <quint8> (it.value().toUShort());
        else if (it.key() == "DN")
            service.deviceName = it.value();
    }
}

void MDNS::processMdnsResponse(const DNS::Message &message)
{
    QList <DNS::Record> allRecords;
    allRecords.append(message.answers);
    allRecords.append(message.additional);

    for (const DNS::Record &record : allRecords)
    {
        if (record.type == DNS::Type::PTR && record.name == MATTER_COMMISSION_SERVICE)
        {
            MatterService &service = m_services[record.ptrName];
            service.instanceName = record.ptrName;
        }
    }

    for (const DNS::Record &record : allRecords)
    {
        for (auto it = m_services.begin(); it != m_services.end(); it++)
        {
            MatterService &service = it.value();

            if (record.type == DNS::Type::SRV && record.name == service.instanceName)
            {
                service.hostName = record.srvTarget;
                service.port = record.srvPort;
            }
            else if (record.type == DNS::Type::TXT && record.name == service.instanceName)
                parseTxtRecord(record, service);
            else if ((record.type == DNS::Type::A || record.type == DNS::Type::AAAA) && record.name == service.hostName)
                service.address = record.address;
        }
    }

    for (auto it = m_services.begin(); it != m_services.end(); it++)
    {
        const MatterService &service = it.value();

        if (!service.address.isNull() && service.port)
        {
            logInfo << "Matter device found:" << service.instanceName << "at" << service.address.toString() << ":" << service.port << "discriminator:" << service.discriminator;
            emit serviceFound(service);
        }
    }
}

void MDNS::browse(void)
{
    QByteArray query = encodeQuery(MATTER_COMMISSION_SERVICE, DNS::Type::PTR);
    m_socket->writeDatagram(query, QHostAddress(MDNS_MULTICAST_ADDR), MDNS_PORT);
    logInfo << "mDNS browse for commissionable Matter devices";
    m_browseTimer->start(5000);
}

void MDNS::stop(void)
{
    m_browseTimer->stop();
}

void MDNS::resolve(const QString &instanceName)
{
    Q_UNUSED(instanceName)
    // TODO: send targeted SRV/TXT/A queries for specific instance
}

void MDNS::readyRead(void)
{
    while (m_socket->hasPendingDatagrams())
    {
        QByteArray datagram;
        QHostAddress sender;
        quint16 senderPort;

        datagram.resize(m_socket->pendingDatagramSize());
        m_socket->readDatagram(datagram.data(), datagram.size(), &sender, &senderPort);

        DNS::Message msg = decodeMessage(datagram);

        if (msg.isResponse())
            processMdnsResponse(msg);
    }
}

void MDNS::browseTimeout(void)
{
    browse();
}
