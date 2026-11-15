// NOT REWIEWED

#include <QtEndian>
#include "logger.h"
#include "mdns.h"

MDNS::MDNS(QObject *parent) : QObject(parent), m_socket4(new QUdpSocket(this)), m_socket6(new QUdpSocket(this)), m_timer(new QTimer(this))
{
    connect(m_socket4, &QUdpSocket::readyRead, this, &MDNS::readyRead);
    connect(m_socket6, &QUdpSocket::readyRead, this, &MDNS::readyRead);
    connect(m_timer, &QTimer::timeout, this, &MDNS::browse);

    m_timer->setSingleShot(true);

    if (m_socket4->bind(QHostAddress::AnyIPv4, MDNS_PORT, QAbstractSocket::ShareAddress | QAbstractSocket::ReuseAddressHint))
    {
        m_socket4->joinMulticastGroup(QHostAddress(MDNS_ADDRESS_IPV4));
        logInfo << "mDNS listening on" << MDNS_ADDRESS_IPV4 << "port" << MDNS_PORT;
    }

    if (m_socket6->bind(QHostAddress::AnyIPv6, MDNS_PORT, QAbstractSocket::ShareAddress | QAbstractSocket::ReuseAddressHint))
    {
        m_socket6->joinMulticastGroup(QHostAddress(MDNS_ADDRESS_IPV6));
        logInfo << "mDNS listening on" << MDNS_ADDRESS_IPV6 << "port" << MDNS_PORT;
    }
}

void MDNS::browse(void)
{
    QList <QString> list = {MATTER_COMMISSIONABLE_SERVICE, MATTER_OPERATIONAL_SERVICE};

    for (int i = 0; i < list.count(); i++)
    {
        QByteArray query = encodeQuery(list.at(i), DNS::Type::PTR);
        m_socket4->writeDatagram(query, QHostAddress(MDNS_ADDRESS_IPV4), MDNS_PORT);
        m_socket6->writeDatagram(query, QHostAddress(MDNS_ADDRESS_IPV6), MDNS_PORT);
    }

    logInfo << "mDNS browsing for commissionable and operational Matter devices...";
    m_timer->start(MDNS_BROWSE_INTERVAL);
}

void MDNS::stop(void)
{
    m_timer->stop();
}

void MDNS::purgeOperational(const QHostAddress &address)
{
    // some peers (e.g. Shelly 1PM) keep advertising themselves after removal from the fabric, drop the cache entry so subsequent browses don't find the ghost
    for (auto it = m_services.begin(); it != m_services.end(); )
    {
        if (!it.value().operational || it.value().address != address)
        {
            it++;
            continue;
        }

        logInfo << "mDNS operational entry" << it.value().instanceName << "purged";
        it = m_services.erase(it);
    }
}

QByteArray MDNS::encodeName(const QString &name)
{
    QList <QString> list = name.split('.');
    QByteArray data;

    for (int i = 0; i < list.count(); i++)
    {
        QByteArray label = list.at(i).toUtf8();
        data.append(static_cast <char> (label.length())).append(label);
    }

    return data.append('\0');
}

QString MDNS::decodeName(const QByteArray &data, quint32 &offset)
{
    QList <QString> list;
    quint32 position = 0;
    bool jumped = false;

    while (offset < static_cast <quint32> (data.length()))
    {
        quint8 length = static_cast <quint8> (data.at(offset));

        if (!length)
        {
            offset++;
            break;
        }

        if ((length & 0xC0) == 0xC0)
        {
            if (!jumped)
                position = offset + 2;

            offset = static_cast <quint16> ((length & 0x3F) << 8) | static_cast <quint8> (data.at(offset + 1));
            jumped = true;
            continue;
        }

        if (++offset + length > static_cast <quint32> (data.length()))
            break;

        list.append(QString::fromUtf8(data.mid(offset, length)));
        offset += length;
    }

    if (jumped)
        offset = position;

    return list.join('.');
}

QByteArray MDNS::encodeQuery(const QString &name, DNS::Type type)
{
    dnsHeaderStruct header;
    dnsQuestionStruct question;

    memset(&header, 0, sizeof(header));
    header.questions = qToBigEndian <quint16> (1);

    question.type = qToBigEndian(static_cast <quint16> (type));
    question.recordClass = qToBigEndian(static_cast <quint16> (DNS::Class::IN));

    return QByteArray(reinterpret_cast <char*> (&header), sizeof(header)).append(encodeName(name)).append(reinterpret_cast <char*> (&question), sizeof(question));
}

DNS::Message MDNS::decodeMessage(const QByteArray &data)
{
    DNS::Message message;
    dnsHeaderStruct header;
    quint32 offset = sizeof(header);

    if (static_cast <size_t> (data.length()) < sizeof(header))
        return message;

    memcpy(&header, data.constData(), sizeof(header));

    message.id = qFromBigEndian(header.id);
    message.flags = qFromBigEndian(header.flags);

    for (quint16 i = 0; i < qFromBigEndian(header.questions) && offset < static_cast <quint32> (data.length()); i++)
    {
        DNS::Record record;
        parseRecord(data, offset, record, true);
        message.questions.append(record);
    }

    for (quint16 i = 0; i < qFromBigEndian(header.answers) && offset < static_cast <quint32> (data.length()); i++)
    {
        DNS::Record record;
        parseRecord(data, offset, record);
        message.answers.append(record);
    }

    for (quint16 i = 0; i < qFromBigEndian(header.authority) && offset < static_cast <quint32> (data.length()); i++)
    {
        DNS::Record record;
        parseRecord(data, offset, record);
        message.authority.append(record);
    }

    for (quint16 i = 0; i < qFromBigEndian(header.additional) && offset < static_cast <quint32> (data.length()); i++)
    {
        DNS::Record record;
        parseRecord(data, offset, record);
        message.additional.append(record);
    }

    return message;
}

void MDNS::parseRecord(const QByteArray &data, quint32 &offset, DNS::Record &record, bool question)
{
    dnsQuestionStruct header;
    quint32 ttl;
    quint16 length;

    record.name = decodeName(data, offset);

    if (offset + sizeof(header) > static_cast <size_t> (data.length()))
        return;

    memcpy(&header, data.constData() + offset, sizeof(header));
    offset += sizeof(header);

    record.type = static_cast <DNS::Type> (qFromBigEndian(header.type));
    record.recordClass = qFromBigEndian(header.recordClass) & MDNS_CLASS_MASK;

    if (question || offset + sizeof(ttl) + sizeof(length) > static_cast <size_t> (data.length()))
        return;

    memcpy(&ttl, data.constData() + offset, sizeof(ttl));
    memcpy(&length, data.constData() + offset + sizeof(ttl), sizeof(length));

    record.ttl = qFromBigEndian(ttl);
    length = qFromBigEndian(length);
    offset += sizeof(ttl) + sizeof(length);

    if (offset + length > static_cast <quint32> (data.length()))
        return;

    record.data = data.mid(offset, length);

    switch (record.type)
    {
        case DNS::Type::PTR:
        {
            quint32 position = offset;
            record.pointer = decodeName(data, position);
            break;
        }

        case DNS::Type::SRV:
        {
            dnsServiceStruct service;
            quint32 position = offset + sizeof(service);

            if (length < sizeof(service))
                break;

            memcpy(&service, data.constData() + offset, sizeof(service));

            record.priority = qFromBigEndian(service.priority);
            record.weight = qFromBigEndian(service.weight);
            record.port = qFromBigEndian(service.port);
            record.target = decodeName(data, position);
            break;
        }

        case DNS::Type::A:

            if (length == 4)
                record.address = QHostAddress(qFromBigEndian <quint32> (record.data.constData()));

            break;

        case DNS::Type::AAAA:

            if (length == 16)
                record.address = QHostAddress(reinterpret_cast <const quint8*> (record.data.constData()));

            break;

        case DNS::Type::TXT:
        {
            quint32 position = 0;

            while (position < static_cast <quint32> (record.data.length()))
            {
                quint8 size = static_cast <quint8> (record.data.at(position++));
                QString item;
                int index;

                if (position + size > static_cast <quint32> (record.data.length()))
                    break;

                item = QString::fromUtf8(record.data.mid(position, size));
                index = item.indexOf('=');

                if (index > 0)
                    record.text.insert(item.left(index), item.mid(index + 1));

                position += size;
            }

            break;
        }

        default:
            break;
    }

    offset += length;
}

void MDNS::parseText(const DNS::Record &record, MatterService &service)
{
    QList <QString> list = {"D", "VP", "CM", "DN"};

    for (auto it = record.text.begin(); it != record.text.end(); it++)
    {
        switch (list.indexOf(it.key()))
        {
            case 0: service.discriminator = it.value().toUShort(); break;

            case 1:
            {
                QList <QString> item = it.value().split('+');
                service.vendorId = item.value(0).toUShort();
                service.productId = item.value(1).toUShort();
                break;
            }

            case 2: service.commissioningMode = static_cast <quint8> (it.value().toUShort()); break;
            case 3: service.deviceName = it.value(); break;
        }
    }
}

void MDNS::parseResponse(const DNS::Message &message)
{
    QList <DNS::Record> list = message.answers + message.additional;

    for (int i = 0; i < list.count(); i++)
    {
        const DNS::Record &record = list.at(i);
        bool operational = record.name == MATTER_OPERATIONAL_SERVICE;

        if (record.type != DNS::Type::PTR || (!operational && record.name != MATTER_COMMISSIONABLE_SERVICE))
            continue;

        m_services[record.pointer].instanceName = record.pointer;

        if (!operational)
            continue;

        m_services[record.pointer].operational = true;
    }

    for (int i = 0; i < list.count(); i++)
    {
        const DNS::Record &record = list.at(i);

        for (auto it = m_services.begin(); it != m_services.end(); it++)
        {
            MatterService &service = it.value();

            if (record.type == DNS::Type::SRV && record.name == service.instanceName)
            {
                service.hostName = record.target;
                service.port = record.port;
            }
            else if (record.type == DNS::Type::TXT && record.name == service.instanceName)
                parseText(record, service);
            else if (record.type == DNS::Type::A && record.name == service.hostName)
                service.address = record.address;
            else if (record.type == DNS::Type::AAAA && record.name == service.hostName && service.address.isNull())
                service.address = record.address;
        }
    }

    for (auto it = m_services.begin(); it != m_services.end(); it++)
    {
        if (it.value().address.isNull() || !it.value().port)
            continue;

        emit serviceFound(it.value());
    }
}

void MDNS::readyRead(void)
{
    QList <QUdpSocket*> list = {m_socket4, m_socket6};

    for (int i = 0; i < list.count(); i++)
    {
        QUdpSocket *socket = list.at(i);

        while (socket->hasPendingDatagrams())
        {
            QByteArray data;
            DNS::Message message;

            data.resize(static_cast <int> (socket->pendingDatagramSize()));
            socket->readDatagram(data.data(), data.size());
            message = decodeMessage(data);

            if (!(message.flags & MDNS_FLAG_RESPONSE))
                continue;

            parseResponse(message);
        }
    }
}
