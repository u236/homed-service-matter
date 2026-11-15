// NOT REWIEWED

#include <QDBusArgument>
#include <QtEndian>
#include "ble.h"
#include "logger.h"

static QMap <QString, QVariant> dbusProperties(const QDBusArgument &argument)
{
    QMap <QString, QVariant> map;

    argument.beginMap();

    while (!argument.atEnd())
    {
        QString key;
        QVariant value;

        argument.beginMapEntry();
        argument >> key >> value;
        argument.endMapEntry();

        map.insert(key, value);
    }

    argument.endMap();
    return map;
}

static QMap <QString, QMap <QString, QVariant>> dbusInterfaces(const QDBusArgument &argument)
{
    QMap <QString, QMap <QString, QVariant>> map;

    argument.beginMap();

    while (!argument.atEnd())
    {
        QString name;

        argument.beginMapEntry();
        argument >> name;
        map.insert(name, dbusProperties(argument.asVariant().value <QDBusArgument> ()));
        argument.endMapEntry();
    }

    argument.endMap();
    return map;
}

BLE::BLE(QObject *parent) : QObject(parent), m_timer(new QTimer(this)), m_bus(QDBusConnection::systemBus()), m_available(false), m_scanning(false), m_connected(false)
{
    connect(m_timer, &QTimer::timeout, this, &BLE::scanTimeout);
    m_timer->setSingleShot(true);

    findAdapter();

    if (!m_available)
    {
        logInfo << "BLE not available, no BlueZ adapter found";
        return;
    }

    m_bus.connect("org.bluez", "/", "org.freedesktop.DBus.ObjectManager", "InterfacesAdded", this, SLOT(interfacesAdded(QDBusMessage)));
    m_bus.connect("org.bluez", QString(), "org.freedesktop.DBus.Properties", "PropertiesChanged", this, SLOT(propertiesChanged(QString,QMap<QString,QVariant>,QStringList)));

    logInfo << "BLE adapter" << m_adapterPath << "available";
}

void BLE::scan(void)
{
    if (!m_available || m_scanning)
        return;

    QDBusInterface adapter("org.bluez", m_adapterPath, "org.bluez.Adapter1", m_bus);

    adapter.call("SetDiscoveryFilter", QMap <QString, QVariant> {{"Transport", QString("le")}});
    adapter.call("StartDiscovery");

    m_scanning = true;
    m_timer->start(BLE_SCAN_TIMEOUT);

    logInfo << "BLE scanning for Matter devices...";
}

void BLE::stopScan(void)
{
    if (!m_scanning)
        return;

    QDBusInterface adapter("org.bluez", m_adapterPath, "org.bluez.Adapter1", m_bus);

    adapter.call("StopDiscovery");

    m_scanning = false;
    m_timer->stop();
}

void BLE::connectDevice(const QString &path)
{
    stopScan();
    m_devicePath = path;

    QDBusInterface device("org.bluez", path, "org.bluez.Device1", m_bus);

    device.call("Connect");
    logInfo << "BLE connecting to" << path << "...";
}

void BLE::disconnectDevice(void)
{
    if (m_devicePath.isEmpty())
        return;

    QDBusInterface device("org.bluez", m_devicePath, "org.bluez.Device1", m_bus), adapter("org.bluez", m_adapterPath, "org.bluez.Adapter1", m_bus);

    device.call("Disconnect");

    // remove device from BlueZ cache to prevent stale GATT state
    adapter.call("RemoveDevice", QVariant::fromValue(QDBusObjectPath(m_devicePath)));
    clearDevice();
}

void BLE::write(const QByteArray &data)
{
    if (m_c1Path.isEmpty())
        return;

    QDBusInterface characteristic("org.bluez", m_c1Path, "org.bluez.GattCharacteristic1", m_bus);
    QDBusMessage reply;

    logInfo << "BLE C1 write:" << data.toHex(':');
    reply = characteristic.call("WriteValue", QVariant::fromValue(data), QMap <QString, QVariant> {{"type", "request"}});

    if (reply.type() != QDBusMessage::ErrorMessage)
        return;

    logWarning << "BLE C1 write failed:" << reply.errorMessage();
    disconnectDevice();
}

void BLE::subscribe(void)
{
    if (m_c2Path.isEmpty())
        return;

    QDBusInterface characteristic("org.bluez", m_c2Path, "org.bluez.GattCharacteristic1", m_bus);
    QDBusMessage reply = characteristic.call("StartNotify");

    if (reply.type() == QDBusMessage::ErrorMessage)
    {
        logWarning << "BLE C2 notifications start failed:" << reply.errorMessage();
        return;
    }

    logInfo << "BLE C2 notifications started";
}

void BLE::findAdapter(void)
{
    QDBusMessage reply = m_bus.call(QDBusMessage::createMethodCall("org.bluez", "/", "org.freedesktop.DBus.ObjectManager", "GetManagedObjects"));

    if (reply.type() != QDBusMessage::ReplyMessage || reply.arguments().isEmpty())
        return;

    const QDBusArgument &argument = reply.arguments().at(0).value <QDBusArgument> ();

    argument.beginMap();

    while (!argument.atEnd())
    {
        QDBusObjectPath path;

        argument.beginMapEntry();
        argument >> path;

        if (dbusInterfaces(argument.asVariant().value <QDBusArgument> ()).contains("org.bluez.Adapter1"))
        {
            m_adapterPath = path.path();
            m_available = true;
        }

        argument.endMapEntry();
    }

    argument.endMap();
}

void BLE::findCharacteristics(void)
{
    QDBusMessage reply;

    if (m_connected || m_devicePath.isEmpty())
        return;

    reply = m_bus.call(QDBusMessage::createMethodCall("org.bluez", "/", "org.freedesktop.DBus.ObjectManager", "GetManagedObjects"));

    if (reply.type() != QDBusMessage::ReplyMessage || reply.arguments().isEmpty())
        return;

    const QDBusArgument &argument = reply.arguments().at(0).value <QDBusArgument> ();

    argument.beginMap();

    while (!argument.atEnd())
    {
        QDBusObjectPath path;
        QMap <QString, QMap <QString, QVariant>> interfaces;
        QString uuid;

        argument.beginMapEntry();
        argument >> path;
        interfaces = dbusInterfaces(argument.asVariant().value <QDBusArgument> ());
        argument.endMapEntry();

        if (!interfaces.contains("org.bluez.GattCharacteristic1") || !path.path().startsWith(m_devicePath))
            continue;

        uuid = interfaces.value("org.bluez.GattCharacteristic1").value("UUID").toString();

        if (uuid == BLE_C1_UUID)
        {
            m_c1Path = path.path();
            logInfo << "BLE C1 characteristic" << m_c1Path << "found";
        }
        else if (uuid == BLE_C2_UUID)
        {
            m_c2Path = path.path();
            logInfo << "BLE C2 characteristic" << m_c2Path << "found";
        }
    }

    argument.endMap();

    if (m_c1Path.isEmpty() || m_c2Path.isEmpty())
        return;

    m_connected = true;
    emit connected();
}

void BLE::clearDevice(void)
{
    m_devicePath.clear();
    m_c1Path.clear();
    m_c2Path.clear();
}

void BLE::interfacesAdded(const QDBusMessage &message)
{
    QMap <QString, QMap <QString, QVariant>> interfaces;

    if (message.arguments().count() < 2)
        return;

    interfaces = dbusInterfaces(message.arguments().at(1).value <QDBusArgument> ());

    if (m_scanning && interfaces.contains("org.bluez.Device1"))
    {
        QMap <QString, QVariant> properties = interfaces.value("org.bluez.Device1"), serviceData = qdbus_cast <QMap <QString, QVariant>> (properties.value("ServiceData"));
        QByteArray data = serviceData.value(BLE_SERVICE_UUID).toByteArray();
        bleServiceDataStruct service;
        BLEDevice device;

        if (!serviceData.contains(BLE_SERVICE_UUID))
            return;

        device.path = message.arguments().at(0).value <QDBusObjectPath> ().path();
        device.address = properties.value("Address").toString();
        device.name = properties.value("Name").toString();

        if (static_cast <size_t> (data.length()) >= sizeof(service))
        {
            memcpy(&service, data.constData(), sizeof(service));
            device.discriminator = qFromLittleEndian(service.discriminator);
            device.vendorId = qFromLittleEndian(service.vendorId);
            device.productId = qFromLittleEndian(service.productId);
        }

        logInfo << "BLE Matter device" << device.address << "found, discriminator" << device.discriminator << "vendor id" << QString::asprintf("0x%04x", device.vendorId) << "product id" << QString::asprintf("0x%04x", device.productId) << "name" << (device.name.isEmpty() ? "(empty)" : device.name);
        emit deviceFound(device);
    }

    if (m_devicePath.isEmpty() || !interfaces.contains("org.bluez.GattCharacteristic1"))
        return;

    findCharacteristics();
}

void BLE::propertiesChanged(const QString &interface, const QMap <QString, QVariant> &changed, const QStringList &)
{
    if (interface == "org.bluez.Device1")
    {
        if (changed.value("ServicesResolved").toBool())
            findCharacteristics();

        if (changed.contains("Connected") && !changed.value("Connected").toBool())
        {
            clearDevice();
            m_connected = false;
            emit disconnected();
        }
    }

    if (interface == "org.bluez.GattCharacteristic1" && changed.contains("Value"))
    {
        QVariant value = changed.value("Value");
        QByteArray data;

        if (value.canConvert <QDBusArgument> ())
            value.value <QDBusArgument> () >> data;
        else
            data = value.toByteArray();

        if (data.isEmpty())
            return;

        emit dataReceived(data);
    }
}

void BLE::scanTimeout(void)
{
    stopScan();
    logInfo << "BLE scan timeout";
}

void BTP::startHandshake(void)
{
    btpHandshakeRequestStruct request;

    request.flags = BTP_FLAG_HANDSHAKE | BTP_FLAG_MANAGEMENT | BTP_FLAG_BEGINNING | BTP_FLAG_END;
    request.opcode = BTP_HANDSHAKE_REQUEST;
    request.versions = qToLittleEndian <quint32> (1 << (BTP_VERSION - 2));
    request.mtu = 0; // use negotiated ATT MTU
    request.window = BTP_DEFAULT_WINDOW;

    logInfo << "BTP handshake request sent, MTU" << BTP_DEFAULT_MTU << "window" << BTP_DEFAULT_WINDOW;
    emit writeData(QByteArray(reinterpret_cast <char*> (&request), sizeof(request)));
}

void BTP::parseData(const QByteArray &data)
{
    quint8 flags, sequence;
    int offset = 1;

    if (data.isEmpty())
        return;

    flags = static_cast <quint8> (data.at(0));

    if (flags & BTP_FLAG_HANDSHAKE)
    {
        btpHandshakeResponseStruct response;

        if (static_cast <size_t> (data.length()) < sizeof(response))
            return;

        memcpy(&response, data.constData(), sizeof(response));

        m_ready = true;
        m_mtu = qFromLittleEndian(response.mtu);
        m_window = response.window;
        m_txSequence = 0;
        m_rxSequence = 0;

        logInfo << "BTP handshake response received, version" << response.version << "MTU" << m_mtu << "window" << m_window;
        emit handshakeFinished();
        return;
    }

    if (flags & BTP_FLAG_ACK)
        offset++;

    if (flags & BTP_FLAG_MANAGEMENT || offset >= data.length())
        return;

    sequence = static_cast <quint8> (data.at(offset++));

    if (flags & BTP_FLAG_BEGINNING)
    {
        if (offset + 2 > data.length())
            return;

        offset += 2;
        m_buffer.clear();
    }

    m_buffer.append(data.mid(offset));
    m_rxSequence = sequence;

    // acknowledgement is sent with next outgoing message
    if (!(flags & BTP_FLAG_END))
        return;

    emit messageReceived(m_buffer);
    m_buffer.clear();
}

void BTP::sendMessage(const QByteArray &message)
{
    int offset = 0;

    if (!m_ready)
        return;

    while (offset < message.length())
    {
        QByteArray packet;
        quint8 flags = offset ? 0 : BTP_FLAG_BEGINNING | BTP_FLAG_ACK;
        int length = qMin(message.length() - offset, offset ? m_mtu - 2 : m_mtu - 5);

        if (offset + length >= message.length())
            flags |= BTP_FLAG_END;

        packet.append(static_cast <char> (flags));

        if (flags & BTP_FLAG_ACK)
            packet.append(static_cast <char> (m_rxSequence));

        packet.append(static_cast <char> (m_txSequence++));

        if (flags & BTP_FLAG_BEGINNING)
        {
            quint16 value = qToLittleEndian <quint16> (message.length());
            packet.append(reinterpret_cast <char*> (&value), sizeof(value));
        }

        packet.append(message.mid(offset, length));
        offset += length;

        emit writeData(packet);
    }
}
