#include "ble.h"
#include "logger.h"
#include <QDBusReply>
#include <QDBusArgument>
#include <QtEndian>

BLE::BLE(QObject *parent) : QObject(parent), m_bus(QDBusConnection::systemBus()), m_available(false), m_scanning(false), m_connected(false), m_scanTimer(new QTimer(this))
{

    m_scanTimer->setSingleShot(true);
    connect(m_scanTimer, &QTimer::timeout, this, &BLE::scanTimeout);

    findAdapter();

    if (!m_available)
    {
        logInfo << "BLE not available (no BlueZ adapter found)";
        return;
    }

    // listen for new devices and property changes
    m_bus.connect("org.bluez", "/", "org.freedesktop.DBus.ObjectManager", "InterfacesAdded", this, SLOT(interfacesAdded(QDBusMessage)));
    m_bus.connect("org.bluez", QString(), "org.freedesktop.DBus.Properties", "PropertiesChanged", this, SLOT(propertiesChanged(QString,QMap<QString,QVariant>,QStringList)));

    logInfo << "BLE available, adapter:" << m_adapterPath;
}

void BLE::findAdapter(void)
{
    QDBusMessage reply = m_bus.call(QDBusMessage::createMethodCall("org.bluez", "/", "org.freedesktop.DBus.ObjectManager", "GetManagedObjects"));

    if (reply.type() != QDBusMessage::ReplyMessage || reply.arguments().isEmpty())
        return;

    const QDBusArgument &arg = reply.arguments().at(0).value <QDBusArgument> ();
    arg.beginMap();

    while (!arg.atEnd())
    {
        QDBusObjectPath path;
        arg.beginMapEntry();
        arg >> path;

        const QDBusArgument &interfaces = arg.asVariant().value <QDBusArgument> ();
        interfaces.beginMap();

        while (!interfaces.atEnd())
        {
            QString interface;
            interfaces.beginMapEntry();
            interfaces >> interface;
            interfaces.beginMap();
            while (!interfaces.atEnd()) { interfaces.beginMapEntry(); QString k; QVariant v; interfaces >> k >> v; interfaces.endMapEntry(); }
            interfaces.endMap();
            interfaces.endMapEntry();

            if (interface == "org.bluez.Adapter1")
            {
                m_adapterPath = path.path();
                m_available = true;
            }
        }

        interfaces.endMap();
        arg.endMapEntry();
    }

    arg.endMap();
}

void BLE::parseServiceData(const QByteArray &data, BLEDevice &device)
{
    if (data.size() < 8)
        return;

    // Matter BLE advertisement service data format:
    // byte 0: version/flags
    // byte 1-2: discriminator (little-endian)
    // byte 3-4: vendor ID (little-endian)
    // byte 5-6: product ID (little-endian)
    quint8 flags = static_cast <quint8> (data.at(0));
    Q_UNUSED(flags)

    device.discriminator = qFromLittleEndian <quint16> (reinterpret_cast <const uchar*> (data.constData() + 1));
    device.vendorId = qFromLittleEndian <quint16> (reinterpret_cast <const uchar*> (data.constData() + 3));
    device.productId = qFromLittleEndian <quint16> (reinterpret_cast <const uchar*> (data.constData() + 5));
}

void BLE::scan(void)
{
    if (!m_available || m_scanning)
        return;

    m_discovered.clear();

    QDBusInterface adapter("org.bluez", m_adapterPath, "org.bluez.Adapter1", m_bus);
    adapter.call("SetDiscoveryFilter", QVariantMap {{"Transport", QString("le")}});
    adapter.call("StartDiscovery");

    m_scanning = true;
    m_scanTimer->start(10000);

    logInfo << "BLE scanning for Matter devices...";
}

void BLE::stopScan(void)
{
    if (!m_scanning)
        return;

    QDBusInterface adapter("org.bluez", m_adapterPath, "org.bluez.Adapter1", m_bus);
    adapter.call("StopDiscovery");

    m_scanning = false;
    m_scanTimer->stop();
}

void BLE::connectDevice(const QString &path)
{
    stopScan();
    m_devicePath = path;

    QDBusInterface device("org.bluez", path, "org.bluez.Device1", m_bus);
    device.call("Connect");

    logInfo << "BLE connecting to" << path;

    // characteristics will be discovered after connection via PropertiesChanged
}

void BLE::disconnectDevice(void)
{
    if (m_devicePath.isEmpty())
        return;

    QDBusInterface device("org.bluez", m_devicePath, "org.bluez.Device1", m_bus);
    device.call("Disconnect");

    // remove device from BlueZ cache to prevent stale GATT state
    QDBusInterface adapter("org.bluez", m_adapterPath, "org.bluez.Adapter1", m_bus);
    adapter.call("RemoveDevice", QVariant::fromValue(QDBusObjectPath(m_devicePath)));

    m_devicePath.clear();
    m_c1Path.clear();
    m_c2Path.clear();
}

void BLE::write(const QByteArray &data)
{
    if (m_c1Path.isEmpty())
        return;

    logInfo << "BLE write" << data.size() << "bytes to C1:" << data.toHex();

    QDBusInterface c1("org.bluez", m_c1Path, "org.bluez.GattCharacteristic1", m_bus);
    QDBusMessage reply = c1.call("WriteValue", QVariant::fromValue(data), QVariantMap {{"type", "request"}});

    if (reply.type() == QDBusMessage::ErrorMessage)
    {
        logWarning << "BLE write error:" << reply.errorMessage();
        disconnectDevice();
    }
}

void BLE::subscribe(void)
{
    if (m_c2Path.isEmpty())
        return;

    QDBusInterface c2("org.bluez", m_c2Path, "org.bluez.GattCharacteristic1", m_bus);
    QDBusMessage reply = c2.call("StartNotify");

    if (reply.type() == QDBusMessage::ErrorMessage)
        logWarning << "BLE StartNotify error:" << reply.errorMessage();
    else
        logInfo << "BLE C2 notifications started";
}

void BLE::discoverCharacteristics(void)
{
    if (m_connected || m_devicePath.isEmpty())
        return;

    QDBusMessage reply = m_bus.call(QDBusMessage::createMethodCall("org.bluez", "/", "org.freedesktop.DBus.ObjectManager", "GetManagedObjects"));

    if (reply.type() != QDBusMessage::ReplyMessage || reply.arguments().isEmpty())
        return;

    const QDBusArgument &arg = reply.arguments().at(0).value <QDBusArgument> ();
    arg.beginMap();

    while (!arg.atEnd())
    {
        QDBusObjectPath path;
        arg.beginMapEntry();
        arg >> path;

        const QDBusArgument &ifaces = arg.asVariant().value <QDBusArgument> ();
        ifaces.beginMap();

        while (!ifaces.atEnd())
        {
            QString interface;
            QMap <QString, QVariant> props;

            ifaces.beginMapEntry();
            ifaces >> interface;

            const QDBusArgument &propsArg = ifaces.asVariant().value <QDBusArgument> ();
            propsArg.beginMap();

            while (!propsArg.atEnd())
            {
                QString key;
                QVariant value;
                propsArg.beginMapEntry();
                propsArg >> key >> value;
                props.insert(key, value);
                propsArg.endMapEntry();
            }

            propsArg.endMap();
            ifaces.endMapEntry();

            if (interface == "org.bluez.GattCharacteristic1" && path.path().startsWith(m_devicePath))
            {
                QString uuid = props.value("UUID").toString();

                if (uuid == MATTER_BLE_C1_UUID)
                {
                    m_c1Path = path.path();
                    logInfo << "BLE C1 characteristic found:" << m_c1Path;
                }
                else if (uuid == MATTER_BLE_C2_UUID)
                {
                    m_c2Path = path.path();
                    logInfo << "BLE C2 characteristic found:" << m_c2Path;
                }
            }
        }

        ifaces.endMap();
        arg.endMapEntry();
    }

    arg.endMap();

    if (!m_c1Path.isEmpty() && !m_c2Path.isEmpty() && !m_connected)
    {
        m_connected = true;
        emit connected();
    }
}

void BLE::interfacesAdded(const QDBusMessage &message)
{
    if (message.arguments().size() < 2)
        return;

    QString path = message.arguments().at(0).value <QDBusObjectPath> ().path();
    const QDBusArgument &arg = message.arguments().at(1).value <QDBusArgument> ();

    QMap <QString, QMap <QString, QVariant>> interfaces;
    arg.beginMap();

    while (!arg.atEnd())
    {
        QString interface;
        QMap <QString, QVariant> props;

        arg.beginMapEntry();
        arg >> interface;

        const QDBusArgument &propsArg = arg.asVariant().value <QDBusArgument> ();
        propsArg.beginMap();

        while (!propsArg.atEnd())
        {
            QString key;
            QVariant value;
            propsArg.beginMapEntry();
            propsArg >> key >> value;
            props.insert(key, value);
            propsArg.endMapEntry();
        }

        propsArg.endMap();
        arg.endMapEntry();

        interfaces.insert(interface, props);
    }

    arg.endMap();

    if (interfaces.contains("org.bluez.Device1") && m_scanning)
    {
        QMap <QString, QVariant> props = interfaces.value("org.bluez.Device1");
        QString address = props.value("Address").toString();
        QString name = props.value("Name").toString();

        QMap <QString, QVariant> serviceData = qdbus_cast <QMap <QString, QVariant>> (props.value("ServiceData"));

        if (!serviceData.contains(MATTER_BLE_SERVICE_UUID))
            return;

        BLEDevice device;
        device.path = path;
        device.address = props.value("Address").toString();
        device.name = props.value("Name").toString();

        parseServiceData(serviceData.value(MATTER_BLE_SERVICE_UUID).toByteArray(), device);

        m_discovered.insert(device.address, device);

        logInfo << "BLE Matter device found:" << device.name << device.address << "discriminator:" << device.discriminator;
        emit deviceFound(device);
    }

    if (interfaces.contains("org.bluez.GattCharacteristic1") && !m_devicePath.isEmpty())
        discoverCharacteristics();
}

void BLE::propertiesChanged(const QString &interface, const QMap <QString, QVariant> &changed, const QStringList &invalidated)
{
    Q_UNUSED(invalidated)

    if (interface == "org.bluez.Device1" && changed.contains("ServicesResolved") && changed.value("ServicesResolved").toBool())
        discoverCharacteristics();

    if (interface == "org.bluez.Device1" && changed.contains("Connected") && !changed.value("Connected").toBool())
    {
        m_devicePath.clear();
        m_c1Path.clear();
        m_c2Path.clear();
        m_connected = false;
        emit disconnected();
    }

    if (interface == "org.bluez.GattCharacteristic1" && changed.contains("Value"))
    {
        QByteArray value;
        QVariant variant = changed.value("Value");

        if (variant.canConvert <QDBusArgument> ())
        {
            const QDBusArgument arg = variant.value <QDBusArgument> ();
            arg >> value;
        }
        else
        {
            value = variant.toByteArray();
        }

        if (!value.isEmpty())
            emit dataReceived(value);
    }
}

void BLE::scanTimeout(void)
{
    stopScan();
    logInfo << "BLE scan timeout";
}
