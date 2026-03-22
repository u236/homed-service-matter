#include "controller.h"
#include "device.h"
#include "expose.h"
#include "logger.h"

void DeviceObject::updateEndpoint(quint8 endpointId, const QString &property, const QVariant &value)
{
    Endpoint endpoint = m_endpoints.value(endpointId);

    if (endpoint.isNull())
        return;

    endpoint->status().insert(property, value);
    emit endpointUpdated(this, endpointId);
}

void DeviceList::setFabricCredentials(const QByteArray &fabricKey, quint64 rootCAId, const QByteArray &ipk, const QByteArray &operationalKey, const QByteArray &controllerNOC, const QByteArray &controllerRCAC)
{
    m_fabricKey = fabricKey;
    m_rootCAId = rootCAId;
    m_ipk = ipk;
    m_operationalKey = operationalKey;
    m_controllerNOC = controllerNOC;
    m_controllerRCAC = controllerRCAC;
}

DeviceList::DeviceList(QSettings *config, QObject *parent) : QObject(parent), m_timer(new QTimer(this)), m_sync(false), m_rootCAId(0)
{
    QFile file(config->value("device/expose", "/usr/share/homed-common/expose.json").toString());

    ExposeObject::registerMetaTypes();

    m_file.setFileName(config->value("device/database", "/opt/homed-matter/database.json").toString());

    if (file.open(QFile::ReadOnly))
    {
        m_exposeOptions = QJsonDocument::fromJson(file.readAll()).object().toVariantMap();
        file.close();
    }

    connect(m_timer, &QTimer::timeout, this, &DeviceList::writeDatabase);
    m_timer->setSingleShot(true);
}

DeviceList::~DeviceList(void)
{
    m_sync = true;
    writeDatabase();
}

void DeviceList::init(void)
{
    QJsonObject json;

    if (!m_file.open(QFile::ReadOnly))
        return;

    json = QJsonDocument::fromJson(m_file.readAll()).object();
    unserialize(json.value("devices").toArray());

    QJsonObject fabric = json.value("fabric").toObject();
    m_fabricKey = QByteArray::fromHex(fabric.value("key").toString().toUtf8());
    m_rootCAId = fabric.value("rootCAId").toString().toULongLong(nullptr, 16);
    m_ipk = QByteArray::fromHex(fabric.value("ipk").toString().toUtf8());
    m_operationalKey = QByteArray::fromHex(fabric.value("operationalKey").toString().toUtf8());
    m_controllerNOC = QByteArray::fromHex(fabric.value("controllerNOC").toString().toUtf8());
    m_controllerRCAC = QByteArray::fromHex(fabric.value("controllerRCAC").toString().toUtf8());

    m_file.close();
}

void DeviceList::store(bool sync)
{
    if (sync)
        m_sync = true;

    m_timer->start(STORE_DATABASE_DELAY);
}

Device DeviceList::byName(const QString &name, int *index)
{
    for (int i = 0; i < count(); i++)
    {
        if (at(i)->address() != name && at(i)->name() != name)
            continue;

        if (index)
            *index = i;

        return at(i);
    }

    return Device();
}

Device DeviceList::byNodeId(quint64 nodeId)
{
    for (int i = 0; i < count(); i++)
    {
        if (at(i).staticCast<DeviceObject>()->nodeId() == nodeId)
            return at(i);
    }

    return Device();
}

Device DeviceList::parse(const QJsonObject &json)
{
    QString name = mqttSafe(json.value("name").toString());
    quint64 nodeId = static_cast <quint64> (json.value("nodeId").toDouble());

    if (name.isEmpty() || !nodeId)
        return Device();

    Device device(new DeviceObject(nodeId, name));

    if (json.contains("active"))
        device->setActive(json.value("active").toBool());

    if (json.contains("discovery"))
        device->setDiscovery(json.value("discovery").toBool());

    if (json.contains("cloud"))
        device->setCloud(json.value("cloud").toBool());

    device->setNote(json.value("note").toString());

    DeviceObject *obj = reinterpret_cast <DeviceObject*> (device.data());
    obj->setVendorId(static_cast <quint16> (json.value("vendorId").toInt()));
    obj->setProductId(static_cast <quint16> (json.value("productId").toInt()));
    obj->setManufacturerName(json.value("manufacturerName").toString());
    obj->setModelName(json.value("modelName").toString());

    if (json.contains("networkAddress"))
        obj->setNetworkAddress(QHostAddress(json.value("networkAddress").toString()));

    if (json.contains("networkPort"))
        obj->setNetworkPort(static_cast <quint16> (json.value("networkPort").toInt()));

    return device;
}

void DeviceList::unserialize(const QJsonArray &devices)
{
    quint16 count = 0;

    for (auto it = devices.begin(); it != devices.end(); it++)
    {
        QJsonObject json = it->toObject();
        Device device;

        if (!byName(json.value("name").toString()).isNull())
            continue;

        device = parse(json);

        if (device.isNull())
            continue;

        append(device);
        count++;
    }

    if (count)
        logInfo << count << "devices loaded";
}

QJsonArray DeviceList::serialize(void)
{
    QJsonArray array;

    for (int i = 0; i < count(); i++)
    {
        const Device &device = at(i);
        DeviceObject *obj = reinterpret_cast <DeviceObject*> (device.data());
        QJsonObject json = {{"nodeId", static_cast <double> (obj->nodeId())}, {"name", device->name()}, {"active", device->active()}, {"cloud", device->cloud()}, {"discovery", device->discovery()}};

        if (obj->vendorId())
            json.insert("vendorId", obj->vendorId());

        if (obj->productId())
            json.insert("productId", obj->productId());

        if (!device->manufacturerName().isEmpty())
            json.insert("manufacturerName", device->manufacturerName());

        if (!device->modelName().isEmpty())
            json.insert("modelName", device->modelName());

        if (!device->note().isEmpty())
            json.insert("note", device->note());

        if (!obj->networkAddress().isNull())
            json.insert("networkAddress", obj->networkAddress().toString());

        if (obj->networkPort() != 5540)
            json.insert("networkPort", obj->networkPort());

        array.append(json);
    }

    return array;
}

void DeviceList::writeDatabase(void)
{
    QJsonObject fabric;

    if (!m_fabricKey.isEmpty())
    {
        fabric.insert("key", QString(m_fabricKey.toHex()));
        fabric.insert("rootCAId", QString::number(m_rootCAId, 16));
        fabric.insert("ipk", QString(m_ipk.toHex()));
        fabric.insert("operationalKey", QString(m_operationalKey.toHex()));
        fabric.insert("controllerNOC", QString(m_controllerNOC.toHex()));
        fabric.insert("controllerRCAC", QString(m_controllerRCAC.toHex()));
    }

    QJsonObject json = {{"devices", serialize()}, {"fabric", fabric}, {"names", m_names}, {"timestamp", QDateTime::currentSecsSinceEpoch()}, {"version", SERVICE_VERSION}};

    emit statusUpdated(json);

    if (!m_sync)
        return;

    json.remove("names");
    m_sync = false;

    if (reinterpret_cast <Controller*> (parent())->writeFile(m_file, QJsonDocument(json).toJson(QJsonDocument::Compact)))
        return;

    logWarning << "Database not stored";
}
