#include "controller.h"
#include "device.h"
#include "expose.h"
#include "clusters.h"
#include "crypto.h"
#include "logger.h"

void DeviceObject::updateEndpoint(quint8 endpointId, const QString &property, const QVariant &value)
{
    Endpoint endpoint = m_endpoints.value(endpointId);

    if (endpoint.isNull())
        return;

    endpoint->status().insert(property, value);
    emit endpointUpdated(this, endpointId);
}

quint64 DeviceList::generateNodeId(void)
{
    quint64 nodeId;

    do
    {
        QByteArray bytes = Crypto::randomBytes(4);

        // ensure all 4 bytes are non-zero
        for (int i = 0; i < 4; i++)
        {
            if (bytes.at(i) == 0)
                bytes[i] = static_cast <char> ((static_cast <quint8> (Crypto::randomBytes(1).at(0)) % 254) + 1);
        }

        nodeId = 0;

        for (int i = 0; i < 4; i++)
            nodeId |= static_cast <quint64> (static_cast <quint8> (bytes.at(i))) << (i * 8);

    } while (byNodeId(nodeId).data());

    return nodeId;
}

void DeviceList::setupEndpoint(DeviceObject *device, quint8 endpointId, const QList <quint32> &clusters, quint16 colorCapabilities)
{
    Device holder;

    for (int i = 0; i < count(); i++)
    {
        if (at(i).data() == device)
        {
            holder = at(i);
            break;
        }
    }

    if (holder.isNull())
        return;

    Endpoint endpoint = device->endpoints().value(endpointId);

    if (endpoint.isNull())
    {
        endpoint = Endpoint(new EndpointObject(endpointId, holder));
        device->endpoints().insert(endpointId, endpoint);
    }

    reinterpret_cast <EndpointObject*> (endpoint.data())->clusters() = clusters;

    auto addExpose = [&](ExposeObject *obj, const QString &name)
    {
        Expose expose(obj);
        expose->setName(name);
        expose->setParent(endpoint.data());
        endpoint->exposes().append(expose);
        device->options().insert(name, m_exposeOptions.value(name));
        logInfo << "Endpoint" << endpointId << "on" << device->name() << ":" << name;
    };

    if (clusters.contains(Clusters::OnOff::Id) && endpoint->exposes().isEmpty())
    {
        if (clusters.contains(Clusters::LevelControl::Id) || clusters.contains(Clusters::ColorControl::Id))
        {
            QList <QVariant> options;

            if (clusters.contains(Clusters::LevelControl::Id))
                options.append("level");

            if (colorCapabilities & 0x0009)
                options.append("color");

            if (colorCapabilities & 0x0010)
                options.append("colorTemperature");

            if ((colorCapabilities & 0x0019) == 0x0019)
                options.append("colorMode");

            addExpose(new LightObject, "light");
            device->options().insert(QString("light_%1").arg(endpointId), options);
        }
        else
        {
            addExpose(new SwitchObject, "switch");
        }
    }

    if (clusters.contains(Clusters::TemperatureMeasurement::Id))
        addExpose(new SensorObject("temperature"), "temperature");

    if (clusters.contains(Clusters::RelativeHumidityMeasurement::Id))
        addExpose(new SensorObject("humidity"), "humidity");

    if (clusters.contains(Clusters::ElectricalPowerMeasurement::Id))
        addExpose(new SensorObject("power"), "power");

    if (clusters.contains(Clusters::ElectricalEnergyMeasurement::Id))
        addExpose(new SensorObject("energy"), "energy");
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

void DeviceList::updateMultiple(DeviceObject *device)
{
    QMap <QString, int> exposeCounts;

    for (auto it = device->endpoints().begin(); it != device->endpoints().end(); it++)
    {
        for (int i = 0; i < it.value()->exposes().count(); i++)
        {
            QString name = it.value()->exposes().at(i)->name().split('_').value(0);
            exposeCounts[name]++;
        }
    }

    for (auto it = device->endpoints().begin(); it != device->endpoints().end(); it++)
    {
        for (int i = 0; i < it.value()->exposes().count(); i++)
        {
            QString name = it.value()->exposes().at(i)->name().split('_').value(0);
            it.value()->exposes().at(i)->setMultiple(exposeCounts.value(name) > 1);
        }
    }
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
    quint64 nodeId = json.value("id").toString().toULongLong(nullptr, 16);

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
    obj->setFabricIndex(static_cast <quint8> (json.value("fabricIndex").toInt()));

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
        QJsonObject json = {{"id", QString::number(obj->nodeId(), 16)}, {"name", device->name()}, {"active", device->active()}, {"cloud", device->cloud()}, {"discovery", device->discovery()}};

        if (obj->vendorId())
            json.insert("vendorId", obj->vendorId());

        if (obj->productId())
            json.insert("productId", obj->productId());

        if (obj->fabricIndex())
            json.insert("fabricIndex", obj->fabricIndex());

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

        if (!obj->endpoints().isEmpty())
        {
            QJsonArray endpoints;

            for (auto it = obj->endpoints().begin(); it != obj->endpoints().end(); it++)
            {
                EndpointObject *ep = reinterpret_cast <EndpointObject*> (it.value().data());
                QJsonObject epJson = {{"endpointId", ep->id()}};

                if (!ep->clusters().isEmpty())
                {
                    QJsonArray clusters;

                    for (int i = 0; i < ep->clusters().count(); i++)
                        clusters.append(static_cast <qint64> (ep->clusters().at(i)));

                    epJson.insert("clusters", clusters);
                }

                endpoints.append(epJson);
            }

            json.insert("endpoints", endpoints);
        }

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
