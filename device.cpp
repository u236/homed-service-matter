// NOT REWIEWED

#include "controller.h"
#include "device.h"
#include "expose.h"
#include "clusters.h"
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

void DeviceList::addEndpoint(DeviceObject *device, quint8 endpointId, const QList <quint32> &clusters)
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
}

void DeviceList::setupEndpoint(DeviceObject *device, quint8 endpointId)
{
    Endpoint endpoint = device->endpoints().value(endpointId);

    if (endpoint.isNull())
        return;

    EndpointObject *ep = reinterpret_cast <EndpointObject*> (endpoint.data());
    const QList <quint32> &clusters = ep->clusters();
    quint16 caps = static_cast <quint16> (ep->meta().value("colorCapabilities").toInt());

    auto addExpose = [&](ExposeObject *obj, const QString &name)
    {
        for (const Expose &existing : endpoint->exposes())
        {
            if (existing->name() == name)
            {
                delete obj;
                return;
            }
        }

        Expose expose(obj);
        expose->setName(name);
        expose->setParent(endpoint.data());
        endpoint->exposes().append(expose);
        device->options().insert(name, m_exposeOptions.value(name));
        logInfo << device << "endpoint" << endpointId << "expose" << name;
    };

    if (clusters.contains(Clusters::OnOff::Id) && endpoint->exposes().isEmpty())
    {
        if (clusters.contains(Clusters::LevelControl::Id) || clusters.contains(Clusters::ColorControl::Id))
        {
            QList <QVariant> options;

            if (clusters.contains(Clusters::LevelControl::Id))
                options.append("level");

            if (caps & 0x0001)
                options.append("color");

            if (caps & 0x0010)
            {
                options.append("colorTemperature");

                if (ep->meta().contains("colorTempMin") && ep->meta().contains("colorTempMax"))
                    device->options().insert(QString("colorTemperature_%1").arg(endpointId), QMap <QString, QVariant> {{"min", ep->meta().value("colorTempMin")}, {"max", ep->meta().value("colorTempMax")}});
            }

            if ((caps & 0x0011) == 0x0011)
                options.append("colorMode");

            addExpose(new LightObject, "light");
            device->options().insert(QString("light_%1").arg(endpointId), options);
        }
        else
        {
            addExpose(new SwitchObject, "switch");
        }
    }

    if (clusters.contains(Clusters::PowerSource::Id))
    {
        addExpose(new SensorObject("battery"), "battery");
        device->setBatteryPowered(true);
    }

    if (clusters.contains(Clusters::Switch::Id))
    {
        addExpose(new SensorObject("action"), "action");

        // per-endpoint action enum from Switch FeatureMap + MultiPressMax (Matter §1.13); meta is filled
        // by the discovery follow-up read or loaded from JSON on unserialize before setupEndpoint runs
        quint32 features = ep->meta().value("switchFeatures").toUInt();
        quint8 multiPressMax = static_cast <quint8> (ep->meta().value("switchMultiPressMax").toUInt());

        // encoder heuristic: an endpoint that advertises MSM with a high MultiPressMax cap and lacks MSL is
        // virtually never a real button — it's a rotary encoder where MultiPressComplete.count carries the
        // detent burst size (e.g. IKEA BILRESA: cap=18, no LongPress). collapse single/double/triple/multi
        // into a single "step" action and publish the raw count alongside as a numeric "step" property.
        bool encoder = (features & Clusters::Switch::Features::MSM) && !(features & Clusters::Switch::Features::MSL) && multiPressMax > 5;

        if (encoder)
            addExpose(new SensorObject("count"), "count");

        if (features)
        {
            QList <QVariant> actions;

            if (features & Clusters::Switch::Features::LS)
                actions.append("latched");

            if (encoder)
            {
                actions.append("start");
                actions.append("stop");
            }
            else if (features & Clusters::Switch::Features::MSM)
            {
                quint8 cap = multiPressMax ? multiPressMax : 1;
                if (cap >= 1) actions.append("singleClick");
                if (cap >= 2) actions.append("doubleClick");
                if (cap >= 3) actions.append("tripleClick");
                if (cap >= 4) actions.append("multipleClick");
            }
            else if (features & Clusters::Switch::Features::MSR)
            {
                actions.append("singleClick");
            }

            if (features & Clusters::Switch::Features::MSL)
            {
                actions.append("hold");
                actions.append("release");
            }

            if (!actions.isEmpty())
                device->options().insert(QString("action_%1").arg(endpointId), QMap <QString, QVariant> {{"enum", actions}});
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
    QFile file(config->value("device/expose", reinterpret_cast <HOMEd*> (parent)->basePath().append("share/homed-common/expose.json")).toString());

    ExposeObject::registerMetaTypes();

    m_names = config->value("mqtt/names", false).toBool();
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
    quint64 nodeId = json.value("nodeId").toString().toULongLong(nullptr, 16);

    if (!nodeId) // TODO: remove after migration from 0.0.4
        nodeId = json.value("id").toString().toULongLong(nullptr, 16);

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

    if (json.contains("thread"))
        obj->setThread(json.value("thread").toBool());
    else if (obj->networkAddress().protocol() == QAbstractSocket::IPv6Protocol)
        obj->setThread(true);

    if (json.contains("lastSeen"))
        obj->setLastSeen(json.value("lastSeen").toVariant().toLongLong());

    if (json.contains("resumptionID"))
        obj->setResumptionID(QByteArray::fromHex(json.value("resumptionID").toString().toLatin1()));

    if (json.contains("resumptionSharedSecret"))
        obj->setResumptionSharedSecret(QByteArray::fromHex(json.value("resumptionSharedSecret").toString().toLatin1()));

    if (json.contains("session"))
    {
        QJsonObject session = json.value("session").toObject();
        obj->setSessionLocalId(static_cast <quint16> (session.value("localId").toInt()));
        obj->setSessionPeerId(static_cast <quint16> (session.value("peerId").toInt()));
        obj->setSessionI2RKey(QByteArray::fromHex(session.value("i2rKey").toString().toLatin1()));
        obj->setSessionR2IKey(QByteArray::fromHex(session.value("r2iKey").toString().toLatin1()));
        obj->setSessionAttestation(QByteArray::fromHex(session.value("attestation").toString().toLatin1()));
        obj->setSessionLocalCounter(static_cast <quint32> (session.value("localCounter").toVariant().toULongLong()));
        obj->setSessionIdleInterval(static_cast <quint32> (session.value("idleInterval").toVariant().toULongLong()));
        obj->setSessionActiveInterval(static_cast <quint32> (session.value("activeInterval").toVariant().toULongLong()));
        obj->setSessionActiveThreshold(static_cast <quint16> (session.value("activeThreshold").toInt()));
    }

    QJsonArray endpoints = json.value("endpoints").toArray();

    for (auto it = endpoints.begin(); it != endpoints.end(); it++)
    {
        QJsonObject epJson = it->toObject();
        quint8 endpointId = static_cast <quint8> (epJson.value("endpointId").toInt());

        Endpoint endpoint(new EndpointObject(endpointId, device));
        EndpointObject *ep = reinterpret_cast <EndpointObject*> (endpoint.data());

        QJsonArray clusters = epJson.value("clusters").toArray();

        for (auto ci = clusters.begin(); ci != clusters.end(); ci++)
            ep->clusters().append(static_cast <quint32> (ci->toVariant().toULongLong()));

        ep->meta().insert(epJson.value("meta").toObject().toVariantMap());

        obj->endpoints().insert(endpointId, endpoint);
    }

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

        // recreate exposes from restored endpoints + clusters
        DeviceObject *obj = reinterpret_cast <DeviceObject*> (device.data());

        for (auto ep = obj->endpoints().begin(); ep != obj->endpoints().end(); ep++)
            setupEndpoint(obj, ep.key());

        updateMultiple(obj);
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
        QJsonObject json = {{"nodeId", QString::number(obj->nodeId(), 16)}, {"name", device->name()}, {"active", device->active()}, {"cloud", device->cloud()}, {"discovery", device->discovery()}};

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

        if (obj->thread())
            json.insert("thread", true);

        if (obj->lastSeen())
            json.insert("lastSeen", obj->lastSeen());

        if (!obj->resumptionID().isEmpty())
            json.insert("resumptionID", QString::fromLatin1(obj->resumptionID().toHex()));

        if (!obj->resumptionSharedSecret().isEmpty())
            json.insert("resumptionSharedSecret", QString::fromLatin1(obj->resumptionSharedSecret().toHex()));

        if (obj->hasPersistedSession())
        {
            QJsonObject session = {
                {"localId", obj->sessionLocalId()},
                {"peerId", obj->sessionPeerId()},
                {"i2rKey", QString::fromLatin1(obj->sessionI2RKey().toHex())},
                {"r2iKey", QString::fromLatin1(obj->sessionR2IKey().toHex())},
                {"attestation", QString::fromLatin1(obj->sessionAttestation().toHex())},
                {"localCounter", static_cast <qint64> (obj->sessionLocalCounter())},
                {"idleInterval", static_cast <qint64> (obj->sessionIdleInterval())},
                {"activeInterval", static_cast <qint64> (obj->sessionActiveInterval())},
                {"activeThreshold", obj->sessionActiveThreshold()}
            };
            json.insert("session", session);
        }

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

                if (!ep->meta().isEmpty())
                    epJson.insert("meta", QJsonObject::fromVariantMap(ep->meta()));

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

    HOMEd *homed = reinterpret_cast <HOMEd*> (parent());
    QJsonObject json = {{"devices", serialize()}, {"fabric", fabric}, {"names", m_names}, {"timestamp", QDateTime::currentSecsSinceEpoch()}, {"version", SERVICE_VERSION}};

    homed->mqttPublishStatus(json);

    if (!m_sync)
        return;

    json.remove("names");
    m_sync = false;

    if (homed->writeFile(m_file, QJsonDocument(json).toJson(QJsonDocument::Compact)))
        return;

    logWarning << "Database not stored";
}
