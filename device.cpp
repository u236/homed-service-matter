// NOT REWIEWED

#include "controller.h"
#include "logger.h"

void DeviceObject::storeSession(SessionInfo *session)
{
    m_sessionLocalId = session->localSessionId;
    m_sessionPeerId = session->peerSessionId;
    m_sessionEncryptKey = session->i2rKey;
    m_sessionDecryptKey = session->r2iKey;
    m_sessionAttestation = session->attestationChallenge;
    m_sessionCounter = 0;
    m_sessionIdleInterval = session->idleInterval;
    m_sessionActiveInterval = session->activeInterval;
    m_sessionActiveThreshold = session->activeThreshold;
}

void DeviceObject::restoreSession(SessionInfo &session)
{
    session.localSessionId = m_sessionLocalId;
    session.peerSessionId = m_sessionPeerId;
    session.i2rKey = m_sessionEncryptKey;
    session.r2iKey = m_sessionDecryptKey;
    session.attestationChallenge = m_sessionAttestation;
    session.peerAddress = m_networkAddress;
    session.peerPort = m_networkPort;
    session.peerNodeId = m_nodeId;
    session.localMessageCounter = m_sessionCounter;
    session.idleInterval = m_sessionIdleInterval;
    session.activeInterval = m_sessionActiveInterval;
    session.activeThreshold = m_sessionActiveThreshold;
    session.active = true;
}

void DeviceObject::parseSession(const QJsonObject &json)
{
    m_sessionLocalId = static_cast <quint16> (json.value("localId").toInt());
    m_sessionPeerId = static_cast <quint16> (json.value("peerId").toInt());
    m_sessionEncryptKey = QByteArray::fromHex(json.value("i2rKey").toString().toLatin1());
    m_sessionDecryptKey = QByteArray::fromHex(json.value("r2iKey").toString().toLatin1());
    m_sessionAttestation = QByteArray::fromHex(json.value("attestation").toString().toLatin1());
    m_sessionCounter = static_cast <quint32> (json.value("localCounter").toVariant().toULongLong());
    m_sessionIdleInterval = static_cast <quint32> (json.value("idleInterval").toVariant().toULongLong());
    m_sessionActiveInterval = static_cast <quint32> (json.value("activeInterval").toVariant().toULongLong());
    m_sessionActiveThreshold = static_cast <quint16> (json.value("activeThreshold").toInt());
}

QJsonObject DeviceObject::serializeSession(void)
{
    QJsonObject json;

    json.insert("localId", m_sessionLocalId);
    json.insert("peerId", m_sessionPeerId);
    json.insert("i2rKey", QString(m_sessionEncryptKey.toHex()));
    json.insert("r2iKey", QString(m_sessionDecryptKey.toHex()));
    json.insert("attestation", QString(m_sessionAttestation.toHex()));
    json.insert("localCounter", static_cast <qint64> (m_sessionCounter));
    json.insert("idleInterval", static_cast <qint64> (m_sessionIdleInterval));
    json.insert("activeInterval", static_cast <qint64> (m_sessionActiveInterval));
    json.insert("activeThreshold", m_sessionActiveThreshold);

    return json;
}

void DeviceObject::updateEndpoint(quint8 endpointId)
{
    if (m_endpoints.value(endpointId).isNull())
        return;

    emit endpointUpdated(this, endpointId);
}

DeviceList::DeviceList(QSettings *config, QObject *parent) : QObject(parent), m_databaseTimer(new QTimer(this)), m_sync(false), m_rootCaId(0)
{
    QFile file(config->value("device/expose", reinterpret_cast <HOMEd*> (parent)->basePath().append("share/homed-common/expose.json")).toString());

    ExposeObject::registerMetaTypes();

    m_databaseFile.setFileName(config->value("device/database", "/opt/homed-matter/database.json").toString());
    m_names = config->value("mqtt/names", false).toBool();

    if (file.open(QFile::ReadOnly))
    {
        m_exposeOptions = QJsonDocument::fromJson(file.readAll()).object().toVariantMap();
        file.close();
    }

    connect(m_databaseTimer, &QTimer::timeout, this, &DeviceList::writeDatabase);
    m_databaseTimer->setSingleShot(true);
}

DeviceList::~DeviceList(void)
{
    m_sync = true;
    writeDatabase();
}

void DeviceList::init(void)
{
    QJsonObject json, fabric;

    if (!m_databaseFile.open(QFile::ReadOnly))
        return;

    json = QJsonDocument::fromJson(m_databaseFile.readAll()).object();
    fabric = json.value("fabric").toObject();

    unserializeDevices(json.value("devices").toArray());

    m_fabricKey = QByteArray::fromHex(fabric.value("key").toString().toUtf8());
    m_ipk = QByteArray::fromHex(fabric.value("ipk").toString().toUtf8());
    m_operationalKey = QByteArray::fromHex(fabric.value("operationalKey").toString().toUtf8());
    m_controllerNoc = QByteArray::fromHex(fabric.value("controllerNOC").toString().toUtf8());
    m_controllerRcac = QByteArray::fromHex(fabric.value("controllerRCAC").toString().toUtf8());
    m_rootCaId = fabric.value("rootCAId").toString().toULongLong(nullptr, 16);

    m_databaseFile.close();
}

void DeviceList::storeDatabase(bool sync)
{
    if (sync)
        m_sync = true;

    m_databaseTimer->start(STORE_DATABASE_DELAY);
}

void DeviceList::setFabricCredentials(const QByteArray &fabricKey, const QByteArray &ipk, const QByteArray &operationalKey, const QByteArray &controllerNoc, const QByteArray &controllerRcac, quint64 rootCaId)
{
    m_fabricKey = fabricKey;
    m_ipk = ipk;
    m_operationalKey = operationalKey;
    m_controllerNoc = controllerNoc;
    m_controllerRcac = controllerRcac;
    m_rootCaId = rootCaId;
}

quint64 DeviceList::generateNodeId(void)
{
    while (true)
    {
        QByteArray data = Crypto::randomData(4);
        quint64 nodeId = 0;

        // all bytes must be non-zero
        for (int i = 0; i < data.length(); i++)
        {
            quint8 value = static_cast <quint8> (data.at(i));

            if (!value)
                value = static_cast <quint8> (static_cast <quint8> (Crypto::randomData(1).at(0)) % 254 + 1);

            nodeId |= static_cast <quint64> (value) << (i * 8);
        }

        if (byNodeId(nodeId).isNull())
            return nodeId;
    }
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
        if (at(i)->nodeId() != nodeId)
            continue;

        return at(i);
    }

    return Device();
}

Device DeviceList::parse(const QJsonObject &json)
{
    QString name = mqttSafe(json.value("name").toString());
    quint64 nodeId = json.value("nodeId").toString().toULongLong(nullptr, 16);
    QJsonArray endpoints = json.value("endpoints").toArray();
    Device device;

    if (!nodeId) // TODO: remove after migration from 0.0.4
        nodeId = json.value("id").toString().toULongLong(nullptr, 16);

    if (name.isEmpty() || !nodeId)
        return Device();

    device = Device(new DeviceObject(nodeId, name));

    if (json.contains("active"))
        device->setActive(json.value("active").toBool());

    if (json.contains("discovery"))
        device->setDiscovery(json.value("discovery").toBool());

    if (json.contains("cloud"))
        device->setCloud(json.value("cloud").toBool());

    device->setNote(json.value("note").toString());
    device->setVendorId(static_cast <quint16> (json.value("vendorId").toInt()));
    device->setProductId(static_cast <quint16> (json.value("productId").toInt()));
    device->setManufacturerName(json.value("manufacturerName").toString());
    device->setModelName(json.value("modelName").toString());
    device->setFabricIndex(static_cast <quint8> (json.value("fabricIndex").toInt()));

    if (json.contains("networkAddress"))
        device->setNetworkAddress(QHostAddress(json.value("networkAddress").toString()));

    if (json.contains("networkPort"))
        device->setNetworkPort(static_cast <quint16> (json.value("networkPort").toInt()));

    if (json.contains("thread"))
        device->setThread(json.value("thread").toBool());
    else if (device->networkAddress().protocol() == QAbstractSocket::IPv6Protocol)
        device->setThread(true);

    if (json.contains("lastSeen"))
        device->setLastSeen(json.value("lastSeen").toVariant().toLongLong());

    device->setResumption(QByteArray::fromHex(json.value("resumptionID").toString().toLatin1()), QByteArray::fromHex(json.value("resumptionSharedSecret").toString().toLatin1()));

    if (json.contains("session"))
        device->parseSession(json.value("session").toObject());

    for (int i = 0; i < endpoints.count(); i++)
    {
        QJsonObject item = endpoints.at(i).toObject();
        QJsonArray clusters = item.value("clusters").toArray();
        quint8 endpointId = static_cast <quint8> (item.value("endpointId").toInt());
        Endpoint endpoint(new EndpointObject(endpointId, device));

        for (int j = 0; j < clusters.count(); j++)
            endpoint->clusters().append(static_cast <quint32> (clusters.at(j).toVariant().toULongLong()));

        endpoint->meta().insert(item.value("meta").toObject().toVariantMap());
        device->endpoints().insert(endpointId, endpoint);
    }

    return device;
}

void DeviceList::addEndpoint(DeviceObject *device, quint8 endpointId, const QList <quint32> &clusters)
{
    Endpoint endpoint = device->endpoints().value(endpointId);
    Device item;

    for (int i = 0; i < count(); i++)
    {
        if (at(i).data() != device)
            continue;

        item = at(i);
        break;
    }

    if (item.isNull())
        return;

    if (endpoint.isNull())
    {
        endpoint = Endpoint(new EndpointObject(endpointId, item));
        device->endpoints().insert(endpointId, endpoint);
    }

    endpoint->clusters() = clusters;
}

void DeviceList::setupEndpoint(DeviceObject *device, quint8 endpointId)
{
    const Endpoint &endpoint = device->endpoints().value(endpointId);
    QList <quint32> clusters;
    quint32 capabilities;
    bool hueSaturation, colorTemperature;

    if (endpoint.isNull())
        return;

    clusters = endpoint->clusters();
    capabilities = static_cast <quint16> (endpoint->meta().value("colorCapabilities").toInt());
    hueSaturation = capabilities & Clusters::ColorControl::Capabilities::HueSaturation;
    colorTemperature = capabilities & Clusters::ColorControl::Capabilities::ColorTemperature;

    if (clusters.contains(Clusters::OnOff::Id))
    {
        endpoint->properties().append(Property(new Properties::Status));
        endpoint->actions().append(Action(new Actions::Status));

        if (endpoint->exposes().isEmpty())
        {
            if (clusters.contains(Clusters::LevelControl::Id) || clusters.contains(Clusters::ColorControl::Id))
            {
                QList <QVariant> options;

                if (clusters.contains(Clusters::LevelControl::Id))
                    options.append("level");

                // XY capability is ignored, some color temperature lamps (e.g. IKEA TRADFRI WS) report it without color support
                if (hueSaturation)
                    options.append("color");

                if (colorTemperature)
                {
                    options.append("colorTemperature");

                    if (endpoint->meta().contains("colorTempMin") && endpoint->meta().contains("colorTempMax"))
                        device->options().insert(QString("colorTemperature_%1").arg(endpointId), QMap <QString, QVariant> {{"min", endpoint->meta().value("colorTempMin")}, {"max", endpoint->meta().value("colorTempMax")}});
                }

                if (hueSaturation && colorTemperature)
                    options.append("colorMode");

                endpoint->exposes().append(Expose(new LightObject));
                device->options().insert(QString("light_%1").arg(endpointId), options);
            }
            else
                endpoint->exposes().append(Expose(new SwitchObject));
        }

        // StartUpOnOff attribute is mandatory with lighting feature only
        if (endpoint->meta().value("onOffFeatures").toUInt() & Clusters::OnOff::Features::LT)
        {
            endpoint->properties().append(Property(new Properties::PowerOnStatus));
            endpoint->actions().append(Action(new Actions::PowerOnStatus));
            endpoint->exposes().append(Expose(new SelectObject("powerOnStatus")));
        }
    }

    if (clusters.contains(Clusters::LevelControl::Id))
    {
        endpoint->properties().append(Property(new Properties::Level));
        endpoint->actions().append(Action(new Actions::Level));
    }

    if (clusters.contains(Clusters::ColorControl::Id))
    {
        if (hueSaturation)
        {
            endpoint->properties().append(Property(new Properties::ColorHS));
            endpoint->actions().append(Action(new Actions::ColorHS));
        }

        if (colorTemperature)
        {
            endpoint->properties().append(Property(new Properties::ColorTemperature));
            endpoint->actions().append(Action(new Actions::ColorTemperature));
        }

        if (hueSaturation && colorTemperature)
            endpoint->properties().append(Property(new Properties::ColorMode));
    }

    if (clusters.contains(Clusters::DoorLock::Id))
    {
        endpoint->properties().append(Property(new Properties::Lock));
        endpoint->actions().append(Action(new Actions::Lock));
    }

    if (clusters.contains(Clusters::WindowCovering::Id))
    {
        endpoint->properties().append(Property(new Properties::CoverPosition));
        endpoint->actions().append(Action(new Actions::CoverStatus));
        endpoint->actions().append(Action(new Actions::CoverPosition));
    }

    if (clusters.contains(Clusters::PowerSource::Id))
    {
        endpoint->properties().append(Property(new Properties::Battery));
        endpoint->exposes().append(Expose(new SensorObject("battery")));
        device->setBatteryPowered(true);
    }

    if (clusters.contains(Clusters::Switch::Id))
    {
        quint32 features = endpoint->meta().value("switchFeatures").toUInt();
        quint8 multiPressMax = static_cast <quint8> (endpoint->meta().value("switchMultiPressMax").toUInt());
        bool encoder = (features & Clusters::Switch::Features::MSM) && !(features & Clusters::Switch::Features::MSL) && multiPressMax > 5;
        QList <QVariant> actions;

        endpoint->properties().append(Property(new Properties::SwitchAction));
        endpoint->exposes().append(Expose(new SensorObject("action")));

        // multi press switch without long press and high multi press maximum is rotary encoder (e.g. IKEA BILRESA)
        if (encoder)
        {
            endpoint->properties().append(Property(new Properties::SwitchCount));
            endpoint->exposes().append(Expose(new SensorObject("count")));
        }

        if (features & Clusters::Switch::Features::LS)
            actions.append("latched");

        if (encoder)
            actions.append(QList <QVariant> {"start", "stop"});
        else if (features & Clusters::Switch::Features::MSM)
        {
            QList <QVariant> list = {"singleClick", "doubleClick", "tripleClick", "multipleClick"};
            actions.append(list.mid(0, multiPressMax ? multiPressMax : 1));
        }
        else if (features & Clusters::Switch::Features::MSR)
            actions.append("singleClick");

        if (features & Clusters::Switch::Features::MSL)
            actions.append(QList <QVariant> {"hold", "release"});

        if (!actions.isEmpty())
        {
            device->options().insert(QString("action_%1").arg(endpointId), m_exposeOptions.value("action"));
            device->updateOption(QString("action_%1").arg(endpointId), "enum", actions);
        }
    }

    if (clusters.contains(Clusters::BooleanState::Id))
    {
        switch (endpoint->meta().value("deviceType").toUInt())
        {
            case Clusters::DeviceTypes::ContactSensor:
                endpoint->properties().append(Property(new Properties::Contact));
                endpoint->exposes().append(Expose(new BinaryObject("contact")));
                break;

            case Clusters::DeviceTypes::WaterLeakDetector:
                endpoint->properties().append(Property(new Properties::WaterLeak));
                endpoint->exposes().append(Expose(new BinaryObject("waterLeak")));
                break;

            default:
                logWarning << device << "endpoint" << endpointId << "boolean state device type" << QString::asprintf("0x%04x", endpoint->meta().value("deviceType").toUInt()) << "not supported";
                break;
        }
    }

    if (clusters.contains(Clusters::OccupancySensing::Id))
    {
        endpoint->properties().append(Property(new Properties::Occupancy));
        endpoint->exposes().append(Expose(new BinaryObject("occupancy")));
    }

    if (clusters.contains(Clusters::TemperatureMeasurement::Id))
    {
        endpoint->properties().append(Property(new Properties::Temperature));
        endpoint->exposes().append(Expose(new SensorObject("temperature")));
    }

    if (clusters.contains(Clusters::RelativeHumidityMeasurement::Id))
    {
        endpoint->properties().append(Property(new Properties::Humidity));
        endpoint->exposes().append(Expose(new SensorObject("humidity")));
    }

    if (clusters.contains(Clusters::ElectricalPowerMeasurement::Id))
    {
        quint32 features = endpoint->meta().value("powerFeatures").toUInt();

        if (features & (Clusters::ElectricalPowerMeasurement::Features::DIRC | Clusters::ElectricalPowerMeasurement::Features::ALTC))
        {
            endpoint->properties().append(Property(new Properties::Voltage));
            endpoint->properties().append(Property(new Properties::Current));
            endpoint->exposes().append(Expose(new SensorObject("voltage")));
            endpoint->exposes().append(Expose(new SensorObject("current")));
        }

        endpoint->properties().append(Property(new Properties::Power));
        endpoint->exposes().append(Expose(new SensorObject("power")));

        if (features & Clusters::ElectricalPowerMeasurement::Features::ALTC)
        {
            endpoint->properties().append(Property(new Properties::Frequency));
            endpoint->exposes().append(Expose(new SensorObject("frequency")));
        }
    }

    if (clusters.contains(Clusters::ElectricalEnergyMeasurement::Id))
    {
        endpoint->properties().append(Property(new Properties::Energy));
        endpoint->exposes().append(Expose(new SensorObject("energy")));
    }

    for (int i = 0; i < endpoint->properties().count(); i++)
        endpoint->properties().at(i)->setParent(endpoint.data());

    for (int i = 0; i < endpoint->actions().count(); i++)
        endpoint->actions().at(i)->setParent(endpoint.data());

    for (int i = 0; i < endpoint->exposes().count(); i++)
    {
        const Expose &expose = endpoint->exposes().at(i);

        expose->setParent(endpoint.data());
        device->options().insert(expose->name(), m_exposeOptions.value(expose->name()));

        logInfo << device << "endpoint" << endpointId << "expose" << expose->name() << "added";
    }
}

void DeviceList::updateMultiple(DeviceObject *device)
{
    QMap <QString, int> map;

    for (auto it = device->endpoints().begin(); it != device->endpoints().end(); it++)
    {
        for (int i = 0; i < it.value()->properties().count(); i++)
            map[it.value()->properties().at(i)->name()]++;
    }

    for (auto it = device->endpoints().begin(); it != device->endpoints().end(); it++)
    {
        const Endpoint &endpoint = it.value();
        bool multiple = false;

        for (int i = 0; i < endpoint->properties().count() && !multiple; i++)
            multiple = map.value(endpoint->properties().at(i)->name()) > 1;

        for (int i = 0; i < endpoint->exposes().count(); i++)
            endpoint->exposes().at(i)->setMultiple(multiple);

        for (int i = 0; i < endpoint->properties().count(); i++)
            endpoint->properties().at(i)->setMultiple(multiple);
    }
}

void DeviceList::unserializeDevices(const QJsonArray &devices)
{
    for (int i = 0; i < devices.count(); i++)
    {
        QJsonObject json = devices.at(i).toObject();
        Device device;

        if (!byName(json.value("name").toString()).isNull())
            continue;

        device = parse(json);

        if (device.isNull())
            continue;

        append(device);

        for (auto it = device->endpoints().begin(); it != device->endpoints().end(); it++)
            setupEndpoint(device.data(), it.key());

        updateMultiple(device.data());
    }

    if (!count())
        return;

    logInfo << count() << "devices loaded";
}

QJsonArray DeviceList::serializeDevices(void)
{
    QJsonArray array;

    for (int i = 0; i < count(); i++)
    {
        const Device &device = at(i);
        QJsonObject json = {{"nodeId", device->address()}, {"name", device->name()}, {"active", device->active()}, {"discovery", device->discovery()}, {"cloud", device->cloud()}};

        if (device->vendorId())
            json.insert("vendorId", device->vendorId());

        if (device->productId())
            json.insert("productId", device->productId());

        if (device->fabricIndex())
            json.insert("fabricIndex", device->fabricIndex());

        if (!device->manufacturerName().isEmpty())
            json.insert("manufacturerName", device->manufacturerName());

        if (!device->modelName().isEmpty())
            json.insert("modelName", device->modelName());

        if (!device->note().isEmpty())
            json.insert("note", device->note());

        if (!device->networkAddress().isNull())
            json.insert("networkAddress", device->networkAddress().toString());

        if (device->networkPort() != MATTER_PORT)
            json.insert("networkPort", device->networkPort());

        if (device->thread())
            json.insert("thread", true);

        if (device->lastSeen())
            json.insert("lastSeen", device->lastSeen());

        if (!device->resumptionId().isEmpty())
            json.insert("resumptionID", QString(device->resumptionId().toHex()));

        if (!device->resumptionSecret().isEmpty())
            json.insert("resumptionSharedSecret", QString(device->resumptionSecret().toHex()));

        if (device->sessionStored())
            json.insert("session", device->serializeSession());

        if (!device->endpoints().isEmpty())
        {
            QJsonArray endpoints;

            for (auto it = device->endpoints().begin(); it != device->endpoints().end(); it++)
            {
                const Endpoint &endpoint = it.value();
                QJsonObject item = {{"endpointId", endpoint->id()}};

                if (!endpoint->clusters().isEmpty())
                {
                    QJsonArray clusters;

                    for (int j = 0; j < endpoint->clusters().count(); j++)
                        clusters.append(static_cast <qint64> (endpoint->clusters().at(j)));

                    item.insert("clusters", clusters);
                }

                if (!endpoint->meta().isEmpty())
                    item.insert("meta", QJsonObject::fromVariantMap(endpoint->meta()));

                endpoints.append(item);
            }

            json.insert("endpoints", endpoints);
        }

        array.append(json);
    }

    return array;
}

void DeviceList::writeDatabase(void)
{
    HOMEd *controller = reinterpret_cast <HOMEd*> (parent());
    QJsonObject json, fabric;

    if (!m_fabricKey.isEmpty())
    {
        fabric.insert("key", QString(m_fabricKey.toHex()));
        fabric.insert("rootCAId", QString::number(m_rootCaId, 16));
        fabric.insert("ipk", QString(m_ipk.toHex()));
        fabric.insert("operationalKey", QString(m_operationalKey.toHex()));
        fabric.insert("controllerNOC", QString(m_controllerNoc.toHex()));
        fabric.insert("controllerRCAC", QString(m_controllerRcac.toHex()));
    }

    json = {{"devices", serializeDevices()}, {"fabric", fabric}, {"names", m_names}, {"timestamp", QDateTime::currentSecsSinceEpoch()}, {"version", SERVICE_VERSION}};
    controller->mqttPublishStatus(json);

    if (!m_sync)
        return;

    json.remove("names");
    m_sync = false;

    if (controller->writeFile(m_databaseFile, QJsonDocument(json).toJson(QJsonDocument::Compact)))
        return;

    logWarning << "Database not stored";
}
