#include "controller.h"
#include "expose.h"
#include "logger.h"

Controller::Controller(const QString &configFile) : HOMEd(SERVICE_VERSION, configFile), m_timer(new QTimer(this)), m_matter(new Matter(getConfig(), this)), m_commands(QMetaEnum::fromType <Command> ())
{
    m_haPrefix = getConfig()->value("homeassistant/prefix", "homeassistant").toString();
    m_haStatus = getConfig()->value("homeassistant/status", "homeassistant/status").toString();
    m_haEnabled = getConfig()->value("homeassistant/enabled", false).toBool();
    m_haUpdate = getConfig()->value("homeassistant/update", false).toBool();

    connect(m_timer, &QTimer::timeout, this, &Controller::updateProperties);

    connect(m_matter, &Matter::updateAvailability, this, &Controller::updateAvailability);
    connect(m_matter, &Matter::deviceEvent, this, &Controller::deviceEvent);
    connect(m_matter, &Matter::deviceShared, this, &Controller::deviceShared); // TODO: do we need this?
    connect(m_matter, &Matter::statusUpdated, this, &Controller::statusUpdated);

    m_timer->setSingleShot(true);

    for (int i = 0; i < m_matter->devices()->count(); i++)
    {
        const Device &device = m_matter->devices()->at(i);
        connect(device.data(), &DeviceObject::deviceUpdated, this, &Controller::deviceUpdated);
        connect(device.data(), &DeviceObject::endpointUpdated, this, &Controller::endpointUpdated);
        m_matter->connectDevice(device.data()); // TODO: maybe add m_matter->init() for connect to devices
    }
}

void Controller::publishExposes(DeviceObject *device, bool remove)
{
    device->publishExposes(this, device->address(), QString("%1_%2").arg(uniqueId(), device->address()), m_haPrefix, m_haEnabled, m_haUpdate, m_matter->devices()->names(), remove);

    if (remove)
        return;

    m_timer->start(UPDATE_PROPERTIES_DELAY);
}

void Controller::publishProperties(const Device &device)
{
    for (auto it = device->endpoints().begin(); it != device->endpoints().end(); it++)
        endpointUpdated(device.data(), it.key());
}

void Controller::mqttConnected(void)
{
    mqttSubscribe(mqttTopic("command/%1").arg(serviceTopic()));
    mqttSubscribe(mqttTopic("td/%1/#").arg(serviceTopic()));

    for (int i = 0; i < m_matter->devices()->count(); i++)
        publishExposes(m_matter->devices()->at(i).data());

    if (m_haEnabled)
    {
        mqttPublishDiscovery("Matter", SERVICE_VERSION, m_haPrefix);
        mqttSubscribe(m_haStatus);
    }

    for (int i = 0; i < m_matter->devices()->count(); i++)
        updateAvailability(m_matter->devices()->at(i).data());

    m_matter->devices()->store();
    mqttPublishStatus();
}

// NOT REVIEWED
void Controller::mqttReceived(const QByteArray &message, const QMqttTopicName &topic)
{
    QString subTopic = topic.name().replace(0, mqttTopic().length(), QString());
    QJsonObject json = QJsonDocument::fromJson(message).object();

    if (subTopic == QString("command/%1").arg(serviceTopic()))
    {
        switch (static_cast <Command> (m_commands.keyToValue(json.value("action").toString().toUtf8().constData())))
        {
            case Command::restartService:
            {
                logWarning << "Restart request received...";
                mqttPublish(topic.name(), QJsonObject(), true);
                QCoreApplication::exit(EXIT_RESTART);
                break;
            }

            case Command::updateDevice:
            {
                Device device = m_matter->devices()->byName(json.value("device").toString());

                if (device.isNull())
                {
                    logWarning << "Device" << json.value("device").toString() << "update failed, device not found";
                    break;
                }

                if (json.contains("name"))
                {
                    QString name = mqttSafe(json.value("name").toString());
                    Device other = m_matter->devices()->byName(name);

                    if (device != other && !other.isNull())
                    {
                        logWarning << "Device" << name << "update failed, name already in use";
                        mqttPublish(mqttTopic("event/%1").arg(serviceTopic()), {{"device", name}, {"event", m_matter->eventName(Matter::Event::nameDuplicate)}});
                        break;
                    }

                    if (device->name() != name)
                    {
                        mqttPublish(mqttTopic("device/%1/%2").arg(serviceTopic(), m_matter->devices()->names() ? device->name() : device->address()), QJsonObject(), true);
                        publishExposes(device.data(), true);
                        mqttPublish(mqttTopic("event/%1").arg(serviceTopic()), {{"device", device->name()}, {"event", m_matter->eventName(Matter::Event::aboutToRename)}});
                        device->setName(name);
                    }
                }

                if (json.contains("active"))
                    device->setActive(json.value("active").toBool());

                if (json.contains("discovery"))
                    device->setDiscovery(json.value("discovery").toBool());

                if (json.contains("cloud"))
                    device->setCloud(json.value("cloud").toBool());

                logInfo << device << "successfully updated";

                if (device->availability() != Availability::Unknown)
                    mqttPublish(mqttTopic("device/%1/%2").arg(serviceTopic(), m_matter->devices()->names() ? device->name() : device->address()), {{"status", device->availability() == Availability::Online ? "online" : "offline"}}, true);

                publishExposes(device.data());
                mqttPublish(mqttTopic("event/%1").arg(serviceTopic()), {{"device", device->name()}, {"event", m_matter->eventName(Matter::Event::updated)}});
                m_matter->devices()->store(true);
                break;
            }

            case Command::removeDevice:
            {
                Device device = m_matter->devices()->byName(json.value("device").toString());

                if (!device.isNull())
                    m_matter->removeDevice(reinterpret_cast <DeviceObject*> (device.data()));

                break;
            }

            case Command::getProperties:
            {
                Device device = m_matter->devices()->byName(json.value("device").toString());

                if (!device.isNull())
                    publishProperties(device);

                break;
            }

            case Command::connectDevice:
            {
                quint32 passcode;
                quint16 discriminator;
                bool shortDiscriminator;

                if (json.contains("payload") && Matter::parseQRCode(json.value("payload").toString(), passcode, discriminator))
                {
                    shortDiscriminator = false;
                }
                else if (json.contains("code") && Matter::parseManualCode(json.value("code").toString(), passcode, discriminator))
                {
                    shortDiscriminator = true;
                }
                else
                {
                    logWarning << "Invalid or missing setup code";
                    break;
                }

                quint64 nodeId = m_matter->devices()->generateNodeId();
                bool mdnsOnly = json.value("mdns").toBool();
                logInfo << "Adding device, passcode:" << passcode << "discriminator:" << discriminator << (shortDiscriminator ? "(short)" : "(full)") << "nodeId:" << QString::number(nodeId, 16);
                m_matter->connectDevice(passcode, discriminator, shortDiscriminator, nodeId, mdnsOnly);
                break;
            }

            case Command::shareDevice:
            {
                Device device = m_matter->devices()->byName(json.value("device").toString());

                if (device.isNull() || !device->active())
                {
                    logWarning << "Device not found or offline for sharing";
                    break;
                }

                quint16 timeout = static_cast <quint16> (json.value("timeout").toInt(300));

                if (timeout < 180) timeout = 180;
                if (timeout > 900) timeout = 900;

                m_matter->shareDevice(device.data(), timeout);
                break;
            }
        }
    }
    else if (subTopic.startsWith(QString("td/%1/").arg(serviceTopic())))
    {
        QList <QString> list = subTopic.remove(QString("td/%1/").arg(serviceTopic())).split('/');
        Device device = m_matter->devices()->byName(list.value(0));

        if (device.isNull() || !device->active())
            return;

        quint8 endpointId = static_cast <quint8> (list.value(1).toInt());

        for (auto it = json.begin(); it != json.end(); it++)
        {
            if (!it.value().toVariant().isValid())
                continue;

            if (endpointId)
            {
                m_matter->sendCommand(device.data(), endpointId, it.key(), it.value().toVariant());
            }
            else
            {
                for (auto ep = device->endpoints().begin(); ep != device->endpoints().end(); ep++)
                    m_matter->sendCommand(device.data(), ep.key(), it.key(), it.value().toVariant());
            }
        }
    }
    else if (topic.name() == m_haStatus)
    {
        if (message != "online")
            return;

        m_timer->start(UPDATE_PROPERTIES_DELAY);
    }
}

void Controller::updateAvailability(DeviceObject *device)
{
    QString status = device->availability() == Availability::Online ? "online" : "offline";
    mqttPublish(mqttTopic("device/%1/%2").arg(serviceTopic(), m_matter->devices()->names() ? device->name() : device->address()), {{"status", status}}, true);
    logInfo << device << "is" << status;
}

void Controller::updateProperties(void)
{
    for (int i = 0; i < m_matter->devices()->count(); i++)
        publishProperties(m_matter->devices()->at(i));
}

void Controller::deviceUpdated(DeviceObject *device)
{
    logInfo << device << "successfully updated";
    publishExposes(device);
    m_matter->devices()->store(true);
}

void Controller::endpointUpdated(DeviceObject *device, quint8 endpointId) // TODO: use properties instead of exposes
{
    Endpoint endpoint = device->endpoints().value(endpointId);
    QString topic = mqttTopic("fd/%1/%2").arg(serviceTopic(), m_matter->devices()->names() ? device->name() : device->address());

    if (endpoint.isNull() || endpoint->status().isEmpty())
        return;

    for (int i = 0; i < endpoint->exposes().count(); i++)
    {
        if (!endpoint->exposes().at(i)->multiple())
            continue;

        topic.append(QString("/%1").arg(endpointId));
        break;
    }

    mqttPublish(topic, QJsonObject::fromVariantMap(endpoint->status()));
}

// NOT REVIEWED
void Controller::deviceEvent(DeviceObject *device, Matter::Event event, const QJsonObject &json)
{
    QMap <QString, QVariant> map = {{"event", m_matter->eventName(event)}};

    if (device)
        map.insert("device", device->name());

    map.insert(json.toVariantMap());

    switch (event)
    {
        case Matter::Event::added:
        {
            logInfo << device << "commissioned successfully";

            connect(device, &DeviceObject::deviceUpdated, this, &Controller::deviceUpdated);
            connect(device, &DeviceObject::endpointUpdated, this, &Controller::endpointUpdated);

            m_matter->devices()->append(Device(device));

            if (device->availability() != Availability::Unknown)
                mqttPublish(mqttTopic("device/%1/%2").arg(serviceTopic(), m_matter->devices()->names() ? device->name() : device->address()), {{"status", device->availability() == Availability::Online ? "online" : "offline"}}, true);

            publishExposes(device);
            m_matter->devices()->store(true);
            break;
        }

        case Matter::Event::removed:
        {
            int index = -1;
            m_matter->devices()->byName(device->name(), &index);

            if (index < 0)
                break;

            disconnect(device, &DeviceObject::deviceUpdated, this, &Controller::deviceUpdated);
            disconnect(device, &DeviceObject::endpointUpdated, this, &Controller::endpointUpdated);

            logInfo << device << "removed" << (json.value("success").toBool() ? "gracefully" : "forcefully");

            mqttPublish(mqttTopic("device/%1/%2").arg(serviceTopic(), m_matter->devices()->names() ? device->name() : device->address()), QJsonObject(), true);
            publishExposes(device, true);
            m_matter->devices()->removeAt(index);
            m_matter->devices()->store(true);
            break;
        }

        default:
            break;
    }

    mqttPublish(mqttTopic("event/%1").arg(serviceTopic()), QJsonObject::fromVariantMap(map));
}

void Controller::deviceShared(DeviceObject *device, const QString &manualCode, const QString &qrCode, quint16 timeout)
{
    QString topic = mqttTopic("device/%1/%2").arg(serviceTopic(), m_matter->devices()->names() ? device->name() : device->address());
    mqttPublish(topic, {{"status", "online"}, {"share", QJsonObject {{"manualCode", manualCode}, {"qrCode", qrCode}, {"expire", QDateTime::currentSecsSinceEpoch() + timeout}}}}, true); // TODO: check message format
    QTimer::singleShot(timeout * 1000, this, [this, topic, device]() { mqttPublish(topic, {{"status", device->availability() == Availability::Online ? "online" : "offline"}}, true); });
}

void Controller::statusUpdated(const QJsonObject &json)
{
    mqttPublish(mqttTopic("status/%1").arg(serviceTopic()), json, true);
}
