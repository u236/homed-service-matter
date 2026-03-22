#include <QtEndian>
#include <QDateTime>
#include <cstring>
#include "matter.h"
#include "color.h"
#include "logger.h"
#include "tlv.h"
#include "clusters.h"

using namespace MatterProtocol;

Matter::Matter(QObject *parent) : QObject(parent), m_udp(new QUdpSocket(this)), m_mrp(new MRP(this)), m_mdns(new MDNS(this)), m_sessions(new SessionManager(this)), m_searchTimer(new QTimer(this)), m_reconnectTimer(new QTimer(this)), m_pingTimer(new QTimer(this)), m_port(5540), m_debug(false), m_searching(false), m_searchShortDiscriminator(false), m_searchPasscode(0), m_searchDiscriminator(0), m_messageCounter(0), m_exchangeCounter(0), m_sessionCounter(1), m_fabricId(1), m_nodeId(1)
{
    connect(m_udp, &QUdpSocket::readyRead, this, &Matter::readyRead);
    connect(m_searchTimer, &QTimer::timeout, this, &Matter::searchTimeout);
    connect(m_reconnectTimer, &QTimer::timeout, this, &Matter::reconnectTimeout);
    connect(m_pingTimer, &QTimer::timeout, this, &Matter::pingTimeout);
    connect(m_mrp, &MRP::retransmit, this, &Matter::mrpRetransmit);
    connect(m_mrp, &MRP::retransmitFailed, this, &Matter::mrpRetransmitFailed);
    connect(m_mrp, &MRP::sendStandaloneAck, this, &Matter::mrpSendStandaloneAck);
    connect(m_mdns, &MDNS::serviceFound, this, &Matter::mdnsServiceFound);

    m_searchTimer->setSingleShot(true);
    m_reconnectTimer->setSingleShot(true);
    m_pingTimer->start(10000);

    // fabric credentials will be set by Controller after database init
    m_devices = nullptr;
    m_pendingCASE = nullptr;
    m_caseDevice = nullptr;
    m_caseExchangeId = 0;
    m_caseNeedsCommissioningComplete = false;
    m_pendingCommissionDevice = nullptr;
    m_pendingRemoveDevice = nullptr;

    // start message counter from random value to avoid replay detection after restart
    QByteArray counterBytes = Crypto::randomBytes(4);
    memcpy(&m_messageCounter, counterBytes.constData(), 4);

    if (!m_udp->bind(QHostAddress::Any, m_port))
        logWarning << "Failed to bind UDP port" << m_port;
    else
        logInfo << "Matter controller listening on port" << m_port;
}

void Matter::setFabricCredentials(const QByteArray &fabricKey, quint64 rootCAId, const QByteArray &ipk, const QByteArray &operationalKey, const QByteArray &controllerNOC, const QByteArray &controllerRCAC)
{
    m_fabricKey = fabricKey;
    m_rootCAId = rootCAId;
    m_ipk = ipk;
    m_operationalKey = operationalKey;

    ECPoint fabricPub = ECPoint::fromMultiply(ECPoint::generator(), BigNum(m_fabricKey).bn());
    m_fabricPublicKey = fabricPub.toUncompressed();

    ECPoint opPub = ECPoint::fromMultiply(ECPoint::generator(), BigNum(m_operationalKey).bn());
    m_operationalPubKey = opPub.toUncompressed();

    if (!controllerNOC.isEmpty() && !controllerRCAC.isEmpty())
    {
        m_controllerNOC = controllerNOC;
        m_controllerRCAC = controllerRCAC;
    }
    else
    {
        m_controllerRCAC = generateFabricCert(m_fabricId, 0, m_fabricPublicKey, true);
        m_controllerNOC = generateFabricCert(m_fabricId, m_nodeId, m_operationalPubKey, false);
    }

    logInfo << "Fabric credentials loaded, rootCAId:" << QString::number(m_rootCAId, 16);
}

void Matter::connectDevice(DeviceObject *device)
{
    if (m_pendingCASE)
    {
        if (!m_caseQueue.contains(device))
            m_caseQueue.append(device);

        return;
    }

    SessionInfo *existing = m_sessions->findByPeerNodeId(device->nodeId());

    if (existing && existing->active)
    {
        logDebug(m_debug) << "Already have active session for" << device->name();
        return;
    }

    QHostAddress address = device->networkAddress();
    quint16 port = device->networkPort();

    if (address.isNull())
    {
        logWarning << "No address known for" << device->name();
        return;
    }

    CASESession *session = new CASESession(this);

    connect(session, &CASESession::sendSigma1, this, &Matter::caseSendSigma1);
    connect(session, &CASESession::sendSigma3, this, &Matter::caseSendSigma3);
    connect(session, &CASESession::established, this, &Matter::caseEstablished);
    connect(session, &CASESession::failed, this, &Matter::caseFailed);

    m_pendingCASE = session;
    m_caseDevice = device;
    m_caseExchangeId = m_exchangeCounter++;
    m_caseAddress = address;
    m_casePort = port;

    quint16 sessionId = m_sessionCounter++;

    logInfo << "Starting CASE with" << device->name() << "at" << address.toString() << ":" << port;

    session->start(sessionId, device->nodeId(),
                   m_fabricKey, m_fabricPublicKey,
                   m_operationalKey, m_operationalPubKey,
                   m_fabricId, m_nodeId, m_rootCAId,
                   m_ipk, m_controllerNOC, m_controllerRCAC);
}

void Matter::discoverDevice(DeviceObject *device)
{
    SessionInfo *session = m_sessions->findByPeerNodeId(device->nodeId());

    if (!session || !session->active)
        return;

    logInfo << "Discovering endpoints for" << device->name();

    // step 1: read PartsList from endpoint 0
    QList <AttributePath> paths;
    paths.append(AttributePath(0, Clusters::Descriptor::Id, Clusters::Descriptor::Attributes::PartsList));

    QByteArray payload = InteractionModel::encodeReadRequest(paths);
    sendEncrypted(session, static_cast <quint8> (InteractionModelOpcode::ReadRequest), static_cast <quint16> (ProtocolId::InteractionModel), payload, m_exchangeCounter++, true);
}

void Matter::removeDevice(DeviceObject *device)
{
    SessionInfo *session = m_sessions->findByPeerNodeId(device->nodeId());

    if (!session || !session->active)
    {
        logWarning << "No active session for" << device->name();
        emit deviceRemoved(device, false);
        return;
    }

    logInfo << "Sending RemoveFabric to" << device->name() << "fabricIndex:" << device->fabricIndex();

    m_pendingRemoveDevice = device;

    MatterTLV::Encoder fields;
    fields.openStructure();
    fields.encodeUnsignedInt(0, device->fabricIndex());
    fields.closeContainer();

    QByteArray payload = InteractionModel::encodeInvokeRequest(CommandPath(0, Clusters::OperationalCredentials::Id, Clusters::OperationalCredentials::Commands::RemoveFabric), fields);
    sendEncrypted(session, static_cast <quint8> (InteractionModelOpcode::InvokeRequest), static_cast <quint16> (ProtocolId::InteractionModel), payload, m_exchangeCounter++, true);

    session->active = false;
}

void Matter::addDevice(quint32 passcode, quint16 discriminator, bool shortDiscriminator, quint64 nodeId)
{
    m_searching = true;
    m_searchPasscode = passcode;
    m_searchDiscriminator = discriminator;
    m_searchShortDiscriminator = shortDiscriminator;

    m_searchTimer->start(60000);
    m_searchNodeId = nodeId;
    logInfo << "Searching for commissionable device, discriminator:" << discriminator << (shortDiscriminator ? "(short)" : "(full)") << "nodeId:" << nodeId;
    m_mdns->browse();
}

// --- Send command to a commissioned device ---

void Matter::sendCommand(DeviceObject *device, quint8 endpointId, const QString &name, const QVariant &value)
{
    SessionInfo *session = m_sessions->findByPeerNodeId(device->nodeId());

    if (!session)
    {
        logWarning << "No active session for device" << device->name();
        handleDeviceUnreachable(device);
        return;
    }

    QByteArray payload;

    if (name == "status")
    {
        QString status = value.toString();

        if (status == "toggle")
            payload = InteractionModel::encodeToggleCommand(endpointId);
        else
            payload = InteractionModel::encodeOnOffCommand(endpointId, status == "on");
    }
    else if (name == "level")
        payload = InteractionModel::encodeMoveToLevelCommand(endpointId, static_cast <quint8> (value.toUInt()));
    else if (name == "colorTemperature")
        payload = InteractionModel::encodeMoveToColorTemperatureCommand(endpointId, static_cast <quint16> (value.toUInt()));
    else if (name == "color")
    {
        QList <QVariant> list = value.toList();

        if (list.count() >= 3)
        {
            Color color(list.at(0).toDouble() / 0xFF, list.at(1).toDouble() / 0xFF, list.at(2).toDouble() / 0xFF);
            double h, s;
            color.toHS(&h, &s);
            payload = InteractionModel::encodeMoveToHueAndSaturationCommand(endpointId, static_cast <quint8> (h * 0xFF), static_cast <quint8> (s * 0xFF));
        }
    }
    else if (name == "lock")
        payload = InteractionModel::encodeLockCommand(endpointId, value.toString() == "lock");
    else if (name == "cover")
        payload = InteractionModel::encodeCoverCommand(endpointId, static_cast <quint8> (value.toUInt()));
    else if (name == "coverPosition")
        payload = InteractionModel::encodeCoverCommand(endpointId, 3, static_cast <quint16> (value.toUInt()));

    if (payload.isEmpty())
    {
        logWarning << "Unknown command:" << name;
        return;
    }

    logInfo << "Sending command" << name << "to" << device->name() << "endpoint" << endpointId;
    sendEncrypted(session, static_cast <quint8> (InteractionModelOpcode::InvokeRequest), static_cast <quint16> (ProtocolId::InteractionModel), payload, m_exchangeCounter++, true);
}

void Matter::readAttributes(DeviceObject *device, const QList <AttributePath> &paths)
{
    SessionInfo *session = m_sessions->findByPeerNodeId(device->nodeId());

    if (!session)
    {
        logWarning << "No active session for device" << device->name();
        handleDeviceUnreachable(device);
        return;
    }

    QByteArray payload = InteractionModel::encodeReadRequest(paths);
    sendEncrypted(session, static_cast <quint8> (InteractionModelOpcode::ReadRequest), static_cast <quint16> (ProtocolId::InteractionModel), payload, m_exchangeCounter++, true);
}

// --- Low-level message sending ---

void Matter::sendRawDatagram(const QByteArray &data, const QHostAddress &address, quint16 port)
{
    m_udp->writeDatagram(data, address, port);
}

void Matter::sendUnencrypted(quint8 opcode, quint16 protocolId, const QByteArray &payload, quint16 exchangeId, const QHostAddress &address, quint16 port, bool initiator, quint32 ackCounter)
{
    MessageHeader msgHeader;
    msgHeader.flags = 0x04; // source node ID present
    msgHeader.securityFlags = 0x00;
    msgHeader.sessionId = 0;
    msgHeader.messageCounter = ++m_messageCounter;
    msgHeader.sourceNodeId = m_nodeId;

    ProtocolHeader protoHeader;
    protoHeader.exchangeFlags = static_cast <quint8> (ExchangeFlag::Reliability);

    if (initiator)
        protoHeader.exchangeFlags |= static_cast <quint8> (ExchangeFlag::Initiator);

    if (ackCounter)
    {
        protoHeader.exchangeFlags |= static_cast <quint8> (ExchangeFlag::Acknowledgement);
        protoHeader.ackCounter = ackCounter;
        m_mrp->cancelPendingAck(ackCounter);
    }

    protoHeader.opcode = opcode;
    protoHeader.exchangeId = exchangeId;
    protoHeader.protocolId = protocolId;

    QByteArray data = MessageCodec::encodeMessage(msgHeader, protoHeader, payload);
    sendRawDatagram(data, address, port);
    m_mrp->messageSent(data, address, port, msgHeader.messageCounter, protoHeader.exchangeId, true);
}

void Matter::sendEncrypted(SessionInfo *session, quint8 opcode, quint16 protocolId, const QByteArray &payload, quint16 exchangeId, bool initiator, quint32 ackCounter)
{
    session->localMessageCounter++;

    MessageHeader msgHeader;
    msgHeader.flags = 0x00;
    msgHeader.securityFlags = 0x00;
    msgHeader.sessionId = session->peerSessionId;
    msgHeader.messageCounter = session->localMessageCounter;

    QByteArray header = MessageCodec::encodeHeader(msgHeader);

    // build protocol header + payload (this is what gets encrypted)
    ProtocolHeader protoHeader;
    protoHeader.exchangeFlags = static_cast <quint8> (ExchangeFlag::Reliability);

    if (initiator)
        protoHeader.exchangeFlags |= static_cast <quint8> (ExchangeFlag::Initiator);

    if (ackCounter)
    {
        protoHeader.exchangeFlags |= static_cast <quint8> (ExchangeFlag::Acknowledgement);
        protoHeader.ackCounter = ackCounter;
        m_mrp->cancelPendingAck(ackCounter);
    }

    protoHeader.opcode = opcode;
    protoHeader.exchangeId = exchangeId;
    protoHeader.protocolId = protocolId;

    QByteArray plaintext = MessageCodec::encodeProtocolHeader(protoHeader);
    plaintext.append(payload);

    QByteArray nonce = SessionManager::buildNonce(msgHeader.securityFlags, msgHeader.messageCounter, session->active ? m_nodeId : 0);
    QByteArray encrypted = Crypto::aesCcmEncrypt(session->i2rKey, nonce, header, plaintext, SESSION_TAG_LENGTH);

    QByteArray data = header;
    data.append(encrypted);

    sendRawDatagram(data, session->peerAddress, session->peerPort);
    m_mrp->messageSent(data, session->peerAddress, session->peerPort, msgHeader.messageCounter, exchangeId, true);
}

// --- Incoming message handling ---

void Matter::handleSecureChannel(const MessageHeader &msgHeader, const ProtocolHeader &protoHeader, const QByteArray &payload, const QHostAddress &address, quint16 port)
{
    Q_UNUSED(address)
    Q_UNUSED(port)

    switch (static_cast <SecureChannelOpcode> (protoHeader.opcode))
    {
        case SecureChannelOpcode::PBKDFParamResponse:
        {
            for (auto it = m_pendingCommissions.begin(); it != m_pendingCommissions.end(); it++)
            {
                if (it.value().exchangeId == protoHeader.exchangeId)
                {
                    it.value().pase->setLastPeerMessageCounter(msgHeader.messageCounter);
                    it.value().pase->handlePBKDFParamResponse(payload);
                    break;
                }
            }

            break;
        }

        case SecureChannelOpcode::PASEPake2:
        {
            for (auto it = m_pendingCommissions.begin(); it != m_pendingCommissions.end(); it++)
            {
                if (it.value().exchangeId == protoHeader.exchangeId)
                {
                    it.value().pase->setLastPeerMessageCounter(msgHeader.messageCounter);
                    it.value().pase->handlePake2(payload);
                    break;
                }
            }

            break;
        }

        case SecureChannelOpcode::StatusReport:
        {
            // check if this is for a PASE session
            for (auto it = m_pendingCommissions.begin(); it != m_pendingCommissions.end(); it++)
            {
                if (it.value().exchangeId == protoHeader.exchangeId && it.value().state == CommissioningState::PASE)
                {
                    it.value().pase->handleStatusReport(payload);
                    return;
                }
            }

            // check if this is for a CASE session
            if (m_pendingCASE && protoHeader.exchangeId == m_caseExchangeId)
            {
                m_pendingCASE->handleStatusReport(payload);
                return;
            }

            logDebug(m_debug) << "StatusReport from session" << msgHeader.sessionId;
            break;
        }

        case SecureChannelOpcode::CASESigma1:
            logDebug(m_debug) << "CASE Sigma1 from" << msgHeader.sourceNodeId;
            break;

        case SecureChannelOpcode::CASESigma2:
        {
            if (m_pendingCASE)
            {
                m_pendingCASE->setLastPeerMessageCounter(msgHeader.messageCounter);
                m_pendingCASE->handleSigma2(payload);
            }

            break;
        }

        case SecureChannelOpcode::MRPStandaloneAck:
            break;

        default:
            logWarning << "Unknown secure channel opcode:" << QString::number(protoHeader.opcode, 16);
            break;
    }
}

void Matter::handleInteractionModel(const MessageHeader &msgHeader, const ProtocolHeader &protoHeader, const QByteArray &payload, const QHostAddress &address, quint16 port)
{
    Q_UNUSED(address)
    Q_UNUSED(port)

    switch (static_cast <InteractionModelOpcode> (protoHeader.opcode))
    {
        case InteractionModelOpcode::ReportData:
        {
            QList <AttributeReport> reports = InteractionModel::decodeReportData(payload);
            QList <AttributePath> pendingSubPaths;
            SessionInfo *pendingSubSession = nullptr;
            DeviceObject *pendingSubDevice = nullptr;

            // check for subscriptionId and suppressResponse in ReportData
            {
                MatterTLV::Decoder rdDecoder(payload);
                MatterTLV::Element rdRoot = rdDecoder.decode();

                for (const MatterTLV::Element &el : rdRoot.children)
                {
                    if (el.tag == 0)
                        logDebug(m_debug) << "ReportData subscriptionId:" << el.value.toUInt();
                    if (el.tag == 3)
                        logDebug(m_debug) << "ReportData suppressResponse:" << el.value.toBool();
                }
            }

            for (const AttributeReport &report : reports)
            {
                if (report.hasError)
                {
                    logWarning << "Attribute error, cluster:" << QString::number(report.path.clusterId, 16) << "attr:" << QString::number(report.path.attributeId, 16) << "status:" << report.status;
                    continue;
                }

                logDebug(m_debug) << "Attribute, ep:" << report.path.endpointId << "cluster:" << QString::number(report.path.clusterId, 16) << "attr:" << QString::number(report.path.attributeId, 16) << "value:" << report.value;

                // update device state from subscription reports
                {
                    SessionInfo *attrSession = m_sessions->findByLocalId(msgHeader.sessionId);

                    if (attrSession)
                    {
                        for (int i = 0; i < m_devices->count(); i++)
                        {
                            DeviceObject *dev = reinterpret_cast <DeviceObject*> (m_devices->at(i).data());

                            if (dev->nodeId() == attrSession->peerNodeId)
                            {
                                if (report.path.clusterId == Clusters::OnOff::Id && report.path.attributeId == Clusters::OnOff::Attributes::OnOff)
                                    dev->updateEndpoint(report.path.endpointId, "status", report.value.toBool() ? "on" : "off");
                                else if (report.path.clusterId == Clusters::LevelControl::Id && report.path.attributeId == Clusters::LevelControl::Attributes::CurrentLevel)
                                    dev->updateEndpoint(report.path.endpointId, "level", report.value.toUInt());
                                else if (report.path.clusterId == Clusters::ColorControl::Id && (report.path.attributeId == Clusters::ColorControl::Attributes::CurrentHue || report.path.attributeId == Clusters::ColorControl::Attributes::CurrentSaturation))
                                {
                                    Endpoint ep = dev->endpoints().value(report.path.endpointId);

                                    if (!ep.isNull())
                                    {
                                        if (report.path.attributeId == Clusters::ColorControl::Attributes::CurrentHue)
                                            ep->status().insert("colorH", report.value.toUInt());
                                        else
                                            ep->status().insert("colorS", report.value.toUInt());

                                        if (ep->status().contains("colorH") && ep->status().contains("colorS"))
                                        {
                                            Color color = Color::fromHS(ep->status().value("colorH").toDouble() / 0xFF, ep->status().value("colorS").toDouble() / 0xFF);
                                            dev->updateEndpoint(report.path.endpointId, "color", QVariant(QList <QVariant> {static_cast <int> (color.r() * 0xFF), static_cast <int> (color.g() * 0xFF), static_cast <int> (color.b() * 0xFF)}));
                                        }
                                    }
                                }
                                else if (report.path.clusterId == Clusters::ColorControl::Id && report.path.attributeId == Clusters::ColorControl::Attributes::ColorTemperatureMireds)
                                    dev->updateEndpoint(report.path.endpointId, "colorTemperature", report.value.toUInt());
                                else if (report.path.clusterId == Clusters::TemperatureMeasurement::Id && report.path.attributeId == Clusters::TemperatureMeasurement::Attributes::MeasuredValue)
                                    dev->updateEndpoint(report.path.endpointId, "temperature", report.value.toDouble() / 100.0);
                                else if (report.path.clusterId == Clusters::RelativeHumidityMeasurement::Id && report.path.attributeId == Clusters::RelativeHumidityMeasurement::Attributes::MeasuredValue)
                                    dev->updateEndpoint(report.path.endpointId, "humidity", report.value.toDouble() / 100.0);
                                else if (report.path.clusterId == Clusters::ElectricalPowerMeasurement::Id && report.path.attributeId == Clusters::ElectricalPowerMeasurement::Attributes::ActivePower)
                                    dev->updateEndpoint(report.path.endpointId, "power", report.value.toLongLong() / 1000.0);
                                else if (report.path.clusterId == Clusters::ElectricalEnergyMeasurement::Id && report.path.attributeId == Clusters::ElectricalEnergyMeasurement::Attributes::CumulativeEnergyImported)
                                {
                                    for (const MatterTLV::Element &child : report.rawValue.children)
                                    {
                                        if (child.tag == 0)
                                            dev->updateEndpoint(report.path.endpointId, "energy", child.value.toLongLong() / 1000.0);
                                    }
                                }

                                break;
                            }
                        }
                    }
                }

                // check if this is part of commissioning (BasicInformation read)
                for (auto it = m_pendingCommissions.begin(); it != m_pendingCommissions.end(); it++)
                {
                    PendingCommission &commission = it.value();

                    if (commission.state == CommissioningState::ReadBasicInfo && commission.device)
                    {
                        if (report.path.clusterId == Clusters::BasicInformation::Id)
                        {
                            switch (report.path.attributeId)
                            {
                                case Clusters::BasicInformation::Attributes::VendorName:
                                    commission.device->setManufacturerName(report.value.toString());
                                    break;

                                case Clusters::BasicInformation::Attributes::ProductName:
                                    commission.device->setModelName(report.value.toString());
                                    break;

                                case Clusters::BasicInformation::Attributes::VendorID:
                                    commission.device->setVendorId(report.value.toUInt());
                                    break;

                                case Clusters::BasicInformation::Attributes::ProductID:
                                    commission.device->setProductId(report.value.toUInt());
                                    break;
                            }
                        }
                    }
                }
            }

            // process Descriptor cluster reports — build endpoints and exposes
            {
                SessionInfo *reportSession = m_sessions->findByLocalId(msgHeader.sessionId);
                DeviceObject *reportDevice = nullptr;

                if (reportSession)
                {
                    for (int i = 0; i < m_devices->count(); i++)
                    {
                        DeviceObject *dev = reinterpret_cast <DeviceObject*> (m_devices->at(i).data());

                        if (dev->nodeId() == reportSession->peerNodeId)
                        {
                            reportDevice = dev;
                            break;
                        }
                    }
                }

                if (reportDevice)
                {
                    Device reportDeviceHolder; // keep shared pointer alive

                    for (int di = 0; di < m_devices->count(); di++)
                    {
                        if (m_devices->at(di).data() == reportDevice)
                        {
                            reportDeviceHolder = m_devices->at(di);
                            break;
                        }
                    }

                    // step 1 response: PartsList — request ServerList for discovered endpoints
                    QList <quint8> discoveredEndpoints;

                    for (const AttributeReport &report : reports)
                    {
                        if (!report.hasError && report.path.clusterId == Clusters::Descriptor::Id && report.path.attributeId == Clusters::Descriptor::Attributes::PartsList && report.path.endpointId == 0)
                        {
                            // PartsList is an array — parse children
                            for (const MatterTLV::Element &child : report.rawValue.children)
                                discoveredEndpoints.append(static_cast <quint8> (child.value.toUInt()));
                        }
                    }

                    if (!discoveredEndpoints.isEmpty() && reportDevice->endpoints().isEmpty())
                    {
                        logInfo << "Found" << discoveredEndpoints.count() << "endpoints on" << reportDevice->name();

                        QList <AttributePath> serverPaths;

                        for (quint8 ep : discoveredEndpoints)
                            serverPaths.append(AttributePath(ep, Clusters::Descriptor::Id, Clusters::Descriptor::Attributes::ServerList));

                        QByteArray serverPayload = InteractionModel::encodeReadRequest(serverPaths);
                        sendEncrypted(reportSession, static_cast <quint8> (InteractionModelOpcode::ReadRequest), static_cast <quint16> (ProtocolId::InteractionModel), serverPayload, m_exchangeCounter++, true);
                    }

                    // step 2 response: ServerList — create exposes and subscribe
                    QMap <quint8, QList <quint32>> endpointClusters;

                    for (const AttributeReport &report : reports)
                    {
                        if (report.hasError || report.path.clusterId != Clusters::Descriptor::Id || report.path.attributeId != Clusters::Descriptor::Attributes::ServerList)
                            continue;

                        // ServerList is an array — parse children
                        logDebug(m_debug) << "ServerList for ep" << report.path.endpointId << ":" << report.rawValue.children.count() << "clusters, type:" << static_cast <int> (report.rawValue.type);

                        for (const MatterTLV::Element &child : report.rawValue.children)
                        {
                            quint32 clusterId = child.value.toUInt();
                            endpointClusters[report.path.endpointId].append(clusterId);
                        }
                    }

                    // create endpoints and exposes
                    for (auto it = endpointClusters.begin(); it != endpointClusters.end(); it++)
                    {
                        if (it.key() > 0)
                            m_devices->setupEndpoint(reportDevice, it.key(), it.value());
                    }

                    m_devices->updateMultiple(reportDevice);

                    // collect subscribe paths for after StatusResponse
                    if (!endpointClusters.isEmpty() && reportSession)
                    {
                        for (auto it = endpointClusters.begin(); it != endpointClusters.end(); it++)
                        {
                            quint8 epId = it.key();

                            if (epId == 0)
                                continue;

                            if (it.value().contains(Clusters::OnOff::Id))
                                pendingSubPaths.append(AttributePath(epId, Clusters::OnOff::Id, Clusters::OnOff::Attributes::OnOff));

                            if (it.value().contains(Clusters::LevelControl::Id))
                                pendingSubPaths.append(AttributePath(epId, Clusters::LevelControl::Id, Clusters::LevelControl::Attributes::CurrentLevel));

                            if (it.value().contains(Clusters::ColorControl::Id))
                            {
                                pendingSubPaths.append(AttributePath(epId, Clusters::ColorControl::Id, Clusters::ColorControl::Attributes::CurrentHue));
                                pendingSubPaths.append(AttributePath(epId, Clusters::ColorControl::Id, Clusters::ColorControl::Attributes::CurrentSaturation));
                                pendingSubPaths.append(AttributePath(epId, Clusters::ColorControl::Id, Clusters::ColorControl::Attributes::ColorTemperatureMireds));
                            }

                            if (it.value().contains(Clusters::TemperatureMeasurement::Id))
                                pendingSubPaths.append(AttributePath(epId, Clusters::TemperatureMeasurement::Id, Clusters::TemperatureMeasurement::Attributes::MeasuredValue));

                            if (it.value().contains(Clusters::RelativeHumidityMeasurement::Id))
                                pendingSubPaths.append(AttributePath(epId, Clusters::RelativeHumidityMeasurement::Id, Clusters::RelativeHumidityMeasurement::Attributes::MeasuredValue));

                            if (it.value().contains(Clusters::ElectricalPowerMeasurement::Id))
                                pendingSubPaths.append(AttributePath(epId, Clusters::ElectricalPowerMeasurement::Id, Clusters::ElectricalPowerMeasurement::Attributes::ActivePower));

                            if (it.value().contains(Clusters::ElectricalEnergyMeasurement::Id))
                                pendingSubPaths.append(AttributePath(epId, Clusters::ElectricalEnergyMeasurement::Id, Clusters::ElectricalEnergyMeasurement::Attributes::CumulativeEnergyImported));
                        }

                        pendingSubSession = reportSession;
                        pendingSubDevice = reportDevice;
                    }
                }
            }

            // send StatusResponse (success) to acknowledge ReportData
            SessionInfo *session = m_sessions->findByLocalId(msgHeader.sessionId);

            if (session && !reports.isEmpty())
            {
                logDebug(m_debug) << "Sending StatusResponse(0) for ReportData, exchange:" << protoHeader.exchangeId << "ack:" << msgHeader.messageCounter;
                QByteArray statusPayload = InteractionModel::encodeStatusResponse(0);
                sendEncrypted(session, static_cast <quint8> (InteractionModelOpcode::StatusResponse), static_cast <quint16> (ProtocolId::InteractionModel), statusPayload, protoHeader.exchangeId, !protoHeader.isInitiator(), msgHeader.messageCounter);
            }

            // send SubscribeRequest after StatusResponse has been sent
            if (!pendingSubPaths.isEmpty() && pendingSubSession && pendingSubDevice)
            {
                logInfo << "Subscribing to" << pendingSubPaths.count() << "attributes on" << pendingSubDevice->name();
                m_subscribedPaths[pendingSubDevice->nodeId()] = pendingSubPaths;
                QByteArray subPayload = InteractionModel::encodeSubscribeRequest(pendingSubPaths, 0, 60);
                sendEncrypted(pendingSubSession, static_cast <quint8> (InteractionModelOpcode::SubscribeRequest), static_cast <quint16> (ProtocolId::InteractionModel), subPayload, m_exchangeCounter++, true);
                pendingSubDevice->deviceUpdated(pendingSubDevice);
            }

            // continue commissioning if applicable
            for (auto it = m_pendingCommissions.begin(); it != m_pendingCommissions.end(); it++)
            {
                if (it.value().state == CommissioningState::ReadBasicInfo)
                {
                    it.value().state = CommissioningState::RequestPAI;
                    continueCommissioning(it.value());
                    break;
                }
            }

            break;
        }

        case InteractionModelOpcode::StatusResponse:
        {
            quint8 status = InteractionModel::decodeStatusResponse(payload);
            logDebug(m_debug) << "StatusResponse:" << status;

            // TimedRequest was ACKed with StatusResponse(0) — now send the actual command
            if (status == 0)
            {
                for (auto it = m_pendingCommissions.begin(); it != m_pendingCommissions.end(); it++)
                {
                    if (it.value().timedInvokePending)
                    {
                        it.value().lastPeerCounter = msgHeader.messageCounter;
                        continueCommissioning(it.value());
                        break;
                    }
                }
            }

            break;
        }

        case InteractionModelOpcode::SubscribeResponse:
        {
            MatterTLV::Decoder decoder(payload);
            MatterTLV::Element root = decoder.decode();
            quint32 subscriptionId = 0;
            quint16 maxInterval = 0;

            for (const MatterTLV::Element &el : root.children)
            {
                if (el.tag == 0) subscriptionId = el.value.toUInt();
                if (el.tag == 2) maxInterval = el.value.toUInt();
            }

            logInfo << "Subscription established, id:" << subscriptionId << "maxInterval:" << maxInterval;
            break;
        }

        case InteractionModelOpcode::InvokeResponse:
        {
            QList <CommandResponse> responses = InteractionModel::decodeInvokeResponse(payload);

            logDebug(m_debug) << "InvokeResponse received, entries:" << responses.count() << "payload size:" << payload.size();

            for (const CommandResponse &response : responses)
            {
                logDebug(m_debug) << "InvokeResponse, cluster:" << QString::number(response.path.clusterId, 16) << "cmd:" << QString::number(response.path.commandId, 16) << "status:" << response.status;

                // check commissioning responses
                for (auto it = m_pendingCommissions.begin(); it != m_pendingCommissions.end(); it++)
                {
                    PendingCommission &commission = it.value();

                    if (commission.state == CommissioningState::ArmFailSafe && response.path.clusterId == Clusters::GeneralCommissioning::Id && response.path.commandId == Clusters::GeneralCommissioning::Commands::ArmFailSafeResponse)
                    {
                        logDebug(m_debug) << "ArmFailSafe response, setting regulatory config...";
                        commission.state = CommissioningState::SetRegulatoryConfig;
                        continueCommissioning(commission);
                        break;
                    }

                    if (commission.state == CommissioningState::SetRegulatoryConfig && response.path.clusterId == Clusters::GeneralCommissioning::Id && response.path.commandId == Clusters::GeneralCommissioning::Commands::SetRegulatoryConfigResponse)
                    {
                        logDebug(m_debug) << "SetRegulatoryConfig response, reading basic info...";
                        commission.state = CommissioningState::ReadBasicInfo;
                        continueCommissioning(commission);
                        break;
                    }

                    if (commission.state == CommissioningState::RequestPAI && response.path.clusterId == Clusters::OperationalCredentials::Id && response.path.commandId == Clusters::OperationalCredentials::Commands::CertificateChainResponse)
                    {
                        logDebug(m_debug) << "PAI certificate received, requesting DAC...";
                        commission.state = CommissioningState::RequestDAC;
                        continueCommissioning(commission);
                        break;
                    }

                    if (commission.state == CommissioningState::RequestDAC && response.path.clusterId == Clusters::OperationalCredentials::Id && response.path.commandId == Clusters::OperationalCredentials::Commands::CertificateChainResponse)
                    {
                        logDebug(m_debug) << "DAC certificate received, requesting attestation...";
                        commission.state = CommissioningState::RequestAttestation;
                        continueCommissioning(commission);
                        break;
                    }

                    if (commission.state == CommissioningState::RequestAttestation && response.path.clusterId == Clusters::OperationalCredentials::Id && response.path.commandId == Clusters::OperationalCredentials::Commands::AttestationResponse)
                    {
                        logDebug(m_debug) << "Attestation received, sending CSR request...";
                        commission.state = CommissioningState::CSRRequest;
                        continueCommissioning(commission);
                        break;
                    }

                    if (commission.state == CommissioningState::CSRRequest && response.path.clusterId == Clusters::OperationalCredentials::Id && response.path.commandId == Clusters::OperationalCredentials::Commands::CSRResponse)
                    {
                        logDebug(m_debug) << "CSRResponse received";

                        for (const MatterTLV::Element &field : response.data.children)
                        {
                            if (field.tag == 0 && field.type == MatterTLV::Type::ByteString)
                            {
                                MatterTLV::Decoder nocsrDecoder(field.value.toByteArray());
                                MatterTLV::Element nocsrRoot = nocsrDecoder.decode();

                                for (const MatterTLV::Element &el : nocsrRoot.children)
                                {
                                    if (el.tag == 1 && el.type == MatterTLV::Type::ByteString)
                                        commission.devicePublicKey = Crypto::parseCSRPublicKey(el.value.toByteArray());
                                }
                            }
                        }

                        if (commission.devicePublicKey.isEmpty())
                        {
                            logWarning << "Failed to parse device public key from CSR";
                            break;
                        }

                        logDebug(m_debug) << "Device public key extracted," << commission.devicePublicKey.length() << "bytes";

                        commission.rcacTLV = generateFabricCert(m_fabricId, 0, m_fabricPublicKey, true);
                        commission.nocTLV = generateFabricCert(m_fabricId, commission.device->nodeId(), commission.devicePublicKey, false);

                        logDebug(m_debug) << "Generated RCAC" << commission.rcacTLV.length() << "bytes, NOC" << commission.nocTLV.length() << "bytes";
        logDebug(m_debug) << "NOC hex:" << commission.nocTLV.toHex();
        logDebug(m_debug) << "RCAC hex:" << commission.rcacTLV.toHex();

                        commission.state = CommissioningState::AddTrustedRootCert;
                        continueCommissioning(commission);
                        break;
                    }

                    if (commission.state == CommissioningState::AddTrustedRootCert && response.path.clusterId == Clusters::OperationalCredentials::Id && response.path.commandId == Clusters::OperationalCredentials::Commands::AddTrustedRootCertificate)
                    {
                        if (response.status != 0)
                        {
                            logWarning << "AddTrustedRootCertificate failed, status:" << response.status;
                            break;
                        }

                        logDebug(m_debug) << "AddTrustedRootCertificate accepted, sending AddNOC...";
                        commission.state = CommissioningState::AddNOC;
                        continueCommissioning(commission);
                        break;
                    }

                    if (commission.state == CommissioningState::AddNOC && response.path.clusterId == Clusters::OperationalCredentials::Id && response.path.commandId == Clusters::OperationalCredentials::Commands::NOCResponse)
                    {
                        quint8 nocStatus = 0xFF;

                        for (const MatterTLV::Element &field : response.data.children)
                        {
                            if (field.tag == 0) nocStatus = field.value.toUInt();
                            if (field.tag == 1) commission.device->setFabricIndex(field.value.toUInt());
                        }

                        if (nocStatus != 0)
                        {
                            logWarning << "AddNOC failed, status:" << nocStatus;
                            break;
                        }

                        logInfo << "AddNOC success, starting CASE for CommissioningComplete...";
                        commission.device->setNetworkAddress(commission.address);
                        commission.device->setNetworkPort(commission.port);

                        m_caseNeedsCommissioningComplete = true;
                        connectDevice(commission.device);

                        // clean up PASE session
                        m_sessions->removeSession(commission.localSessionId);
                        m_pendingCommissions.remove(commission.localSessionId);

                        if (commission.pase)
                            commission.pase->deleteLater();

                        break;
                    }

                    if (commission.state == CommissioningState::CommissioningComplete && response.path.clusterId == Clusters::GeneralCommissioning::Id && response.path.commandId == Clusters::GeneralCommissioning::Commands::CommissioningCompleteResponse)
                    {
                        logInfo << "Commissioning complete!";
                        commission.state = CommissioningState::Done;
                        continueCommissioning(commission);
                        break;
                    }
                }
            }

            // handle RemoveFabric response (NOCResponse cmd 0x08)
            if (m_pendingRemoveDevice)
            {
                for (const CommandResponse &response : responses)
                {
                    if (response.path.clusterId == Clusters::OperationalCredentials::Id && response.path.commandId == Clusters::OperationalCredentials::Commands::NOCResponse)
                    {
                        quint8 status = 0xFF;

                        for (const MatterTLV::Element &field : response.data.children)
                        {
                            if (field.tag == 0) status = field.value.toUInt();
                        }

                        emit deviceRemoved(m_pendingRemoveDevice, status == 0);
                        m_pendingRemoveDevice = nullptr;
                    }
                }
            }

            // read back subscribed attributes after successful device command
            {
                SessionInfo *session = m_sessions->findByLocalId(msgHeader.sessionId);

                if (session && m_subscribedPaths.contains(session->peerNodeId))
                {
                    QByteArray readPayload = InteractionModel::encodeReadRequest(m_subscribedPaths.value(session->peerNodeId));
                    sendEncrypted(session, static_cast <quint8> (InteractionModelOpcode::ReadRequest), static_cast <quint16> (ProtocolId::InteractionModel), readPayload, m_exchangeCounter++, true);
                }
            }

            // handle CommissioningComplete response on CASE session (after AddNOC → CASE)
            if (m_pendingCommissionDevice)
            {
                for (const CommandResponse &response : responses)
                {
                    if (response.path.clusterId == Clusters::GeneralCommissioning::Id && response.path.commandId == Clusters::GeneralCommissioning::Commands::CommissioningCompleteResponse)
                    {
                        logInfo << "CommissioningComplete on CASE success, device fully commissioned";
                        emit deviceCommissioned(m_pendingCommissionDevice);
                        m_pendingCommissionDevice = nullptr;
                    }
                }
            }

            break;
        }

        default:
            logWarning << "Unknown IM opcode:" << QString::number(protoHeader.opcode, 16);
            break;
    }
}

// --- Commissioning flow ---

void Matter::startCommissioning(const MatterService &service)
{
    PASESession *pase = new PASESession(this);

    connect(pase, &PASESession::sendPBKDFParamRequest, this, &Matter::paseSendPBKDFParamRequest);
    connect(pase, &PASESession::sendPake1, this, &Matter::paseSendPake1);
    connect(pase, &PASESession::sendPake3, this, &Matter::paseSendPake3);
    connect(pase, &PASESession::established, this, &Matter::paseEstablished);
    connect(pase, &PASESession::failed, this, &Matter::paseFailed);

    quint16 sessionId = m_sessionCounter++;
    quint16 exchangeId = m_exchangeCounter++;

    PendingCommission commission;
    commission.pase = pase;
    commission.address = service.address;
    commission.port = service.port;
    commission.exchangeId = exchangeId;
    commission.localSessionId = sessionId;
    commission.passcode = m_searchPasscode;
    commission.assignedNodeId = m_searchNodeId;
    commission.service = service;
    commission.state = CommissioningState::PASE;

    m_pendingCommissions.insert(sessionId, commission);

    logInfo << "Starting commissioning with" << service.address.toString() << ":" << service.port;
    pase->start(commission.passcode, sessionId);
}

void Matter::continueCommissioning(PendingCommission &commission)
{
    SessionInfo *session = m_sessions->findByLocalId(commission.localSessionId);

    if (!session)
    {
        logWarning << "No session for commissioning";
        return;
    }

    switch (commission.state)
    {
        case CommissioningState::ArmFailSafe:
        {
            logDebug(m_debug) << "Sending ArmFailSafe...";

            MatterTLV::Encoder fields;
            fields.openStructure();
            fields.encodeUnsignedInt(0, 900);  // expiryLengthSeconds
            fields.encodeUnsignedInt(1, 1);    // breadcrumb
            fields.closeContainer();

            QByteArray payload = InteractionModel::encodeInvokeRequest(CommandPath(0, Clusters::GeneralCommissioning::Id, Clusters::GeneralCommissioning::Commands::ArmFailSafe), fields);
            sendEncrypted(session, static_cast <quint8> (InteractionModelOpcode::InvokeRequest), static_cast <quint16> (ProtocolId::InteractionModel), payload, m_exchangeCounter++, true);
            break;
        }

        case CommissioningState::SetRegulatoryConfig:
        {
            logDebug(m_debug) << "Sending SetRegulatoryConfig...";

            MatterTLV::Encoder fields;
            fields.openStructure();
            fields.encodeUnsignedInt(0, 0);                  // newRegulatoryConfig: Indoor (0)
            fields.encodeUTF8String(1, QString("XX"));       // countryCode
            fields.encodeUnsignedInt(2, 0);                  // breadcrumb
            fields.closeContainer();

            QByteArray payload = InteractionModel::encodeInvokeRequest(CommandPath(0, Clusters::GeneralCommissioning::Id, Clusters::GeneralCommissioning::Commands::SetRegulatoryConfig), fields);
            sendEncrypted(session, static_cast <quint8> (InteractionModelOpcode::InvokeRequest), static_cast <quint16> (ProtocolId::InteractionModel), payload, m_exchangeCounter++, true);
            break;
        }

        case CommissioningState::ReadBasicInfo:
        {
            logDebug(m_debug) << "Reading BasicInformation cluster...";

            QList <AttributePath> paths;
            paths.append(AttributePath(0, Clusters::BasicInformation::Id, Clusters::BasicInformation::Attributes::VendorName));
            paths.append(AttributePath(0, Clusters::BasicInformation::Id, Clusters::BasicInformation::Attributes::VendorID));
            paths.append(AttributePath(0, Clusters::BasicInformation::Id, Clusters::BasicInformation::Attributes::ProductName));
            paths.append(AttributePath(0, Clusters::BasicInformation::Id, Clusters::BasicInformation::Attributes::ProductID));
            paths.append(AttributePath(0, Clusters::BasicInformation::Id, Clusters::BasicInformation::Attributes::SoftwareVersionString));

            QByteArray payload = InteractionModel::encodeReadRequest(paths);
            sendEncrypted(session, static_cast <quint8> (InteractionModelOpcode::ReadRequest), static_cast <quint16> (ProtocolId::InteractionModel), payload, m_exchangeCounter++, true);
            break;
        }

        case CommissioningState::RequestPAI:
        {
            logDebug(m_debug) << "Requesting PAI certificate...";

            MatterTLV::Encoder fields;
            fields.openStructure();
            fields.encodeUnsignedInt(0, 1);  // CertificateType = PAI
            fields.closeContainer();

            QByteArray payload = InteractionModel::encodeInvokeRequest(CommandPath(0, Clusters::OperationalCredentials::Id, Clusters::OperationalCredentials::Commands::CertificateChainRequest), fields);
            sendEncrypted(session, static_cast <quint8> (InteractionModelOpcode::InvokeRequest), static_cast <quint16> (ProtocolId::InteractionModel), payload, m_exchangeCounter++, true);
            break;
        }

        case CommissioningState::RequestDAC:
        {
            logDebug(m_debug) << "Requesting DAC certificate...";

            MatterTLV::Encoder fields;
            fields.openStructure();
            fields.encodeUnsignedInt(0, 2);  // CertificateType = DAC
            fields.closeContainer();

            QByteArray payload = InteractionModel::encodeInvokeRequest(CommandPath(0, Clusters::OperationalCredentials::Id, Clusters::OperationalCredentials::Commands::CertificateChainRequest), fields);
            sendEncrypted(session, static_cast <quint8> (InteractionModelOpcode::InvokeRequest), static_cast <quint16> (ProtocolId::InteractionModel), payload, m_exchangeCounter++, true);
            break;
        }

        case CommissioningState::RequestAttestation:
        {
            logDebug(m_debug) << "Requesting attestation...";

            MatterTLV::Encoder fields;
            fields.openStructure();
            fields.encodeByteString(0, Crypto::randomBytes(32));  // AttestationNonce
            fields.closeContainer();

            QByteArray payload = InteractionModel::encodeInvokeRequest(CommandPath(0, Clusters::OperationalCredentials::Id, Clusters::OperationalCredentials::Commands::AttestationRequest), fields);
            sendEncrypted(session, static_cast <quint8> (InteractionModelOpcode::InvokeRequest), static_cast <quint16> (ProtocolId::InteractionModel), payload, m_exchangeCounter++, true);
            break;
        }

        case CommissioningState::CSRRequest:
        {
            logDebug(m_debug) << "Sending CSRRequest...";

            MatterTLV::Encoder fields;
            fields.openStructure();
            fields.encodeByteString(0, Crypto::randomBytes(32)); // CSRNonce
            fields.closeContainer();

            QByteArray payload = InteractionModel::encodeInvokeRequest(CommandPath(0, Clusters::OperationalCredentials::Id, Clusters::OperationalCredentials::Commands::CSRRequest), fields);
            sendEncrypted(session, static_cast <quint8> (InteractionModelOpcode::InvokeRequest), static_cast <quint16> (ProtocolId::InteractionModel), payload, m_exchangeCounter++, true);
            break;
        }

        case CommissioningState::AddTrustedRootCert:
        {
            logDebug(m_debug) << "Sending AddTrustedRootCertificate...";

            MatterTLV::Encoder fields;
            fields.openStructure();
            fields.encodeByteString(0, commission.rcacTLV);
            fields.closeContainer();

            QByteArray payload = InteractionModel::encodeInvokeRequest(CommandPath(0, Clusters::OperationalCredentials::Id, Clusters::OperationalCredentials::Commands::AddTrustedRootCertificate), fields);
            sendEncrypted(session, static_cast <quint8> (InteractionModelOpcode::InvokeRequest), static_cast <quint16> (ProtocolId::InteractionModel), payload, m_exchangeCounter++, true);
            break;
        }

        case CommissioningState::AddNOC:
        {
            logDebug(m_debug) << "Sending AddNOC...";

            MatterTLV::Encoder fields;
            fields.openStructure();
            fields.encodeByteString(0, commission.nocTLV);   // NOCValue
            // tag 1: ICACValue (skip, no intermediate CA)
            fields.encodeByteString(2, m_ipk);               // IPKValue (16 bytes)
            fields.encodeUnsignedInt(3, m_nodeId);            // CaseAdminSubject
            fields.encodeUnsignedInt(4, 0xFFF1);              // AdminVendorId (test)
            fields.closeContainer();

            QByteArray payload = InteractionModel::encodeInvokeRequest(CommandPath(0, Clusters::OperationalCredentials::Id, Clusters::OperationalCredentials::Commands::AddNOC), fields);
            sendEncrypted(session, static_cast <quint8> (InteractionModelOpcode::InvokeRequest), static_cast <quint16> (ProtocolId::InteractionModel), payload, m_exchangeCounter++, true);
            break;
        }

        case CommissioningState::CommissioningComplete:
        {
            if (!commission.timedInvokePending)
            {
                logDebug(m_debug) << "Sending TimedRequest for CommissioningComplete...";
                commission.exchangeId = m_exchangeCounter++;
                QByteArray payload = InteractionModel::encodeTimedRequest(5000);
                sendEncrypted(session, static_cast <quint8> (InteractionModelOpcode::TimedRequest), static_cast <quint16> (ProtocolId::InteractionModel), payload, commission.exchangeId, true);
                commission.timedInvokePending = true;
                break;
            }

            commission.timedInvokePending = false;
            logDebug(m_debug) << "Sending CommissioningComplete...";

            MatterTLV::Encoder fields;
            fields.openStructure();
            fields.closeContainer();

            QByteArray payload = InteractionModel::encodeInvokeRequest(CommandPath(0, Clusters::GeneralCommissioning::Id, Clusters::GeneralCommissioning::Commands::CommissioningComplete), fields, true);
            sendEncrypted(session, static_cast <quint8> (InteractionModelOpcode::InvokeRequest), static_cast <quint16> (ProtocolId::InteractionModel), payload, commission.exchangeId, true, commission.lastPeerCounter);
            break;
        }

        case CommissioningState::Done:
        {
            logDebug(m_debug) << "CommissioningComplete success, starting CASE...";
            session->peerNodeId = commission.device->nodeId();
            session->active = false;
            emit deviceCommissioned(commission.device);

            connectDevice(commission.device);

            m_pendingCommissions.remove(commission.localSessionId);

            if (commission.pase)
                commission.pase->deleteLater();

            break;
        }

        default:
            break;
    }
}

// --- Certificate generation ---

QByteArray Matter::generateFabricCert(quint64 fabricId, quint64 nodeId, const QByteArray &subjectPubKey, bool isRCAC)
{
    QByteArray derCert = Crypto::generateX509Cert(m_rootCAId, fabricId, nodeId, subjectPubKey, m_fabricKey, m_fabricPublicKey, isRCAC);

    if (derCert.isEmpty())
    {
        logWarning << "Failed to generate X.509 certificate";
        return QByteArray();
    }

    QByteArray tlvCert = Crypto::x509DerToMatterTLV(derCert);
    logDebug(m_debug) << "Generated" << (isRCAC ? "RCAC" : "NOC") << derCert.length() << "DER bytes," << tlvCert.length() << "TLV bytes";

    if (!isRCAC)
        logDebug(m_debug) << "NOC DER hex:" << derCert.toHex();
    return tlvCert;
}

// --- Standalone ACK ---

void Matter::sendStandaloneAck(quint32 ackCounter, quint16 exchangeId, quint16 sessionId, const QHostAddress &address, quint16 port, bool initiator)
{
    SessionInfo *session = m_sessions->findByLocalId(sessionId);

    if (session && session->active)
    {
        session->localMessageCounter++;

        MessageHeader msgHeader;
        msgHeader.flags = 0x00;
        msgHeader.securityFlags = 0x00;
        msgHeader.sessionId = session->peerSessionId;
        msgHeader.messageCounter = session->localMessageCounter;

        QByteArray header = MessageCodec::encodeHeader(msgHeader);

        ProtocolHeader protoHeader;
        protoHeader.exchangeFlags = static_cast <quint8> (ExchangeFlag::Acknowledgement);

        if (initiator)
            protoHeader.exchangeFlags |= static_cast <quint8> (ExchangeFlag::Initiator);
        protoHeader.opcode = static_cast <quint8> (SecureChannelOpcode::MRPStandaloneAck);
        protoHeader.exchangeId = exchangeId;
        protoHeader.protocolId = static_cast <quint16> (ProtocolId::SecureChannel);
        protoHeader.ackCounter = ackCounter;

        QByteArray plaintext = MessageCodec::encodeProtocolHeader(protoHeader);
        QByteArray nonce = SessionManager::buildNonce(msgHeader.securityFlags, msgHeader.messageCounter, session->active ? m_nodeId : 0);
        QByteArray encrypted = Crypto::aesCcmEncrypt(session->i2rKey, nonce, header, plaintext, SESSION_TAG_LENGTH);

        QByteArray data = header;
        data.append(encrypted);
        sendRawDatagram(data, session->peerAddress, session->peerPort);
    }
    else
    {
        MessageHeader msgHeader;
        msgHeader.flags = 0x00;
        msgHeader.securityFlags = 0x00;
        msgHeader.sessionId = sessionId;
        msgHeader.messageCounter = ++m_messageCounter;

        ProtocolHeader protoHeader;
        protoHeader.exchangeFlags = static_cast <quint8> (ExchangeFlag::Acknowledgement);

        if (initiator)
            protoHeader.exchangeFlags |= static_cast <quint8> (ExchangeFlag::Initiator);

        protoHeader.opcode = static_cast <quint8> (SecureChannelOpcode::MRPStandaloneAck);
        protoHeader.exchangeId = exchangeId;
        protoHeader.protocolId = static_cast <quint16> (ProtocolId::SecureChannel);
        protoHeader.ackCounter = ackCounter;

        QByteArray data = MessageCodec::encodeMessage(msgHeader, protoHeader, QByteArray());
        sendRawDatagram(data, address, port);
    }
}

// --- UDP read ---

void Matter::readyRead(void)
{
    while (m_udp->hasPendingDatagrams())
    {
        QByteArray datagram;
        QHostAddress sender;
        quint16 senderPort;

        datagram.resize(m_udp->pendingDatagramSize());
        m_udp->readDatagram(datagram.data(), datagram.size(), &sender, &senderPort);

        // normalize IPv4-mapped IPv6 to plain IPv4
        bool ok;
        quint32 ipv4 = sender.toIPv4Address(&ok);

        if (ok)
            sender = QHostAddress(ipv4);

        MessageHeader msgHeader;
        ProtocolHeader protoHeader;
        quint32 headerOffset, payloadOffset;

        if (!MessageCodec::decodeHeader(datagram, msgHeader, headerOffset))
        {
            logDebug(m_debug) << "Invalid message header from" << sender.toString() << "size:" << datagram.size() << "hex:" << datagram.left(16).toHex();
            continue;
        }

        if (m_mrp->isDuplicate(sender, msgHeader.messageCounter))
            continue;

        QByteArray payload;

        if (msgHeader.sessionId != 0)
        {
            // encrypted session
            SessionInfo *session = m_sessions->findByLocalId(msgHeader.sessionId);

            if (!session)
                continue;

            QByteArray header = datagram.left(headerOffset);
            QByteArray ciphertext = datagram.mid(headerOffset);

            payload = m_sessions->decrypt(session, msgHeader.securityFlags, msgHeader.messageCounter, session->peerNodeId, header, ciphertext);

            if (payload.isEmpty())
            {
                logDebug(m_debug) << "Decryption failed for session" << msgHeader.sessionId << "counter:" << msgHeader.messageCounter << "from" << sender.toString() << "size:" << ciphertext.size();
                continue;
            }

            logDebug(m_debug) << "Decrypted message from session" << msgHeader.sessionId << "counter:" << msgHeader.messageCounter << "size:" << payload.size();
            session->lastSeen = QDateTime::currentMSecsSinceEpoch();
        }
        else
        {
            payload = datagram.mid(headerOffset);
        }

        if (!MessageCodec::decodeProtocolHeader(payload, 0, protoHeader, payloadOffset))
        {
            logDebug(m_debug) << "Invalid protocol header from" << sender.toString();
            continue;
        }

        m_mrp->messageReceived(msgHeader.messageCounter, protoHeader.exchangeId, protoHeader.hasAck(), protoHeader.ackCounter, sender, senderPort, msgHeader.sessionId, protoHeader.needsAck(), protoHeader.isInitiator());

        QByteArray messagePayload = payload.mid(payloadOffset);

        switch (static_cast <ProtocolId> (protoHeader.protocolId))
        {
            case ProtocolId::SecureChannel:
                handleSecureChannel(msgHeader, protoHeader, messagePayload, sender, senderPort);
                break;

            case ProtocolId::InteractionModel:
                handleInteractionModel(msgHeader, protoHeader, messagePayload, sender, senderPort);
                break;

            default:
                logWarning << "Unknown protocol:" << QString::number(protoHeader.protocolId, 16);
                break;
        }
    }
}

// --- Timer callbacks ---

void Matter::searchTimeout(void)
{
    m_searching = false;
    m_mdns->stop();
    logWarning << "Device search timeout, device not found";
}

void Matter::reconnectTimeout(void)
{
    if (!m_devices)
        return;

    bool hasOffline = false;

    for (int i = 0; i < m_devices->count(); i++)
    {
        DeviceObject *device = reinterpret_cast <DeviceObject*> (m_devices->at(i).data());

        if (device->availability() != Availability::Online && !device->networkAddress().isNull())
        {
            connectDevice(device);
            hasOffline = true;
        }
    }

    if (hasOffline)
        m_reconnectTimer->start(30000);
}

void Matter::pingTimeout(void)
{
    if (!m_devices)
        return;

    qint64 now = QDateTime::currentMSecsSinceEpoch();

    for (int i = 0; i < m_devices->count(); i++)
    {
        DeviceObject *device = reinterpret_cast <DeviceObject*> (m_devices->at(i).data());

        if (device->availability() != Availability::Online)
            continue;

        SessionInfo *session = m_sessions->findByPeerNodeId(device->nodeId());

        if (!session)
        {
            handleDeviceUnreachable(device);
            continue;
        }

        if (session->lastSeen && now - session->lastSeen > 10000)
        {
            QList <AttributePath> paths = m_subscribedPaths.value(device->nodeId());

            if (paths.isEmpty())
                paths.append(AttributePath(0, Clusters::BasicInformation::Id, Clusters::BasicInformation::Attributes::DataModelRevision));

            QByteArray payload = InteractionModel::encodeReadRequest(paths);
            sendEncrypted(session, static_cast <quint8> (InteractionModelOpcode::ReadRequest), static_cast <quint16> (ProtocolId::InteractionModel), payload, m_exchangeCounter++, true);
        }
    }
}

void Matter::mrpRetransmit(const QByteArray &data, const QHostAddress &address, quint16 port)
{
    sendRawDatagram(data, address, port);
}

void Matter::handleDeviceUnreachable(DeviceObject *device)
{
    SessionInfo *session = m_sessions->findByPeerNodeId(device->nodeId());

    if (session)
        m_sessions->removeSession(session->localSessionId);

    if (device->availability() == Availability::Online)
    {
        logWarning << "Device" << device->name() << "is unreachable, marking offline";
        device->setAvailability(Availability::Offline);
        emit deviceOffline(device);
    }

    connectDevice(device);

    if (!m_reconnectTimer->isActive())
        m_reconnectTimer->start(30000);
}

void Matter::mrpRetransmitFailed(quint32 messageCounter, quint16 exchangeId, const QHostAddress &address, quint16 port)
{
    logWarning << "Message delivery failed, counter:" << messageCounter << "exchange:" << exchangeId;

    // check if this is a pending CASE handshake failure
    if (m_pendingCASE && m_caseAddress == address)
    {
        caseFailed("MRP retransmit failed");
        return;
    }

    SessionInfo *session = m_sessions->findByPeerAddress(address, port);

    if (!session || !m_devices)
        return;

    quint64 nodeId = session->peerNodeId;

    for (int i = 0; i < m_devices->count(); i++)
    {
        DeviceObject *device = reinterpret_cast <DeviceObject*> (m_devices->at(i).data());

        if (device->nodeId() == nodeId)
        {
            handleDeviceUnreachable(device);
            break;
        }
    }
}

void Matter::mrpSendStandaloneAck(quint32 ackCounter, quint16 exchangeId, quint16 sessionId, const QHostAddress &address, quint16 port, bool initiator)
{
    sendStandaloneAck(ackCounter, exchangeId, sessionId, address, port, initiator);
}

void Matter::mdnsServiceFound(const MatterService &service)
{
    if (!m_searching)
        return;

    // match discriminator
    if (m_searchShortDiscriminator)
    {
        if ((service.discriminator >> 8) != m_searchDiscriminator)
            return;
    }
    else
    {
        if (service.discriminator != m_searchDiscriminator)
            return;
    }

    // check if already commissioning this device
    for (auto it = m_pendingCommissions.begin(); it != m_pendingCommissions.end(); it++)
    {
        if (it.value().address == service.address && it.value().port == service.port)
            return;
    }

    logInfo << "Commissionable device found:" << service.deviceName << "discriminator:" << service.discriminator << "at" << service.address.toString() << ":" << service.port;

    m_searching = false;
    m_searchTimer->stop();
    m_mdns->stop();

    startCommissioning(service);
}

// --- PASE signal handlers ---

void Matter::paseSendPBKDFParamRequest(const QByteArray &payload, quint16 localSessionId)
{
    if (!m_pendingCommissions.contains(localSessionId))
        return;

    const PendingCommission &commission = m_pendingCommissions.value(localSessionId);
    sendUnencrypted(static_cast <quint8> (SecureChannelOpcode::PBKDFParamRequest), static_cast <quint16> (ProtocolId::SecureChannel), payload, commission.exchangeId, commission.address, commission.port, true);
}

void Matter::paseSendPake1(const QByteArray &payload)
{
    PASESession *pase = qobject_cast <PASESession*> (sender());

    if (!pase)
        return;

    quint16 sessionId = pase->localSessionId();

    if (!m_pendingCommissions.contains(sessionId))
        return;

    const PendingCommission &commission = m_pendingCommissions.value(sessionId);
    sendUnencrypted(static_cast <quint8> (SecureChannelOpcode::PASEPake1), static_cast <quint16> (ProtocolId::SecureChannel), payload, commission.exchangeId, commission.address, commission.port, true, pase->lastPeerMessageCounter());
}

void Matter::paseSendPake3(const QByteArray &payload)
{
    PASESession *pase = qobject_cast <PASESession*> (sender());

    if (!pase)
        return;

    quint16 sessionId = pase->localSessionId();

    if (!m_pendingCommissions.contains(sessionId))
        return;

    const PendingCommission &commission = m_pendingCommissions.value(sessionId);
    sendUnencrypted(static_cast <quint8> (SecureChannelOpcode::PASEPake3), static_cast <quint16> (ProtocolId::SecureChannel), payload, commission.exchangeId, commission.address, commission.port, true, pase->lastPeerMessageCounter());
}

void Matter::paseEstablished(quint16 localSessionId, quint16 peerSessionId)
{
    if (!m_pendingCommissions.contains(localSessionId))
        return;

    PendingCommission &commission = m_pendingCommissions[localSessionId];

    // register encrypted session
    SessionInfo session;
    session.localSessionId = localSessionId;
    session.peerSessionId = peerSessionId;
    session.i2rKey = commission.pase->encryptKey();
    session.r2iKey = commission.pase->decryptKey();
    session.attestationChallenge = commission.pase->attestationChallenge();
    session.peerAddress = commission.address;
    session.peerPort = commission.port;
    session.peerNodeId = 0; // unknown until commissioning
    session.localMessageCounter = 0;
    session.active = false; // not yet operational

    m_sessions->addSession(session);

    // create device object
    quint64 nodeId = commission.assignedNodeId;
    commission.device = new DeviceObject(nodeId, QString("matter_%1").arg(nodeId));
    commission.device->setVendorId(commission.service.vendorId);
    commission.device->setProductId(commission.service.productId);
    commission.device->setNetworkAddress(commission.address);
    commission.device->setNetworkPort(commission.port);

    // start commissioning: ArmFailSafe → ReadBasicInfo → CommissioningComplete
    commission.state = CommissioningState::ArmFailSafe;
    continueCommissioning(commission);
}

void Matter::paseFailed(const QString &reason)
{
    PASESession *pase = qobject_cast <PASESession*> (sender());

    if (!pase)
        return;

    logWarning << "PASE failed:" << reason;

    quint16 sessionId = pase->localSessionId();
    m_pendingCommissions.remove(sessionId);
    pase->deleteLater();
}

// --- CASE signal handlers ---

void Matter::caseSendSigma1(const QByteArray &payload, quint16 localSessionId)
{
    Q_UNUSED(localSessionId)

    if (!m_pendingCASE)
        return;

    sendUnencrypted(static_cast <quint8> (SecureChannelOpcode::CASESigma1), static_cast <quint16> (ProtocolId::SecureChannel), payload, m_caseExchangeId, m_caseAddress, m_casePort, true);
}

void Matter::caseSendSigma3(const QByteArray &payload)
{
    if (!m_pendingCASE)
        return;

    sendUnencrypted(static_cast <quint8> (SecureChannelOpcode::CASESigma3), static_cast <quint16> (ProtocolId::SecureChannel), payload, m_caseExchangeId, m_caseAddress, m_casePort, true, m_pendingCASE->lastPeerMessageCounter());
}

void Matter::caseEstablished(quint16 localSessionId, quint16 peerSessionId)
{
    if (!m_pendingCASE || !m_caseDevice)
        return;

    // register encrypted session
    SessionInfo session;
    session.localSessionId = localSessionId;
    session.peerSessionId = peerSessionId;
    session.i2rKey = m_pendingCASE->encryptKey();
    session.r2iKey = m_pendingCASE->decryptKey();
    session.attestationChallenge = m_pendingCASE->attestationChallenge();
    session.peerNodeId = m_caseDevice->nodeId();
    session.localMessageCounter = 0;
    session.active = true;

    session.peerAddress = m_caseDevice->networkAddress();
    session.peerPort = m_caseDevice->networkPort();
    session.lastSeen = QDateTime::currentMSecsSinceEpoch();

    // remove old (dead) session
    SessionInfo *existing = m_sessions->findByPeerNodeId(m_caseDevice->nodeId());

    if (existing)
        m_sessions->removeSession(existing->localSessionId);

    m_sessions->addSession(session);

    logInfo << "CASE session established with" << m_caseDevice->name();

    // discover device endpoints (read PartsList from endpoint 0)
    if (m_caseDevice->endpoints().isEmpty())
        discoverDevice(m_caseDevice);

    // send CommissioningComplete on CASE session only during initial commissioning
    SessionInfo *caseSession = m_sessions->findByLocalId(localSessionId);

    if (caseSession && m_caseNeedsCommissioningComplete)
    {
        m_caseNeedsCommissioningComplete = false;
        m_pendingCommissionDevice = m_caseDevice;
        logDebug(m_debug) << "Sending CommissioningComplete on CASE session...";

        MatterTLV::Encoder fields;
        fields.openStructure();
        fields.closeContainer();

        QByteArray payload = InteractionModel::encodeInvokeRequest(CommandPath(0, Clusters::GeneralCommissioning::Id, Clusters::GeneralCommissioning::Commands::CommissioningComplete), fields);
        sendEncrypted(caseSession, static_cast <quint8> (InteractionModelOpcode::InvokeRequest), static_cast <quint16> (ProtocolId::InteractionModel), payload, m_exchangeCounter++, true);
    }

    m_caseDevice->setAvailability(Availability::Online);
    emit deviceOnline(m_caseDevice);

    m_pendingCASE->deleteLater();
    m_pendingCASE = nullptr;
    m_caseDevice = nullptr;

    // connect next queued device
    if (!m_caseQueue.isEmpty())
        connectDevice(m_caseQueue.takeFirst());
}

void Matter::caseFailed(const QString &reason)
{
    logWarning << "CASE failed:" << reason;

    if (m_pendingCASE)
    {
        m_pendingCASE->deleteLater();
        m_pendingCASE = nullptr;
    }

    m_caseDevice = nullptr;

    if (!m_reconnectTimer->isActive())
        m_reconnectTimer->start(30000);

    // connect next queued device
    if (!m_caseQueue.isEmpty())
        connectDevice(m_caseQueue.takeFirst());
}

// --- Setup code parsing ---

static const char base38Alphabet[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-.";

static QByteArray base38Decode(const QString &encoded)
{
    QByteArray result;
    int i = 0;

    while (i < encoded.length())
    {
        int charsInChunk = qMin(encoded.length() - i, 5);
        int bytesInChunk = charsInChunk == 5 ? 3 : (charsInChunk == 4 ? 2 : 1);

        quint32 value = 0;
        quint32 base = 1;

        for (int j = 0; j < charsInChunk; j++)
        {
            const char *p = strchr(base38Alphabet, encoded.at(i + j).toLatin1());

            if (!p)
                return QByteArray();

            value += static_cast <quint32> (p - base38Alphabet) * base;
            base *= 38;
        }

        for (int j = 0; j < bytesInChunk; j++)
        {
            result.append(static_cast <char> (value & 0xFF));
            value >>= 8;
        }

        i += charsInChunk;
    }

    return result;
}

bool Matter::parseQRCode(const QString &payload, quint32 &passcode, quint16 &discriminator)
{
    if (!payload.startsWith("MT:"))
        return false;

    QByteArray data = base38Decode(payload.mid(3));

    if (data.length() < 11)
        return false;

    // 88-bit payload, little-endian bitfield:
    // bits  0-2:  version (3)
    // bits  3-18: vendorId (16)
    // bits 19-34: productId (16)
    // bits 35-36: commissioningFlow (2)
    // bits 37-44: rendezvousFlags (8)
    // bits 45-56: discriminator (12)
    // bits 57-83: passcode (27)
    // bits 84-87: padding (4)

    quint64 low;
    memcpy(&low, data.constData(), 8);
    low = qFromLittleEndian(low);

    quint32 high = 0;
    memcpy(&high, data.constData() + 8, 3);
    high = qFromLittleEndian(high);

    discriminator = static_cast <quint16> ((low >> 45) & 0xFFF);
    passcode = static_cast <quint32> (((low >> 57) | (static_cast <quint64> (high) << 7)) & 0x7FFFFFF);

    if (passcode == 0 || passcode > 99999998)
        return false;

    return true;
}

bool Matter::parseManualCode(const QString &code, quint32 &passcode, quint16 &discriminator)
{
    QString clean;

    for (const QChar &ch : code)
    {
        if (ch.isDigit())
            clean.append(ch);
    }

    if (clean.length() != 11 && clean.length() != 21)
        return false;

    quint32 chunk1 = clean.mid(0, 1).toUInt();
    quint32 chunk2 = clean.mid(1, 5).toUInt();
    quint32 chunk3 = clean.mid(6, 4).toUInt();

    // short discriminator (4 bits): chunk1 bits[0:1] (MSBs) + chunk2 bits[14:15] (LSBs)
    discriminator = static_cast <quint16> (((chunk1 & 0x3) << 2) | ((chunk2 >> 14) & 0x3));

    // passcode (27 bits): chunk2 bits[0:13] (LSBs) + chunk3 bits[0:12] (MSBs)
    passcode = (chunk2 & 0x3FFF) | (chunk3 << 14);

    if (passcode == 0 || passcode > 99999998)
        return false;

    return true;
}
