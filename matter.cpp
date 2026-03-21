#include "matter.h"
#include "logger.h"
#include "tlv.h"
#include "clusters.h"

using namespace MatterProtocol;

Matter::Matter(QObject *parent) : QObject(parent), m_udp(new QUdpSocket(this)), m_mrp(new MRP(this)), m_mdns(new MDNS(this)), m_sessions(new SessionManager(this)), m_permitJoinTimer(new QTimer(this)), m_port(5540), m_permitJoin(false), m_passcode(PASE_DEFAULT_PASSCODE), m_messageCounter(0), m_exchangeCounter(0), m_sessionCounter(1), m_fabricId(1), m_nodeId(1)
{
    connect(m_udp, &QUdpSocket::readyRead, this, &Matter::readyRead);
    connect(m_permitJoinTimer, &QTimer::timeout, this, &Matter::permitJoinTimeout);
    connect(m_mrp, &MRP::retransmit, this, &Matter::mrpRetransmit);
    connect(m_mrp, &MRP::retransmitFailed, this, &Matter::mrpRetransmitFailed);
    connect(m_mrp, &MRP::sendStandaloneAck, this, &Matter::mrpSendStandaloneAck);
    connect(m_mdns, &MDNS::serviceFound, this, &Matter::mdnsServiceFound);

    m_permitJoinTimer->setSingleShot(true);

    if (!m_udp->bind(QHostAddress::Any, m_port))
        logWarning << "Failed to bind UDP port" << m_port;
    else
        logInfo << "Matter controller listening on port" << m_port;
}

void Matter::setPermitJoin(quint32 duration)
{
    m_permitJoin = duration > 0;

    if (m_permitJoin)
    {
        m_permitJoinTimer->start(duration * 1000);
        m_sessionCounter = 1;
        logInfo << "Permit join enabled for" << duration << "seconds";
        m_mdns->browse();
    }
    else
    {
        m_permitJoinTimer->stop();
        m_mdns->stop();
        logInfo << "Permit join disabled";
    }
}

void Matter::setPasscode(quint32 passcode)
{
    m_passcode = passcode;
}

// --- Send command to a commissioned device ---

void Matter::sendCommand(DeviceObject *device, quint8 endpointId, const QString &name, const QVariant &value)
{
    SessionInfo *session = m_sessions->findByPeerNodeId(device->nodeId());

    if (!session)
    {
        logWarning << "No active session for device" << device->name();
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

void Matter::sendEncrypted(SessionInfo *session, quint8 opcode, quint16 protocolId, const QByteArray &payload, quint16 exchangeId, bool initiator)
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

    protoHeader.opcode = opcode;
    protoHeader.exchangeId = exchangeId;
    protoHeader.protocolId = protocolId;

    QByteArray plaintext = MessageCodec::encodeProtocolHeader(protoHeader);
    plaintext.append(payload);

    QByteArray nonce = SessionManager::buildNonce(msgHeader.securityFlags, msgHeader.messageCounter, m_nodeId);
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

            logInfo << "StatusReport from session" << msgHeader.sessionId;
            break;
        }

        case SecureChannelOpcode::CASESigma1:
            logInfo << "CASE Sigma1 from" << msgHeader.sourceNodeId;
            break;

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

            for (const AttributeReport &report : reports)
            {
                if (report.hasError)
                {
                    logWarning << "Attribute error, cluster:" << QString::number(report.path.clusterId, 16) << "attr:" << QString::number(report.path.attributeId, 16) << "status:" << report.status;
                    continue;
                }

                logInfo << "Attribute, ep:" << report.path.endpointId << "cluster:" << QString::number(report.path.clusterId, 16) << "attr:" << QString::number(report.path.attributeId, 16) << "value:" << report.value;

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

            // send StatusResponse (success) to acknowledge ReportData
            SessionInfo *session = m_sessions->findByLocalId(msgHeader.sessionId);

            if (session)
            {
                QByteArray statusPayload = InteractionModel::encodeStatusResponse(0);
                sendEncrypted(session, static_cast <quint8> (InteractionModelOpcode::StatusResponse), static_cast <quint16> (ProtocolId::InteractionModel), statusPayload, protoHeader.exchangeId, false);
            }

            // continue commissioning if applicable
            for (auto it = m_pendingCommissions.begin(); it != m_pendingCommissions.end(); it++)
            {
                if (it.value().state == CommissioningState::ReadBasicInfo)
                {
                    it.value().state = CommissioningState::CommissioningComplete;
                    continueCommissioning(it.value());
                    break;
                }
            }

            break;
        }

        case InteractionModelOpcode::StatusResponse:
        {
            quint8 status = InteractionModel::decodeStatusResponse(payload);
            logInfo << "StatusResponse:" << status;
            break;
        }

        case InteractionModelOpcode::InvokeResponse:
        {
            QList <CommandResponse> responses = InteractionModel::decodeInvokeResponse(payload);

            for (const CommandResponse &response : responses)
            {
                logInfo << "InvokeResponse, cluster:" << QString::number(response.path.clusterId, 16) << "cmd:" << QString::number(response.path.commandId, 16) << "status:" << response.status;

                // check commissioning responses
                for (auto it = m_pendingCommissions.begin(); it != m_pendingCommissions.end(); it++)
                {
                    PendingCommission &commission = it.value();

                    if (commission.state == CommissioningState::ArmFailSafe && response.path.clusterId == Clusters::GeneralCommissioning::Id && response.path.commandId == Clusters::GeneralCommissioning::Commands::ArmFailSafeResponse)
                    {
                        logInfo << "ArmFailSafe response, reading basic info...";
                        commission.state = CommissioningState::ReadBasicInfo;
                        continueCommissioning(commission);
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

            break;
        }

        case InteractionModelOpcode::SubscribeResponse:
            logInfo << "SubscribeResponse received";
            break;

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
    commission.service = service;
    commission.state = CommissioningState::PASE;

    m_pendingCommissions.insert(sessionId, commission);

    logInfo << "Starting commissioning with" << service.address.toString() << ":" << service.port;
    pase->start(m_passcode, sessionId);
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
            logInfo << "Sending ArmFailSafe...";

            MatterTLV::Encoder fields;
            fields.openStructure();
            fields.encodeUnsignedInt(0, 900);  // expiryLengthSeconds
            fields.encodeUnsignedInt(1, 1);    // breadcrumb
            fields.closeContainer();

            QByteArray payload = InteractionModel::encodeInvokeRequest(CommandPath(0, Clusters::GeneralCommissioning::Id, Clusters::GeneralCommissioning::Commands::ArmFailSafe), fields);
            sendEncrypted(session, static_cast <quint8> (InteractionModelOpcode::InvokeRequest), static_cast <quint16> (ProtocolId::InteractionModel), payload, m_exchangeCounter++, true);
            break;
        }

        case CommissioningState::ReadBasicInfo:
        {
            logInfo << "Reading BasicInformation cluster...";

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

        case CommissioningState::CommissioningComplete:
        {
            logInfo << "Sending CommissioningComplete...";

            MatterTLV::Encoder fields;
            fields.openStructure();
            fields.closeContainer();

            QByteArray payload = InteractionModel::encodeInvokeRequest(CommandPath(0, Clusters::GeneralCommissioning::Id, Clusters::GeneralCommissioning::Commands::CommissioningComplete), fields);
            sendEncrypted(session, static_cast <quint8> (InteractionModelOpcode::InvokeRequest), static_cast <quint16> (ProtocolId::InteractionModel), payload, m_exchangeCounter++, true);
            break;
        }

        case CommissioningState::Done:
        {
            logInfo << "Device" << commission.device->name() << "commissioned successfully";
            commission.device->setAvailability(Availability::Online);
            session->peerNodeId = commission.device->nodeId();
            session->active = true;
            emit deviceCommissioned(commission.device);
            m_pendingCommissions.remove(commission.localSessionId);

            if (commission.pase)
                commission.pase->deleteLater();

            break;
        }

        default:
            break;
    }
}

// --- Standalone ACK ---

void Matter::sendStandaloneAck(quint32 ackCounter, quint16 exchangeId, quint16 sessionId, const QHostAddress &address, quint16 port)
{
    MessageHeader msgHeader;
    msgHeader.flags = 0x00;
    msgHeader.securityFlags = 0x00;
    msgHeader.sessionId = sessionId;
    msgHeader.messageCounter = ++m_messageCounter;

    ProtocolHeader protoHeader;
    protoHeader.exchangeFlags = static_cast <quint8> (ExchangeFlag::Acknowledgement);
    protoHeader.opcode = static_cast <quint8> (SecureChannelOpcode::MRPStandaloneAck);
    protoHeader.exchangeId = exchangeId;
    protoHeader.protocolId = static_cast <quint16> (ProtocolId::SecureChannel);
    protoHeader.ackCounter = ackCounter;

    QByteArray data = MessageCodec::encodeMessage(msgHeader, protoHeader, QByteArray());
    sendRawDatagram(data, address, port);
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
            logWarning << "Invalid message header from" << sender.toString() << "size:" << datagram.size() << "hex:" << datagram.left(16).toHex();
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
            {
                logWarning << "Unknown session" << msgHeader.sessionId << "from" << sender.toString();
                continue;
            }

            QByteArray header = datagram.left(headerOffset);
            QByteArray ciphertext = datagram.mid(headerOffset);

            payload = m_sessions->decrypt(session, msgHeader.securityFlags, msgHeader.messageCounter, session->peerNodeId, header, ciphertext);

            if (payload.isEmpty())
            {
                logWarning << "Decryption failed for session" << msgHeader.sessionId;
                continue;
            }
        }
        else
        {
            payload = datagram.mid(headerOffset);
        }

        if (!MessageCodec::decodeProtocolHeader(payload, 0, protoHeader, payloadOffset))
        {
            logWarning << "Invalid protocol header from" << sender.toString();
            continue;
        }

        m_mrp->messageReceived(msgHeader.messageCounter, protoHeader.exchangeId, protoHeader.hasAck(), protoHeader.ackCounter, sender, senderPort, msgHeader.sessionId, protoHeader.needsAck());

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

void Matter::permitJoinTimeout(void)
{
    m_permitJoin = false;
    m_mdns->stop();
    logInfo << "Permit join timeout";
}

void Matter::mrpRetransmit(const QByteArray &data, const QHostAddress &address, quint16 port)
{
    sendRawDatagram(data, address, port);
}

void Matter::mrpRetransmitFailed(quint32 messageCounter, quint16 exchangeId)
{
    logWarning << "Message delivery failed, counter:" << messageCounter << "exchange:" << exchangeId;
}

void Matter::mrpSendStandaloneAck(quint32 ackCounter, quint16 exchangeId, quint16 sessionId, const QHostAddress &address, quint16 port)
{
    sendStandaloneAck(ackCounter, exchangeId, sessionId, address, port);
}

void Matter::mdnsServiceFound(const MatterService &service)
{
    if (!m_permitJoin)
        return;

    // check if already commissioning this device
    for (auto it = m_pendingCommissions.begin(); it != m_pendingCommissions.end(); it++)
    {
        if (it.value().address == service.address && it.value().port == service.port)
            return;
    }

    // limit retries
    if (m_sessionCounter > 3)
    {
        logWarning << "Max commissioning retries reached";
        return;
    }

    logInfo << "Commissionable device found:" << service.deviceName << "discriminator:" << service.discriminator << "at" << service.address.toString() << ":" << service.port;

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
    quint64 nodeId = m_nodeId + m_sessionCounter;
    commission.device = new DeviceObject(nodeId, commission.service.deviceName.isEmpty() ? QString("matter_%1").arg(commission.service.discriminator) : commission.service.deviceName);
    commission.device->setVendorId(commission.service.vendorId);
    commission.device->setProductId(commission.service.productId);

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
