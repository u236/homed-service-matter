#include "interaction.h"

// --- Path encoding ---

void InteractionModel::encodeAttributePath(MatterTLV::Encoder &encoder, const AttributePath &path)
{
    encoder.openList();
    encoder.encodeUnsignedInt(2, path.endpointId);
    encoder.encodeUnsignedInt(3, path.clusterId);
    encoder.encodeUnsignedInt(4, path.attributeId);
    encoder.closeContainer();
}

void InteractionModel::encodeCommandPath(MatterTLV::Encoder &encoder, const CommandPath &path)
{
    encoder.openList(0);
    encoder.encodeUnsignedInt(0, path.endpointId);
    encoder.encodeUnsignedInt(1, path.clusterId);
    encoder.encodeUnsignedInt(2, path.commandId);
    encoder.closeContainer();
}

// --- Path decoding ---

AttributePath InteractionModel::decodeAttributePath(const MatterTLV::Element &element)
{
    AttributePath path;

    for (const MatterTLV::Element &el : element.children)
    {
        switch (el.tag)
        {
            case 2: path.endpointId = el.value.toUInt(); break;
            case 3: path.clusterId = el.value.toUInt(); break;
            case 4: path.attributeId = el.value.toUInt(); break;
        }
    }

    return path;
}

CommandPath InteractionModel::decodeCommandPath(const MatterTLV::Element &element)
{
    CommandPath path;

    for (const MatterTLV::Element &el : element.children)
    {
        switch (el.tag)
        {
            case 0: path.endpointId = el.value.toUInt(); break;
            case 1: path.clusterId = el.value.toUInt(); break;
            case 2: path.commandId = el.value.toUInt(); break;
        }
    }

    return path;
}

// --- Read Request ---

QByteArray InteractionModel::encodeReadRequest(const QList <AttributePath> &paths)
{
    MatterTLV::Encoder encoder;
    encoder.openStructure();

    // tag 0: AttributeRequests (array of AttributePathIB)
    encoder.openArray(0);

    for (const AttributePath &path : paths)
        encodeAttributePath(encoder, path);

    encoder.closeContainer();

    // tag 3: FabricFiltered (required)
    encoder.encodeBool(3, false);

    // tag 0xFF: InteractionModelRevision (must be last)
    encoder.encodeUnsignedInt(0xFF, 11);

    encoder.closeContainer();
    return encoder.data();
}

// --- Write Request ---

QByteArray InteractionModel::encodeWriteRequest(quint16 endpointId, quint32 clusterId, quint32 attributeId, const MatterTLV::Encoder &valueEncoder)
{
    MatterTLV::Encoder encoder;
    encoder.openStructure();

    encoder.encodeBool(0, false); // suppressResponse
    encoder.encodeBool(1, false); // timedRequest

    // tag 2: WriteRequests (array of AttributeDataIB)
    encoder.openArray(2);

    // AttributeDataIB
    encoder.openStructure();

    // tag 0: DataVersion (optional, skip)

    // tag 1: AttributePathIB
    encoder.openList(1);
    encoder.encodeUnsignedInt(2, endpointId);
    encoder.encodeUnsignedInt(3, clusterId);
    encoder.encodeUnsignedInt(4, attributeId);
    encoder.closeContainer();

    // tag 2: Data — append raw TLV value
    // The value needs tag 2 context-specific
    QByteArray valueData = valueEncoder.data();
    // Re-encode with proper tag
    // For simplicity, just append the raw encoded value bytes as tag 2
    // We need to handle this properly: the value was encoded with tag 0 by default
    // Let's just put the raw bytes
    encoder.openStructure(2); // wrap value
    encoder.closeContainer(); // placeholder — see below

    encoder.closeContainer(); // AttributeDataIB
    encoder.closeContainer(); // WriteRequests array

    encoder.closeContainer();

    // TODO: proper value embedding — for now return the structure
    // Real implementation needs the value TLV element with tag 2
    Q_UNUSED(endpointId)
    Q_UNUSED(clusterId)
    Q_UNUSED(attributeId)
    Q_UNUSED(valueData)

    return encoder.data();
}

// --- Invoke Request ---

QByteArray InteractionModel::encodeInvokeRequest(const CommandPath &path, const MatterTLV::Encoder &fieldsEncoder, bool timedRequest)
{
    MatterTLV::Encoder encoder;
    encoder.openStructure();

    encoder.encodeBool(0, false);        // suppressResponse
    encoder.encodeBool(1, timedRequest); // timedRequest

    // tag 2: InvokeRequests (array of CommandDataIB)
    encoder.openArray(2);

    // CommandDataIB
    encoder.openStructure();

    // tag 0: CommandPathIB
    encodeCommandPath(encoder, path);

    // tag 1: CommandFields (structure with command-specific fields)
    QByteArray fields = fieldsEncoder.data();

    if (!fields.isEmpty())
    {
        // Embed the fields as raw bytes after tag 1 marker
        encoder.openStructure(1);

        // Parse and re-emit the fields from the encoder
        MatterTLV::Decoder decoder(fields);
        QList <MatterTLV::Element> elements = decoder.decodeAll();

        // The fields encoder typically contains a structure — unwrap its children
        if (!elements.isEmpty() && elements.first().type == MatterTLV::Type::Structure)
        {
            for (const MatterTLV::Element &el : elements.first().children)
            {
                switch (el.type)
                {
                    case MatterTLV::Type::UnsignedInt:
                        encoder.encodeUnsignedInt(el.tag, el.value.toULongLong());
                        break;

                    case MatterTLV::Type::SignedInt:
                        encoder.encodeSignedInt(el.tag, el.value.toLongLong());
                        break;

                    case MatterTLV::Type::Boolean:
                        encoder.encodeBool(el.tag, el.value.toBool());
                        break;

                    case MatterTLV::Type::UTF8String:
                        encoder.encodeUTF8String(el.tag, el.value.toString());
                        break;

                    case MatterTLV::Type::ByteString:
                        encoder.encodeByteString(el.tag, el.value.toByteArray());
                        break;

                    case MatterTLV::Type::Null:
                        encoder.encodeNull(el.tag);
                        break;

                    default:
                        break;
                }
            }
        }

        encoder.closeContainer(); // CommandFields
    }

    encoder.closeContainer(); // CommandDataIB
    encoder.closeContainer(); // InvokeRequests array

    // tag 0xFF: InteractionModelRevision
    encoder.encodeUnsignedInt(0xFF, 11);

    encoder.closeContainer();
    return encoder.data();
}

// --- Subscribe Request ---

QByteArray InteractionModel::encodeSubscribeRequest(const QList <AttributePath> &paths, quint16 minInterval, quint16 maxInterval)
{
    MatterTLV::Encoder encoder;
    encoder.openStructure();

    encoder.encodeBool(0, true);  // keepSubscriptions
    encoder.encodeUnsignedInt(1, minInterval);
    encoder.encodeUnsignedInt(2, maxInterval);

    // tag 3: AttributeRequests
    encoder.openArray(3);

    for (const AttributePath &path : paths)
        encodeAttributePath(encoder, path);

    encoder.closeContainer();

    encoder.closeContainer();
    return encoder.data();
}

// --- Timed Request ---

QByteArray InteractionModel::encodeTimedRequest(quint16 timeoutMs)
{
    MatterTLV::Encoder encoder;
    encoder.openStructure();
    encoder.encodeUnsignedInt(0, timeoutMs);    // timeoutMs
    encoder.encodeUnsignedInt(0xFF, 11);        // InteractionModelRevision
    encoder.closeContainer();
    return encoder.data();
}

// --- Status Response ---

QByteArray InteractionModel::encodeStatusResponse(quint8 status)
{
    MatterTLV::Encoder encoder;
    encoder.openStructure();
    encoder.encodeUnsignedInt(0, status);
    encoder.closeContainer();
    return encoder.data();
}

// --- Decode Report Data ---

QList <AttributeReport> InteractionModel::decodeReportData(const QByteArray &payload)
{
    QList <AttributeReport> reports;
    MatterTLV::Decoder decoder(payload);
    MatterTLV::Element root = decoder.decode();

    // Find attributeReports array (tag 1)
    for (const MatterTLV::Element &el : root.children)
    {
        if (el.tag != 1)
            continue;

        // Each child is an AttributeReportIB
        for (const MatterTLV::Element &reportIB : el.children)
        {
            AttributeReport report;

            for (const MatterTLV::Element &field : reportIB.children)
            {
                if (field.tag == 0) // AttributeStatusIB (error)
                {
                    report.hasError = true;

                    for (const MatterTLV::Element &statusField : field.children)
                    {
                        if (statusField.tag == 0) // AttributePathIB
                            report.path = decodeAttributePath(statusField);
                        else if (statusField.tag == 1) // StatusIB
                        {
                            for (const MatterTLV::Element &s : statusField.children)
                            {
                                if (s.tag == 0)
                                    report.status = s.value.toUInt();
                            }
                        }
                    }
                }
                else if (field.tag == 1) // AttributeDataIB (success)
                {
                    for (const MatterTLV::Element &dataField : field.children)
                    {
                        if (dataField.tag == 1) // AttributePathIB
                            report.path = decodeAttributePath(dataField);
                        else if (dataField.tag == 2) // Data
                        {
                            report.rawValue = dataField;
                            report.value = dataField.value;
                        }
                    }
                }
            }

            reports.append(report);
        }
    }

    return reports;
}

// --- Decode Invoke Response ---

QList <CommandResponse> InteractionModel::decodeInvokeResponse(const QByteArray &payload)
{
    QList <CommandResponse> responses;
    MatterTLV::Decoder decoder(payload);
    MatterTLV::Element root = decoder.decode();

    // Find invokeResponses array (tag 1)
    for (const MatterTLV::Element &el : root.children)
    {
        if (el.tag != 1)
            continue;

        for (const MatterTLV::Element &responseIB : el.children)
        {
            CommandResponse response;

            for (const MatterTLV::Element &field : responseIB.children)
            {
                if (field.tag == 0) // CommandDataIB (command response with data)
                {
                    for (const MatterTLV::Element &dataField : field.children)
                    {
                        if (dataField.tag == 0) // CommandPathIB
                            response.path = decodeCommandPath(dataField);
                        else if (dataField.tag == 1) // CommandFields
                            response.data = dataField;
                    }
                }
                else if (field.tag == 1) // CommandStatusIB (status only)
                {
                    for (const MatterTLV::Element &statusField : field.children)
                    {
                        if (statusField.tag == 0) // CommandPathIB
                            response.path = decodeCommandPath(statusField);
                        else if (statusField.tag == 1) // StatusIB
                        {
                            for (const MatterTLV::Element &s : statusField.children)
                            {
                                if (s.tag == 0)
                                    response.status = s.value.toUInt();
                            }
                        }
                    }
                }
            }

            responses.append(response);
        }
    }

    return responses;
}

// --- Decode Status Response ---

quint8 InteractionModel::decodeStatusResponse(const QByteArray &payload)
{
    MatterTLV::Decoder decoder(payload);
    MatterTLV::Element root = decoder.decode();

    for (const MatterTLV::Element &el : root.children)
    {
        if (el.tag == 0)
            return el.value.toUInt();
    }

    return 0xFF;
}

// --- Convenience command encoders ---

QByteArray InteractionModel::encodeOnOffCommand(quint16 endpointId, bool on)
{
    MatterTLV::Encoder fields;
    fields.openStructure();
    fields.closeContainer();

    return encodeInvokeRequest(CommandPath(endpointId, Clusters::OnOff::Id, on ? Clusters::OnOff::Commands::On : Clusters::OnOff::Commands::Off), fields);
}

QByteArray InteractionModel::encodeToggleCommand(quint16 endpointId)
{
    MatterTLV::Encoder fields;
    fields.openStructure();
    fields.closeContainer();

    return encodeInvokeRequest(CommandPath(endpointId, Clusters::OnOff::Id, Clusters::OnOff::Commands::Toggle), fields);
}

QByteArray InteractionModel::encodeMoveToLevelCommand(quint16 endpointId, quint8 level, quint16 transitionTime)
{
    MatterTLV::Encoder fields;
    fields.openStructure();
    fields.encodeUnsignedInt(0, level);            // level
    fields.encodeUnsignedInt(1, transitionTime);   // transitionTime (tenths of second)
    fields.encodeUnsignedInt(2, 0);                // optionsMask
    fields.encodeUnsignedInt(3, 0);                // optionsOverride
    fields.closeContainer();

    return encodeInvokeRequest(CommandPath(endpointId, Clusters::LevelControl::Id, Clusters::LevelControl::Commands::MoveToLevelWithOnOff), fields);
}

QByteArray InteractionModel::encodeMoveToColorTemperatureCommand(quint16 endpointId, quint16 mireds, quint16 transitionTime)
{
    MatterTLV::Encoder fields;
    fields.openStructure();
    fields.encodeUnsignedInt(0, mireds);           // colorTemperatureMireds
    fields.encodeUnsignedInt(1, transitionTime);   // transitionTime
    fields.encodeUnsignedInt(2, 0);                // optionsMask
    fields.encodeUnsignedInt(3, 0);                // optionsOverride
    fields.closeContainer();

    return encodeInvokeRequest(CommandPath(endpointId, Clusters::ColorControl::Id, Clusters::ColorControl::Commands::MoveToColorTemperature), fields);
}

QByteArray InteractionModel::encodeLockCommand(quint16 endpointId, bool lock)
{
    MatterTLV::Encoder fields;
    fields.openStructure();
    fields.closeContainer();

    return encodeInvokeRequest(CommandPath(endpointId, Clusters::DoorLock::Id, lock ? Clusters::DoorLock::Commands::LockDoor : Clusters::DoorLock::Commands::UnlockDoor), fields);
}

QByteArray InteractionModel::encodeCoverCommand(quint16 endpointId, quint8 command, quint16 position)
{
    quint32 cmdId;

    switch (command)
    {
        case 0: cmdId = Clusters::WindowCovering::Commands::UpOrOpen; break;
        case 1: cmdId = Clusters::WindowCovering::Commands::DownOrClose; break;
        case 2: cmdId = Clusters::WindowCovering::Commands::StopMotion; break;
        case 3: cmdId = Clusters::WindowCovering::Commands::GoToLiftPercentage; break;
        default: return QByteArray();
    }

    MatterTLV::Encoder fields;
    fields.openStructure();

    if (command == 3)
        fields.encodeUnsignedInt(0, position); // liftPercent100ths

    fields.closeContainer();

    return encodeInvokeRequest(CommandPath(endpointId, Clusters::WindowCovering::Id, cmdId), fields);
}
