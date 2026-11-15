// NOT REWIEWED

#include "interaction.h"

QByteArray InteractionModel::readRequest(const QList <AttributePath> &attributes)
{
    MatterTLV::Encoder encoder;

    encoder.openStructure();
    encoder.openArray(0);

    for (int i = 0; i < attributes.count(); i++)
        encodeAttributePath(encoder, attributes.at(i));

    encoder.closeContainer();
    encoder.encodeBool(3, false); // fabric filtered
    encoder.encodeUnsignedInt(INTERACTION_MODEL_REVISION_TAG, INTERACTION_MODEL_REVISION);
    encoder.closeContainer();

    return encoder.data();
}

QByteArray InteractionModel::writeRequest(const AttributePath &path, MatterTLV::Encoder &value)
{
    MatterTLV::Encoder encoder;

    encoder.openStructure();
    encoder.encodeBool(0, false); // suppress response
    encoder.encodeBool(1, false); // timed request
    encoder.openArray(2);
    encoder.openStructure();

    encoder.openList(1);
    encoder.encodeUnsignedInt(2, path.endpointId);
    encoder.encodeUnsignedInt(3, path.clusterId);
    encoder.encodeUnsignedInt(4, path.attributeId);
    encoder.closeContainer();

    // value is encoded by caller with tag 0, re-encode it with data tag
    encodeElement(encoder, 2, MatterTLV::Decoder(value.data()).decode());

    encoder.closeContainer();
    encoder.closeContainer();
    encoder.encodeUnsignedInt(INTERACTION_MODEL_REVISION_TAG, INTERACTION_MODEL_REVISION);
    encoder.closeContainer();

    return encoder.data();
}

QByteArray InteractionModel::invokeRequest(const CommandPath &path, MatterTLV::Encoder &fields, bool timed)
{
    MatterTLV::Encoder encoder;
    QByteArray data = fields.data();

    encoder.openStructure();
    encoder.encodeBool(0, false); // suppress response
    encoder.encodeBool(1, timed);
    encoder.openArray(2);
    encoder.openStructure();

    encodeCommandPath(encoder, path);

    if (!data.isEmpty())
    {
        QList <MatterTLV::Element> list = MatterTLV::Decoder(data).decodeAll();

        encoder.openStructure(1);

        // fields are encoded by caller as anonymous structure, re-encode its children only
        if (!list.isEmpty() && list.first().type == MatterTLV::Type::Structure)
        {
            const MatterTLV::Element &structure = list.first();

            for (int i = 0; i < structure.children.count(); i++)
                encodeElement(encoder, structure.children.at(i).tag, structure.children.at(i));
        }

        encoder.closeContainer();
    }

    encoder.closeContainer();
    encoder.closeContainer();
    encoder.encodeUnsignedInt(INTERACTION_MODEL_REVISION_TAG, INTERACTION_MODEL_REVISION);
    encoder.closeContainer();

    return encoder.data();
}

QByteArray InteractionModel::subscribeRequest(const QList <AttributePath> &attributes, const QList <EventPath> &events, quint16 minInterval, quint16 maxInterval)
{
    MatterTLV::Encoder encoder;

    encoder.openStructure();
    encoder.encodeBool(0, false); // keep subscriptions
    encoder.encodeUnsignedInt(1, minInterval);
    encoder.encodeUnsignedInt(2, maxInterval);
    encoder.openArray(3);

    for (int i = 0; i < attributes.count(); i++)
        encodeAttributePath(encoder, attributes.at(i));

    encoder.closeContainer();

    if (!events.isEmpty())
    {
        encoder.openArray(4);

        for (int i = 0; i < events.count(); i++)
            encodeEventPath(encoder, events.at(i));

        encoder.closeContainer();
    }

    encoder.encodeBool(7, false); // fabric filtered
    encoder.encodeUnsignedInt(INTERACTION_MODEL_REVISION_TAG, INTERACTION_MODEL_REVISION);
    encoder.closeContainer();

    return encoder.data();
}

QByteArray InteractionModel::timedRequest(quint16 timeout)
{
    MatterTLV::Encoder encoder;

    encoder.openStructure();
    encoder.encodeUnsignedInt(0, timeout);
    encoder.encodeUnsignedInt(INTERACTION_MODEL_REVISION_TAG, INTERACTION_MODEL_REVISION);
    encoder.closeContainer();

    return encoder.data();
}

QByteArray InteractionModel::statusResponse(quint8 status)
{
    MatterTLV::Encoder encoder;

    encoder.openStructure();
    encoder.encodeUnsignedInt(0, status);
    encoder.closeContainer();

    return encoder.data();
}

QList <AttributeReport> InteractionModel::attributeReports(const QByteArray &payload)
{
    MatterTLV::Element root = MatterTLV::Decoder(payload).decode();
    QList <AttributeReport> list;

    for (int i = 0; i < root.children.count(); i++)
    {
        const MatterTLV::Element &reports = root.children.at(i);

        if (reports.tag != 1)
            continue;

        for (int j = 0; j < reports.children.count(); j++)
        {
            const MatterTLV::Element &item = reports.children.at(j);
            AttributeReport report;

            for (int k = 0; k < item.children.count(); k++)
            {
                const MatterTLV::Element &field = item.children.at(k);

                switch (field.tag)
                {
                    case 0: // attribute status
                    {
                        report.error = true;

                        for (int l = 0; l < field.children.count(); l++)
                        {
                            const MatterTLV::Element &element = field.children.at(l);

                            switch (element.tag)
                            {
                                case 0: report.path = decodeAttributePath(element); break;
                                case 1: report.status = decodeStatus(element); break;
                            }
                        }

                        break;
                    }

                    case 1: // attribute data
                    {
                        for (int l = 0; l < field.children.count(); l++)
                        {
                            const MatterTLV::Element &element = field.children.at(l);

                            switch (element.tag)
                            {
                                case 1: report.path = decodeAttributePath(element); break;
                                case 2: report.data = element; report.value = element.value; break;
                            }
                        }

                        break;
                    }
                }
            }

            list.append(report);
        }
    }

    return list;
}

QList <EventReport> InteractionModel::eventReports(const QByteArray &payload)
{
    MatterTLV::Element root = MatterTLV::Decoder(payload).decode();
    QList <EventReport> list;

    for (int i = 0; i < root.children.count(); i++)
    {
        const MatterTLV::Element &reports = root.children.at(i);

        if (reports.tag != 2)
            continue;

        for (int j = 0; j < reports.children.count(); j++)
        {
            const MatterTLV::Element &item = reports.children.at(j);
            EventReport report;

            for (int k = 0; k < item.children.count(); k++)
            {
                const MatterTLV::Element &field = item.children.at(k);

                // event status reports are ignored, event data timestamps are ignored too
                if (field.tag != 1)
                    continue;

                for (int l = 0; l < field.children.count(); l++)
                {
                    const MatterTLV::Element &element = field.children.at(l);

                    switch (element.tag)
                    {
                        case 0: report.path = decodeEventPath(element); break;
                        case 1: report.eventNumber = element.value.toULongLong(); break;
                        case 2: report.priority = static_cast <quint8> (element.value.toUInt()); break;
                        case 7: report.data = element; break;
                    }
                }
            }

            if (!report.path.clusterId)
                continue;

            list.append(report);
        }
    }

    return list;
}

QList <CommandResponse> InteractionModel::commandResponses(const QByteArray &payload)
{
    MatterTLV::Element root = MatterTLV::Decoder(payload).decode();
    QList <CommandResponse> list;

    for (int i = 0; i < root.children.count(); i++)
    {
        const MatterTLV::Element &responses = root.children.at(i);

        if (responses.tag != 1)
            continue;

        for (int j = 0; j < responses.children.count(); j++)
        {
            const MatterTLV::Element &item = responses.children.at(j);
            CommandResponse response;

            for (int k = 0; k < item.children.count(); k++)
            {
                const MatterTLV::Element &field = item.children.at(k);

                if (field.tag > 1)
                    continue;

                // command data contains path and fields, command status contains path and status
                for (int l = 0; l < field.children.count(); l++)
                {
                    const MatterTLV::Element &element = field.children.at(l);

                    switch (element.tag)
                    {
                        case 0: response.path = decodeCommandPath(element); break;

                        case 1:

                            if (field.tag)
                                response.status = decodeStatus(element);
                            else
                                response.data = element;

                            break;
                    }
                }
            }

            list.append(response);
        }
    }

    return list;
}

quint8 InteractionModel::status(const QByteArray &payload)
{
    MatterTLV::Element root = MatterTLV::Decoder(payload).decode();

    for (int i = 0; i < root.children.count(); i++)
    {
        if (root.children.at(i).tag)
            continue;

        return static_cast <quint8> (root.children.at(i).value.toUInt());
    }

    return 0xFF;
}

void InteractionModel::encodeAttributePath(MatterTLV::Encoder &encoder, const AttributePath &path)
{
    encoder.openList();
    encoder.encodeUnsignedInt(2, path.endpointId);
    encoder.encodeUnsignedInt(3, path.clusterId);
    encoder.encodeUnsignedInt(4, path.attributeId);
    encoder.closeContainer();
}

void InteractionModel::encodeEventPath(MatterTLV::Encoder &encoder, const EventPath &path)
{
    encoder.openList();
    encoder.encodeUnsignedInt(1, path.endpointId);
    encoder.encodeUnsignedInt(2, path.clusterId);
    encoder.encodeUnsignedInt(3, path.eventId);

    if (path.urgent)
        encoder.encodeBool(4, true);

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

void InteractionModel::encodeElement(MatterTLV::Encoder &encoder, int tag, const MatterTLV::Element &element)
{
    switch (element.type)
    {
        case MatterTLV::Type::SignedInt:   encoder.encodeSignedInt(tag, element.value.toLongLong()); break;
        case MatterTLV::Type::UnsignedInt: encoder.encodeUnsignedInt(tag, element.value.toULongLong()); break;
        case MatterTLV::Type::Boolean:     encoder.encodeBool(tag, element.value.toBool()); break;
        case MatterTLV::Type::UTF8String:  encoder.encodeUTF8String(tag, element.value.toString()); break;
        case MatterTLV::Type::ByteString:  encoder.encodeByteString(tag, element.value.toByteArray()); break;
        case MatterTLV::Type::Null:        encoder.encodeNull(tag); break;
        default:                           break;
    }
}

AttributePath InteractionModel::decodeAttributePath(const MatterTLV::Element &element)
{
    AttributePath path;

    for (int i = 0; i < element.children.count(); i++)
    {
        const MatterTLV::Element &item = element.children.at(i);

        switch (item.tag)
        {
            case 2: path.endpointId = static_cast <quint16> (item.value.toUInt()); break;
            case 3: path.clusterId = item.value.toUInt(); break;
            case 4: path.attributeId = item.value.toUInt(); break;
        }
    }

    return path;
}

EventPath InteractionModel::decodeEventPath(const MatterTLV::Element &element)
{
    EventPath path;

    for (int i = 0; i < element.children.count(); i++)
    {
        const MatterTLV::Element &item = element.children.at(i);

        switch (item.tag)
        {
            case 1: path.endpointId = static_cast <quint16> (item.value.toUInt()); break;
            case 2: path.clusterId = item.value.toUInt(); break;
            case 3: path.eventId = item.value.toUInt(); break;
            case 4: path.urgent = item.value.toBool(); break;
        }
    }

    return path;
}

CommandPath InteractionModel::decodeCommandPath(const MatterTLV::Element &element)
{
    CommandPath path;

    for (int i = 0; i < element.children.count(); i++)
    {
        const MatterTLV::Element &item = element.children.at(i);

        switch (item.tag)
        {
            case 0: path.endpointId = static_cast <quint16> (item.value.toUInt()); break;
            case 1: path.clusterId = item.value.toUInt(); break;
            case 2: path.commandId = item.value.toUInt(); break;
        }
    }

    return path;
}

quint8 InteractionModel::decodeStatus(const MatterTLV::Element &element)
{
    quint8 status = 0;

    for (int i = 0; i < element.children.count(); i++)
    {
        if (element.children.at(i).tag)
            continue;

        status = static_cast <quint8> (element.children.at(i).value.toUInt());
    }

    return status;
}
