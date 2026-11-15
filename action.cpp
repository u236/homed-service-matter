#include "action.h"
#include "color.h"
#include "interaction.h"

QByteArray Actions::Status::request(quint16 endpointId, const QVariant &data)
{
    QList <QString> list = {"off", "on", "toggle"};
    MatterTLV::Encoder fields;
    quint32 commandId;

    switch (list.indexOf(data.toString()))
    {
        case 1:  commandId = Clusters::OnOff::Commands::On; break;
        case 2:  commandId = Clusters::OnOff::Commands::Toggle; break;
        default: commandId = Clusters::OnOff::Commands::Off; break;
    }

    fields.openStructure();
    fields.closeContainer();

    return InteractionModel::invokeRequest(CommandPath(endpointId, Clusters::OnOff::Id, commandId), fields);
}

QByteArray Actions::Level::request(quint16 endpointId, const QVariant &data)
{
    MatterTLV::Encoder fields;

    fields.openStructure();
    fields.encodeUnsignedInt(0, static_cast <quint8> (data.toUInt() * 0xFE / 0xFF)); // level, 0xFE is maximum
    fields.encodeUnsignedInt(1, 0); // transition time
    fields.encodeUnsignedInt(2, 0); // options mask
    fields.encodeUnsignedInt(3, 0); // options override
    fields.closeContainer();

    return InteractionModel::invokeRequest(CommandPath(endpointId, Clusters::LevelControl::Id, Clusters::LevelControl::Commands::MoveToLevelWithOnOff), fields);
}

QByteArray Actions::ColorHS::request(quint16 endpointId, const QVariant &data)
{
    QList <QVariant> list = data.toList();
    MatterTLV::Encoder fields;
    double hue, saturation;

    if (list.count() < 3)
        return QByteArray();

    Color(list.at(0).toDouble() / 0xFF, list.at(1).toDouble() / 0xFF, list.at(2).toDouble() / 0xFF).toHS(&hue, &saturation);

    fields.openStructure();
    fields.encodeUnsignedInt(0, static_cast <quint8> (hue * 0xFE));
    fields.encodeUnsignedInt(1, static_cast <quint8> (saturation * 0xFE));
    fields.encodeUnsignedInt(2, 0); // transition time
    fields.encodeUnsignedInt(3, 0); // options mask
    fields.encodeUnsignedInt(4, 0); // options override
    fields.closeContainer();

    return InteractionModel::invokeRequest(CommandPath(endpointId, Clusters::ColorControl::Id, Clusters::ColorControl::Commands::MoveToHueAndSaturation), fields);
}

QByteArray Actions::ColorTemperature::request(quint16 endpointId, const QVariant &data)
{
    MatterTLV::Encoder fields;

    fields.openStructure();
    fields.encodeUnsignedInt(0, static_cast <quint16> (data.toUInt()));
    fields.encodeUnsignedInt(1, 0); // transition time
    fields.encodeUnsignedInt(2, 0); // options mask
    fields.encodeUnsignedInt(3, 0); // options override
    fields.closeContainer();

    return InteractionModel::invokeRequest(CommandPath(endpointId, Clusters::ColorControl::Id, Clusters::ColorControl::Commands::MoveToColorTemperature), fields);
}

QByteArray Actions::Lock::request(quint16 endpointId, const QVariant &data)
{
    MatterTLV::Encoder fields;

    fields.openStructure();
    fields.closeContainer();

    return InteractionModel::invokeRequest(CommandPath(endpointId, Clusters::DoorLock::Id, data.toString() == "lock" ? Clusters::DoorLock::Commands::LockDoor : Clusters::DoorLock::Commands::UnlockDoor), fields);
}

QByteArray Actions::CoverStatus::request(quint16 endpointId, const QVariant &data)
{
    MatterTLV::Encoder fields;
    quint32 commandId;

    switch (data.toUInt())
    {
        case 0:  commandId = Clusters::WindowCovering::Commands::UpOrOpen; break;
        case 1:  commandId = Clusters::WindowCovering::Commands::DownOrClose; break;
        case 2:  commandId = Clusters::WindowCovering::Commands::StopMotion; break;
        default: return QByteArray();
    }

    fields.openStructure();
    fields.closeContainer();

    return InteractionModel::invokeRequest(CommandPath(endpointId, Clusters::WindowCovering::Id, commandId), fields);
}

QByteArray Actions::CoverPosition::request(quint16 endpointId, const QVariant &data)
{
    MatterTLV::Encoder fields;

    fields.openStructure();
    fields.encodeUnsignedInt(0, static_cast <quint16> (data.toUInt()));
    fields.closeContainer();

    return InteractionModel::invokeRequest(CommandPath(endpointId, Clusters::WindowCovering::Id, Clusters::WindowCovering::Commands::GoToLiftPercentage), fields);
}

QByteArray Actions::PowerOnStatus::request(quint16 endpointId, const QVariant &data)
{
    QList <QString> list = {"off", "on", "toggle", "previous"};
    int index = list.indexOf(data.toString());
    MatterTLV::Encoder value;

    switch (index)
    {
        case 0 ... 2: value.encodeUnsignedInt(0, static_cast <quint64> (index)); break;
        case 3:       value.encodeNull(0); break; // null means previous state
        default:      return QByteArray();
    }

    return InteractionModel::writeRequest(AttributePath(endpointId, Clusters::OnOff::Id, Clusters::OnOff::Attributes::StartUpOnOff), value);
}
