#include "action.h"
#include "color.h"
#include "interaction.h"

namespace Actions
{

QByteArray Status::request(quint16 endpointId, const QVariant &data)
{
    QString status = data.toString();
    quint32 cmdId = Clusters::OnOff::Commands::Off;

    if (status == "on")
        cmdId = Clusters::OnOff::Commands::On;
    else if (status == "toggle")
        cmdId = Clusters::OnOff::Commands::Toggle;

    MatterTLV::Encoder fields;
    fields.openStructure();
    fields.closeContainer();

    return InteractionModel::encodeInvokeRequest(CommandPath(endpointId, Clusters::OnOff::Id, cmdId), fields);
}

QByteArray Level::request(quint16 endpointId, const QVariant &data)
{
    // consumer scale is 0..0xFF, peer's MoveToLevel takes 0..0xFE
    quint8 level = static_cast <quint8> (data.toUInt() * 0xFE / 0xFF);

    MatterTLV::Encoder fields;
    fields.openStructure();
    fields.encodeUnsignedInt(0, level);
    fields.encodeUnsignedInt(1, 0); // transitionTime (tenths of seconds)
    fields.encodeUnsignedInt(2, 0); // optionsMask
    fields.encodeUnsignedInt(3, 0); // optionsOverride
    fields.closeContainer();

    return InteractionModel::encodeInvokeRequest(CommandPath(endpointId, Clusters::LevelControl::Id, Clusters::LevelControl::Commands::MoveToLevelWithOnOff), fields);
}

QByteArray ColorHS::request(quint16 endpointId, const QVariant &data)
{
    QList <QVariant> list = data.toList();

    if (list.count() < 3)
        return QByteArray();

    Color color(list.at(0).toDouble() / 0xFF, list.at(1).toDouble() / 0xFF, list.at(2).toDouble() / 0xFF);
    double h, s;
    color.toHS(&h, &s);

    MatterTLV::Encoder fields;
    fields.openStructure();
    fields.encodeUnsignedInt(0, static_cast <quint8> (h * 0xFE)); // hue
    fields.encodeUnsignedInt(1, static_cast <quint8> (s * 0xFE)); // saturation
    fields.encodeUnsignedInt(2, 0);                                // transitionTime
    fields.encodeUnsignedInt(3, 0);                                // optionsMask
    fields.encodeUnsignedInt(4, 0);                                // optionsOverride
    fields.closeContainer();

    return InteractionModel::encodeInvokeRequest(CommandPath(endpointId, Clusters::ColorControl::Id, Clusters::ColorControl::Commands::MoveToHueAndSaturation), fields);
}

QByteArray ColorTemperature::request(quint16 endpointId, const QVariant &data)
{
    MatterTLV::Encoder fields;
    fields.openStructure();
    fields.encodeUnsignedInt(0, static_cast <quint16> (data.toUInt())); // colorTemperatureMireds
    fields.encodeUnsignedInt(1, 0);                                     // transitionTime
    fields.encodeUnsignedInt(2, 0);                                     // optionsMask
    fields.encodeUnsignedInt(3, 0);                                     // optionsOverride
    fields.closeContainer();

    return InteractionModel::encodeInvokeRequest(CommandPath(endpointId, Clusters::ColorControl::Id, Clusters::ColorControl::Commands::MoveToColorTemperature), fields);
}

QByteArray Lock::request(quint16 endpointId, const QVariant &data)
{
    quint32 cmdId = data.toString() == "lock" ? Clusters::DoorLock::Commands::LockDoor : Clusters::DoorLock::Commands::UnlockDoor;

    MatterTLV::Encoder fields;
    fields.openStructure();
    fields.closeContainer();

    return InteractionModel::encodeInvokeRequest(CommandPath(endpointId, Clusters::DoorLock::Id, cmdId), fields);
}

QByteArray CoverStatus::request(quint16 endpointId, const QVariant &data)
{
    quint32 cmdId;

    switch (data.toUInt())
    {
        case 0: cmdId = Clusters::WindowCovering::Commands::UpOrOpen; break;
        case 1: cmdId = Clusters::WindowCovering::Commands::DownOrClose; break;
        case 2: cmdId = Clusters::WindowCovering::Commands::StopMotion; break;
        default: return QByteArray();
    }

    MatterTLV::Encoder fields;
    fields.openStructure();
    fields.closeContainer();

    return InteractionModel::encodeInvokeRequest(CommandPath(endpointId, Clusters::WindowCovering::Id, cmdId), fields);
}

QByteArray CoverPosition::request(quint16 endpointId, const QVariant &data)
{
    MatterTLV::Encoder fields;
    fields.openStructure();
    fields.encodeUnsignedInt(0, static_cast <quint16> (data.toUInt())); // liftPercent100ths
    fields.closeContainer();

    return InteractionModel::encodeInvokeRequest(CommandPath(endpointId, Clusters::WindowCovering::Id, Clusters::WindowCovering::Commands::GoToLiftPercentage), fields);
}

}
