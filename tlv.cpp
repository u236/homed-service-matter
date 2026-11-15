// NOT REWIEWED

#include <QtEndian>
#include "tlv.h"

using namespace MatterTLV;

void Encoder::encodeSignedInt(int tag, qint64 value)
{
    quint8 code = value >= -128 && value <= 127 ? 0x00 : value >= -32768 && value <= 32767 ? 0x01 : value >= -2147483648LL && value <= 2147483647LL ? 0x02 : 0x03;

    encodeControl(static_cast <quint8> (Type::SignedInt) | code, tag);
    encodeValue(static_cast <quint64> (value), 1 << code);
}

void Encoder::encodeUnsignedInt(int tag, quint64 value)
{
    quint8 code = value <= 0xFF ? 0x00 : value <= 0xFFFF ? 0x01 : value <= 0xFFFFFFFF ? 0x02 : 0x03;

    encodeControl(static_cast <quint8> (Type::UnsignedInt) | code, tag);
    encodeValue(value, 1 << code);
}

void Encoder::encodeBool(int tag, bool value)
{
    encodeControl(static_cast <quint8> (Type::Boolean) | (value ? 0x01 : 0x00), tag);
}

void Encoder::encodeFloat(int tag, float value)
{
    quint32 data;

    memcpy(&data, &value, sizeof(data));

    encodeControl(static_cast <quint8> (Type::Float), tag);
    encodeValue(data, sizeof(data));
}

void Encoder::encodeDouble(int tag, double value)
{
    quint64 data;

    memcpy(&data, &value, sizeof(data));

    encodeControl(static_cast <quint8> (Type::Double), tag);
    encodeValue(data, sizeof(data));
}

void Encoder::encodeUTF8String(int tag, const QString &value)
{
    encodeString(Type::UTF8String, tag, value.toUtf8());
}

void Encoder::encodeByteString(int tag, const QByteArray &value)
{
    encodeString(Type::ByteString, tag, value);
}

void Encoder::encodeNull(int tag)
{
    encodeControl(static_cast <quint8> (Type::Null), tag);
}

void Encoder::openStructure(int tag)
{
    encodeControl(static_cast <quint8> (Type::Structure), tag);
}

void Encoder::openArray(int tag)
{
    encodeControl(static_cast <quint8> (Type::Array), tag);
}

void Encoder::openList(int tag)
{
    encodeControl(static_cast <quint8> (Type::List), tag);
}

void Encoder::closeContainer(void)
{
    m_data.append(static_cast <char> (Type::EndOfContainer));
}

void Encoder::encodeRaw(const QByteArray &data)
{
    m_data.append(data);
}

void Encoder::encodeControl(quint8 control, int tag)
{
    if (tag < 0)
    {
        m_data.append(static_cast <char> (control));
        return;
    }

    m_data.append(static_cast <char> (control | static_cast <quint8> (TagControl::ContextSpecific)));
    m_data.append(static_cast <char> (tag));
}

void Encoder::encodeValue(quint64 value, quint8 length)
{
    for (quint8 i = 0; i < length; i++)
        m_data.append(static_cast <char> (value >> (i * 8)));
}

void Encoder::encodeString(Type type, int tag, const QByteArray &value)
{
    quint32 length = static_cast <quint32> (value.length());

    encodeControl(static_cast <quint8> (type) | (length < 256 ? 0x00 : 0x01), tag);
    encodeValue(length, length < 256 ? 1 : length < 65536 ? 2 : 4);

    m_data.append(value);
}

quint8 Decoder::readByte(void)
{
    if (m_offset >= static_cast <quint32> (m_data.length()))
        return 0;

    return static_cast <quint8> (m_data.at(m_offset++));
}

QByteArray Decoder::readBytes(quint32 count)
{
    QByteArray data;

    if (m_offset + count > static_cast <quint32> (m_data.length()))
        return QByteArray();

    data = m_data.mid(m_offset, count);
    m_offset += count;

    return data;
}

qint64 Decoder::readSignedInt(quint8 size)
{
    qint64 value = static_cast <qint64> (readUnsignedInt(size));

    if (size < 8 && (value & (1LL << (size * 8 - 1))))
        value |= ~((1LL << (size * 8)) - 1);

    return value;
}

quint64 Decoder::readUnsignedInt(quint8 size)
{
    quint64 value = 0;

    for (quint8 i = 0; i < size; i++)
        value |= static_cast <quint64> (readByte()) << (i * 8);

    return value;
}

Element Decoder::decode(void)
{
    quint8 control, type, code, tag = 0;

    if (m_offset >= static_cast <quint32> (m_data.length()))
        return Element();

    control = readByte();
    type = control & 0x1F;
    code = control & 0x03;

    if ((control & 0xE0) == static_cast <quint8> (TagControl::ContextSpecific))
        tag = readByte();

    switch (type)
    {
        case 0x00 ... 0x03: return Element(Type::SignedInt, tag, readSignedInt(1 << code));
        case 0x04 ... 0x07: return Element(Type::UnsignedInt, tag, readUnsignedInt(1 << code));
        case 0x08 ... 0x09: return Element(Type::Boolean, tag, type == 0x09);

        case 0x0A:
        {
            quint32 data = qFromLittleEndian <quint32> (readBytes(sizeof(data)).constData());
            float value;

            memcpy(&value, &data, sizeof(value));
            return Element(Type::Float, tag, value);
        }

        case 0x0B:
        {
            quint64 data = qFromLittleEndian <quint64> (readBytes(sizeof(data)).constData());
            double value;

            memcpy(&value, &data, sizeof(value));
            return Element(Type::Double, tag, value);
        }

        case 0x0C ... 0x0F: return Element(Type::UTF8String, tag, QString::fromUtf8(readBytes(static_cast <quint32> (readUnsignedInt(1 << code)))));
        case 0x10 ... 0x13: return Element(Type::ByteString, tag, readBytes(static_cast <quint32> (readUnsignedInt(1 << code))));
        case 0x14:          return Element(Type::Null, tag);

        case 0x15 ... 0x17:
        {
            Element container(static_cast <Type> (type), tag);

            while (m_offset < static_cast <quint32> (m_data.length()))
            {
                if ((static_cast <quint8> (m_data.at(m_offset)) & 0x1F) == static_cast <quint8> (Type::EndOfContainer))
                {
                    m_offset++;
                    break;
                }

                container.children.append(decode());
            }

            return container;
        }

        case 0x18: return Element(Type::EndOfContainer, 0);
        default:   return Element();
    }
}

QList <Element> Decoder::decodeAll(void)
{
    QList <Element> list;

    while (m_offset < static_cast <quint32> (m_data.length()))
        list.append(decode());

    return list;
}
