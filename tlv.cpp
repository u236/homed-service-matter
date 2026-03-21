#include "tlv.h"

using namespace MatterTLV;

void Encoder::encodeControl(Type type, quint8 tag)
{
    quint8 control = static_cast <quint8> (type);

    if (tag)
        control |= static_cast <quint8> (TagControl::ContextSpecific);

    m_data.append(static_cast <char> (control));

    if (tag)
        m_data.append(static_cast <char> (tag));
}

void Encoder::encodeLength(quint32 length)
{
    if (length < 256)
    {
        m_data.append(static_cast <char> (length));
    }
    else if (length < 65536)
    {
        m_data.append(static_cast <char> (length & 0xFF));
        m_data.append(static_cast <char> ((length >> 8) & 0xFF));
    }
    else
    {
        m_data.append(static_cast <char> (length & 0xFF));
        m_data.append(static_cast <char> ((length >> 8) & 0xFF));
        m_data.append(static_cast <char> ((length >> 16) & 0xFF));
        m_data.append(static_cast <char> ((length >> 24) & 0xFF));
    }
}

void Encoder::encodeSignedInt(quint8 tag, qint64 value)
{
    quint8 size;

    if (value >= -128 && value <= 127)
        size = 1;
    else if (value >= -32768 && value <= 32767)
        size = 2;
    else if (value >= -2147483648LL && value <= 2147483647LL)
        size = 4;
    else
        size = 8;

    quint8 control = static_cast <quint8> (Type::SignedInt);

    switch (size)
    {
        case 1: control |= 0x00; break;
        case 2: control |= 0x01; break;
        case 4: control |= 0x02; break;
        case 8: control |= 0x03; break;
    }

    if (tag)
        control |= static_cast <quint8> (TagControl::ContextSpecific);

    m_data.append(static_cast <char> (control));

    if (tag)
        m_data.append(static_cast <char> (tag));

    for (quint8 i = 0; i < size; i++)
        m_data.append(static_cast <char> ((value >> (i * 8)) & 0xFF));
}

void Encoder::encodeUnsignedInt(quint8 tag, quint64 value)
{
    quint8 size;

    if (value <= 0xFF)
        size = 1;
    else if (value <= 0xFFFF)
        size = 2;
    else if (value <= 0xFFFFFFFF)
        size = 4;
    else
        size = 8;

    quint8 control = static_cast <quint8> (Type::UnsignedInt);

    switch (size)
    {
        case 1: control |= 0x00; break;
        case 2: control |= 0x01; break;
        case 4: control |= 0x02; break;
        case 8: control |= 0x03; break;
    }

    if (tag)
        control |= static_cast <quint8> (TagControl::ContextSpecific);

    m_data.append(static_cast <char> (control));

    if (tag)
        m_data.append(static_cast <char> (tag));

    for (quint8 i = 0; i < size; i++)
        m_data.append(static_cast <char> ((value >> (i * 8)) & 0xFF));
}

void Encoder::encodeBool(quint8 tag, bool value)
{
    quint8 control = static_cast <quint8> (value ? 0x09 : 0x08);

    if (tag)
        control |= static_cast <quint8> (TagControl::ContextSpecific);

    m_data.append(static_cast <char> (control));

    if (tag)
        m_data.append(static_cast <char> (tag));
}

void Encoder::encodeFloat(quint8 tag, float value)
{
    encodeControl(Type::Float, tag);

    const char *bytes = reinterpret_cast <const char*> (&value);

    for (int i = 0; i < 4; i++)
        m_data.append(bytes[i]);
}

void Encoder::encodeDouble(quint8 tag, double value)
{
    encodeControl(Type::Double, tag);

    const char *bytes = reinterpret_cast <const char*> (&value);

    for (int i = 0; i < 8; i++)
        m_data.append(bytes[i]);
}

void Encoder::encodeUTF8String(quint8 tag, const QString &value)
{
    QByteArray utf8 = value.toUtf8();
    quint8 control = static_cast <quint8> (Type::UTF8String);

    if (utf8.length() < 256)
        control |= 0x00;
    else
        control |= 0x01;

    if (tag)
        control |= static_cast <quint8> (TagControl::ContextSpecific);

    m_data.append(static_cast <char> (control));

    if (tag)
        m_data.append(static_cast <char> (tag));

    encodeLength(static_cast <quint32> (utf8.length()));
    m_data.append(utf8);
}

void Encoder::encodeByteString(quint8 tag, const QByteArray &value)
{
    quint8 control = static_cast <quint8> (Type::ByteString);

    if (value.length() < 256)
        control |= 0x00;
    else
        control |= 0x01;

    if (tag)
        control |= static_cast <quint8> (TagControl::ContextSpecific);

    m_data.append(static_cast <char> (control));

    if (tag)
        m_data.append(static_cast <char> (tag));

    encodeLength(static_cast <quint32> (value.length()));
    m_data.append(value);
}

void Encoder::encodeNull(quint8 tag)
{
    encodeControl(Type::Null, tag);
}

void Encoder::openStructure(quint8 tag)
{
    encodeControl(Type::Structure, tag);
}

void Encoder::openArray(quint8 tag)
{
    encodeControl(Type::Array, tag);
}

void Encoder::openList(quint8 tag)
{
    encodeControl(Type::List, tag);
}

void Encoder::closeContainer(void)
{
    m_data.append(static_cast <char> (Type::EndOfContainer));
}

quint8 Decoder::readByte(void)
{
    if (m_offset >= static_cast <quint32> (m_data.length()))
        return 0;

    return static_cast <quint8> (m_data.at(m_offset++));
}

QByteArray Decoder::readBytes(quint32 count)
{
    if (m_offset + count > static_cast <quint32> (m_data.length()))
        return QByteArray();

    QByteArray result = m_data.mid(m_offset, count);
    m_offset += count;
    return result;
}

qint64 Decoder::readSignedInt(quint8 size)
{
    qint64 value = 0;

    for (quint8 i = 0; i < size; i++)
        value |= static_cast <quint64> (readByte()) << (i * 8);

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
    if (m_offset >= static_cast <quint32> (m_data.length()))
        return Element();

    quint8 control = readByte();
    quint8 typeField = control & 0x1F;
    quint8 tagControl = control & 0xE0;
    quint8 tag = 0;

    if (tagControl == static_cast <quint8> (TagControl::ContextSpecific))
        tag = readByte();

    quint8 sizeCode = typeField & 0x03;

    switch (typeField)
    {
        case 0x00: case 0x01: case 0x02: case 0x03: // SignedInt 1/2/4/8
        {
            quint8 size = 1 << sizeCode;
            return Element(Type::SignedInt, tag, readSignedInt(size));
        }

        case 0x04: case 0x05: case 0x06: case 0x07: // UnsignedInt 1/2/4/8
        {
            quint8 size = 1 << sizeCode;
            return Element(Type::UnsignedInt, tag, readUnsignedInt(size));
        }

        case 0x08: // Boolean false
            return Element(Type::Boolean, tag, false);

        case 0x09: // Boolean true
            return Element(Type::Boolean, tag, true);

        case 0x0A: // Float
        {
            QByteArray bytes = readBytes(4);
            float value;
            memcpy(&value, bytes.constData(), 4);
            return Element(Type::Float, tag, value);
        }

        case 0x0B: // Double
        {
            QByteArray bytes = readBytes(8);
            double value;
            memcpy(&value, bytes.constData(), 8);
            return Element(Type::Double, tag, value);
        }

        case 0x0C: case 0x0D: case 0x0E: case 0x0F: // UTF8String 1/2/4/8 byte length
        {
            quint32 length = readUnsignedInt(1 << sizeCode);
            return Element(Type::UTF8String, tag, QString::fromUtf8(readBytes(length)));
        }

        case 0x10: case 0x11: case 0x12: case 0x13: // ByteString 1/2/4/8 byte length
        {
            quint32 length = readUnsignedInt(1 << sizeCode);
            return Element(Type::ByteString, tag, readBytes(length));
        }

        case 0x14: // Null
            return Element(Type::Null, tag);

        case 0x15: // Structure
        case 0x16: // Array
        case 0x17: // List
        {
            Element container(static_cast <Type> (typeField), tag);

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

        case 0x18: // EndOfContainer
            return Element(Type::EndOfContainer, 0);

        default:
            return Element();
    }
}

QList <Element> Decoder::decodeAll(void)
{
    QList <Element> elements;

    while (m_offset < static_cast <quint32> (m_data.length()))
        elements.append(decode());

    return elements;
}
