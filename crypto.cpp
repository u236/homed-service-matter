#include "crypto.h"

#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/ecdsa.h>
#include "tlv.h"
#include <QtEndian>

EC_GROUP *ECPoint::s_group = nullptr;

// --- Crypto namespace ---

QByteArray Crypto::pbkdf2(const QByteArray &password, const QByteArray &salt, quint32 iterations, quint32 keyLength)
{
    QByteArray result(keyLength, 0);

    PKCS5_PBKDF2_HMAC(password.constData(), password.length(), reinterpret_cast <const unsigned char*> (salt.constData()), salt.length(), iterations, EVP_sha256(), keyLength, reinterpret_cast <unsigned char*> (result.data()));

    return result;
}

QByteArray Crypto::hkdfSha256(const QByteArray &ikm, const QByteArray &salt, const QByteArray &info, quint32 length)
{
    // Manual HKDF implementation (RFC 5869) to avoid OpenSSL EVP empty-salt issues

    // Extract: PRK = HMAC-SHA256(salt, IKM)
    // If salt is empty, use HashLen (32) zero bytes
    QByteArray effectiveSalt = salt.isEmpty() ? QByteArray(32, 0) : salt;
    QByteArray prk = hmacSha256(effectiveSalt, ikm);

    // Expand: T = T(1) || T(2) || ... where T(i) = HMAC-SHA256(PRK, T(i-1) || info || i)
    QByteArray result;
    QByteArray prev;
    quint8 counter = 1;

    while (static_cast <quint32> (result.length()) < length)
    {
        QByteArray input = prev;
        input.append(info);
        input.append(static_cast <char> (counter));

        prev = hmacSha256(prk, input);
        result.append(prev);
        counter++;
    }

    return result.left(length);
}

QByteArray Crypto::hmacSha256(const QByteArray &key, const QByteArray &data)
{
    QByteArray result(32, 0);
    unsigned int length = 32;

    HMAC(EVP_sha256(), key.constData(), key.length(), reinterpret_cast <const unsigned char*> (data.constData()), data.length(), reinterpret_cast <unsigned char*> (result.data()), &length);

    return result;
}

QByteArray Crypto::sha256(const QByteArray &data)
{
    QByteArray result(32, 0);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, data.constData(), data.length());

    unsigned int length = 32;
    EVP_DigestFinal_ex(ctx, reinterpret_cast <unsigned char*> (result.data()), &length);
    EVP_MD_CTX_free(ctx);

    return result;
}

QByteArray Crypto::aesCcmEncrypt(const QByteArray &key, const QByteArray &nonce, const QByteArray &aad, const QByteArray &plaintext, quint8 tagLength)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if (!ctx)
        return QByteArray();

    QByteArray result(plaintext.length() + tagLength, 0);
    int length = 0;

    EVP_EncryptInit_ex(ctx, EVP_aes_128_ccm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, nonce.length(), nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, tagLength, nullptr);
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, reinterpret_cast <const unsigned char*> (key.constData()), reinterpret_cast <const unsigned char*> (nonce.constData()));
    EVP_EncryptUpdate(ctx, nullptr, &length, nullptr, plaintext.length());

    if (!aad.isEmpty())
        EVP_EncryptUpdate(ctx, nullptr, &length, reinterpret_cast <const unsigned char*> (aad.constData()), aad.length());

    EVP_EncryptUpdate(ctx, reinterpret_cast <unsigned char*> (result.data()), &length, reinterpret_cast <const unsigned char*> (plaintext.constData()), plaintext.length());
    EVP_EncryptFinal_ex(ctx, reinterpret_cast <unsigned char*> (result.data()) + length, &length);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, tagLength, result.data() + plaintext.length());

    EVP_CIPHER_CTX_free(ctx);
    return result;
}

QByteArray Crypto::aesCcmDecrypt(const QByteArray &key, const QByteArray &nonce, const QByteArray &aad, const QByteArray &ciphertext, quint8 tagLength)
{
    if (ciphertext.length() < tagLength)
        return QByteArray();

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if (!ctx)
        return QByteArray();

    int encLength = ciphertext.length() - tagLength;
    QByteArray result(encLength, 0);
    QByteArray tag = ciphertext.mid(encLength, tagLength);
    int length = 0;

    EVP_DecryptInit_ex(ctx, EVP_aes_128_ccm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, nonce.length(), nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, tagLength, tag.data());
    EVP_DecryptInit_ex(ctx, nullptr, nullptr, reinterpret_cast <const unsigned char*> (key.constData()), reinterpret_cast <const unsigned char*> (nonce.constData()));
    EVP_DecryptUpdate(ctx, nullptr, &length, nullptr, encLength);

    if (!aad.isEmpty())
        EVP_DecryptUpdate(ctx, nullptr, &length, reinterpret_cast <const unsigned char*> (aad.constData()), aad.length());

    int ret = EVP_DecryptUpdate(ctx, reinterpret_cast <unsigned char*> (result.data()), &length, reinterpret_cast <const unsigned char*> (ciphertext.constData()), encLength);

    EVP_CIPHER_CTX_free(ctx);

    if (ret <= 0)
        return QByteArray();

    return result;
}

QByteArray Crypto::sha1(const QByteArray &data)
{
    QByteArray result(20, 0);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    EVP_DigestInit_ex(ctx, EVP_sha1(), nullptr);
    EVP_DigestUpdate(ctx, data.constData(), data.length());

    unsigned int length = 20;
    EVP_DigestFinal_ex(ctx, reinterpret_cast <unsigned char*> (result.data()), &length);
    EVP_MD_CTX_free(ctx);

    return result;
}

QByteArray Crypto::ecdsaSign(const QByteArray &privateKey, const QByteArray &message)
{
    EC_KEY *eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    BIGNUM *privBN = BN_bin2bn(reinterpret_cast <const unsigned char*> (privateKey.constData()), privateKey.length(), nullptr);
    EC_KEY_set_private_key(eckey, privBN);

    const EC_GROUP *group = EC_KEY_get0_group(eckey);
    EC_POINT *pubPoint = EC_POINT_new(group);
    EC_POINT_mul(group, pubPoint, privBN, nullptr, nullptr, nullptr);
    EC_KEY_set_public_key(eckey, pubPoint);

    // use EVP high-level API for signing (handles SHA-256 internally)
    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_assign_EC_KEY(pkey, eckey);

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(mdctx, nullptr, EVP_sha256(), nullptr, pkey);
    EVP_DigestSignUpdate(mdctx, message.constData(), message.length());

    size_t derSigLen = 0;
    EVP_DigestSignFinal(mdctx, nullptr, &derSigLen);

    QByteArray derSig(derSigLen, 0);
    EVP_DigestSignFinal(mdctx, reinterpret_cast <unsigned char*> (derSig.data()), &derSigLen);
    derSig.resize(derSigLen);

    EVP_MD_CTX_free(mdctx);

    // parse DER signature to extract raw r, s
    const unsigned char *derPtr = reinterpret_cast <const unsigned char*> (derSig.constData());
    ECDSA_SIG *sig = d2i_ECDSA_SIG(nullptr, &derPtr, derSig.length());

    QByteArray result;

    if (sig)
    {
        const BIGNUM *r, *s;
        ECDSA_SIG_get0(sig, &r, &s);

        // low-S normalization
        BIGNUM *order = BN_new();
        BIGNUM *halfOrder = BN_new();
        EC_GROUP_get_order(group, order, nullptr);
        BN_rshift1(halfOrder, order);

        BIGNUM *normalizedS = BN_dup(s);

        if (BN_cmp(s, halfOrder) > 0)
            BN_sub(normalizedS, order, s);

        result.resize(64);
        memset(result.data(), 0, 64);
        BN_bn2bin(r, reinterpret_cast <unsigned char*> (result.data()) + (32 - BN_num_bytes(r)));
        BN_bn2bin(normalizedS, reinterpret_cast <unsigned char*> (result.data()) + 32 + (32 - BN_num_bytes(normalizedS)));

        BN_free(normalizedS);
        BN_free(halfOrder);
        BN_free(order);
        ECDSA_SIG_free(sig);
    }

    EC_POINT_free(pubPoint);
    BN_free(privBN);
    // eckey is freed by EVP_PKEY_free (EVP_PKEY_assign takes ownership)
    EVP_PKEY_free(pkey);

    return result;
}

bool Crypto::ecdsaVerify(const QByteArray &publicKey, const QByteArray &message, const QByteArray &signature)
{
    if (publicKey.length() != 65 || signature.length() != 64)
        return false;

    QByteArray hash = sha256(message);

    EC_KEY *eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_POINT *point = EC_POINT_new(EC_KEY_get0_group(eckey));
    EC_POINT_oct2point(EC_KEY_get0_group(eckey), point, reinterpret_cast <const unsigned char*> (publicKey.constData()), 65, nullptr);
    EC_KEY_set_public_key(eckey, point);

    ECDSA_SIG *sig = ECDSA_SIG_new();
    BIGNUM *r = BN_bin2bn(reinterpret_cast <const unsigned char*> (signature.constData()), 32, nullptr);
    BIGNUM *s = BN_bin2bn(reinterpret_cast <const unsigned char*> (signature.constData()) + 32, 32, nullptr);
    ECDSA_SIG_set0(sig, r, s);

    int result = ECDSA_do_verify(reinterpret_cast <const unsigned char*> (hash.constData()), hash.length(), sig, eckey);

    ECDSA_SIG_free(sig);
    EC_POINT_free(point);
    EC_KEY_free(eckey);

    return result == 1;
}

QByteArray Crypto::parseCSRPublicKey(const QByteArray &derCSR)
{
    const unsigned char *p = reinterpret_cast <const unsigned char*> (derCSR.constData());
    X509_REQ *req = d2i_X509_REQ(nullptr, &p, derCSR.length());

    if (!req)
        return QByteArray();

    EVP_PKEY *pkey = X509_REQ_get_pubkey(req);

    if (!pkey)
    {
        X509_REQ_free(req);
        return QByteArray();
    }

    EC_KEY *ec = EVP_PKEY_get1_EC_KEY(pkey);

    if (!ec)
    {
        EVP_PKEY_free(pkey);
        X509_REQ_free(req);
        return QByteArray();
    }

    const EC_POINT *point = EC_KEY_get0_public_key(ec);
    const EC_GROUP *group = EC_KEY_get0_group(ec);
    size_t len = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, nullptr, 0, nullptr);

    QByteArray result(static_cast <int> (len), 0);
    EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, reinterpret_cast <unsigned char*> (result.data()), len, nullptr);

    EC_KEY_free(ec);
    EVP_PKEY_free(pkey);
    X509_REQ_free(req);

    return result;
}

static EVP_PKEY *createECKeyFromRaw(const QByteArray &privKey)
{
    EC_KEY *ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    BIGNUM *priv = BN_bin2bn(reinterpret_cast <const unsigned char*> (privKey.constData()), privKey.length(), nullptr);
    EC_KEY_set_private_key(ec, priv);

    const EC_GROUP *group = EC_KEY_get0_group(ec);
    EC_POINT *pub = EC_POINT_new(group);
    EC_POINT_mul(group, pub, priv, nullptr, nullptr, nullptr);
    EC_KEY_set_public_key(ec, pub);

    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_assign_EC_KEY(pkey, ec);

    EC_POINT_free(pub);
    BN_free(priv);
    return pkey;
}

static EVP_PKEY *createECPubKeyFromRaw(const QByteArray &pubKey)
{
    EC_KEY *ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_POINT *point = EC_POINT_new(EC_KEY_get0_group(ec));
    EC_POINT_oct2point(EC_KEY_get0_group(ec), point, reinterpret_cast <const unsigned char*> (pubKey.constData()), pubKey.length(), nullptr);
    EC_KEY_set_public_key(ec, point);

    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_assign_EC_KEY(pkey, ec);

    EC_POINT_free(point);
    return pkey;
}

static void addMatterDNEntry(X509_NAME *name, const char *oid, quint64 value)
{
    ASN1_OBJECT *obj = OBJ_txt2obj(oid, 1);
    QString hex = QString("%1").arg(value, 16, 16, QLatin1Char('0')).toUpper();
    QByteArray utf8 = hex.toUtf8();
    X509_NAME_add_entry_by_OBJ(name, obj, MBSTRING_UTF8, reinterpret_cast <const unsigned char*> (utf8.constData()), utf8.length(), -1, 0);
    ASN1_OBJECT_free(obj);
}

QByteArray Crypto::generateX509Cert(quint64 rootCAId, quint64 fabricId, quint64 nodeId, const QByteArray &subjectPubKey, const QByteArray &signerPrivKey, const QByteArray &signerPubKey, bool isRCAC)
{
    X509 *cert = X509_new();
    X509_set_version(cert, 2); // v3

    // serial number
    QByteArray serial = randomBytes(8);
    serial[0] = serial[0] & 0x7F;
    BIGNUM *serialBN = BN_bin2bn(reinterpret_cast <const unsigned char*> (serial.constData()), serial.length(), nullptr);
    BN_to_ASN1_INTEGER(serialBN, X509_get_serialNumber(cert));
    BN_free(serialBN);

    // validity
    X509_gmtime_adj(X509_getm_notBefore(cert), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert), 3650L * 86400);

    // issuer DN (always references root CA)
    X509_NAME *issuer = X509_get_issuer_name(cert);
    addMatterDNEntry(issuer, "1.3.6.1.4.1.37244.1.4", rootCAId);

    // subject DN
    X509_NAME *subject = X509_get_subject_name(cert);

    if (isRCAC)
    {
        addMatterDNEntry(subject, "1.3.6.1.4.1.37244.1.4", rootCAId);
    }
    else
    {
        // node-id (tag 0x11) must come before fabric-id (tag 0x15) for ascending tag order
        addMatterDNEntry(subject, "1.3.6.1.4.1.37244.1.1", nodeId);
        addMatterDNEntry(subject, "1.3.6.1.4.1.37244.1.5", fabricId);
    }

    // subject public key
    EVP_PKEY *subjectKey = createECPubKeyFromRaw(subjectPubKey);
    X509_set_pubkey(cert, subjectKey);
    EVP_PKEY_free(subjectKey);

    // extensions
    X509V3_CTX ctx;
    X509V3_set_ctx(&ctx, cert, cert, nullptr, nullptr, 0);

    X509_EXTENSION *ext;

    if (isRCAC)
    {
        ext = X509V3_EXT_nconf_nid(nullptr, &ctx, NID_basic_constraints, const_cast <char*> ("critical,CA:TRUE"));
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);

        ext = X509V3_EXT_nconf_nid(nullptr, &ctx, NID_key_usage, const_cast <char*> ("critical,keyCertSign,cRLSign"));
    }
    else
    {
        ext = X509V3_EXT_nconf_nid(nullptr, &ctx, NID_basic_constraints, const_cast <char*> ("critical,CA:FALSE"));
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);

        ext = X509V3_EXT_nconf_nid(nullptr, &ctx, NID_key_usage, const_cast <char*> ("critical,digitalSignature"));
    }

    X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);

    if (!isRCAC)
    {
        ext = X509V3_EXT_nconf_nid(nullptr, &ctx, NID_ext_key_usage, const_cast <char*> ("serverAuth,clientAuth"));
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    }

    ext = X509V3_EXT_nconf_nid(nullptr, &ctx, NID_subject_key_identifier, const_cast <char*> ("hash"));
    X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);

    if (isRCAC)
    {
        ext = X509V3_EXT_nconf_nid(nullptr, &ctx, NID_authority_key_identifier, const_cast <char*> ("keyid"));
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    }
    else
    {
        // manually set AKID for NOC using signer's public key hash
        QByteArray akidHash = sha1(signerPubKey);
        ASN1_OCTET_STRING *akidOctet = ASN1_OCTET_STRING_new();
        ASN1_OCTET_STRING_set(akidOctet, reinterpret_cast <const unsigned char*> (akidHash.constData()), akidHash.length());
        AUTHORITY_KEYID *akid = AUTHORITY_KEYID_new();
        akid->keyid = akidOctet;
        ext = X509V3_EXT_i2d(NID_authority_key_identifier, 0, akid);
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
        AUTHORITY_KEYID_free(akid);
    }

    // sign
    EVP_PKEY *signerKey = createECKeyFromRaw(signerPrivKey);
    X509_sign(cert, signerKey, EVP_sha256());
    EVP_PKEY_free(signerKey);

    // serialize to DER
    unsigned char *derBuf = nullptr;
    int derLen = i2d_X509(cert, &derBuf);
    QByteArray result(reinterpret_cast <char*> (derBuf), derLen);
    OPENSSL_free(derBuf);

    X509_free(cert);

    return result;
}

static quint64 parseMatterIdFromHex(const QString &hex)
{
    return hex.toULongLong(nullptr, 16);
}

static void convertDNToMatterTLV(X509_NAME *name, MatterTLV::Encoder &enc)
{
    for (int i = 0; i < X509_NAME_entry_count(name); i++)
    {
        X509_NAME_ENTRY *entry = X509_NAME_get_entry(name, i);
        ASN1_OBJECT *obj = X509_NAME_ENTRY_get_object(entry);
        ASN1_STRING *val = X509_NAME_ENTRY_get_data(entry);

        char oidBuf[128];
        OBJ_obj2txt(oidBuf, sizeof(oidBuf), obj, 1);
        QString oid(oidBuf);
        QString value = QString::fromUtf8(reinterpret_cast <const char*> (ASN1_STRING_get0_data(val)), ASN1_STRING_length(val));

        int matterTag = -1;

        if (oid == "1.3.6.1.4.1.37244.1.1") matterTag = 0x11;      // node-id
        else if (oid == "1.3.6.1.4.1.37244.1.4") matterTag = 0x14;  // rcac-id
        else if (oid == "1.3.6.1.4.1.37244.1.5") matterTag = 0x15;  // fabric-id

        if (matterTag >= 0)
        {
            // force UInt64 encoding (8 bytes) as required by Matter cert spec
            quint64 id = parseMatterIdFromHex(value);
            QByteArray raw;
            raw.append(static_cast <char> (0x27));                              // UnsignedInt 8-byte + context-specific
            raw.append(static_cast <char> (matterTag));
            raw.append(reinterpret_cast <const char*> (&id), 8);               // LE
            enc.encodeRaw(raw);
        }
    }
}

QByteArray Crypto::x509DerToMatterTLV(const QByteArray &derCert)
{
    const unsigned char *p = reinterpret_cast <const unsigned char*> (derCert.constData());
    X509 *cert = d2i_X509(nullptr, &p, derCert.length());

    if (!cert)
        return QByteArray();

    MatterTLV::Encoder tlv;
    tlv.openStructure();

    // tag 1: serialNumber
    const ASN1_INTEGER *serialASN = X509_get0_serialNumber(cert);
    BIGNUM *serialBN = ASN1_INTEGER_to_BN(serialASN, nullptr);
    QByteArray serial(BN_num_bytes(serialBN), 0);
    BN_bn2bin(serialBN, reinterpret_cast <unsigned char*> (serial.data()));
    BN_free(serialBN);
    tlv.encodeByteString(1, serial);

    // tag 2: signatureAlgorithm
    tlv.encodeUnsignedInt(2, 1);

    // tag 3: issuer
    tlv.openList(3);
    convertDNToMatterTLV(X509_get_issuer_name(cert), tlv);
    tlv.closeContainer();

    // tag 4/5: notBefore/notAfter
    const quint32 matterEpoch = 946684800;

    struct tm tmBefore, tmAfter;
    ASN1_TIME_to_tm(X509_get0_notBefore(cert), &tmBefore);
    ASN1_TIME_to_tm(X509_get0_notAfter(cert), &tmAfter);
    quint32 notBefore = static_cast <quint32> (timegm(&tmBefore) - matterEpoch);
    quint32 notAfter = static_cast <quint32> (timegm(&tmAfter) - matterEpoch);
    tlv.encodeUnsignedInt(4, notBefore);
    tlv.encodeUnsignedInt(5, notAfter);

    // tag 6: subject
    tlv.openList(6);
    convertDNToMatterTLV(X509_get_subject_name(cert), tlv);
    tlv.closeContainer();

    // tag 7/8: pubKeyAlg, curveId
    tlv.encodeUnsignedInt(7, 1);
    tlv.encodeUnsignedInt(8, 1);

    // tag 9: publicKey
    EVP_PKEY *pubPkey = X509_get0_pubkey(cert);
    EC_KEY *pubEc = EVP_PKEY_get0_EC_KEY(pubPkey);
    const EC_POINT *pubPoint = EC_KEY_get0_public_key(pubEc);
    const EC_GROUP *group = EC_KEY_get0_group(pubEc);
    size_t pubLen = EC_POINT_point2oct(group, pubPoint, POINT_CONVERSION_UNCOMPRESSED, nullptr, 0, nullptr);
    QByteArray pubKey(static_cast <int> (pubLen), 0);
    EC_POINT_point2oct(group, pubPoint, POINT_CONVERSION_UNCOMPRESSED, reinterpret_cast <unsigned char*> (pubKey.data()), pubLen, nullptr);
    tlv.encodeByteString(9, pubKey);

    // tag 10: extensions
    tlv.openList(10);

    // BasicConstraints
    int bcIdx = X509_get_ext_by_NID(cert, NID_basic_constraints, -1);

    if (bcIdx >= 0)
    {
        BASIC_CONSTRAINTS *bc = reinterpret_cast <BASIC_CONSTRAINTS*> (X509V3_EXT_d2i(X509_get_ext(cert, bcIdx)));
        tlv.openStructure(1);
        tlv.encodeBool(1, bc->ca != 0);
        BASIC_CONSTRAINTS_free(bc);
        tlv.closeContainer();
    }

    // KeyUsage
    int kuIdx = X509_get_ext_by_NID(cert, NID_key_usage, -1);

    if (kuIdx >= 0)
    {
        ASN1_BIT_STRING *ku = reinterpret_cast <ASN1_BIT_STRING*> (X509V3_EXT_d2i(X509_get_ext(cert, kuIdx)));
        quint16 kuBits = 0;

        if (ASN1_BIT_STRING_get_bit(ku, 0)) kuBits |= 0x0001; // digitalSignature
        if (ASN1_BIT_STRING_get_bit(ku, 5)) kuBits |= 0x0020; // keyCertSign
        if (ASN1_BIT_STRING_get_bit(ku, 6)) kuBits |= 0x0040; // cRLSign

        tlv.encodeUnsignedInt(2, kuBits);
        ASN1_BIT_STRING_free(ku);
    }

    // ExtKeyUsage
    int ekuIdx = X509_get_ext_by_NID(cert, NID_ext_key_usage, -1);

    if (ekuIdx >= 0)
    {
        EXTENDED_KEY_USAGE *eku = reinterpret_cast <EXTENDED_KEY_USAGE*> (X509V3_EXT_d2i(X509_get_ext(cert, ekuIdx)));
        tlv.openArray(3);

        for (int i = 0; i < sk_ASN1_OBJECT_num(eku); i++)
        {
            ASN1_OBJECT *obj = sk_ASN1_OBJECT_value(eku, i);
            int nid = OBJ_obj2nid(obj);

            if (nid == NID_server_auth) tlv.encodeUnsignedInt(-1, 2);
            else if (nid == NID_client_auth) tlv.encodeUnsignedInt(-1, 1);
        }

        tlv.closeContainer();
        EXTENDED_KEY_USAGE_free(eku);
    }

    // SubjectKeyIdentifier
    int skidIdx = X509_get_ext_by_NID(cert, NID_subject_key_identifier, -1);

    if (skidIdx >= 0)
    {
        ASN1_OCTET_STRING *skid = reinterpret_cast <ASN1_OCTET_STRING*> (X509V3_EXT_d2i(X509_get_ext(cert, skidIdx)));
        tlv.encodeByteString(4, QByteArray(reinterpret_cast <const char*> (ASN1_STRING_get0_data(skid)), ASN1_STRING_length(skid)));
        ASN1_OCTET_STRING_free(skid);
    }

    // AuthorityKeyIdentifier
    int akidIdx = X509_get_ext_by_NID(cert, NID_authority_key_identifier, -1);

    if (akidIdx >= 0)
    {
        AUTHORITY_KEYID *akid = reinterpret_cast <AUTHORITY_KEYID*> (X509V3_EXT_d2i(X509_get_ext(cert, akidIdx)));

        if (akid->keyid)
            tlv.encodeByteString(5, QByteArray(reinterpret_cast <const char*> (ASN1_STRING_get0_data(akid->keyid)), ASN1_STRING_length(akid->keyid)));

        AUTHORITY_KEYID_free(akid);
    }

    tlv.closeContainer(); // extensions

    // tag 11: signature (raw r||s)
    const ASN1_BIT_STRING *sigBitStr;
    const X509_ALGOR *sigAlg;
    X509_get0_signature(&sigBitStr, &sigAlg, cert);

    const unsigned char *sigData = ASN1_STRING_get0_data(sigBitStr);
    ECDSA_SIG *ecSig = d2i_ECDSA_SIG(nullptr, &sigData, ASN1_STRING_length(sigBitStr));

    if (ecSig)
    {
        const BIGNUM *r, *s;
        ECDSA_SIG_get0(ecSig, &r, &s);

        QByteArray rawSig(64, 0);
        BN_bn2bin(r, reinterpret_cast <unsigned char*> (rawSig.data()) + (32 - BN_num_bytes(r)));
        BN_bn2bin(s, reinterpret_cast <unsigned char*> (rawSig.data()) + 32 + (32 - BN_num_bytes(s)));

        tlv.encodeByteString(11, rawSig);
        ECDSA_SIG_free(ecSig);
    }

    tlv.closeContainer(); // structure

    X509_free(cert);
    return tlv.data();
}

QByteArray Crypto::randomBytes(quint32 length)
{
    QByteArray result(length, 0);
    RAND_bytes(reinterpret_cast <unsigned char*> (result.data()), length);
    return result;
}

// --- ECPoint ---

void ECPoint::initGroup(void)
{
    if (!s_group)
        s_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
}

EC_GROUP *ECPoint::group(void)
{
    initGroup();
    return s_group;
}

ECPoint::ECPoint(void)
{
    initGroup();
    m_point = EC_POINT_new(s_group);
}

ECPoint::ECPoint(const ECPoint &other)
{
    initGroup();
    m_point = EC_POINT_dup(other.m_point, s_group);
}

ECPoint::~ECPoint(void)
{
    if (m_point)
        EC_POINT_free(m_point);
}

ECPoint &ECPoint::operator=(const ECPoint &other)
{
    if (this != &other)
        EC_POINT_copy(m_point, other.m_point);

    return *this;
}

bool ECPoint::isValid(void) const
{
    return m_point && EC_POINT_is_on_curve(s_group, m_point, nullptr);
}

bool ECPoint::setFromUncompressed(const QByteArray &data)
{
    return EC_POINT_oct2point(s_group, m_point, reinterpret_cast <const unsigned char*> (data.constData()), data.length(), nullptr) == 1;
}

QByteArray ECPoint::toUncompressed(void) const
{
    size_t length = EC_POINT_point2oct(s_group, m_point, POINT_CONVERSION_UNCOMPRESSED, nullptr, 0, nullptr);
    QByteArray result(length, 0);
    EC_POINT_point2oct(s_group, m_point, POINT_CONVERSION_UNCOMPRESSED, reinterpret_cast <unsigned char*> (result.data()), length, nullptr);
    return result;
}

ECPoint ECPoint::generator(void)
{
    initGroup();
    ECPoint result;
    EC_POINT_copy(result.m_point, EC_GROUP_get0_generator(s_group));
    return result;
}

ECPoint ECPoint::fromMultiply(const ECPoint &point, const BIGNUM *scalar)
{
    ECPoint result;
    BN_CTX *ctx = BN_CTX_new();
    EC_POINT_mul(s_group, result.m_point, nullptr, point.m_point, scalar, ctx);
    BN_CTX_free(ctx);
    return result;
}

ECPoint ECPoint::add(const ECPoint &a, const ECPoint &b)
{
    ECPoint result;
    BN_CTX *ctx = BN_CTX_new();
    EC_POINT_add(s_group, result.m_point, a.m_point, b.m_point, ctx);
    BN_CTX_free(ctx);
    return result;
}

ECPoint ECPoint::subtract(const ECPoint &a, const ECPoint &b)
{
    ECPoint negB(b);
    EC_POINT_invert(s_group, negB.m_point, nullptr);
    return add(a, negB);
}

// --- BigNum ---

BigNum::BigNum(void)
{
    m_bn = BN_new();
}

BigNum::BigNum(const QByteArray &data)
{
    m_bn = BN_bin2bn(reinterpret_cast <const unsigned char*> (data.constData()), data.length(), nullptr);
}

BigNum::BigNum(const BigNum &other)
{
    m_bn = BN_dup(other.m_bn);
}

BigNum::~BigNum(void)
{
    if (m_bn)
        BN_free(m_bn);
}

BigNum &BigNum::operator=(const BigNum &other)
{
    if (this != &other)
        BN_copy(m_bn, other.m_bn);

    return *this;
}

QByteArray BigNum::toByteArray(int length) const
{
    int bnLength = BN_num_bytes(m_bn);

    if (length == 0)
        length = bnLength;

    QByteArray result(length, 0);
    BN_bn2bin(m_bn, reinterpret_cast <unsigned char*> (result.data()) + (length - bnLength));
    return result;
}

BigNum BigNum::mod(const BigNum &a, const BigNum &m)
{
    BigNum result;
    BN_CTX *ctx = BN_CTX_new();
    BN_mod(result.m_bn, a.m_bn, m.m_bn, ctx);
    BN_CTX_free(ctx);
    return result;
}

BigNum BigNum::fromOrder(void)
{
    ECPoint::initGroup();
    BigNum result;
    EC_GROUP_get_order(ECPoint::group(), result.m_bn, nullptr);
    return result;
}
