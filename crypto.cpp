#include "crypto.h"

#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/ecdsa.h>
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
