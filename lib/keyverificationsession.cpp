// SPDX-FileCopyrightText: 2022 Tobias Fella <fella@posteo.de>
// SPDX-License-Identifier: LGPL-2.1-or-later

#include "keyverificationsession.h"

#include "connection.h"
#include "database.h"
#include "e2ee/qolmaccount.h"
#include "e2ee/qolmutils.h"
#include "olm/sas.h"

#include "events/event.h"

#include <QtCore/QCryptographicHash>
#include <QtCore/QTimer>
#include <QtCore/QUuid>
#include <QtCore/QStandardPaths>

#include <chrono>

using namespace Quotient;
using namespace std::chrono;

QByteArray hashAndEncode(const QByteArray& payload)
{
    return QCryptographicHash::hash(payload, QCryptographicHash::Sha256)
        .toBase64(QByteArray::OmitTrailingEquals);
}

const QStringList supportedMethods = { SasV1Method };

QStringList commonSupportedMethods(const QStringList& remoteMethods)
{
    QStringList result;
    for (const auto& method : remoteMethods) {
        if (supportedMethods.contains(method)) {
            result += method;
        }
    }
    return result;
}

KeyVerificationSession::KeyVerificationSession(
    QString remoteUserId, const KeyVerificationRequestEvent& event,
    Connection* connection, bool encrypted)
    : QObject(connection)
    , m_remoteUserId(std::move(remoteUserId))
    , m_remoteDeviceId(event.fromDevice())
    , m_transactionId(event.transactionId())
    , m_connection(connection)
    , m_encrypted(encrypted)
    , m_remoteSupportedMethods(event.methods())
{
    const auto& currentTime = QDateTime::currentDateTime();
    const auto timeoutTime =
        std::min(event.timestamp().addSecs(600), currentTime.addSecs(120));
    const milliseconds timeout{ currentTime.msecsTo(timeoutTime) };
    if (timeout > 5s)
        init(timeout);
    // Otherwise don't even bother starting up
}

KeyVerificationSession::KeyVerificationSession(QString userId, QString deviceId,
                                               Connection* connection)
    : QObject(connection)
    , m_remoteUserId(std::move(userId))
    , m_remoteDeviceId(std::move(deviceId))
    , m_transactionId(QUuid::createUuid().toString())
    , m_connection(connection)
    , m_encrypted(false)
{
    init(600s);
    QMetaObject::invokeMethod(this, &KeyVerificationSession::sendRequest);
}

void KeyVerificationSession::init(milliseconds timeout)
{
    QTimer::singleShot(timeout, this, [this] { cancelVerification(TIMEOUT); });

    m_sas = olm_sas(new std::byte[olm_sas_size()]);
    auto randomSize = olm_create_sas_random_length(m_sas);
    auto random = getRandom(randomSize);
    olm_create_sas(m_sas, random.data(), randomSize);
}

KeyVerificationSession::~KeyVerificationSession()
{
    olm_clear_sas(m_sas);
    delete[] reinterpret_cast<std::byte*>(m_sas);
}

void KeyVerificationSession::handleEvent(const KeyVerificationEvent& baseEvent)
{
    if (!switchOnType(
            baseEvent,
            [this](const KeyVerificationCancelEvent& event) {
                setError(stringToError(event.code()));
                setState(CANCELED);
                return true;
            },
            [this](const KeyVerificationStartEvent& event) {
                if (state() != WAITINGFORREADY && state() != READY)
                    return false;
                handleStart(event);
                return true;
            },
            [this](const KeyVerificationReadyEvent& event) {
                if (state() == WAITINGFORREADY)
                    handleReady(event);
                // ACCEPTED is also fine here because it's possible to receive
                // ready and start in the same sync, in which case start might
                // be handled before ready.
                return state() == WAITINGFORREADY || state() == ACCEPTED;
            },
            [this](const KeyVerificationAcceptEvent& event) {
                if (state() != WAITINGFORACCEPT)
                    return false;
                m_commitment = event.commitment();
                sendKey();
                setState(WAITINGFORKEY);
                return true;
            },
            [this](const KeyVerificationKeyEvent& event) {
                if (state() != ACCEPTED && state() != WAITINGFORKEY)
                    return false;
                handleKey(event);
                return true;
            },
            [this](const KeyVerificationMacEvent& event) {
                if (state() != WAITINGFORMAC)
                    return false;
                handleMac(event);
                return true;
            },
            [this](const KeyVerificationDoneEvent&) { return state() == DONE; }))
        cancelVerification(UNEXPECTED_MESSAGE);
}

struct EmojiStoreEntry : EmojiEntry {
    QHash<QString, QString> translatedDescriptions;

    explicit EmojiStoreEntry(const QJsonObject& json)
        : EmojiEntry{ fromJson<QString>(json["emoji"]),
                      fromJson<QString>(json["description"]) }
        , translatedDescriptions{ fromJson<QHash<QString, QString>>(
              json["translated_descriptions"]) }
    {}
};

using EmojiStore = QVector<EmojiStoreEntry>;

EmojiStore loadEmojiStore()
{
    QFile dataFile(QStandardPaths::locate(QStandardPaths::AppDataLocation,
                                          "sas-emoji.json")); // Will it also run from builddir?
    dataFile.open(QFile::ReadOnly);
    return fromJson<EmojiStore>(
        QJsonDocument::fromJson(dataFile.readAll()).array());
}

EmojiEntry emojiForCode(int code, const QString& language)
{
    static const EmojiStore emojiStore = loadEmojiStore();
    const auto& entry = emojiStore[code];
    if (!language.isEmpty())
        if (const auto translatedDescription =
            emojiStore[code].translatedDescriptions.value(language);
            !translatedDescription.isNull())
            return { entry.emoji, translatedDescription };

    return SLICE(entry, EmojiEntry);
}

void KeyVerificationSession::handleKey(const KeyVerificationKeyEvent& event)
{
    auto eventKey = event.key();
    olm_sas_set_their_key(m_sas, eventKey.data(), eventKey.size());

    if (startSentByUs) {
        if (hashAndEncode(eventKey + m_startEvent) != m_commitment) {
            qCWarning(E2EE) << "Commitment mismatch; aborting verification";
            cancelVerification(MISMATCHED_COMMITMENT);
            return;
        }
    } else {
        sendKey();
    }

    std::string key(olm_sas_pubkey_length(m_sas), '\0');
    olm_sas_get_pubkey(m_sas, key.data(), key.size());

    std::array<std::byte, 6> output{};
    const auto infoTemplate =
        startSentByUs ? "MATRIX_KEY_VERIFICATION_SAS|%1|%2|%3|%4|%5|%6|%7"_ls
                      : "MATRIX_KEY_VERIFICATION_SAS|%4|%5|%6|%1|%2|%3|%7"_ls;

    const auto info = infoTemplate
                          .arg(m_connection->userId(), m_connection->deviceId(),
                               key.data(), m_remoteUserId, m_remoteDeviceId,
                               event.key(), m_transactionId)
                          .toLatin1();
    olm_sas_generate_bytes(m_sas, info.data(), info.size(), output.data(),
                           output.size());

    static constexpr auto x3f = std::byte{ 0x3f };
    const std::array<std::byte, 7> code{
        output[0] >> 2,
        (output[0] << 4 & x3f) | output[1] >> 4,
        (output[1] << 2 & x3f) | output[2] >> 6,
        output[2] & x3f,
        output[3] >> 2,
        (output[3] << 4 & x3f) | output[4] >> 4,
        (output[4] << 2 & x3f) | output[5] >> 6
    };

    const auto uiLanguages = QLocale().uiLanguages();
    const auto preferredLanguage = uiLanguages.isEmpty()
                                       ? QString()
                                       : uiLanguages.front().section('-', 0, 0);
    for (const auto& c : code)
        m_sasEmojis += emojiForCode(std::to_integer<int>(c), preferredLanguage);

    emit sasEmojisChanged();
    emit keyReceived();
    setState(WAITINGFORVERIFICATION);
}

QString KeyVerificationSession::calculateMac(const QString& input,
                                             bool verifying,
                                             const QString& keyId)
{
    QByteArray inputBytes = input.toLatin1();
    QByteArray outputBytes(olm_sas_mac_length(m_sas), '\0');
    const auto macInfo =
        (verifying ? "MATRIX_KEY_VERIFICATION_MAC%3%4%1%2%5%6"_ls
                   : "MATRIX_KEY_VERIFICATION_MAC%1%2%3%4%5%6"_ls)
            .arg(m_connection->userId(), m_connection->deviceId(),
                 m_remoteUserId, m_remoteDeviceId, m_transactionId, keyId)
            .toLatin1();
    olm_sas_calculate_mac(m_sas, inputBytes.data(), inputBytes.size(),
                          macInfo.data(), macInfo.size(), outputBytes.data(),
                          outputBytes.size());
    return QString::fromLatin1(outputBytes.data(), outputBytes.indexOf('='));
}

void KeyVerificationSession::sendMac()
{
    QString edKeyId = "ed25519:" % m_connection->deviceId();

    auto keys = calculateMac(edKeyId, false);

    QJsonObject mac;
    auto key = m_connection->olmAccount()->deviceKeys().keys[edKeyId];
    mac[edKeyId] = calculateMac(key, false, edKeyId);

    m_connection->sendToDevice(m_remoteUserId, m_remoteDeviceId,
                               KeyVerificationMacEvent(m_transactionId, keys,
                                                       mac),
                               m_encrypted);
    setState (macReceived ? DONE : WAITINGFORMAC);
    m_verified = true;
    if (!m_pendingEdKeyId.isEmpty()) {
        trustKeys();
    }
}

void KeyVerificationSession::sendDone()
{
    m_connection->sendToDevice(m_remoteUserId, m_remoteDeviceId,
                               KeyVerificationDoneEvent(m_transactionId),
                               m_encrypted);
}

void KeyVerificationSession::sendKey()
{
    QByteArray keyBytes(olm_sas_pubkey_length(m_sas), '\0');
    olm_sas_get_pubkey(m_sas, keyBytes.data(), keyBytes.size());
    m_connection->sendToDevice(m_remoteUserId, m_remoteDeviceId,
                               KeyVerificationKeyEvent(m_transactionId,
                                                       keyBytes),
                               m_encrypted);
}


void KeyVerificationSession::cancelVerification(Error error)
{
    m_connection->sendToDevice(m_remoteUserId, m_remoteDeviceId,
                               KeyVerificationCancelEvent(m_transactionId,
                                                          errorToString(error)),
                               m_encrypted);
    setState(CANCELED);
    setError(error);
    emit finished();
    deleteLater();
}

void KeyVerificationSession::sendReady()
{
    auto methods = commonSupportedMethods(m_remoteSupportedMethods);

    if (methods.isEmpty()) {
        cancelVerification(UNKNOWN_METHOD);
        return;
    }

    m_connection->sendToDevice(
        m_remoteUserId, m_remoteDeviceId,
        KeyVerificationReadyEvent(m_transactionId, m_connection->deviceId(),
                                  methods),
        m_encrypted);
    setState(READY);

    if (methods.size() == 1) {
        sendStartSas();
    }
}

void KeyVerificationSession::sendStartSas()
{
    startSentByUs = true;
    KeyVerificationStartEvent event(m_transactionId, m_connection->deviceId());
    m_startEvent =
        QJsonDocument(event.contentJson()).toJson(QJsonDocument::Compact);
    m_connection->sendToDevice(m_remoteUserId, m_remoteDeviceId, event,
                               m_encrypted);
    setState(WAITINGFORACCEPT);
}

void KeyVerificationSession::handleReady(const KeyVerificationReadyEvent& event)
{
    setState(READY);
    m_remoteSupportedMethods = event.methods();
    auto methods = commonSupportedMethods(m_remoteSupportedMethods);

    if (methods.isEmpty())
        cancelVerification(UNKNOWN_METHOD);
    else if (methods.size() == 1)
        sendStartSas(); // -> WAITINGFORACCEPT
}

void KeyVerificationSession::handleStart(const KeyVerificationStartEvent& event)
{
    if (startSentByUs) {
        if (m_remoteUserId > m_connection->userId() || (m_remoteUserId == m_connection->userId() && m_remoteDeviceId > m_connection->deviceId())) {
            return;
        } else {
            startSentByUs = false;
        }
    }
    QByteArray publicKey(olm_sas_pubkey_length(m_sas), '\0');
    olm_sas_get_pubkey(m_sas, publicKey.data(), publicKey.size());
    const auto canonicalJson =
        QJsonDocument(event.contentJson()).toJson(QJsonDocument::Compact);

    m_connection->sendToDevice(
        m_remoteUserId, m_remoteDeviceId,
        KeyVerificationAcceptEvent(m_transactionId,
                                   hashAndEncode(publicKey + canonicalJson)),
        m_encrypted);
    setState(ACCEPTED);
}

void KeyVerificationSession::handleMac(const KeyVerificationMacEvent& event)
{
    QStringList keys = event.mac().keys();
    keys.sort();
    const auto& key = keys.join(",");
    const QString edKeyId = "ed25519:"_ls % m_remoteDeviceId;

    if (calculateMac(m_connection->edKeyForUserDevice(m_remoteUserId, m_remoteDeviceId), true, edKeyId) != event.mac()[edKeyId]) {
        cancelVerification(KEY_MISMATCH);
        return;
    }

    if (calculateMac(key, true) != event.keys()) {
        cancelVerification(KEY_MISMATCH);
        return;
    }

    m_pendingEdKeyId = edKeyId;

    if (m_verified) {
        trustKeys();
    }
}

void KeyVerificationSession::trustKeys()
{
    m_connection->database()->setSessionVerified(m_pendingEdKeyId);
    emit m_connection->sessionVerified(m_remoteUserId, m_remoteDeviceId);
    macReceived = true;

    if (state() == WAITINGFORMAC) {
        setState(DONE);
        sendDone();
        emit finished();
        deleteLater();
    }
}

QVector<EmojiEntry> KeyVerificationSession::sasEmojis() const
{
    return m_sasEmojis;
}

void KeyVerificationSession::sendRequest()
{
    m_connection->sendToDevice(
        m_remoteUserId, m_remoteDeviceId,
        KeyVerificationRequestEvent(m_transactionId, m_connection->deviceId(),
                                    supportedMethods,
                                    QDateTime::currentDateTime()),
        m_encrypted);
    setState(WAITINGFORREADY);
}

KeyVerificationSession::State KeyVerificationSession::state() const
{
    return m_state;
}

void KeyVerificationSession::setState(KeyVerificationSession::State state)
{
    m_state = state;
    emit stateChanged();
}

KeyVerificationSession::Error KeyVerificationSession::error() const
{
    return m_error;
}

void KeyVerificationSession::setError(Error error)
{
    m_error = error;
    emit errorChanged();
}

QString KeyVerificationSession::errorToString(Error error)
{
    switch(error) {
        case NONE:
            return "none"_ls;
        case TIMEOUT:
            return "m.timeout"_ls;
        case USER:
            return "m.user"_ls;
        case UNEXPECTED_MESSAGE:
            return "m.unexpected_message"_ls;
        case UNKNOWN_TRANSACTION:
            return "m.unknown_transaction"_ls;
        case UNKNOWN_METHOD:
            return "m.unknown_method"_ls;
        case KEY_MISMATCH:
            return "m.key_mismatch"_ls;
        case USER_MISMATCH:
            return "m.user_mismatch"_ls;
        case INVALID_MESSAGE:
            return "m.invalid_message"_ls;
        case SESSION_ACCEPTED:
            return "m.accepted"_ls;
        case MISMATCHED_COMMITMENT:
            return "m.mismatched_commitment"_ls;
        case MISMATCHED_SAS:
            return "m.mismatched_sas"_ls;
        default:
            return "m.user"_ls;
    }
}

KeyVerificationSession::Error KeyVerificationSession::stringToError(const QString& error)
{
    if (error == "m.timeout"_ls) {
        return REMOTE_TIMEOUT;
    } else if (error == "m.user"_ls) {
        return REMOTE_USER;
    } else if (error == "m.unexpected_message"_ls) {
        return REMOTE_UNEXPECTED_MESSAGE;
    } else if (error == "m.unknown_message"_ls) {
        return REMOTE_UNEXPECTED_MESSAGE;
    } else if (error == "m.unknown_transaction"_ls) {
        return REMOTE_UNKNOWN_TRANSACTION;
    } else if (error == "m.unknown_method"_ls) {
        return REMOTE_UNKNOWN_METHOD;
    } else if (error == "m.key_mismatch"_ls) {
        return REMOTE_KEY_MISMATCH;
    } else if (error == "m.user_mismatch"_ls) {
        return REMOTE_USER_MISMATCH;
    } else if (error == "m.invalid_message"_ls) {
        return REMOTE_INVALID_MESSAGE;
    } else if (error == "m.accepted"_ls) {
        return REMOTE_SESSION_ACCEPTED;
    } else if (error == "m.mismatched_commitment"_ls) {
        return REMOTE_MISMATCHED_COMMITMENT;
    } else if (error == "m.mismatched_sas"_ls) {
        return REMOTE_MISMATCHED_SAS;
    }
    return NONE;
}

QString KeyVerificationSession::remoteDeviceId() const
{
    return m_remoteDeviceId;
}
