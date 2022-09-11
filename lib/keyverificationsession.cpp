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

class KeyVerificationSession::Private {
public:
    const QString remoteUserId;
    const QString remoteDeviceId;
    const QString transactionId;
    Connection* connection;
    bool encrypted = false;
    QStringList remoteSupportedMethods{};
    OlmSAS* sas = nullptr;
    QVector<EmojiEntry> sasEmojis;
    bool startSentByUs = false;
    Expected<State, Error> state = INCOMING;
    QByteArray startEvent{};
    QByteArray commitment{};
    bool macReceived = false;
    bool verified = false;
    QString pendingEdKeyId{};
    KeyVerificationSession* q = nullptr;

    ~Private();

    void init(std::chrono::milliseconds timeout, KeyVerificationSession* qInit);
    void handleReady(const KeyVerificationReadyEvent& event);
    void handleStart(const KeyVerificationStartEvent& event);
    void handleKey(const KeyVerificationKeyEvent& event);
    void handleMac(const KeyVerificationMacEvent& event);
    void sendStartSas();
    void sendKey();
    void trustKeys();
    //! \note Setting the state to DONE or CANCELED will deleteLater() the
    //! session
    void setState(State newState);
    //! Set the error code and switch the state to CANCELED
    void setError(Error newError);
    void setError(const QString& errorString)
    {
        setError(stringToError(errorString));
    }
    static QString errorToString(Error error);
    static Error stringToError(const QString& error);

    QByteArray macInfo(bool verifying, const QString& key = "KEY_IDS"_ls);
    QString calculateMac(const QString& input, bool verifying, const QString& keyId= "KEY_IDS"_ls);
};

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
    , d(makeImpl<Private>(std::move(remoteUserId), event.fromDevice(),
                          event.transactionId(), connection, encrypted,
                          event.methods()))
{
    const auto& currentTime = QDateTime::currentDateTime();
    const auto timeoutTime =
        std::min(event.timestamp().addSecs(600), currentTime.addSecs(120));
    const milliseconds timeout{ currentTime.msecsTo(timeoutTime) };
    if (timeout > 5s)
        d->init(timeout, this);
    // Otherwise don't even bother starting up
}

KeyVerificationSession::KeyVerificationSession(QString userId, QString deviceId,
                                               Connection* connection)
    : QObject(connection)
    , d(makeImpl<Private>(std::move(userId), std::move(deviceId),
                          QUuid::createUuid().toString(), connection))
{
    d->init(600s, this);
    QMetaObject::invokeMethod(this, [this] {
        d->connection->sendToDevice(
            d->remoteUserId, d->remoteDeviceId,
            KeyVerificationRequestEvent(d->transactionId,
                                        d->connection->deviceId(),
                                        supportedMethods,
                                        QDateTime::currentDateTime()),
            d->encrypted);
        d->setState(WAITINGFORREADY);
    });
}

void KeyVerificationSession::Private::init(milliseconds timeout,
                                           KeyVerificationSession* qInit)
{
    sas = olm_sas(new std::byte[olm_sas_size()]);
    const auto randomSize = olm_create_sas_random_length(sas);
    auto random = getRandom(randomSize);
    olm_create_sas(sas, random.data(), randomSize);

    q = qInit; // From now, KeyVerificationSession is officially initialised
    QTimer::singleShot(timeout, q, [this] { q->cancelVerification(TIMEOUT); });
}

KeyVerificationSession::Private::~Private()
{
    olm_clear_sas(sas);
    delete[] reinterpret_cast<std::byte*>(sas);
}

void KeyVerificationSession::handleEvent(const KeyVerificationEvent& baseEvent)
{
    if (!switchOnType(
            baseEvent,
            [this](const KeyVerificationCancelEvent& event) {
                d->setError(event.code());
                return true;
            },
            [this](const KeyVerificationStartEvent& event) {
                if (state() != WAITINGFORREADY && state() != READY)
                    return false;
                d->handleStart(event);
                return true;
            },
            [this](const KeyVerificationReadyEvent& event) {
                if (state() == WAITINGFORREADY)
                    d->handleReady(event);
                // ACCEPTED is also fine here because it's possible to receive
                // ready and start in the same sync, in which case start might
                // be handled before ready.
                return state() == WAITINGFORREADY || state() == ACCEPTED;
            },
            [this](const KeyVerificationAcceptEvent& event) {
                if (state() != WAITINGFORACCEPT)
                    return false;
                d->commitment = event.commitment();
                d->sendKey();
                d->setState(WAITINGFORKEY);
                return true;
            },
            [this](const KeyVerificationKeyEvent& event) {
                if (state() != ACCEPTED && state() != WAITINGFORKEY)
                    return false;
                d->handleKey(event);
                return true;
            },
            [this](const KeyVerificationMacEvent& event) {
                if (state() != WAITINGFORMAC)
                    return false;
                d->handleMac(event);
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

void KeyVerificationSession::Private::handleKey(const KeyVerificationKeyEvent& event)
{
    auto eventKey = event.key();
    olm_sas_set_their_key(sas, eventKey.data(), eventKey.size());

    if (startSentByUs) {
        if (hashAndEncode(eventKey + startEvent) != commitment) {
            qCWarning(E2EE) << "Commitment mismatch; aborting verification";
            q->cancelVerification(MISMATCHED_COMMITMENT);
            return;
        }
    } else {
        sendKey();
    }

    std::string key(olm_sas_pubkey_length(sas), '\0');
    olm_sas_get_pubkey(sas, key.data(), key.size());

    std::array<std::byte, 6> output{};
    const auto infoTemplate =
        startSentByUs ? "MATRIX_KEY_VERIFICATION_SAS|%1|%2|%3|%4|%5|%6|%7"_ls
                      : "MATRIX_KEY_VERIFICATION_SAS|%4|%5|%6|%1|%2|%3|%7"_ls;

    const auto info = infoTemplate
                          .arg(connection->userId(), connection->deviceId(),
                               key.data(), remoteUserId, remoteDeviceId,
                               event.key(), transactionId)
                          .toLatin1();
    olm_sas_generate_bytes(sas, info.data(), info.size(), output.data(),
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
        sasEmojis += emojiForCode(std::to_integer<int>(c), preferredLanguage);

    emit q->sasEmojisChanged();
    emit q->keyReceived();
    setState(WAITINGFORVERIFICATION);
}

QString KeyVerificationSession::Private::calculateMac(const QString& input,
                                                      bool verifying,
                                                      const QString& keyId)
{
    QByteArray inputBytes = input.toLatin1();
    QByteArray outputBytes(olm_sas_mac_length(sas), '\0');
    const auto macInfo =
        (verifying ? "MATRIX_KEY_VERIFICATION_MAC%3%4%1%2%5%6"_ls
                   : "MATRIX_KEY_VERIFICATION_MAC%1%2%3%4%5%6"_ls)
            .arg(connection->userId(), connection->deviceId(), remoteUserId,
                 remoteDeviceId, transactionId, keyId)
            .toLatin1();
    olm_sas_calculate_mac(sas, inputBytes.data(), inputBytes.size(),
                          macInfo.data(), macInfo.size(), outputBytes.data(),
                          outputBytes.size());
    return QString::fromLatin1(outputBytes.data(), outputBytes.indexOf('='));
}

void KeyVerificationSession::sasVerified()
{
    QString edKeyId = "ed25519:" % d->connection->deviceId();

    auto keys = d->calculateMac(edKeyId, false);

    QJsonObject mac;
    auto key = d->connection->olmAccount()->deviceKeys().keys[edKeyId];
    mac[edKeyId] = d->calculateMac(key, false, edKeyId);

    d->connection->sendToDevice(d->remoteUserId, d->remoteDeviceId,
                                KeyVerificationMacEvent(d->transactionId, keys,
                                                        mac),
                                d->encrypted);
    d->setState(d->macReceived ? DONE : WAITINGFORMAC);
    d->verified = true;
    if (!d->pendingEdKeyId.isEmpty()) {
        d->trustKeys();
    }
}

void KeyVerificationSession::Private::sendKey()
{
    QByteArray keyBytes(olm_sas_pubkey_length(sas), '\0');
    olm_sas_get_pubkey(sas, keyBytes.data(), keyBytes.size());
    connection->sendToDevice(remoteUserId, remoteDeviceId,
                             KeyVerificationKeyEvent(transactionId, keyBytes),
                             encrypted);
}

void KeyVerificationSession::cancelVerification(Error error)
{
    d->connection->sendToDevice(
        d->remoteUserId, d->remoteDeviceId,
        KeyVerificationCancelEvent(d->transactionId,
                                   Private::errorToString(error)),
        d->encrypted);
    d->setError(error);
    emit finished();
    deleteLater();
}

void KeyVerificationSession::setReady()
{
    auto methods = commonSupportedMethods(d->remoteSupportedMethods);

    if (methods.isEmpty()) {
        cancelVerification(UNKNOWN_METHOD);
        return;
    }

    d->connection->sendToDevice(
        d->remoteUserId, d->remoteDeviceId,
        KeyVerificationReadyEvent(d->transactionId, d->connection->deviceId(),
                                  methods),
        d->encrypted);
    d->setState(READY);

    if (methods.size() == 1) {
        d->sendStartSas();
    }
}

void KeyVerificationSession::Private::sendStartSas()
{
    startSentByUs = true;
    KeyVerificationStartEvent event(transactionId, connection->deviceId());
    startEvent =
        QJsonDocument(event.contentJson()).toJson(QJsonDocument::Compact);
    connection->sendToDevice(remoteUserId, remoteDeviceId, event, encrypted);
    setState(WAITINGFORACCEPT);
}

void KeyVerificationSession::Private::handleReady(
    const KeyVerificationReadyEvent& event)
{
    setState(READY);
    remoteSupportedMethods = event.methods();
    auto methods = commonSupportedMethods(remoteSupportedMethods);

    if (methods.isEmpty())
        q->cancelVerification(UNKNOWN_METHOD);
    else if (methods.size() == 1)
        sendStartSas(); // -> WAITINGFORACCEPT
}

void KeyVerificationSession::Private::handleStart(
    const KeyVerificationStartEvent& event)
{
    if (startSentByUs) {
        if (remoteUserId > connection->userId()
            || (remoteUserId == connection->userId()
                && remoteDeviceId > connection->deviceId()))
            return;

        startSentByUs = false;
    }
    QByteArray publicKey(olm_sas_pubkey_length(sas), '\0');
    olm_sas_get_pubkey(sas, publicKey.data(), publicKey.size());
    const auto canonicalJson =
        QJsonDocument(event.contentJson()).toJson(QJsonDocument::Compact);

    connection->sendToDevice(
        remoteUserId, remoteDeviceId,
        KeyVerificationAcceptEvent(transactionId,
                                   hashAndEncode(publicKey + canonicalJson)),
        encrypted);
    setState(ACCEPTED);
}

void KeyVerificationSession::Private::handleMac(
    const KeyVerificationMacEvent& event)
{
    auto keys = event.mac().keys();
    keys.sort();
    const auto& key = keys.join(",");
    const QString edKeyId = "ed25519:"_ls % remoteDeviceId;

    if (calculateMac(connection->edKeyForUserDevice(remoteUserId,
                                                    remoteDeviceId),
                     true, edKeyId)
        != event.mac().value(edKeyId)) {
        q->cancelVerification(KEY_MISMATCH);
        return;
    }

    if (calculateMac(key, true) != event.keys()) {
        q->cancelVerification(KEY_MISMATCH);
        return;
    }

    pendingEdKeyId = edKeyId;

    if (verified) {
        trustKeys();
    }
}

void KeyVerificationSession::Private::trustKeys()
{
    connection->database()->setSessionVerified(pendingEdKeyId);
    emit connection->sessionVerified(remoteUserId, remoteDeviceId); // FIXME
    macReceived = true;

    if (state && *state == WAITINGFORMAC) {
        setState(DONE);
        connection->sendToDevice(remoteUserId, remoteDeviceId,
                                 KeyVerificationDoneEvent(transactionId),
                                 encrypted);
        emit q->finished();
        q->deleteLater();
    }
}

QString KeyVerificationSession::remoteDeviceId() const
{
    return d->remoteDeviceId;
}

QVector<EmojiEntry> KeyVerificationSession::sasEmojis() const
{
    return d->sasEmojis;
}

KeyVerificationSession::State KeyVerificationSession::state() const
{
    return d->state.value_or(CANCELED);
}

void KeyVerificationSession::Private::setState(
    KeyVerificationSession::State newState)
{
    if (!state) {
        qCritical(E2EE) << "The session is already in error state:"
                        << state.error();
        Q_ASSERT(false);
    }
    auto& normalState = *state;
    if (newState == normalState)
        return;
    if (newState < normalState) {
        qCritical(E2EE) << "Incorrect state transition:" << normalState << "->"
                        << newState;
        Q_ASSERT(false);
    }
    normalState = newState;
    emit q->stateChanged();
}

KeyVerificationSession::Error KeyVerificationSession::error() const
{
    return d->state ? NONE : d->state.error();
}

void KeyVerificationSession::Private::setError(Error newError)
{
    state = newError;
    emit q->stateChanged();
}

QString KeyVerificationSession::Private::errorToString(Error error)
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

KeyVerificationSession::Error KeyVerificationSession::Private::stringToError(
    const QString& error)
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
