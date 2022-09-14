// SPDX-FileCopyrightText: 2022 Tobias Fella <fella@posteo.de>
//
// SPDX-License-Identifier: LGPL-2.1-or-later


#include <QTest>
#include "testutils.h"
#include <qt_connection_util.h>

class TestKeyVerificationSession : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void testVerification()
    {
        CREATE_CONNECTION(a, "alice1", "secret", "AliceDesktop")
        CREATE_CONNECTION(b, "alice1", "secret", "AlicePhone")

        QPointer<KeyVerificationSession> aSession{};
        connect(a.get(), &Connection::newKeyVerificationSession, this, [&](KeyVerificationSession* session) {
            aSession = session;
            QVERIFY(session->remoteDeviceId() == b->deviceId());
            QVERIFY(session->state() == KeyVerificationSession::WAITINGFORREADY);
            connectSingleShot(session, &KeyVerificationSession::stateChanged, this, [=](){
                QVERIFY(session->state() == KeyVerificationSession::ACCEPTED || session->state() == KeyVerificationSession::READY);
                connectSingleShot(session, &KeyVerificationSession::stateChanged, this, [=](){
                    QVERIFY(session->state() == KeyVerificationSession::WAITINGFORVERIFICATION);
                    session->sasVerified();
                });
            });
        });
        a->startKeyVerificationSession(b->deviceId());
        connect(b.get(), &Connection::newKeyVerificationSession, this, [=](KeyVerificationSession* session) {
            QVERIFY(session->remoteDeviceId() == a->deviceId());
            QVERIFY(session->state() == KeyVerificationSession::INCOMING);
            session->setReady();
            // KeyVerificationSession::READY is skipped because we have only one method
            QVERIFY(session->state() == KeyVerificationSession::WAITINGFORACCEPT);
            connectSingleShot(session, &KeyVerificationSession::stateChanged, this, [=](){
                QVERIFY(session->state() == KeyVerificationSession::WAITINGFORKEY || session->state() == KeyVerificationSession::ACCEPTED);
                connectSingleShot(session, &KeyVerificationSession::stateChanged, this, [=]() {
                    QVERIFY(session->state() == KeyVerificationSession::WAITINGFORVERIFICATION);
                    QVERIFY(aSession);
                    QVERIFY(aSession->sasEmojis() == session->sasEmojis());
                    session->sasVerified();
                    QVERIFY(session->state() == KeyVerificationSession::WAITINGFORMAC);
                });
            });

        });
        b->syncLoop();
        a->syncLoop();
        QSignalSpy spy(aSession, &KeyVerificationSession::finished);
        spy.wait(10000);
    }
};
QTEST_GUILESS_MAIN(TestKeyVerificationSession)
#include "testkeyverification.moc"
