// SPDX-FileCopyrightText: 2022 Tobias Fella <fella@posteo.de>
//
// SPDX-License-Identifier: LGPL-2.1-or-later


#include <QTest>
#include "testutils.h"
#include <qt_connection_util.h>

#include <QtTest/QSignalSpy>

class TestKeyVerificationSession : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void testVerification()
    {
        CREATE_CONNECTION(a, "alice1", "secret", "AliceDesktop")
        CREATE_CONNECTION(b, "alice1", "secret", "AlicePhone")

        using KVS = KeyVerificationSession;
	    QPointer<KVS> aSession{};
        connect(a.get(), &Connection::newKeyVerificationSession, this,
                [&](KVS* session) {
                    aSession = session;
                    QVERIFY(session->remoteDeviceId() == b->deviceId());
                    QVERIFY(session->state() == KVS::WAITINGFORREADY);
                    connectSingleShot(
                        session, &KVS::stateChanged, this, [this, session] {
                            QVERIFY(session->state() == KVS::ACCEPTED);
                            connectSingleShot(
                                session, &KVS::stateChanged, this, [session] {
                                    QVERIFY(session->state()
                                            == KVS::WAITINGFORVERIFICATION);
                                    session->sasVerified();
                                });
                        });
                });
        a->startKeyVerificationSession(b->deviceId());
        connect(b.get(), &Connection::newKeyVerificationSession, this,
                [this, a](KVS* session) {
                    QVERIFY(session->remoteDeviceId() == a->deviceId());
                    QVERIFY(session->state() == KVS::INCOMING);
                    session->setReady();
                    // KeyVerificationSession::READY is skipped because we have
                    // only one method
                    QVERIFY(session->state() == KVS::WAITINGFORACCEPT);
                    connectSingleShot(
                        session, &KVS::stateChanged, this, [this, session] {
                            QVERIFY(session->state() == KVS::WAITINGFORKEY
                                    || session->state() == KVS::ACCEPTED);
                            connectSingleShot(
                                session, &KVS::stateChanged, this,
                                [this, session] {
                                    QVERIFY(session->state()
                                            == KVS::WAITINGFORVERIFICATION);
                                    QVERIFY(aSession);
                                    QVERIFY(aSession->sasEmojis()
                                            == session->sasEmojis());
                                    session->sasVerified();
                                    QVERIFY(session->state()
                                            == KVS::WAITINGFORMAC);
                                });
                        });
                });
        b->syncLoop();
        a->syncLoop();
        QSignalSpy spy(aSession, &KVS::finished);
        spy.wait(10000);
    }
};
QTEST_GUILESS_MAIN(TestKeyVerificationSession)
#include "testkeyverification.moc"
