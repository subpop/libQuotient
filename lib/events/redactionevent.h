/******************************************************************************
 * SPDX-FileCopyrightText: 2017 Kitsune Ral <kitsune-ral@users.sf.net>
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#pragma once

#include "roomevent.h"

namespace Quotient {
class RedactionEvent : public RoomEvent {
public:
    DEFINE_EVENT_TYPEID("m.room.redaction", RedactionEvent)

    explicit RedactionEvent(const QJsonObject& obj) : RoomEvent(typeId(), obj)
    {}

    [[deprecated("Use redactedEvents() instead")]]
    QString redactedEvent() const
    {
        return fullJson()["redacts"_ls].toString();
    }
    QStringList redactedEvents() const
    {
        const auto evtIdJson = contentJson()["redacts"_ls];
        if (evtIdJson.isArray())
            return fromJson<QStringList>(evtIdJson); // MSC2244: a list of ids
        if (evtIdJson.isString())
            return { fromJson<QString>(evtIdJson) }; // MSC2174: id in content
        return { fullJson()["redacts"_ls].toString() }; // legacy fallback
    }
    QString reason() const { return contentJson()["reason"_ls].toString(); }
};
REGISTER_EVENT_TYPE(RedactionEvent)
} // namespace Quotient
