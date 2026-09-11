// Copyright (c) 2026 The Version developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_EVENTSIGNAL_H
#define BITCOIN_EVENTSIGNAL_H

#include <cstdint>
#include <functional>
#include <utility>
#include <vector>

/**
 * Minimal ordered multi-subscriber callback list, replacing boost::signals2::signal
 * for this codebase's needs. Not thread-safe and does no automatic slot-lifetime
 * tracking (a connected slot bound to an object must be disconnected before that
 * object is destroyed, same requirement boost::signals2 had here via explicit
 * subscribeToCoreSignals()/unsubscribeFromCoreSignals() pairs).
 */
class SignalConnection
{
public:
    SignalConnection() = default;

private:
    explicit SignalConnection(uint64_t id_) : id(id_) {}
    uint64_t id = 0;
    template <typename Signature> friend class Signal;
};

template <typename Signature>
class Signal;

template <typename R, typename... Args>
class Signal<R(Args...)>
{
public:
    using Slot = std::function<R(Args...)>;

    SignalConnection connect(Slot slot)
    {
        uint64_t id = ++m_nextId;
        m_slots.emplace_back(id, std::move(slot));
        return SignalConnection(id);
    }

    void disconnect(const SignalConnection& conn)
    {
        for (auto it = m_slots.begin(); it != m_slots.end(); ++it) {
            if (it->first == conn.id) {
                m_slots.erase(it);
                return;
            }
        }
    }

    // Invokes every connected slot in order; returns the last slot's result,
    // or a default-constructed R{} if nothing is connected.
    R operator()(Args... args) const
    {
        R result{};
        for (const auto& s : m_slots)
            result = s.second(args...);
        return result;
    }

private:
    uint64_t m_nextId = 0;
    std::vector<std::pair<uint64_t, Slot>> m_slots;
};

template <typename... Args>
class Signal<void(Args...)>
{
public:
    using Slot = std::function<void(Args...)>;

    SignalConnection connect(Slot slot)
    {
        uint64_t id = ++m_nextId;
        m_slots.emplace_back(id, std::move(slot));
        return SignalConnection(id);
    }

    void disconnect(const SignalConnection& conn)
    {
        for (auto it = m_slots.begin(); it != m_slots.end(); ++it) {
            if (it->first == conn.id) {
                m_slots.erase(it);
                return;
            }
        }
    }

    void operator()(Args... args) const
    {
        for (const auto& s : m_slots)
            s.second(args...);
    }

private:
    uint64_t m_nextId = 0;
    std::vector<std::pair<uint64_t, Slot>> m_slots;
};

#endif
