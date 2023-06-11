#pragma once

#include <StreamDeckSDK/ESDAction.h>
#include <StreamDeckSDK/ESDLogger.h>
#include "fanctrl.h"

class MyAction final : public ESDAction
{
  using ESDAction::ESDAction;

public:

    MyAction(
        ESDConnectionManager* esd_connection,
        const std::string& action,
        const std::string& context)
        : ESDAction(esd_connection,action,context)
    {
        updateSpeedAndPower();
    }

    virtual void WillAppear(const nlohmann::json& settings) override
    {
        updateSpeedAndPower();
    }

    virtual void DialPress(const nlohmann::json& settings) override
    {
        m_fanEnabled = !m_fanEnabled;
        fanSetEnabled( m_fanEnabled );

        nlohmann::json payload;
        payload["icon"] = m_fanEnabled ? "./actionOn@2x.png" : "./action@2x.png";
        SetFeedback( payload );
    }

    virtual void DialRotate( const nlohmann::json& settings, int ticks, bool pressed ) override
    {
        int granularity = 5;

        m_fanSpeed = (( m_fanSpeed + ticks*granularity ) / granularity) * granularity;
        m_fanSpeed = std::min( 100, std::max( 1, m_fanSpeed ) );

        nlohmann::json payload;
        payload["value"] = std::format("{}%",m_fanSpeed);
        payload["indicator"]["value"] = m_fanSpeed;
        payload["indicator"]["enabled"] = true;
        SetFeedback( payload );

        fanSetSpeed( m_fanSpeed );
    }

private:

    void updateSpeedAndPower()
    {
        m_fanEnabled = fanGetEnabled();
        m_fanSpeed   = fanGetSpeed();

        nlohmann::json payload;
        payload["icon"] = m_fanEnabled ? "./actionOn@2x.png" : "./action@2x.png";
        payload["value"] = std::format("{}%",m_fanSpeed);
        payload["indicator"]["value"] = m_fanSpeed;
        payload["indicator"]["enabled"] = true;
        SetFeedback( payload );
    }

    bool m_fanEnabled = false;
    int m_fanSpeed = 0;
    
};
