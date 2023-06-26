#pragma once

#include "MyAction.h"

#include <StreamDeckSDK/ESDPlugin.h>
#include <StreamDeckSDK/ESDLogger.h>

class MyPlugin final : public ESDPlugin {
public:
    using ESDPlugin::ESDPlugin;

    virtual std::shared_ptr<ESDAction> GetOrCreateAction(
        const std::string& action,
        const std::string& context
    ) override
    {
        auto it = mActions.find(context);
        if (it != mActions.end()) {
            return it->second;
        }

        if (action == "com.xifansdplugin.myaction") {
            auto impl = std::make_shared<MyAction>(
                mConnectionManager,
                action,
                context
            );
            mActions.emplace(context, impl);
            return impl;
        }

        ESDLog("Asked to get or create unknown action: {}", action);
        return nullptr;
    }

    virtual void SystemDidWakeUp()
    {
        //fanAttemptResync();
    }

private:
    std::map<std::string, std::shared_ptr<MyAction>> mActions;
};
