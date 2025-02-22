
#ifndef SDK_SENTRY_H
#define SDK_SENTRY_H


#if defined(CLIENT_DLL) && defined(SDKCURL) && defined(SDKSENTRY)

#include <helpers/misc_helpers.h>

#include <sdksentry/vendored/sentry.h>
#include <sdkCURL/sdkCURL.h>
#include <helpers/steam_helpers.h>
#include <csignal>
#include <signal.h>

void SetSteamID();
void SentryMsg(const char* logger, const char* text, bool forcesend = false);
void SentryEvent(const char* level, const char* logger, const char* message, sentry_value_t ctx, bool forcesend = false);
// void sdk13_version_callback(IConVar* var, const char* pOldValue, float flOldValue);
void SentrySetTags();


class CSentry : public CAutoGameSystem
{
public:
    CSentry();

    std::atomic<bool>    didinit;
    std::atomic<bool>    didshutdown;
    std::atomic<bool>    crashed;
    volatile sig_atomic_t    sentryLogFilePtr;
    volatile sig_atomic_t    conFileFilePtr;

#ifdef _WIN32
    volatile sig_atomic_t    mainWindowHandle;
#endif

    // ptr to game paths that we set up in sentry init
    volatile char* gamePaths = nullptr;
    volatile size_t gamePathsSize = NULL;

    volatile char* cmdline = nullptr;

#ifdef _WIN32
    PVOID vec_handler_handle = nullptr;
#endif



    void                PostInit() override;
    void                Shutdown() override;
    void                LevelBreadcrumbs(const char* function)
    {
        SentrySetTags();
        char map[128];
        UTIL_GetMap(map);
        char funcmap[256] = {};
        if (map && map[0])
        {
            V_snprintf(funcmap, 255, "%s - map %s", function, map);
        }
        else
        {
            V_snprintf(funcmap, 255, "%s - map %s", function, "nada");
        }
        // sentry_set_transaction(funcmap);
        sentry_add_breadcrumb(sentry_value_new_breadcrumb(NULL, funcmap));
    }
    void LevelInitPreEntity()
    {
        LevelBreadcrumbs(__FUNCTION__);
    }
    void LevelInitPostEntity()
    {
        LevelBreadcrumbs(__FUNCTION__);
    }
    void LevelShutdownPreEntity()
    {
        LevelBreadcrumbs(__FUNCTION__);
    }
    void LevelShutdownPostEntity()
    {
        LevelBreadcrumbs(__FUNCTION__);
    }

    void                SentryInit();

    std::string real_sentry_url = {};

    static sentry_value_t nowCTX;
    static const char*    nowFUNC;

    std::stringstream   sentry_conlog;

    void                SentryURLCB(const curlResponse* curlRepsonseStruct);
};




void _SentryEventThreaded(const char* level, const char* logger, const char* message, sentry_value_t ctx, bool forcesend = false);
void _SentryMsgThreaded(const char* logger, const char* text, bool forcesend);

void SentryAddressBreadcrumb(void* address, const char* optionalName = NULL);

// it's so cool that valve cluelessly was like "oh lets just make functions that are named the same as wapi funcs thats smart and will never backfire"
#ifdef GetObject
#undef GetObject
#endif

#ifdef Yield
#undef Yield
#endif

#ifdef CompareString
#undef CompareString
#endif

#ifdef CreateEvent
#undef CreateEvent
#endif

#ifdef PostMessage
#undef PostMessage
#endif


#endif // defined(CLIENT_DLL) && defined(SDKCURL) && defined(SDKSENTRY)

#endif //SENTRY_H
