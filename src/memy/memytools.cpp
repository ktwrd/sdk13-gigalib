#include <cbase.h>

#include <memy/memytools.h>
#include <helpers/misc_helpers.h>
#include <engine_memutils.h>
// #define memydbg yep

// shared between client and server
modbin* engine_bin          = new modbin();
modbin* server_bin          = new modbin();
modbin* tier0_bin           = new modbin();

// client only
#ifdef CLIENT_DLL
    modbin* vgui_bin        = new modbin();
    modbin* client_bin      = new modbin();
    modbin* gameui_bin      = new modbin();
    modbin* shaderapi_bin   = new modbin();
#endif


char bins_list[][MAX_PATH] =
{
    {},             // engine
    {},             // server
    {},             // tier0
#ifdef CLIENT_DLL
    {},             // vgui
    {},             // client
    {},             // gameui
    {},             // shaderapi
#endif
};

modbin* modbins_list[]
{
    engine_bin,
    server_bin,
    tier0_bin,
#ifdef CLIENT_DLL
    vgui_bin,
    client_bin,
    gameui_bin,
    shaderapi_bin,
#endif
};

memy _memy;
memy::memy()
{
    V_strncpy(bins_list[0], FORCE_OBFUSCATE("engine"),         32);
    V_strncpy(bins_list[1], FORCE_OBFUSCATE("server"),         32);
    V_strncpy(bins_list[2], FORCE_OBFUSCATE("tier0"),          32);
#ifdef CLIENT_DLL
    V_strncpy(bins_list[3], FORCE_OBFUSCATE("vguimatsurface"), 32);
    V_strncpy(bins_list[4], FORCE_OBFUSCATE("client"),         32);
    V_strncpy(bins_list[5], FORCE_OBFUSCATE("GameUI"),         32);
    V_strncpy(bins_list[6], FORCE_OBFUSCATE("shaderapidx9"),   32);
#endif
}

#ifdef SDKCURL
#include <sdkCURL/sdkCURL.h>
#endif

bool memy::Init()
{
    InitAllBins();
#ifdef SDKCURL
    new sdkCURL;
#endif

    return true;
}


bool memy::InitAllBins()
{
    // memy();
    size_t sbin_size = sizeof(bins_list) / sizeof(bins_list[0]);

    // loop thru our bins
    for (size_t ibin = 0; ibin < sbin_size; ibin++)
    {
        if (!InitSingleBin(bins_list[ibin], modbins_list[ibin]))
        {
            Error("[MEMY] Couldn't init %s!", bins_list[ibin]);
        }
    }

#ifdef CLIENT_DLL
    char* clipath = client_bin->binpath;
    V_StripFilename(clipath);
    V_StripLastDir(clipath, MAX_PATH);
    V_StripTrailingSlash(clipath);

    ConVarRef modpath = ConVarRef("_modpath", false);
    if (modpath.IsValid())
    {
        modpath.SetValue(clipath);
    }
    else
    {
        Error("Failed getting mod path!");
    }

#endif

    char* engpath = engine_bin->binpath;
    V_StripFilename(engpath);
    V_StripLastDir(engpath, MAX_PATH);
    V_StripTrailingSlash(engpath);

#if defined (CLIENT_DLL)
    ConVarRef sdkpath = ConVarRef("_sdkpath_cli", false);
#elif defined (GAME_DLL)
    ConVarRef sdkpath = ConVarRef("_sdkpath_srv", false);
#endif
    if (sdkpath.IsValid())
    {
        sdkpath.SetValue(engpath);
    }
    else
    {
        Error("Failed getting SDK2013 path!");
    }

    initEngineSpew();
    return true;
}

bool memy::InitSingleBin(const char* binname, modbin* mbin)
{
    // binname + .dll
    char realbinname[256] = {};

    #ifdef _WIN32
        V_snprintf(realbinname, sizeof(realbinname), "%s.dll", binname);

        HMODULE mhandle;
        mhandle = GetModuleHandleA(realbinname);
        if (!mhandle)
        {
            Error("[MEMY] Couldn't init %s!\n", realbinname);
            return false;
        }

        MODULEINFO minfo;

        GetModuleInformation(GetCurrentProcess(), mhandle, &minfo, sizeof(minfo));

        mbin->addr = reinterpret_cast<uintptr_t>(minfo.lpBaseOfDll);
        mbin->size = minfo.SizeOfImage;
        mbin->end  = mbin->addr + mbin->size;
        GetModuleFileNameA(mhandle, mbin->binpath, MAX_PATH);

        if (!mbin->addr || !mbin->size || !mbin->binpath)
        {
            Error("[MEMY] Couldn't init %s; addr = %x, size = %i, path = %p!\n", realbinname, mbin->addr, mbin->size, mbin->binpath);

            return false;
        }
        #ifdef memydbg
            Warning("memy::InitSingleBin -> name %s, mbase %x, msize %i, path = %s\n", realbinname, mbin->addr, mbin->size, mbin->binpath);
        #endif

    #else
        // binname + .so

        // funny special cases
        if (strcmp(binname, "engine") == 0)
        {
            // client only
            #ifdef CLIENT_DLL
                V_snprintf(realbinname, sizeof(realbinname), "%s.so", binname);
            // server only
            #else
                if (engine->IsDedicatedServer())
                {
                    V_snprintf(realbinname, sizeof(realbinname), "%s_srv.so", binname);
                }
                else
                {
                    V_snprintf(realbinname, sizeof(realbinname), "%s.so", binname);
                }
            #endif
        }
        // linux loads libtier0.so and libtier0_srv.so, and they are different. Yay!
        else if (strcmp(binname, "tier0") == 0)
        {
            // client only
            #ifdef CLIENT_DLL
                V_snprintf(realbinname, sizeof(realbinname), "lib%s.so", binname);
            // server only
            #else
                if (engine->IsDedicatedServer())
                {
                    V_snprintf(realbinname, sizeof(realbinname), "lib%s_srv.so", binname);
                }
                else
                {
                    V_snprintf(realbinname, sizeof(realbinname), "lib%s.so", binname);
                }
            #endif
        }
        else
        {
            V_snprintf(realbinname, sizeof(realbinname), "%s.so", binname);
        }

        void*          mbase = nullptr;
        size_t         msize = 0;
        char path[MAX_PATH]  = {};
        if (GetModuleInformation(realbinname, &mbase, &msize, path))
        {
            Error("memy::InitSingleBin -> GetModuleInformation failed for %s!\n", realbinname);
            return false;
        }

        mbin->addr      = reinterpret_cast<uintptr_t>(mbase);
        mbin->size      = msize;
		mbin->end       = mbin->addr + mbin->size;

        V_strncpy(mbin->binpath, path, MAX_PATH);

        #ifdef memydbg
            Warning("memy::InitSingleBin -> name %s, mbase %x, msize %i, path = %s\n", realbinname, mbin->addr, mbin->size, mbin->binpath);
        #endif

    #endif

    return true;
}

//---------------------------------------------------------------------------------------------------------
// Finds a pattern of bytes in the engine memory given a signature
// Returns the address of the first (and hopefully only) match with an optional offset, otherwise nullptr
// Copied from https://cs.alliedmods.net/sourcemod/source/core/logic/MemoryUtils.cpp#79 because it's faster than anything I've come up with yet
//---------------------------------------------------------------------------------------------------------    
uintptr_t memy::FindPattern(const uintptr_t startaddr, const size_t searchsize, const char* pattern, const size_t sigsize, const size_t offset)
{
    char* ptr   = (char*)startaddr;
    char* end   = (ptr + searchsize) - sigsize;

    bool found;
    while (ptr < end)
    {
        found = true;
        for (size_t i = 0; i < sigsize; i++)
        {
            if (pattern[i] != '\x2A' && pattern[i] != ptr[i])
            {
                found = false;
                break;
            }
        }

        // Translate the found offset into the actual live binary memory space.
        if (found)
        {
            return static_cast<uintptr_t>( (uintptr_t)ptr + offset );
            break;
        }

        ptr++;
    }

    return NULL;
}

// getting the old protection only works on windows...
bool memy::SetMemoryProtection(void* addr, size_t protlen, int wantprot, int* oldprotection)
{
    *oldprotection = 0;
#ifdef _WIN32
    // VirtualProtect requires a valid pointer to store the old protection value
    DWORD prot;
    
    switch (wantprot)
    {
        case (MEM_READ):
        {
            prot = PAGE_READONLY;
            break;
        }
        case (MEM_READ | MEM_WRITE):
        {
            prot = PAGE_READWRITE;
            break;
        }
        case (MEM_READ | MEM_EXEC):
        {
            prot = PAGE_EXECUTE_READ;
            break;
        }
        case (MEM_READ | MEM_WRITE | MEM_EXEC):
        default:
        {
            prot = PAGE_EXECUTE_READWRITE;
            break;
        }
    }
    
    // BOOL is typedef'd as an int on Windows, sometimes (lol), bang bang it to convert it to a bool proper
    return !!(VirtualProtect(addr, protlen, prot, (PDWORD)oldprotection));
#else
    // POSIX - i do not care enough to scrape proc self maps again just for every instance of this operation
    return !(mprotect(LALIGN(addr), protlen + LALDIF(addr), wantprot));
#endif
}


#if defined (POSIX)
//returns 0 if successful
int memy::GetModuleInformation(const char *name, void **base, size_t *length, char path[MAX_PATH])
{
    // this is the only way to do this on linux, lol
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f)
    {
        Warning("memy::GetModInfo -> Couldn't get proc->self->maps\n");
        return 1;
    }

    char buf[PATH_MAX+100];
    while (!feof(f))
    {
        if (!fgets(buf, sizeof(buf), f))
            break;

        char *tmp = strrchr(buf, '\n');
        if (tmp)
            *tmp = '\0';

        char *mapname = strchr(buf, '/');
        if (!mapname)
            continue;

        char perm[5];
        unsigned long begin, end;
        sscanf(buf, "%lx-%lx %4s", &begin, &end, perm);

        if (strcmp(basename(mapname), name) == 0 && perm[0] == 'r' && perm[2] == 'x')
        {
            #ifdef memydbg
                Warning("perm = %s\n", perm);
            #endif
            *base = (void*)begin;
            *length = (size_t)end-begin;
            V_strncpy(path, mapname, MAX_PATH);
            fclose(f);
            return 0;
        }
    }

    fclose(f);
    Warning("memy::GetModInfo -> Couldn't find info for modname %s\n", name);
    return 2;
}
#endif
