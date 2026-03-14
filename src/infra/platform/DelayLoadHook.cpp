// Custom delay-load failure hook for Windows.
//
// PcapPlusPlus links against npcap SDK (via Conan) but CI uses WinPcap
// runtime which lacks npcap-specific exports. This hook intercepts
// delay-load failures for missing functions and returns a stub that
// returns an error value, instead of throwing an SEH exception.
//
// This allows standard pcap functions (pcap_open_offline, pcap_next_ex)
// to work via WinPcap while npcap-only functions fail gracefully.

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <delayimp.h>

#pragma comment(lib, "delayimp.lib")

namespace {

// Stub function returned for missing pcap exports.
// Returns -1 (error) for any call — callers should check return values.
FARPROC WINAPI stubFunction() { return reinterpret_cast<FARPROC>(-1); }

// Delay-load failure hook: called when a function cannot be resolved.
FARPROC WINAPI delayLoadFailureHook(unsigned dliNotify,
                                    PDelayLoadInfo /*pdli*/) {
  if (dliNotify == dliFailGetProc) {
    // A specific function was not found in the DLL.
    // Return a stub instead of crashing.
    return reinterpret_cast<FARPROC>(stubFunction);
  }
  // For dliFailLoadLib (DLL not found at all), return nullptr to let
  // the default handler raise the exception.
  return nullptr;
}

} // namespace

// Register the hook with the MSVC delay-load infrastructure.
extern "C" const PfnDliHook __pfnDliFailureHook2 = delayLoadFailureHook;

#endif // _WIN32
