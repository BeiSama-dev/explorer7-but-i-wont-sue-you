#pragma once
#include "util.h"
#include "common.h"
#include "dbgprint.h"
#include "OptionConfig.h"
#include "OSVersion.h"
#include "TypeDefinitions.h"
#include "MinHook.h"
#include "NscTree.h"
#include <commctrl.h>


static bool IsStartMenuWindow(HWND hwnd, ATOM startMenuAtom)
{
	if (hwnd && GetClassWord(hwnd, GCW_ATOM) == startMenuAtom && GetProp(hwnd, L"StartMenuTag"))
	{
		hwnd_startmenu = hwnd;
		return true;
	}

	return false;
}

static bool IsStartMenuWindowOrChild(HWND hwnd)
{
	WNDCLASS dummy = { 0 };
	ATOM startMenuAtom = GetClassInfo(GetModuleHandle(NULL), L"DV2ControlHost", &dummy);
	if (!startMenuAtom)
		return false;

	for (HWND current = hwnd; current; current = GetParent(current))
	{
		if (IsStartMenuWindow(current, startMenuAtom))
			return true;
	}

	return IsStartMenuWindow(GetAncestor(hwnd, GA_ROOT), startMenuAtom) ||
		IsStartMenuWindow(GetAncestor(hwnd, GA_ROOTOWNER), startMenuAtom);
}

static bool IsShellThemeWindow(HWND hwnd)
{
	if (!hwnd)
		return false;

	HWND taskbar = GetTaskbarWnd();
	if (taskbar && (hwnd == taskbar || IsChild(taskbar, hwnd)))
		return true;

	if (IsStartMenuWindowOrChild(hwnd))
		return true;

	HWND startMenu = GetStartMenuWnd();
	if (startMenu && (hwnd == startMenu || IsChild(startMenu, hwnd)))
		return true;

	HWND thumbnail = GetThumbnailWnd();
	if (thumbnail && (hwnd == thumbnail || IsChild(thumbnail, hwnd)))
		return true;

	return false;
}

static DWORD g_dwStartMenuThemeThreadId = 0;
typedef HWND(WINAPI* CreateWindowExWAPI)(DWORD, LPCWSTR, LPCWSTR, DWORD, int, int, int, int, HWND, HMENU, HINSTANCE, LPVOID);
typedef DPI_AWARENESS_CONTEXT(WINAPI* SetThreadDpiAwarenessContextAPI)(DPI_AWARENESS_CONTEXT);

static CreateWindowExWAPI g_CreateWindowExWOrig = nullptr;
static SetThreadDpiAwarenessContextAPI g_SetThreadDpiAwarenessContext = nullptr;

static HWND WINAPI CreateWindowExW_WindowArrangementHook(DWORD dwExStyle, LPCWSTR lpClassName, LPCWSTR lpWindowName, DWORD dwStyle, int X, int Y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam)
{
	if (!lpClassName || IS_INTRESOURCE(lpClassName) || lstrcmpW(lpClassName, L"WindowManagementEvents") != 0)
		return g_CreateWindowExWOrig(dwExStyle, lpClassName, lpWindowName, dwStyle, X, Y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam);

	DPI_AWARENESS_CONTEXT oldDpiContext = g_SetThreadDpiAwarenessContext ? g_SetThreadDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE) : NULL;
	HWND hwnd = g_CreateWindowExWOrig(dwExStyle, lpClassName, lpWindowName, dwStyle, X, Y, nWidth, nHeight, HWND_MESSAGE, hMenu, hInstance, lpParam);
	if (oldDpiContext)
		g_SetThreadDpiAwarenessContext(oldDpiContext);
	return hwnd;
}

static void HookWindowManagementEventsCreation()
{
	HMODULE user32 = GetModuleHandle(L"user32.dll");
	if (!user32)
		return;

	g_SetThreadDpiAwarenessContext = reinterpret_cast<SetThreadDpiAwarenessContextAPI>(GetProcAddress(user32, "SetThreadDpiAwarenessContext"));
	g_CreateWindowExWOrig = reinterpret_cast<CreateWindowExWAPI>(GetProcAddress(user32, "CreateWindowExW"));
	if (g_CreateWindowExWOrig)
		MH_CreateHook(static_cast<LPVOID>(g_CreateWindowExWOrig), CreateWindowExW_WindowArrangementHook, reinterpret_cast<LPVOID*>(&g_CreateWindowExWOrig));
}

static bool ClassTokenEquals(LPCWSTR token, int tokenLen, LPCWSTR className)
{
	int classNameLen = lstrlenW(className);
	return tokenLen == classNameLen && StrCmpNIW(token, className, classNameLen) == 0;
}

static bool ClassTokenStartsWith(LPCWSTR token, int tokenLen, LPCWSTR prefix)
{
	int prefixLen = lstrlenW(prefix);
	return tokenLen >= prefixLen && StrCmpNIW(token, prefix, prefixLen) == 0;
}

static bool ClassTokenClassEquals(LPCWSTR token, int tokenLen, LPCWSTR className)
{
	LPCWSTR classPart = token;
	for (int i = 0; i + 1 < tokenLen; ++i)
	{
		if (token[i] == L':' && token[i + 1] == L':')
			classPart = token + i + 2;
	}

	return ClassTokenEquals(classPart, tokenLen - (int)(classPart - token), className);
}

static bool IsSystemThemeClass(LPCWSTR pszClassList)
{
	if (!pszClassList || !*pszClassList)
		return false;

	LPCWSTR token = pszClassList;
	while (*token)
	{
		LPCWSTR end = StrChrW(token, L';');
		int tokenLen = (int)(end ? end - token : lstrlenW(token));

		if (!end)
			break;

		token = end + 1;
	}

	return false;
}


static bool IsShellThemeClassToken(LPCWSTR token, int tokenLen)
{
	static const LPCWSTR allowedClasses[] =
	{
		L"StartMenuComposited::Link",
		L"StartMenuComposited::EmptyMarkup",
		// L"Explorer::ListView",
		L"StartMenu::ListView",
		L"StartMenuComposited::ListView",
		L"StartMenuCompositedMFU::ListView",
		L"StartMenuPlaceListComposited::ListView",
		L"TopMatch::ListView",
		L"TopMatchComposited::ListView",
		L"StartPanel",
		L"StartPanelPriv",
		L"StartPanelComposited::StartPanelPriv",
		L"StartPanelCompositedBottom::StartPanelPriv",
		L"TaskBand",
		L"TaskBar",
		L"TaskBarComposited::TaskBar",
		L"TaskBar2::TaskBar",
		L"TaskBar2Composited::TaskBar",
		L"TaskbarComposited::ComboBox",
		// L"Explorer::TreeView",
		L"StartMenuKeyBoard::TreeView",
		L"StartMenuKeyBoardComposited::TreeView",
		L"StartMenuHover::TreeView",
		L"StartMenuHoverComposited::TreeView",
		L"StartMenu::MenuBand",
		L"StartMenu::Toolbar",
		L"TaskBand2::ScrollBar",
		L"TaskBand2Composited::ScrollBar",
		L"TaskBand2",
		L"TaskBand2Vertical::Taskband2",
		L"TaskBand2SmallIcons::Taskband2",
		L"TaskBand2SmallIconsVertical::Taskband2",
		L"TaskBand2Composited::TaskBand2",
		L"TaskBand2CompositedSmallIcons::TaskBand2",
		L"TaskBand2CompositedVertical::TaskBand2",
		L"TaskBand2CompositedSmallIconsVertical::TaskBand2",
		L"TaskbandExtendedUI",
		L"Vertical::TaskbandExtendedUI",
		L"BasicMenuMode::TaskbandExtendedUI",
		L"Touch::TaskbandExtendedUI",
		//L"TrayNotifyFlyout", 10 Has it still.
		//L"Composited::TrayNotifyFlyout",
		L"TaskBar::Rebar",
		L"TaskBarComposited::Rebar",
		L"TaskBar::Toolbar",
		L"TaskBarComposited::Toolbar",
		L"TaskBarVert::Toolbar",
		L"TaskBarVertComposited::Toolbar",
		//L"TrayNotify::Clock",
		//L"TrayNotifyComposited::Clock",
		L"TrayNotify::Toolbar",
		L"TrayNotifyComposited::Toolbar",
		L"TrayNotifyHoriz::Button",
		L"TrayNotifyHorizComposited::Button",
		L"TrayNotifyHoriz::TrayNotify",
		L"TrayNotifyHorizComposited::TrayNotify",
		L"TrayNotifyHorizOpen::Button",
		L"TrayNotifyHorizOpenComposited::Button",
		L"TrayNotifyVert::Button",
		L"TrayNotifyVertComposited::Button",
		L"TrayNotifyVert::TrayNotify",
		L"TrayNotifyVertComposited::TrayNotify",
		L"TrayNotifyVertOpen::Button",
		L"TrayNotifyVertOpenComposited::Button",
		L"ShowDesktop::Button",
		L"VerticalShowDesktop::Button",
		//L"TrayNotify::UserTile", Not needed in Ex7 (There is no usertile)
		//L"TrayNotifyComposited::UserTile",
	};

	for (int i = 0; i < ARRAYSIZE(allowedClasses); ++i)
	{
		if (ClassTokenEquals(token, tokenLen, allowedClasses[i]))
			return true;
	}

	return ClassTokenStartsWith(token, tokenLen, L"StartMenu") ||
		ClassTokenStartsWith(token, tokenLen, L"StartPanel") ||
		ClassTokenStartsWith(token, tokenLen, L"TopMatch");
}

static bool IsShellThemeClass(LPCWSTR pszClassList)
{
	if (!pszClassList || !*pszClassList)
		return false;

	LPCWSTR token = pszClassList;
	while (*token)
	{
		LPCWSTR end = StrChrW(token, L';');
		int tokenLen = (int)(end ? end - token : lstrlenW(token));

		if (IsShellThemeClassToken(token, tokenLen))
			return true;

		if (!end)
			break;

		token = end + 1;
	}

	return false;
}

static bool IsNativeSearchThemeClassToken(LPCWSTR token, int tokenLen)
{
	static const LPCWSTR nativeClasses[] =
	{
		L"SearchBox",
		L"SearchBoxComposited::SearchBox",
		L"InactiveSearchBoxComposited::SearchBox",
		L"SearchEditBox",
		L"TaskBarComposited::Edit",
		L"SearchBoxEdit::Edit",
		L"SearchBoxEditComposited::Edit",
		L"MaxSearchBoxEdit::Edit",
		L"MaxSearchBoxEditComposited::Edit",
		L"InactiveSearchBoxEdit::Edit",
		L"InactiveSearchBoxEditComposited::Edit",
		L"MaxInactiveSearchBoxEdit::Edit",
		L"MaxInactiveSearchBoxEditComposited::Edit",
		L"SearchBox::SearchBoxComposited",
		L"SearchBox::MaxSearchBox",
		L"SearchBox::MaxSearchBoxComposited",
		L"SearchBox::InactiveSearchBox",
		L"SearchBox::InactiveSearchBoxComposited",
		L"SearchBox::MaxInactiveSearchBox",
		L"SearchBox::MaxInactiveSearchBoxComposited",
	};

	for (int i = 0; i < ARRAYSIZE(nativeClasses); ++i)
	{
		if (ClassTokenEquals(token, tokenLen, nativeClasses[i]))
			return true;
	}

	return false;
}

static bool IsNativeSearchThemeClass(LPCWSTR pszClassList)
{
	if (!pszClassList || !*pszClassList)
		return false;

	LPCWSTR token = pszClassList;
	while (*token)
	{
		LPCWSTR end = StrChrW(token, L';');
		int tokenLen = (int)(end ? end - token : lstrlenW(token));

		if (IsNativeSearchThemeClassToken(token, tokenLen))
			return true;

		if (!end)
			break;

		token = end + 1;
	}

	return false;
}


static bool IsStartMenuThemeClassToken(LPCWSTR token, int tokenLen)
{
	static const LPCWSTR allowedClasses[] =
	{
		L"StartMenuComposited::Link",
		L"StartMenuComposited::EmptyMarkup",
		//L"Explorer::ListView",
		L"StartMenu::ListView",
		L"StartMenuComposited::ListView",
		L"StartMenuCompositedMFU::ListView",
		L"StartMenuPlaceListComposited::ListView",
		L"TopMatch::ListView",
		L"TopMatchComposited::ListView",
		L"StartPanel",
		L"StartPanelPriv",
		L"StartPanelComposited::StartPanelPriv",
		L"StartPanelCompositedBottom::StartPanelPriv",
		//L"Explorer::TreeView",
		L"StartMenuKeyBoard::TreeView",
		L"StartMenuKeyBoardComposited::TreeView",
		L"StartMenuHover::TreeView",
		L"StartMenuHoverComposited::TreeView",
		L"StartMenu::MenuBand",
		L"StartMenu::Toolbar"
	};

	for (int i = 0; i < ARRAYSIZE(allowedClasses); ++i)
	{
		if (ClassTokenEquals(token, tokenLen, allowedClasses[i]))
			return true;
	}

	return false;
}

static bool IsStartMenuThemeClass(LPCWSTR pszClassList)
{
	if (!pszClassList || !*pszClassList)
		return false;

	LPCWSTR token = pszClassList;
	while (*token)
	{
		LPCWSTR end = StrChrW(token, L';');
		int tokenLen = (int)(end ? end - token : lstrlenW(token));

		if (IsStartMenuThemeClassToken(token, tokenLen))
			return true;

		if (!end)
			break;

		token = end + 1;
	}

	return false;
}

static bool IsStartMenuThemeThread()
{
	return g_dwStartMenuThemeThreadId == GetCurrentThreadId();
}

static void MaybeTrackStartMenuThemeThread(HWND hwnd, LPCWSTR pszClassList)
{
	if (IsStartMenuThemeThread())
		return;

	if (IsStartMenuWindowOrChild(hwnd) || IsStartMenuThemeClass(pszClassList))
		g_dwStartMenuThemeThreadId = GetCurrentThreadId();
}

static bool IsStartMenuThreadThemeClassToken(LPCWSTR token, int tokenLen)
{
	static const LPCWSTR allowedClasses[] =
	{
		//L"Button",
		//L"Edit",
		//L"EditComposited::Edit",
		//L"Link",
		L"Toolbar",
		L"ListView",
		//L"ScrollBar",
		L"StartMenuComposited::Link",
		L"StartMenuComposited::EmptyMarkup",
		L"StartMenu::ListView",
		L"StartMenuComposited::ListView",
		L"StartMenuCompositedMFU::ListView",
		L"StartMenuPlaceListComposited::ListView",
		L"TopMatch::ListView",
		L"TopMatchComposited::ListView",
		L"StartPanel",
		L"StartPanelPriv",
		L"StartPanelComposited::StartPanelPriv",
		L"StartPanelCompositedBottom::StartPanelPriv",
		L"StartMenuKeyBoard::TreeView",
		L"StartMenuKeyBoardComposited::TreeView",
		L"StartMenuHover::TreeView",
		L"StartMenuHoverComposited::TreeView",
		L"TreeView"
	};

	for (int i = 0; i < ARRAYSIZE(allowedClasses); ++i)
	{
		if (ClassTokenEquals(token, tokenLen, allowedClasses[i]))
			return true;
	}

	return false;
}

static bool IsStartMenuThreadThemeClass(LPCWSTR pszClassList)
{
	if (!pszClassList || !*pszClassList)
		return false;

	LPCWSTR token = pszClassList;
	while (*token)
	{
		LPCWSTR end = StrChrW(token, L';');
		int tokenLen = (int)(end ? end - token : lstrlenW(token));

		if (IsStartMenuThreadThemeClassToken(token, tokenLen))
			return true;

		if (!end)
			break;

		token = end + 1;
	}

	return false;
}

static bool ShouldOpenInactiveTheme(HWND hwnd, LPCWSTR pszClassList)
{
	if (!HasLoadedInactiveTheme())
		return false;

	if (IsSystemThemeClass(pszClassList))
		return false;

	if (IsNativeSearchThemeClass(pszClassList))
		return false;

	MaybeTrackStartMenuThemeThread(hwnd, pszClassList);

	if (hwnd)
		return IsShellThemeWindow(hwnd) || IsShellThemeClass(pszClassList) || (IsStartMenuThemeThread() && IsStartMenuThreadThemeClass(pszClassList));

	return IsShellThemeClass(pszClassList) || (IsStartMenuThemeThread() && IsStartMenuThreadThemeClass(pszClassList));
}

HTHEME __stdcall OpenThemeData_Hook(HWND hwnd, LPCWSTR pszClassList)
{
	bool useInactiveTheme = ShouldOpenInactiveTheme(hwnd, pszClassList);
	if (g_dwTrayThreadId > 0 && g_dwTrayThreadId != GetCurrentThreadId() && !useInactiveTheme)
		return fOpenThemeData(hwnd, pszClassList);

	if (IsClassicTheme())
		return NULL;

	DWORD flags = 2;
	if ((unsigned int)GetScreenDpi() != 96)
		flags |= 1u;

	HTHEME theme = useInactiveTheme ?
		OpenLoadedInactiveTheme(hwnd, pszClassList, flags) :
		fOpenThemeData(hwnd, pszClassList);
	if (theme == nullptr)
		dbgprintf(L"OPENTHEMEDATA FAILED %s", pszClassList);
	return theme;
}
HTHEME __stdcall OpenThemeDataForDpi_Hook(HWND hwnd, LPCWSTR pszClassList, UINT dpi)
{
	bool useInactiveTheme = ShouldOpenInactiveTheme(hwnd, pszClassList);
	if (g_dwTrayThreadId > 0 && g_dwTrayThreadId != GetCurrentThreadId() && !useInactiveTheme)
		return fOpenThemeDataForDpi(hwnd, pszClassList, dpi);

	if (IsClassicTheme())
		return NULL;

	useInactiveTheme = useInactiveTheme && (!pszClassList || lstrcmp(pszClassList, L"ItemsViewAccessible::Header") != 0);

	DWORD flags = 2;
	if (dpi != 96)
		flags |= 1u;

	HTHEME theme = useInactiveTheme ?
		OpenLoadedInactiveTheme(hwnd, pszClassList, flags) :
		fOpenThemeDataForDpi(hwnd, pszClassList, dpi);
	if (theme == nullptr)
		dbgprintf(L"OPENTHEMEDATAFORDPI FAILED %s", pszClassList);
	return theme;
}
HTHEME __stdcall OpenThemeDataEx_Hook(HWND hwnd, LPCWSTR pszClassList, DWORD dwFlags)
{
	bool useInactiveTheme = ShouldOpenInactiveTheme(hwnd, pszClassList);
	if (g_dwTrayThreadId > 0 && g_dwTrayThreadId != GetCurrentThreadId() && !useInactiveTheme)
		return fOpenThemeDataEx(hwnd, pszClassList, dwFlags);

	if (IsClassicTheme())
		return NULL;

	DWORD flags = 2;
	if ((unsigned int)GetScreenDpi() != 96)
		flags |= 1u;

	HTHEME theme = useInactiveTheme ?
		OpenLoadedInactiveTheme(hwnd, pszClassList, dwFlags | flags) :
		fOpenThemeDataEx(hwnd, pszClassList, dwFlags);
	if (theme == nullptr)
		dbgprintf(L"OPENTHEMEDATAEX FAILED %s", pszClassList);
	return theme;
}
void CPniMainDlg_ShowFlyoutNEW() // don't bother with the parameters as we aren't going to use them
{
	// Open Network and Sharing Center instead inside the Windows Control Panel, as a non-immersive alternative
	ShellExecuteW(nullptr, nullptr, L"control.exe", L"/name Microsoft.NetworkAndSharingCenter", nullptr, SW_SHOWNORMAL);

	// End function as we aren't going to do anything else here
	return;
}

void RenderThumbnail(PVOID This, int animoffset, int bNoRedraw)
{
	RECT rc = *(RECT*)((PBYTE)This + 0x68);
	HWND hwnd = *(HWND*)((PBYTE)This + 0x60);
	HTHEME hthem = *(HTHEME*)((PBYTE)This + 0x98);

	renderThumbnail_orig(This, animoffset, bNoRedraw);

	MARGINS mar;
	GetThemeMargins(hthem, NULL, 2, 0, TMT_CONTENTMARGINS, NULL, &mar);
	rc.left += mar.cxLeftWidth;
	rc.right -= mar.cxRightWidth;
	rc.top += mar.cyTopHeight;
	rc.bottom -= mar.cyBottomHeight;
	DwmpUpdateAccentBlurRect(hwnd, &rc);
}

HICON GetUWPIcon(HWND a2)
{
	HICON icon = NULL;
	IShellItemImageFactory* psiif = nullptr;
	IPropertyStore* ips;
	SHGetPropertyStoreForWindow(a2, IID_PPV_ARGS(&ips));
	GUID myGuid = { 0x9F4C2855, 0x9F79, 0x4B39, {0xA8, 0xD0, 0xE1, 0xD4, 0x2D, 0xE1, 0xD5, 0xF3} };
	PROPERTYKEY propertyKey = { myGuid, 5 };
	PROPVARIANT pv;
	ips->GetValue(propertyKey, &pv);
	if (pv.vt == VT_LPWSTR)
	{
		LPCWSTR aumid = pv.pwszVal;
		SHCreateItemInKnownFolder(FOLDERID_AppsFolder, KF_FLAG_DONT_VERIFY, aumid, IID_PPV_ARGS(&psiif));
		if (psiif)
		{
			SIIGBF flags = SIIGBF_ICONONLY;
			HBITMAP hb;
			SIZE size = { GetSystemMetrics(SM_CXICON), GetSystemMetrics(SM_CXICON) };
			HRESULT hr = psiif->GetImage(size, flags, &hb);
			if (SUCCEEDED(hr))
			{
				HIMAGELIST hImageList = ImageList_Create(size.cx, size.cy, ILC_COLOR32, 1, 0);
				if (ImageList_Add(hImageList, hb, NULL) != -1)
				{
					HICON hc = ImageList_GetIcon(hImageList, 0, 0);
					ImageList_Destroy(hImageList);

					// set
					icon = hc;

					DeleteObject(hb);
					psiif->Release();
				}
				DeleteObject(hb);
			}
			psiif->Release();
		}
	}
	ips->Release();
	return icon;
}

PVOID CTaskBandPtr = 0;

VOID CTaskBand_SetWindowIconHook(PVOID This, HWND a2, HICON a3, int a4)
{
	CTaskBandPtr = This;

	auto bIsImmersiveWnd = [](HWND hwnd) -> bool
		{
			return IsShellFrameWindow && IsShellFrameWindow(hwnd);
		};

	if (bIsImmersiveWnd(a2))
	{
		HICON icon = GetUWPIcon(a2);
		if (icon)
		{
			CTaskBand_SetWindowIconOrig(This, a2, icon, a4);
		}
	}
	else
	{
		CTaskBand_SetWindowIconOrig(This, a2, a3, a4);
	}
}

VOID UpdateItemIcon(PVOID This, int a2)
{
	typedef void* (__fastcall* GetTaskItemFunc)(void*);
	typedef HWND(__fastcall* GetWindowFunc)(void*);

	HDPA hdpaTaskThumbnails = *(HDPA*)((PBYTE)This + 0xB0);
	auto v4 = DPA_FastGetPtr(hdpaTaskThumbnails, a2);
	auto vtable = *(uintptr_t**)v4;
	GetTaskItemFunc GetTaskItem = (GetTaskItemFunc)vtable[0x60 / sizeof(uintptr_t)];
	void* v5 = GetTaskItem(v4);
	auto vtable_v5 = *(uintptr_t**)v5;
	GetWindowFunc GetWindow = (GetWindowFunc)vtable_v5[0x98 / sizeof(uintptr_t)];
	HWND v6 = GetWindow(v5);
	if (IsShellFrameWindow && IsShellFrameWindow(v6))
	{
		HICON hc = GetUWPIcon(v6);
		if (hc) SetIconThumb(This, hc, a2, 3);
	}
	else
		UpdateItem(This, a2);

}

// Ittr: Under immersive mode, the differences in ShellHook operation have to be accounted for
HRESULT(__fastcall* OnShellHookMessage)(void* a1);

static DWORD g_win11HotkeyInstallTick = 0;
static DWORD g_win11ShellHookInstallTick = 0;
static bool g_win11ShellHookSuppressedInitialOpen = false;

static HRESULT OpenStartFromImmersiveHotkey21H2()
{
    ULONG build = g_osVersion.BuildNumber();
    if (build < 22000 || build >= 22621)
        return E_FAIL;

    if (!g_win11ShellHookSuppressedInitialOpen && g_win11ShellHookInstallTick &&
        GetTickCount() - g_win11ShellHookInstallTick < 5000)
    {
        g_win11ShellHookSuppressedInitialOpen = true;
        dbgprintf(L"[WINKEY21H2] Suppressed initial shell hook notification");
        return E_FAIL;
    }

    HWND tray = GetTaskbarWnd();
    BOOL posted = tray && PostMessageW(tray, 0x504, 0, 0);
    dbgprintf(L"[WINKEY21H2] OnShellHookMessage tray=%p posted=%d", tray, posted);
    return posted ? S_OK : E_FAIL;
}

HRESULT __fastcall OnShellHookMessageOpenStart_Hook(void* This, unsigned __int64 shellHookMessage, __int64 shellHookData)
{
    (void)This;
    (void)shellHookMessage;
    (void)shellHookData;
    return OpenStartFromImmersiveHotkey21H2();
}
HRESULT __fastcall OnHotkeyInvokeOpenStart_Hook(void* This, int flags)
{
    (void)This;
    if (g_osVersion.BuildNumber() >= 22621 && g_win11HotkeyInstallTick && GetTickCount() - g_win11HotkeyInstallTick < 30000)
    {
        static bool suppressedInitialOpen = false;
        if (!suppressedInitialOpen)
        {
            suppressedInitialOpen = true;
            dbgprintf(L"[WINKEY] Suppressed initial hotkey notification");
            return E_FAIL;
        }
    }

    (void)flags;
    HWND tray = GetTaskbarWnd();
    BOOL posted = tray && PostMessageW(tray, 0x504, 0, 0);
    dbgprintf(L"[WINKEY] OnHotkeyInvoke tray=%p posted=%d", tray, posted);
    return posted ? S_OK : E_FAIL;
}

HRESULT __fastcall ShellHotkeyInvokeOpenStart_Hook(void* This, void* sender, int eventKind)
{
    (void)This;
    (void)sender;
    if (eventKind != 1)
        return S_OK;
    return OnHotkeyInvokeOpenStart_Hook(nullptr, eventKind);
}


bool fShowLauncher = false; // Ittr: First run erroneously shows the start menu, unless we handle it differently

HRESULT OnShellHookMessage_Hook(void* a1) // This gets called when start menu is to be opened - has been a bit temperamental
{
	// Use of fShowLauncher flag is essential to have something resembling stability for overall functionality
	if (fShowLauncher) // If the flag is set...
	{
		PostMessageW(hwnd_taskbar, 0x504, 0, 0); // Fire the message directly that opens Windows 7's start menu - ShellHook unreliable pre-VB
		return S_OK; // Ensure the run is recognised as a success 
	}
	else // However, without the flag, this is presumed to be the first run
	{
		fShowLauncher = true; // Enable the flag for showing the start menu now that this first attempt has run through
		return E_FAIL;  // Then, ensure this run is marked as a failure
	}

	return OnShellHookMessage(a1); // This codepath should ideally never run
}

void SetUpThemeManager()
{
	// Initialize the theme manager and declare the types for the UXTheme apis we're hooking
	ThemeManagerInitialize();

	fOpenThemeData = decltype(fOpenThemeData)(GetProcAddress(GetModuleHandle(L"uxtheme.dll"), "OpenThemeData"));
	fOpenThemeDataForDpi = decltype(fOpenThemeDataForDpi)(GetProcAddress(GetModuleHandle(L"uxtheme.dll"), "OpenThemeDataForDpi"));
	fOpenThemeDataEx = decltype(fOpenThemeDataEx)(GetProcAddress(GetModuleHandle(L"uxtheme.dll"), "OpenThemeDataEx"));

	// Hook UXTheme-related calls for the purpose of our inactive theme system.
	MH_CreateHook(static_cast<LPVOID>(fOpenThemeData), OpenThemeData_Hook, reinterpret_cast<LPVOID*>(&fOpenThemeData));
	MH_CreateHook(static_cast<LPVOID>(fOpenThemeDataForDpi), OpenThemeDataForDpi_Hook, reinterpret_cast<LPVOID*>(&fOpenThemeDataForDpi));
	MH_CreateHook(static_cast<LPVOID>(fOpenThemeDataEx), OpenThemeDataEx_Hook, reinterpret_cast<LPVOID*>(&fOpenThemeDataEx));
}

void FixNonImmersivePniDui()
{
	// Unable to do with patterns alone, as Microsoft removed HrOpenControlPanel
	if (!s_UseDCompFlyouts || !s_EnableImmersiveShellStack)
	{
		HMODULE pnidui = LoadLibrary(L"pnidui.dll");

		if (pnidui) // only run if DLL is present
		{
			void* _ShowFlyout = (void*)FindPattern((uintptr_t)LoadLibrary(L"pnidui.dll"), "48 89 6C 24 18 56 57 41 57 48 83 EC 60");

			if (_ShowFlyout) // first run, VB and later
			{
				MH_CreateHook(static_cast<LPVOID>(_ShowFlyout), CPniMainDlg_ShowFlyoutNEW, reinterpret_cast<LPVOID*>(&CPniMainDlg_ShowFlyout));
			}
			else
			{
				_ShowFlyout = (void*)FindPattern((uintptr_t)LoadLibrary(L"pnidui.dll"), "48 89 74 24 18 48 89 7C 24 20 41 56 48 83 EC 20 40 8A");

				if (_ShowFlyout) // second run, RS4 to TI
				{
					MH_CreateHook(static_cast<LPVOID>(_ShowFlyout), CPniMainDlg_ShowFlyoutNEW, reinterpret_cast<LPVOID*>(&CPniMainDlg_ShowFlyout));
				}
				else
				{
					_ShowFlyout = (void*)FindPattern((uintptr_t)LoadLibrary(L"pnidui.dll"), "48 89 6C 24 18 48 89 74 24 20 57 48 83 EC 20 40 8A FA");

					if (_ShowFlyout) // third run, TH2 to RS3
					{
						MH_CreateHook(static_cast<LPVOID>(_ShowFlyout), CPniMainDlg_ShowFlyoutNEW, reinterpret_cast<LPVOID*>(&CPniMainDlg_ShowFlyout));
					}
					else
					{
						_ShowFlyout = (void*)FindPattern((uintptr_t)LoadLibrary(L"pnidui.dll"), "48 8B C4 56 57 41 56 48 81 EC 80 01 00 00");

						if (_ShowFlyout) // fourth run, TH1
						{
							MH_CreateHook(static_cast<LPVOID>(_ShowFlyout), CPniMainDlg_ShowFlyoutNEW, reinterpret_cast<LPVOID*>(&CPniMainDlg_ShowFlyout));
						}
					}
				}
			}
		}
	}
}

void UpdateTrayWindowDefinitions()
{
	// Hook and update definitions of what windows should be added to the tray - largely for UWP purposes, but essentially zero-cost so included on both immersive on and off modes.
	void* _ShouldAddWindowToTray = (void*)FindPattern((uintptr_t)GetModuleHandle(0), "48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 48 8B F9 33 DB");
	void* _IsWindowNotDesktopOrTray = (void*)FindPattern((uintptr_t)GetModuleHandle(0), "48 89 5C 24 ?? 57 48 83 EC ?? 48 8B F9 33 DB FF 15 ?? ?? ?? ?? 3B C3 74 ?? 48 3B 3D");
	MH_CreateHook(static_cast<LPVOID>(_ShouldAddWindowToTray), ShouldAddWindowToTray, reinterpret_cast<LPVOID*>(&_ShouldAddWindowToTray));
	MH_CreateHook(static_cast<LPVOID>(_IsWindowNotDesktopOrTray), IsWindowNotDesktopOrTray, reinterpret_cast<LPVOID*>(&_IsWindowNotDesktopOrTray));
}

void SetProgramListNscTreeAttributes()
{
	CNSCHost_FillNSCOg = (decltype(CNSCHost_FillNSCOg))FindPattern((uintptr_t)GetModuleHandle(0), "48 89 5C 24 18 57 48 83 EC 30 33 DB 48 8B F9 39 99 CC 00 00 00");
	if (CNSCHost_FillNSCOg)
		MH_CreateHook(static_cast<LPVOID>(CNSCHost_FillNSCOg), CNSCHost_FillNSC, reinterpret_cast<LPVOID*>(&CNSCHost_FillNSCOg)); //this hook is in nsctree.h now
}

void HandleThumbnailColorization()
{
	// CTaskListThumbnailWnd::_Render
	// Thumbnail rendering fix for colorization modes
	char* CTaskListThumbnailWnd_Render = "48 8B C4 48 89 58 08 48 89 68 10 48 89 70 20 44 89 40 18 57 41 54 41 55 41 56 41 57 48 81 EC 90 00 00 00 48 8B F9";
	void* CTLWRPattern = (void*)FindPattern((uintptr_t)GetModuleHandle(NULL), CTaskListThumbnailWnd_Render);

	if (CTLWRPattern)
	{
		MH_CreateHook(static_cast<LPVOID>(CTLWRPattern), RenderThumbnail, reinterpret_cast<LPVOID*>(&renderThumbnail_orig));
	}
}

void RenderStoreAppsOnTaskbar()
{
	if (s_ShowStoreAppsOnTaskbar)
	{
		// Part 1: CTaskListThumbnailWnd::_SetIcon
		// Must be defined so that it can be called by our hook functions
		// However, we only assign the definition if we can actually detect it to begin with
		char* CTaskListThumbnailWnd_SetIcon = "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 49 63 D8 4C 8B 81 B0 00 00 00";
		setIconThumb_t CTLTWSIPattern = (setIconThumb_t)FindPattern((uintptr_t)GetModuleHandle(NULL), CTaskListThumbnailWnd_SetIcon);

		if (CTLTWSIPattern)
		{
			SetIconThumb = CTLTWSIPattern;
		}
		else
		{
			return;
		}

		// Part 2: CTaskBand::_SetWindowIcon 
		// Must be hooked accordingly so the icon can be overridden as necessary for the TaskItem buttons
		char* CTaskBand_SetWindowIcon = "FF F3 55 56 57 41 54 41 55 41 56 41 57 48 81 EC F8 06 00 00";
		void* CTBSWIPattern = (void*)FindPattern((uintptr_t)GetModuleHandle(NULL), CTaskBand_SetWindowIcon);

		if (CTBSWIPattern)
		{
			MH_CreateHook(static_cast<LPVOID>(CTBSWIPattern), CTaskBand_SetWindowIconHook, reinterpret_cast<LPVOID*>(&CTaskBand_SetWindowIconOrig));
		}

		// Part 3: CTaskListThumbnailWnd::_UpdateItemIcon
		// Hooking this function will allow the thumbnail icon to be updated as applicable
		char* CTaskListThumbnailWnd_UpdateItemIcon = "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 30 48 8B 81 B0 00 00 00";
		void* CTLTWUIIPattern = (void*)FindPattern((uintptr_t)GetModuleHandle(NULL), CTaskListThumbnailWnd_UpdateItemIcon);

		if (CTLTWUIIPattern)
		{
			MH_CreateHook(static_cast<LPVOID>(CTLTWUIIPattern), UpdateItemIcon, reinterpret_cast<LPVOID*>(&UpdateItem));
		}
	}
}

void CreateImmersiveShell()
{
	// NOTE: Some of the patch functions are in util.h rather than an imports header because they are used with several patch types
	////////////////////////////////
	// 1. Todo in future *after* feature-set is complete: see how many of these hooks can be ChangeImportedAddress instead of MH_CreateHook (perf optimisation)
	// 2. Code stack used exclusively for UWP mode, hence the conditional statement.
	if (s_EnableImmersiveShellStack == 1) // Run these hooks only if the user has UWP enabled
	{
		// 1. This will *need* serious optimization in the near future as it singlehandedly delays program enumeration and startup by several seconds
		// 2. Prepare the taskbar and thumbnails to handle UWP icons. Further work needed for jumplists and to prevent wrongful classification as "Application Frame Host" in the first place.

		// The rest of this code block is dedicated to ensuring UWP actually runs in the first place
		CreateWindowInBandOrig = decltype(CreateWindowInBandOrig)(GetProcAddress(GetModuleHandle(L"user32.dll"), "CreateWindowInBand"));
		CreateWindowInBandExOrig = decltype(CreateWindowInBandExOrig)(GetProcAddress(GetModuleHandle(L"user32.dll"), "CreateWindowInBandEx"));
		SetWindowBandApiOrg = decltype(SetWindowBandApiOrg)(GetProcAddress(GetModuleHandle(L"user32.dll"), "SetWindowBand"));
		RegisterHotKeyApiOrg = decltype(RegisterHotKeyApiOrg)(GetProcAddress(GetModuleHandle(L"user32.dll"), "RegisterHotKey"));

		MH_CreateHook(static_cast<LPVOID>(CreateWindowInBandOrig), CreateWindowInBandNew, reinterpret_cast<LPVOID*>(&CreateWindowInBandOrig));
		MH_CreateHook(static_cast<LPVOID>(CreateWindowInBandExOrig), CreateWindowInBandExNew, reinterpret_cast<LPVOID*>(&CreateWindowInBandExOrig));
		MH_CreateHook(static_cast<LPVOID>(SetWindowBandApiOrg), SetWindowBandNew, reinterpret_cast<LPVOID*>(&SetWindowBandApiOrg));
		MH_CreateHook(static_cast<LPVOID>(RegisterHotKeyApiOrg), RegisterWindowHotkeyNew, reinterpret_cast<LPVOID*>(&RegisterHotKeyApiOrg));

		MH_CreateHook(GetProcAddress(GetModuleHandle(L"user32.dll"), (LPCSTR)2581), RetTrue, NULL); // GetWindowTrackInfoAsync
		MH_CreateHook(GetProcAddress(GetModuleHandle(L"user32.dll"), (LPCSTR)2563), RetTrue, NULL); // ClearForeground
		MH_CreateHook(GetProcAddress(GetModuleHandle(L"user32.dll"), (LPCSTR)2628), RetTrue, NULL); // CreateWindowGroup
		MH_CreateHook(GetProcAddress(GetModuleHandle(L"user32.dll"), (LPCSTR)2629), RetTrue, NULL); // DeleteWindowGroup
		MH_CreateHook(GetProcAddress(GetModuleHandle(L"user32.dll"), (LPCSTR)2631), RetTrue, NULL); // EnableWindowGroupPolicy
		MH_CreateHook(GetProcAddress(GetModuleHandle(L"user32.dll"), (LPCSTR)2627), RetTrue, NULL); // SetBridgeWindowChild
		MH_CreateHook(GetProcAddress(GetModuleHandle(L"user32.dll"), (LPCSTR)2511), RetTrue, NULL); // SetFallbackForeground
		if (g_osVersion.BuildNumber() < 26100)
		{
			MH_CreateHook(GetProcAddress(GetModuleHandle(L"user32.dll"), (LPCSTR)2566), RetTrue, NULL); // SetWindowArrangement
			MH_CreateHook(GetProcAddress(GetModuleHandle(L"user32.dll"), (LPCSTR)2564), RetTrue, NULL); // RegisterWindowArrangementCallout
			MH_CreateHook(GetProcAddress(GetModuleHandle(L"user32.dll"), (LPCSTR)2567), RetTrue, NULL); // EnableShellWindowManagementBehavior
		}
		MH_CreateHook(GetProcAddress(GetModuleHandle(L"user32.dll"), (LPCSTR)2632), RetTrue, NULL); // SetWindowGroup
		MH_CreateHook(GetProcAddress(GetModuleHandle(L"user32.dll"), (LPCSTR)2579), RetTrue, NULL); // SetWindowShowState
		MH_CreateHook(GetProcAddress(GetModuleHandle(L"user32.dll"), (LPCSTR)2585), RetTrue, NULL); // UpdateWindowTrackingInfo
		MH_CreateHook(GetProcAddress(GetModuleHandle(L"user32.dll"), (LPCSTR)2514), RetTrue, NULL); // RegisterEdgy
		MH_CreateHook(GetProcAddress(GetModuleHandle(L"user32.dll"), (LPCSTR)2542), RetTrue, NULL); // RegisterShellPTPListener
		MH_CreateHook(GetProcAddress(GetModuleHandle(L"user32.dll"), (LPCSTR)2537), RetTrue, NULL); // SendEventMessage
		MH_CreateHook(GetProcAddress(GetModuleHandle(L"user32.dll"), (LPCSTR)2513), RetTrue, NULL); // SetActiveProcessForMonitor
	}

}
void _OnHShellTaskMan()
{
	if (s_EnableImmersiveShellStack == 1)
	{
		// Here we account for the immersive shell's destructive impacts upon certain internal mechanisms of explorer

		// Work out what we need for different Windows 10 versions
		char* XamlLauncher_OnShellHookMessage;
		char* XLOSHMPattern;

		// Check whether the modern DLL exists in Windows
		HMODULE twinUI_PCShell = LoadLibrary(L"twinui.pcshell.dll");
		if (twinUI_PCShell) // If it does...
		{
			if (g_osVersion.BuildNumber() >= 22621)
			{
				if (!g_win11HotkeyInstallTick)
					g_win11HotkeyInstallTick = GetTickCount();

                char* pattern = (char*)FindPattern((uintptr_t)twinUI_PCShell, "48 89 5C 24 10 57 48 83 EC 40 8B FA 48 8B D9 48 8B 89 78 01 00 00 48 85 C9 75 0A");
                if (!pattern)
                    pattern = (char*)FindPattern((uintptr_t)twinUI_PCShell, "48 89 5C 24 08 57 48 83 EC 20 8B FA 48 8B D9 48 8B 89 88 01 00 00 48 85 C9 74 ?? 48 8B 01");
                if (pattern)
                {
                    MH_STATUS status = MH_CreateHook((LPVOID)pattern, OnHotkeyInvokeOpenStart_Hook, NULL);
                    dbgprintf(L"[WINKEY] Install OnHotkeyInvoke target=%p status=%d", pattern, status);
                }
                pattern = (char*)FindPattern((uintptr_t)twinUI_PCShell, "48 83 EC 28 48 8B 49 10 33 C0 41 83 F8 01 BA 08 00 00 00 0F 45 D0 E8 ?? ?? ?? ?? 33 C0 48 83 C4 28 C3");
                if (pattern)
                {
                    MH_STATUS status = MH_CreateHook((LPVOID)pattern, ShellHotkeyInvokeOpenStart_Hook, NULL);
                    dbgprintf(L"[WINKEY] Install ShellHotkeyInvoke target=%p status=%d", pattern, status);
                }
				return;
			}


						if (g_osVersion.BuildNumber() >= 22000 && g_osVersion.BuildNumber() < 22621)
			{
				if (!g_win11ShellHookInstallTick)
					g_win11ShellHookInstallTick = GetTickCount();

				char* pattern = (char*)FindPattern((uintptr_t)twinUI_PCShell,
                    "48 89 5C 24 08 57 48 83 EC 20 48 8B D9 48 8B 89 30 01 00 00 48 85 C9 74 76 48 8B 01");
                if (!pattern)
                {
                    pattern = (char*)FindPattern((uintptr_t)twinUI_PCShell,
                        "48 89 5C 24 08 57 48 83 EC 20 48 8B D9 48 8B 89 ?? ?? 00 00 48 85 C9 74 ?? 48 8B 01");
                }
                if (pattern)
				{
					MH_STATUS status = MH_CreateHook((LPVOID)pattern, OnShellHookMessageOpenStart_Hook, NULL);
					dbgprintf(L"[WINKEY21H2] Install OnShellHookMessage target=%p status=%d", pattern, status);
				}
				else
				{
					dbgprintf(L"[WINKEY21H2] OnShellHookMessage pattern not found");
				}
				return;
			}
XamlLauncher_OnShellHookMessage = "40 53 48 83 EC 20 48 8B D9 48 8B 89 ?? ?? ?? ?? 48 85 C9 74 ?? 48 8B 01 48 8B 40 ?? FF 15 ?? ?? ?? ?? 84 C0 0F 85 ?? ?? ?? ?? 38 83";
			XLOSHMPattern = (char*)FindPattern((uintptr_t)twinUI_PCShell, XamlLauncher_OnShellHookMessage);

			if (XLOSHMPattern) // VB
			{
				MH_CreateHook(static_cast<LPVOID>(XLOSHMPattern), OnShellHookMessage_Hook, reinterpret_cast<LPVOID*>(&XLOSHMPattern));
			}
			else
			{
				XamlLauncher_OnShellHookMessage = "40 53 48 83 EC 20 48 8B D9 48 8B 89 ?? ?? ?? ?? 48 85 C9 74 4E 48 8B 01";
				XLOSHMPattern = (char*)FindPattern((uintptr_t)twinUI_PCShell, XamlLauncher_OnShellHookMessage);

				if (XLOSHMPattern) // RS5, 19H1
				{
					MH_CreateHook(static_cast<LPVOID>(XLOSHMPattern), OnShellHookMessage_Hook, reinterpret_cast<LPVOID*>(&XLOSHMPattern));
				}
				else
				{
					XamlLauncher_OnShellHookMessage = "40 53 48 83 EC 20 48 8B D9 48 8B 89 ?? ?? ?? ?? 48 85 C9 74 59 48 8B 01"; // 0x59 cannot be wildcarded
					XLOSHMPattern = (char*)FindPattern((uintptr_t)twinUI_PCShell, XamlLauncher_OnShellHookMessage);

					if (XLOSHMPattern) // RS4
					{
						MH_CreateHook(static_cast<LPVOID>(XLOSHMPattern), OnShellHookMessage_Hook, reinterpret_cast<LPVOID*>(&XLOSHMPattern));
					}
					else
					{
						XamlLauncher_OnShellHookMessage = "48 89 5C 24 10 57 48 83 EC 30 48 8B D9 48 8B 89 ?? ?? ?? ?? 48 85 C9 75 0A";
						XLOSHMPattern = (char*)FindPattern((uintptr_t)twinUI_PCShell, XamlLauncher_OnShellHookMessage);

						if (XLOSHMPattern) // RS3
						{
							MH_CreateHook(static_cast<LPVOID>(XLOSHMPattern), OnShellHookMessage_Hook, reinterpret_cast<LPVOID*>(&XLOSHMPattern));
						}
						else
						{
							XamlLauncher_OnShellHookMessage = "40 53 48 83 EC 20 48 8B D9 48 8B 89 ?? ?? ?? ?? 48 85 C9 75 07 B8 90 04 07 80 EB 6F 48 8B 01";
							XLOSHMPattern = (char*)FindPattern((uintptr_t)twinUI_PCShell, XamlLauncher_OnShellHookMessage);

							if (XLOSHMPattern) // RS2
							{
								MH_CreateHook(static_cast<LPVOID>(XLOSHMPattern), OnShellHookMessage_Hook, reinterpret_cast<LPVOID*>(&XLOSHMPattern));
							}
							else
							{
								goto _OnHShellTaskMan_TWINUI; // New DLL exists on RS1 but unused for these purposes. Fall back to twinui.dll
							}
						}
					}
				}
			}
		}
		else // RS1 and earlier
		{
_OnHShellTaskMan_TWINUI:
			HMODULE twinui = LoadLibrary(L"twinui.dll");

			if (twinui) // This should always exist, but we check in case it doesn't
			{
				XamlLauncher_OnShellHookMessage = "40 53 48 83 EC 20 48 8B D9 48 8B 89 ?? ?? ?? ?? 48 85 C9 ?? ?? ?? ?? ?? ?? 48 8B 01";
				XLOSHMPattern = (char*)FindPattern((uintptr_t)twinui, XamlLauncher_OnShellHookMessage);

				if (XLOSHMPattern) // RS1
				{
					MH_CreateHook(static_cast<LPVOID>(XLOSHMPattern), OnShellHookMessage_Hook, reinterpret_cast<LPVOID*>(&XLOSHMPattern));
				}
				else
				{
					XamlLauncher_OnShellHookMessage = "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 48 8B B9 ?? ?? ?? ?? 48 8B D9 48 85 FF ?? ?? ?? ?? ?? ?? 48 8B 07";
					XLOSHMPattern = (char*)FindPattern((uintptr_t)twinui, XamlLauncher_OnShellHookMessage);

					if (XLOSHMPattern) // TH2
					{
						MH_CreateHook(static_cast<LPVOID>(XLOSHMPattern), OnShellHookMessage_Hook, reinterpret_cast<LPVOID*>(&XLOSHMPattern));
					}
					else
					{
						XamlLauncher_OnShellHookMessage = "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 48 8B B9 ?? ?? ?? ?? 48 8B D9 48 85 FF 74 62";
						XLOSHMPattern = (char*)FindPattern((uintptr_t)twinui, XamlLauncher_OnShellHookMessage);

						if (XLOSHMPattern) // TH1
						{
							MH_CreateHook(static_cast<LPVOID>(XLOSHMPattern), OnShellHookMessage_Hook, reinterpret_cast<LPVOID*>(&XLOSHMPattern));
						}
					}
				}
			}
		}
	}
}
static bool HasAllowConsentToStealFocus(HWND hwnd)
{
	if (!hwnd)
		return false;

	return GetPropW(hwnd, L"AllowConsentToStealFocus") != NULL;
}

static bool ShouldForceDialogForeground(HWND hwnd)
{
	if (!hwnd)
		return false;

	if (HasAllowConsentToStealFocus(hwnd))
		return true;

	HWND root = GetAncestor(hwnd, GA_ROOT);
	if (root != hwnd && HasAllowConsentToStealFocus(root))
		return true;

	HWND rootOwner = GetAncestor(hwnd, GA_ROOTOWNER);
	return rootOwner != hwnd && HasAllowConsentToStealFocus(rootOwner);
}

static decltype(&MessageBoxW) MessageBoxW_Orig = NULL;

int WINAPI MessageBoxW_Hook(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType)
{
	if (ShouldForceDialogForeground(hWnd))
		uType |= MB_SETFOREGROUND;

	return MessageBoxW_Orig(hWnd, lpText, lpCaption, uType);
}

struct TaskDialogHookContext
{
	PFTASKDIALOGCALLBACK callback;
	LONG_PTR callbackData;
	bool forceForeground;
};

static HRESULT CALLBACK TaskDialogIndirectCallbackHook(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam, LONG_PTR lpRefData)
{
	TaskDialogHookContext* context = reinterpret_cast<TaskDialogHookContext*>(lpRefData);

	if (context && context->forceForeground && msg == TDN_CREATED)
	{
		SetForegroundWindow(hwnd);
		SetActiveWindow(hwnd);
	}

	if (context && context->callback)
		return context->callback(hwnd, msg, wParam, lParam, context->callbackData);

	return S_OK;
}

static decltype(&TaskDialogIndirect) TaskDialogIndirect_Orig = NULL;

HRESULT WINAPI TaskDialogIndirect_Hook(const TASKDIALOGCONFIG* pTaskConfig, int* pnButton, int* pnRadioButton, BOOL* pfVerificationFlagChecked)
{
	if (!pTaskConfig)
		return TaskDialogIndirect_Orig(pTaskConfig, pnButton, pnRadioButton, pfVerificationFlagChecked);

	TASKDIALOGCONFIG config = *pTaskConfig;
	TaskDialogHookContext context =
	{
		config.pfCallback,
		config.lpCallbackData,
		ShouldForceDialogForeground(config.hwndParent)
	};

	if (context.forceForeground || context.callback)
	{
		config.pfCallback = TaskDialogIndirectCallbackHook;
		config.lpCallbackData = reinterpret_cast<LONG_PTR>(&context);
	}

	return TaskDialogIndirect_Orig(&config, pnButton, pnRadioButton, pfVerificationFlagChecked);
}

void HookDialogForeground()
{
	HMODULE user32 = GetModuleHandleW(L"user32.dll");
	if (user32)
	{
		MessageBoxW_Orig = decltype(MessageBoxW_Orig)(GetProcAddress(user32, "MessageBoxW"));
		if (MessageBoxW_Orig)
			MH_CreateHook(static_cast<LPVOID>(MessageBoxW_Orig), MessageBoxW_Hook, reinterpret_cast<LPVOID*>(&MessageBoxW_Orig));
	}

	HMODULE comctl32 = LoadLibraryW(L"comctl32.dll");
	if (comctl32)
	{
		TaskDialogIndirect_Orig = decltype(TaskDialogIndirect_Orig)(GetProcAddress(comctl32, "TaskDialogIndirect"));
		if (TaskDialogIndirect_Orig)
			MH_CreateHook(static_cast<LPVOID>(TaskDialogIndirect_Orig), TaskDialogIndirect_Hook, reinterpret_cast<LPVOID*>(&TaskDialogIndirect_Orig));
	}
}

void ChangeMinhookImports()
{
	MH_Initialize();

	HookDialogForeground(); // Ensure Run error dialogs come to the foreground
	SetUpThemeManager(); // Local visual style management init
	FixNonImmersivePniDui(); // Non-immersive network flyout handling
	UpdateTrayWindowDefinitions(); // Ensure tray exclusion is corrected for modern Windows
	SetProgramListNscTreeAttributes(); // Restore the relevant contents to the program list
	HandleThumbnailColorization(); // Thumbnail colorization to match
	RenderStoreAppsOnTaskbar(); // UWP icon rendering for the taskbar
	CreateImmersiveShell(); // Immersive shell initialisation
	if (g_osVersion.BuildNumber() >= 26100)
		HookWindowManagementEventsCreation(); // Snap/window arrangement compatibility on 24H2+
	_OnHShellTaskMan(); // Handling the immersive shell's impacts on the holographic shell and associated ShellHook messages
}
