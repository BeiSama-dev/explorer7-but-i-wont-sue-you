#include "PinnedList.h"
#include "dbgprint.h"
#include "OSVersion.h"

static bool IsTaskbarModifyCaller(PINNEDLISTMODIFYCALLER caller)
{
	return caller == PMC_TASKBANDPIN
		|| caller == PMC_TASKBANDPINGROUP
		|| caller == PMC_TASKBARPINNABLESURFACEBROKER
		|| caller == PMC_TASKBARPINNABLESURFACEBROKERMIGRATION
		|| caller == PMC_TASKBARPINNINGBROKERFACTORY;
}

static uintptr_t ResolveRelativeCallTarget(uintptr_t callInstruction)
{
	if (!callInstruction || *reinterpret_cast<unsigned char*>(callInstruction) != 0xE8)
		return 0;

	return callInstruction + 5 + *reinterpret_cast<int*>(callInstruction + 1);
}

static uintptr_t FindCTaskbandPinCreateInstanceForPinning(HMODULE twinuiPcshell)
{
	uintptr_t moduleBase = reinterpret_cast<uintptr_t>(twinuiPcshell);

	uintptr_t createInstance = FindPattern(
		moduleBase,
		"40 53 48 83 EC 20 48 8B D9 48 8D 15 ?? ?? ?? ?? B9 80 00 00 00"
	);
	if (createInstance)
		return createInstance;

	auto match = FindPattern(
		moduleBase,
		"48 8D 4C 24 ?? E8 ?? ?? ?? ?? 48 83 64 24 ?? ?? 48 8D 4C 24 ?? E8 ?? ?? ?? ?? 48 8B 8D ?? ?? ?? ?? 85 C0"
	);
	if (match)
		return ResolveRelativeCallTarget(match + 21);

	match = FindPattern(
		moduleBase,
		"0F 1F 44 00 00 48 83 64 24 ?? ?? 48 8D 4C 24 ?? E8 ?? ?? ?? ?? 48 8B 8D ?? ?? ?? ?? 85 C0"
	);
	if (match)
		return ResolveRelativeCallTarget(match + 16);

	return 0;
}

static uintptr_t FindCPinnedListInternalModify(HMODULE twinuiPcshell)
{
	uintptr_t moduleBase = reinterpret_cast<uintptr_t>(twinuiPcshell);

	auto modifyThunk = FindPattern(
		moduleBase,
		"40 53 48 83 EC 30 48 85 D2 75 0C 4D 85 C0 74 07 B8 05 40 00 80 EB 2F 83 64 24 20 00 48 83 C1 E8 E8 ?? ?? ?? ??"
	);
	if (modifyThunk)
	{
		uintptr_t target = ResolveRelativeCallTarget(modifyThunk + 32);
		if (target)
			return target;
	}

	const char* internalSignatures[] =
	{
		"40 55 53 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 F8 F9 FF FF 48 81 EC 08 07 00 00",
		"40 55 53 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 ?? ?? ?? ?? 48 81 EC 08 07 00 00",
		"40 55 53 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 ?? ?? ?? ?? 48 81 EC ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 85 ?? ?? ?? ??"
	};

	for (auto signature : internalSignatures)
	{
		uintptr_t internalModify = FindPattern(moduleBase, signature);
		if (internalModify)
			return internalModify;
	}

	return 0;
}

struct TemporaryCodePatch
{
	void* target = nullptr;
	BYTE original[16] = {};
	SIZE_T size = 0;
	bool applied = false;

	~TemporaryCodePatch()
	{
		Restore();
	}

	HRESULT Apply(void* function)
	{
		target = function;
		size = sizeof(original);

		if (!target)
			return E_POINTER;

		auto code = static_cast<BYTE*>(target);
		if (code[0] != 0x48 || code[1] != 0x8D || code[2] != 0x0D)
			return HRESULT_FROM_WIN32(ERROR_NOT_FOUND);

		DWORD oldProtect = 0;
		if (!VirtualProtect(target, size, PAGE_EXECUTE_READWRITE, &oldProtect))
			return HRESULT_FROM_WIN32(GetLastError());

		CopyMemory(original, target, size);
		BYTE patch[16] = { 0x33, 0xC0, 0xC3 };
		for (SIZE_T i = 3; i < sizeof(patch); ++i)
			patch[i] = 0x90;
		CopyMemory(target, patch, sizeof(patch));
		FlushInstructionCache(GetCurrentProcess(), target, sizeof(patch));

		DWORD ignored = 0;
		VirtualProtect(target, size, oldProtect, &ignored);
		applied = true;
		return S_OK;
	}

	void Restore()
	{
		if (!applied || !target)
			return;

		DWORD oldProtect = 0;
		if (VirtualProtect(target, size, PAGE_EXECUTE_READWRITE, &oldProtect))
		{
			CopyMemory(target, original, size);
			FlushInstructionCache(GetCurrentProcess(), target, size);
			DWORD ignored = 0;
			VirtualProtect(target, size, oldProtect, &ignored);
		}

		applied = false;
	}
};

static void* GetTaskbandIsRestrictedFromPinnedList(void* pinnedList)
{
	if (!pinnedList)
		return nullptr;

	auto vtable = *reinterpret_cast<void***>(pinnedList);
	if (!vtable)
		return nullptr;

	return vtable[0x78 / sizeof(void*)];
}

static SIZE_T GetModuleImageSize24H2(HMODULE module)
{
	if (!module)
		return 0;

	auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(module);
	auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<unsigned char*>(module) + dosHeader->e_lfanew);
	return ntHeaders->OptionalHeader.SizeOfImage;
}

static bool IsParsedPatternAt24H2(uintptr_t address, wiktorArray<int>* patternBytes)
{
	auto scanBytes = reinterpret_cast<unsigned char*>(address);
	const auto size = patternBytes->size;
	const auto data = patternBytes->data;

	for (int i = 0; i < size; ++i)
	{
		if (data[i] != -1 && scanBytes[i] != data[i])
			return false;
	}

	return true;
}

static uintptr_t FindPatternInRange24H2(uintptr_t start, SIZE_T size, const char* signature)
{
	auto patternBytes = patternToByte(signature);
	auto scanBytes = reinterpret_cast<unsigned char*>(start);
	const auto patternSize = patternBytes->size;
	const auto data = patternBytes->data;

	if (size <= static_cast<SIZE_T>(patternSize))
	{
		delete patternBytes;
		return 0;
	}

	for (SIZE_T i = 0; i < size - patternSize; ++i)
	{
		bool found = true;
		for (int j = 0; j < patternSize; ++j)
		{
			if (data[j] != -1 && scanBytes[i + j] != data[j])
			{
				found = false;
				break;
			}
		}

		if (found)
		{
			delete patternBytes;
			return start + i;
		}
	}

	delete patternBytes;
	return 0;
}

static int ScoreInternalModifyCandidate24H2(uintptr_t candidate, SIZE_T availableSize)
{
	int score = 0;
	const SIZE_T searchSize = availableSize < 0xB00 ? availableSize : 0xB00;

	if (FindPatternInRange24H2(candidate, searchSize, "48 8B 01 48 8B 40 78 E8"))
		++score;
	if (FindPatternInRange24H2(candidate, searchSize, "49 8B 4D 00 48 8B 81 D0 00 00 00"))
		++score;
	if (FindPatternInRange24H2(candidate, searchSize, "49 8B D5 48 8D 4D 08 E8 ?? ?? ?? ?? 85 C0"))
		++score;
	if (FindPatternInRange24H2(candidate, searchSize, "49 8B D5 48 8D 4D 08 E8 ?? ?? ?? ?? 44 8B F0"))
		++score;
	if (FindPatternInRange24H2(candidate, searchSize, "44 8B C7 48 8B 55 98 49 8B CD E8"))
		++score;
	if (FindPatternInRange24H2(candidate, searchSize, "41 81 FE 90 04 07 80"))
		++score;

	return score;
}

static uintptr_t FindCTaskbandPinConstructor24H2(HMODULE twinuiPcshell)
{
	const char* signature = "40 53 48 83 EC 20 48 8B D9 E8 ?? ?? ?? ?? 48 8D 05 ?? ?? ?? ?? 48 89";
	uintptr_t moduleBase = reinterpret_cast<uintptr_t>(twinuiPcshell);
	SIZE_T moduleSize = GetModuleImageSize24H2(twinuiPcshell);
	if (!moduleSize)
		return 0;

	uintptr_t bestCandidate = 0;
	int bestScore = 0;
	uintptr_t searchBase = moduleBase;
	SIZE_T remaining = moduleSize;
	while (remaining > 0xA0)
	{
		uintptr_t found = FindPatternInRange24H2(searchBase, remaining, signature);
		if (!found)
			break;

		int score = 0;
		if (FindPatternInRange24H2(found, 0x90, "48 89 03"))
			++score;
		if (FindPatternInRange24H2(found, 0x90, "48 89 43 08"))
			++score;
		if (FindPatternInRange24H2(found, 0x90, "48 89 43 10"))
			++score;
		if (FindPatternInRange24H2(found, 0x90, "48 89 43 18"))
			++score;
		if (FindPatternInRange24H2(found, 0x90, "48 89 43 20"))
			++score;
		if (FindPatternInRange24H2(found, 0x90, "48 89 43 28"))
			++score;
		if (FindPatternInRange24H2(found, 0x90, "48 89 43 30"))
			++score;
		if (FindPatternInRange24H2(found, 0x90, "48 89 43 70"))
			score += 3;

		if (score > bestScore)
		{
			bestScore = score;
			bestCandidate = found;
		}

		SIZE_T advance = (found - searchBase) + 1;
		searchBase += advance;
		remaining -= advance;
	}

	return bestScore >= 8 ? bestCandidate : 0;
}

static bool LooksLikeCTaskbandPinCreateInstance24H2(uintptr_t candidate, uintptr_t constructor)
{
	if (!candidate || !constructor)
		return false;

	const SIZE_T searchSize = 0x80;
	for (SIZE_T offset = 0; offset + 5 < searchSize; ++offset)
	{
		uintptr_t instruction = candidate + offset;
		if (*reinterpret_cast<unsigned char*>(instruction) == 0xE8 && ResolveRelativeCallTarget(instruction) == constructor)
			return true;
	}

	return false;
}

static uintptr_t FindCTaskbandPinCreateInstance24H2(HMODULE twinuiPcshell, uintptr_t constructor)
{
	if (!constructor)
		return 0;

	const char* signature = "40 53 48 83 EC 20 48 8B D9 48 8D 15 ?? ?? ?? ?? B9 80 00 00 00";
	uintptr_t moduleBase = reinterpret_cast<uintptr_t>(twinuiPcshell);
	SIZE_T moduleSize = GetModuleImageSize24H2(twinuiPcshell);
	if (!moduleSize)
		return 0;

	uintptr_t searchBase = moduleBase;
	SIZE_T remaining = moduleSize;
	while (remaining > 0x80)
	{
		uintptr_t found = FindPatternInRange24H2(searchBase, remaining, signature);
		if (!found)
			break;

		if (LooksLikeCTaskbandPinCreateInstance24H2(found, constructor))
			return found;

		SIZE_T advance = (found - searchBase) + 1;
		searchBase += advance;
		remaining -= advance;
	}

	return 0;
}

static bool IsReadablePointer24H2(const void* address)
{
	if (!address)
		return false;

	MEMORY_BASIC_INFORMATION mbi = {};
	if (!VirtualQuery(address, &mbi, sizeof(mbi)))
		return false;

	if (mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)))
		return false;

	return true;
}

static bool IsExecutablePointer24H2(const void* address)
{
	if (!address)
		return false;

	MEMORY_BASIC_INFORMATION mbi = {};
	if (!VirtualQuery(address, &mbi, sizeof(mbi)))
		return false;

	if (mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)))
		return false;

	return (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
}

static bool IsLikelyPinnedListThis24H2(void* candidate)
{
	if (!IsReadablePointer24H2(candidate))
		return false;

	void** vtable = *reinterpret_cast<void***>(candidate);
	if (!IsReadablePointer24H2(vtable))
		return false;

	void* restrictedFunction = vtable[0x78 / sizeof(void*)];
	if (!IsExecutablePointer24H2(restrictedFunction)
		|| !IsExecutablePointer24H2(vtable[0xA8 / sizeof(void*)])
		|| !IsExecutablePointer24H2(vtable[0xD0 / sizeof(void*)]))
		return false;

	unsigned char* target = reinterpret_cast<unsigned char*>(restrictedFunction);
	if (target[0] == 0x48 && target[1] == 0x8B && target[2] == 0x49 && target[3] == 0x18)
		return false;

	return true;
}

static bool AddThisCandidate24H2(void* candidate, int offset, bool indirect, void** candidates, int* candidateOffsets, bool* candidateIndirect, int* candidateCount, int maxCandidates)
{
	if (!candidate || !IsLikelyPinnedListThis24H2(candidate))
		return false;

	for (int i = 0; i < *candidateCount; ++i)
	{
		if (candidates[i] == candidate)
			return false;
	}

	if (*candidateCount >= maxCandidates)
		return false;

	candidates[*candidateCount] = candidate;
	candidateOffsets[*candidateCount] = offset;
	candidateIndirect[*candidateCount] = indirect;
	++(*candidateCount);
	return true;
}

static void CollectPinnedListThisCandidates24H2(void* taskbandPin, void** candidates, int* candidateOffsets, bool* candidateIndirect, int* candidateCount, int maxCandidates)
{
	if (!taskbandPin)
		return;

	for (int offset = 0; offset <= 0x300 && *candidateCount < maxCandidates; offset += static_cast<int>(sizeof(void*)))
	{
		void* directCandidate = static_cast<void*>(static_cast<unsigned char*>(taskbandPin) + offset);
		AddThisCandidate24H2(directCandidate, offset, false, candidates, candidateOffsets, candidateIndirect, candidateCount, maxCandidates);

		void** field = reinterpret_cast<void**>(directCandidate);
		if (IsReadablePointer24H2(field))
		{
			void* indirectCandidate = *field;
			AddThisCandidate24H2(indirectCandidate, offset, true, candidates, candidateOffsets, candidateIndirect, candidateCount, maxCandidates);
		}
	}
}

CPinnedListWrapper::CPinnedListWrapper(IUnknown* flex, int build, PINNEDLISTMODIFYCALLER modifyCaller)
{
	m_build = build;
	m_modifyCaller = modifyCaller;
	if (build >= 10240 && build < 14393)
	{
		m_pinnedList25 = (IPinnedList25*)flex;
		dbgprintf(L"using IPinnedList25");
	}
	else if (build >= 14393 && build < 17763)
	{
		m_flexList = (IFlexibleTaskbarPinnedList*)flex;
		dbgprintf(L"using IFlexibleTaskbarPinnedList");
	}
	else if (build >= 17763)
	{
		m_pinnedList3 = (IPinnedList3*)flex;
		dbgprintf(L"using IPinnedlist3");
	}
}

CPinnedListWrapper::~CPinnedListWrapper()
{
	if (m_pinnedList25)
		m_pinnedList25->Release();
	if (m_flexList)
		m_flexList->Release();
	if (m_pinnedList3)
		m_pinnedList3->Release();
}

HRESULT __stdcall CPinnedListWrapper::QueryInterface(REFIID riid, void** ppvObject)
{
	if (m_pinnedList25)
		return m_pinnedList25->QueryInterface(riid, ppvObject);
	if (m_flexList)
		return m_flexList->QueryInterface(riid, ppvObject);
	if (m_pinnedList3)
		return m_pinnedList3->QueryInterface(riid, ppvObject);
	return S_OK;
}

ULONG __stdcall CPinnedListWrapper::AddRef(void)
{
	ULONG cref;
	if (m_pinnedList25)
		cref = m_pinnedList25->AddRef();
	if (m_flexList)
		cref = m_flexList->AddRef();
	if (m_pinnedList3)
		cref = m_pinnedList3->AddRef();
	return cref;
}

ULONG __stdcall CPinnedListWrapper::Release(void)
{
	ULONG cref;
	if (m_pinnedList25)
		cref = m_pinnedList25->Release();
	if (m_flexList)
		cref = m_flexList->Release();
	if (m_pinnedList3)
		cref = m_pinnedList3->Release();
	if (cref == 0)
		free((void*)this);
	return cref;
}

//.text:00007FF6BEB24439 explorer.exe:$94439 #93A39
HRESULT __stdcall CPinnedListWrapper::EnumObjects(IEnumFullIDList** p1)
{
	if (m_pinnedList25)
		return m_pinnedList25->EnumObjects(p1);
	if (m_flexList)
		return m_flexList->EnumObjects(p1);
	if (m_pinnedList3)
		return m_pinnedList3->EnumObjects(p1);
	return S_OK;
}

HRESULT __stdcall CPinnedListWrapper::Modify(PCIDLIST_ABSOLUTE p1, PCIDLIST_ABSOLUTE p2)
{
	if (m_pinnedList25)
		return m_pinnedList25->Modify(p1, p2);
	if (m_flexList)
		return m_flexList->Modify(p1, p2);
	if (m_pinnedList3)
	{
		if ((m_build == 22621 || m_build == 22631 || m_build >= 26100) && !p1 && p2 && IsTaskbarModifyCaller(m_modifyCaller))
		{
			HRESULT internalResult = ModifyUsingTaskbandInternal(p1, p2);
			if (SUCCEEDED(internalResult))
			{
				HRESULT pinnedResult = m_pinnedList3->IsPinned(p2);
				if (pinnedResult == S_OK)
					return internalResult;
			}
		}

		return m_pinnedList3->Modify(p1, p2, m_modifyCaller);
	}
	return S_OK;
}

HRESULT CPinnedListWrapper::ModifyUsingTaskbandInternal(PCIDLIST_ABSOLUTE oldPidl, PCIDLIST_ABSOLUTE newPidl)
{
	if (m_build != 22621 && m_build != 22631 && m_build < 26100)
		return E_NOTIMPL;

	HMODULE twinuiPcshell = LoadLibraryW(L"twinui.pcshell.dll");
	if (!twinuiPcshell)
		return HRESULT_FROM_WIN32(GetLastError());

	typedef HRESULT(__fastcall* CTaskbandPinCreateInstanceAPI)(void**);
	typedef HRESULT(__fastcall* CPinnedListInternalModifyAPI)(void*, PCIDLIST_ABSOLUTE, PCIDLIST_ABSOLUTE, int, int);

	uintptr_t createInstanceAddress = FindCTaskbandPinCreateInstanceForPinning(twinuiPcshell);
	if (m_build >= 26100)
	{
		uintptr_t constructorAddress = FindCTaskbandPinConstructor24H2(twinuiPcshell);
		createInstanceAddress = FindCTaskbandPinCreateInstance24H2(twinuiPcshell, constructorAddress);
	}
	
	auto createInstance = reinterpret_cast<CTaskbandPinCreateInstanceAPI>(createInstanceAddress);
	uintptr_t internalModifyAddress = FindCPinnedListInternalModify(twinuiPcshell);
	if (m_build >= 26100)
	{
		uintptr_t moduleBase = reinterpret_cast<uintptr_t>(twinuiPcshell);
		SIZE_T moduleSize = GetModuleImageSize24H2(twinuiPcshell);
		if (!internalModifyAddress || internalModifyAddress < moduleBase || internalModifyAddress - moduleBase >= moduleSize ||
			ScoreInternalModifyCandidate24H2(internalModifyAddress, moduleSize - (internalModifyAddress - moduleBase)) < 3)
		{
			return HRESULT_FROM_WIN32(ERROR_PROC_NOT_FOUND);
		}
	}
	
	auto internalModify = reinterpret_cast<CPinnedListInternalModifyAPI>(internalModifyAddress);

	if (!createInstance || !internalModify)
		return HRESULT_FROM_WIN32(ERROR_PROC_NOT_FOUND);

	void* taskbandPin = nullptr;
	HRESULT result = createInstance(&taskbandPin);
	if (FAILED(result))
		return result;

	TemporaryCodePatch isRestrictedPatch;
	HRESULT patchResult = isRestrictedPatch.Apply(GetTaskbandIsRestrictedFromPinnedList(taskbandPin));
	if (SUCCEEDED(patchResult))
		result = internalModify(taskbandPin, oldPidl, newPidl, (int)m_modifyCaller, 0);
	else
		result = patchResult;

	if (taskbandPin)
		reinterpret_cast<IUnknown*>(taskbandPin)->Release();

	return result;
}

HRESULT __stdcall CPinnedListWrapper::GetChangeCount(ULONG* p1)
{
	if (m_pinnedList25)
		return m_pinnedList25->GetChangeCount(p1);
	if (m_flexList)
		return m_flexList->GetChangeCount(p1);
	if (m_pinnedList3)
		return m_pinnedList3->GetChangeCount(p1);
	return S_OK;
}

HRESULT __stdcall CPinnedListWrapper::GetPinnableInfo(IDataObject* p1, int p2, IShellItem2** p3, IShellItem** p4, PWSTR* p5, INT* p6)
{
	if (!s_UseTaskbarPinning)
	{
		// in this situation, we don't take the information
		// this is to prevent potential issues arising with people trying to pin despite being in this mode
		return E_NOINTERFACE;
	}

	if (m_pinnedList25)
		return m_pinnedList25->GetPinnableInfo(p1, p2, p3, p4, p5, p6);
	if (m_flexList)
		return m_flexList->GetPinnableInfo(p1, p2, p3, p4, p5, p6);
	if (m_pinnedList3)
		return m_pinnedList3->GetPinnableInfo(p1, p2, p3, p4, p5, p6);
	return S_OK;
}

HRESULT __stdcall CPinnedListWrapper::IsPinnable(IDataObject* p1, int p2)
{
	if (m_pinnedList25)
		return m_pinnedList25->IsPinnable(p1, p2);
	if (m_flexList)
		return m_flexList->IsPinnable(p1, p2);
	if (m_pinnedList3)
		return m_pinnedList3->IsPinnable(p1, p2);
	return S_OK;
}

HRESULT __stdcall CPinnedListWrapper::Resolve(HWND p1, ULONG p2, PCIDLIST_ABSOLUTE p3, PIDLIST_ABSOLUTE* p4)
{
	if (m_pinnedList25)
		return m_pinnedList25->Resolve(p1, p2, p3, p4);
	if (m_flexList)
		return m_flexList->Resolve(p1, p2, p3, p4);
	if (m_pinnedList3)
		return m_pinnedList3->Resolve(p1, p2, p3, p4);
	return S_OK;
}

HRESULT __stdcall CPinnedListWrapper::IsPinned(PCIDLIST_ABSOLUTE p1)
{
	if (m_pinnedList25)
		return m_pinnedList25->IsPinned(p1);
	if (m_flexList)
		return m_flexList->IsPinned(p1);
	if (m_pinnedList3)
		return m_pinnedList3->IsPinned(p1);
	return S_OK;
}

HRESULT __stdcall CPinnedListWrapper::GetPinnedItem(PCIDLIST_ABSOLUTE p1, PIDLIST_ABSOLUTE* p2)
{
	if (m_pinnedList25)
		return m_pinnedList25->GetPinnedItem(p1, p2);
	if (m_flexList)
		return m_flexList->GetPinnedItem(p1, p2);
	if (m_pinnedList3)
		return m_pinnedList3->GetPinnedItem(p1, p2);
	return S_OK;
}

HRESULT __stdcall CPinnedListWrapper::GetAppIDForPinnedItem(PCIDLIST_ABSOLUTE p1, PWSTR* p2)
{
	// Ittr: Determine whether we should hide immersive items
	bool bHideImmersivePidl = false;

	// Only bother running the filtering code if the option to show store applications on the taskbar is disabled
	if (!s_ShowStoreAppsOnTaskbar)
	{
		ITEMIDLIST_ABSOLUTE* pidlApplicationFolder;
		if (SUCCEEDED(SHGetKnownFolderIDList(FOLDERID_AppsFolder, KF_FLAG_DONT_VERIFY, nullptr, &pidlApplicationFolder)))
		{
			bHideImmersivePidl = ILIsParent(pidlApplicationFolder, p1, TRUE);
		}
		CoTaskMemFree(pidlApplicationFolder);
	}

	// Cause the interface to intentionally fail if pinning is disabled or in the cases where immersive items should be hidden
	if (!s_UseTaskbarPinning || bHideImmersivePidl)
	{
		return E_NOINTERFACE;
	}

	// Pass through to the appropriate PinnedList interface for the user's version of Windows
	if (m_pinnedList25)
		return m_pinnedList25->GetAppIDForPinnedItem(p1, p2);
	if (m_flexList)
		return m_flexList->GetAppIDForPinnedItem(p1, p2);
	if (m_pinnedList3)
		return m_pinnedList3->GetAppIDForPinnedItem(p1, p2);
	return S_OK;
}

HRESULT __stdcall CPinnedListWrapper::ItemChangeNotify(PCIDLIST_ABSOLUTE p1, PCIDLIST_ABSOLUTE p2)
{
	if (m_pinnedList25)
		return m_pinnedList25->ItemChangeNotify(p1, p2);
	if (m_flexList)
		return m_flexList->ItemChangeNotify(p1, p2);
	if (m_pinnedList3)
		return m_pinnedList3->ItemChangeNotify(p1, p2);
	return S_OK;
}

HRESULT __stdcall CPinnedListWrapper::UpdateForRemovedItemsAsNecessary(VOID)
{
	if (m_pinnedList25)
		return m_pinnedList25->UpdateForRemovedItemsAsNecessary();
	if (m_flexList)
		return m_flexList->UpdateForRemovedItemsAsNecessary();
	if (m_pinnedList3)
		return m_pinnedList3->UpdateForRemovedItemsAsNecessary();
	return S_OK;
}
