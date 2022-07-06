/*
* This file was originally generated using ProxiFy with kernel32.dll
* It has been edited manually to add the neccessary functionality.
* See https://www.codeproject.com/Articles/1179147/ProxiFy-Automatic-Proxy-DLL-Generation for more info and sources.
* 
* Credits to 'pannenkoek2012' on the Growtopia forums for figuring this out.
* Here's a link to the forum post: https://www.growtopiagame.com/forums/forum/problems/bugs-glitches/7136549-how-to-make-growtopia-not-use-so-much-cpu-in-a-few-easy-steps
* 
* You have to patch Growtopia to load kernel34.dll instead of kernel32.dll
* When Growtopia calls a function in kernel34.dll, it will redirect it into kernel32.dll
* unless it's the Sleep() function. In this case, it will check if the amount
* of milliseconds to sleep is 0 and change it to 1 instead and then redirect it.
* This prevents Growtopia from consuming all of the processing power while idle.
*/

#include <windows.h>
#include <ostream>
#include <fstream>
HINSTANCE hLThis = 0;
FARPROC p[1633];
HINSTANCE hL = 0;

// This is here for casting a function WITHOUT parameters into a function WITH parameters.
typedef int (*SleepFunc_t)(int32_t);

BOOL WINAPI DllMain(HINSTANCE hInst,DWORD reason,LPVOID)
{
	if (reason == DLL_PROCESS_ATTACH)
	{
		hLThis = hInst;

		// Load the original kernel32.dll
		hL = LoadLibrary("kernel32.dll");
		if(!hL) return false;
	}

	p[0] = GetProcAddress(hL, "AcquireSRWLockExclusive");
	p[1] = GetProcAddress(hL, "AcquireSRWLockShared");
	p[2] = GetProcAddress(hL, "ActivateActCtx");
	p[3] = GetProcAddress(hL, "ActivateActCtxWorker");
	p[4] = GetProcAddress(hL, "AddAtomA");
	p[5] = GetProcAddress(hL, "AddAtomW");
	p[6] = GetProcAddress(hL, "AddConsoleAliasA");
	p[7] = GetProcAddress(hL, "AddConsoleAliasW");
	p[8] = GetProcAddress(hL, "AddDllDirectory");
	p[9] = GetProcAddress(hL, "AddIntegrityLabelToBoundaryDescriptor");
	p[10] = GetProcAddress(hL, "AddLocalAlternateComputerNameA");
	p[11] = GetProcAddress(hL, "AddLocalAlternateComputerNameW");
	p[12] = GetProcAddress(hL, "AddRefActCtx");
	p[13] = GetProcAddress(hL, "AddRefActCtxWorker");
	p[14] = GetProcAddress(hL, "AddResourceAttributeAce");
	p[15] = GetProcAddress(hL, "AddSIDToBoundaryDescriptor");
	p[16] = GetProcAddress(hL, "AddScopedPolicyIDAce");
	p[17] = GetProcAddress(hL, "AddSecureMemoryCacheCallback");
	p[18] = GetProcAddress(hL, "AddVectoredContinueHandler");
	p[19] = GetProcAddress(hL, "AddVectoredExceptionHandler");
	p[20] = GetProcAddress(hL, "AdjustCalendarDate");
	p[21] = GetProcAddress(hL, "AllocConsole");
	p[22] = GetProcAddress(hL, "AllocateUserPhysicalPages");
	p[23] = GetProcAddress(hL, "AllocateUserPhysicalPagesNuma");
	p[24] = GetProcAddress(hL, "AppPolicyGetClrCompat");
	p[25] = GetProcAddress(hL, "AppPolicyGetCreateFileAccess");
	p[26] = GetProcAddress(hL, "AppPolicyGetLifecycleManagement");
	p[27] = GetProcAddress(hL, "AppPolicyGetMediaFoundationCodecLoading");
	p[28] = GetProcAddress(hL, "AppPolicyGetProcessTerminationMethod");
	p[29] = GetProcAddress(hL, "AppPolicyGetShowDeveloperDiagnostic");
	p[30] = GetProcAddress(hL, "AppPolicyGetThreadInitializationType");
	p[31] = GetProcAddress(hL, "AppPolicyGetWindowingModel");
	p[32] = GetProcAddress(hL, "AppXGetOSMaxVersionTested");
	p[33] = GetProcAddress(hL, "ApplicationRecoveryFinished");
	p[34] = GetProcAddress(hL, "ApplicationRecoveryInProgress");
	p[35] = GetProcAddress(hL, "AreFileApisANSI");
	p[36] = GetProcAddress(hL, "AssignProcessToJobObject");
	p[37] = GetProcAddress(hL, "AttachConsole");
	p[38] = GetProcAddress(hL, "BackupRead");
	p[39] = GetProcAddress(hL, "BackupSeek");
	p[40] = GetProcAddress(hL, "BackupWrite");
	p[41] = GetProcAddress(hL, "BaseCheckAppcompatCache");
	p[42] = GetProcAddress(hL, "BaseCheckAppcompatCacheEx");
	p[43] = GetProcAddress(hL, "BaseCheckAppcompatCacheExWorker");
	p[44] = GetProcAddress(hL, "BaseCheckAppcompatCacheWorker");
	p[45] = GetProcAddress(hL, "BaseCheckElevation");
	p[46] = GetProcAddress(hL, "BaseCleanupAppcompatCacheSupport");
	p[47] = GetProcAddress(hL, "BaseCleanupAppcompatCacheSupportWorker");
	p[48] = GetProcAddress(hL, "BaseDestroyVDMEnvironment");
	p[49] = GetProcAddress(hL, "BaseDllReadWriteIniFile");
	p[50] = GetProcAddress(hL, "BaseDumpAppcompatCache");
	p[51] = GetProcAddress(hL, "BaseDumpAppcompatCacheWorker");
	p[52] = GetProcAddress(hL, "BaseElevationPostProcessing");
	p[53] = GetProcAddress(hL, "BaseFlushAppcompatCache");
	p[54] = GetProcAddress(hL, "BaseFlushAppcompatCacheWorker");
	p[55] = GetProcAddress(hL, "BaseFormatObjectAttributes");
	p[56] = GetProcAddress(hL, "BaseFormatTimeOut");
	p[57] = GetProcAddress(hL, "BaseFreeAppCompatDataForProcessWorker");
	p[58] = GetProcAddress(hL, "BaseGenerateAppCompatData");
	p[59] = GetProcAddress(hL, "BaseGetNamedObjectDirectory");
	p[60] = GetProcAddress(hL, "BaseInitAppcompatCacheSupport");
	p[61] = GetProcAddress(hL, "BaseInitAppcompatCacheSupportWorker");
	p[62] = GetProcAddress(hL, "BaseIsAppcompatInfrastructureDisabled");
	p[63] = GetProcAddress(hL, "BaseIsAppcompatInfrastructureDisabledWorker");
	p[64] = GetProcAddress(hL, "BaseIsDosApplication");
	p[65] = GetProcAddress(hL, "BaseQueryModuleData");
	p[66] = GetProcAddress(hL, "BaseReadAppCompatDataForProcessWorker");
	p[67] = GetProcAddress(hL, "BaseSetLastNTError");
	p[68] = GetProcAddress(hL, "BaseThreadInitThunk");
	p[69] = GetProcAddress(hL, "BaseUpdateAppcompatCache");
	p[70] = GetProcAddress(hL, "BaseUpdateAppcompatCacheWorker");
	p[71] = GetProcAddress(hL, "BaseUpdateVDMEntry");
	p[72] = GetProcAddress(hL, "BaseVerifyUnicodeString");
	p[73] = GetProcAddress(hL, "BaseWriteErrorElevationRequiredEvent");
	p[74] = GetProcAddress(hL, "Basep8BitStringToDynamicUnicodeString");
	p[75] = GetProcAddress(hL, "BasepAllocateActivationContextActivationBlock");
	p[76] = GetProcAddress(hL, "BasepAnsiStringToDynamicUnicodeString");
	p[77] = GetProcAddress(hL, "BasepAppContainerEnvironmentExtension");
	p[78] = GetProcAddress(hL, "BasepAppXExtension");
	p[79] = GetProcAddress(hL, "BasepCheckAppCompat");
	p[80] = GetProcAddress(hL, "BasepCheckWebBladeHashes");
	p[81] = GetProcAddress(hL, "BasepCheckWinSaferRestrictions");
	p[82] = GetProcAddress(hL, "BasepConstructSxsCreateProcessMessage");
	p[83] = GetProcAddress(hL, "BasepCopyEncryption");
	p[84] = GetProcAddress(hL, "BasepFinishPackageActivationForSxS");
	p[85] = GetProcAddress(hL, "BasepFreeActivationContextActivationBlock");
	p[86] = GetProcAddress(hL, "BasepFreeAppCompatData");
	p[87] = GetProcAddress(hL, "BasepGetAppCompatData");
	p[88] = GetProcAddress(hL, "BasepGetComputerNameFromNtPath");
	p[89] = GetProcAddress(hL, "BasepGetExeArchType");
	p[90] = GetProcAddress(hL, "BasepGetPackageActivationTokenForSxS");
	p[91] = GetProcAddress(hL, "BasepInitAppCompatData");
	p[92] = GetProcAddress(hL, "BasepIsProcessAllowed");
	p[93] = GetProcAddress(hL, "BasepMapModuleHandle");
	p[94] = GetProcAddress(hL, "BasepNotifyLoadStringResource");
	p[95] = GetProcAddress(hL, "BasepPostSuccessAppXExtension");
	p[96] = GetProcAddress(hL, "BasepProcessInvalidImage");
	p[97] = GetProcAddress(hL, "BasepQueryAppCompat");
	p[98] = GetProcAddress(hL, "BasepQueryModuleChpeSettings");
	p[99] = GetProcAddress(hL, "BasepReleaseAppXContext");
	p[100] = GetProcAddress(hL, "BasepReleaseSxsCreateProcessUtilityStruct");
	p[101] = GetProcAddress(hL, "BasepReportFault");
	p[102] = GetProcAddress(hL, "BasepSetFileEncryptionCompression");
	p[103] = GetProcAddress(hL, "Beep");
	p[104] = GetProcAddress(hL, "BeginUpdateResourceA");
	p[105] = GetProcAddress(hL, "BeginUpdateResourceW");
	p[106] = GetProcAddress(hL, "BindIoCompletionCallback");
	p[107] = GetProcAddress(hL, "BuildCommDCBA");
	p[108] = GetProcAddress(hL, "BuildCommDCBAndTimeoutsA");
	p[109] = GetProcAddress(hL, "BuildCommDCBAndTimeoutsW");
	p[110] = GetProcAddress(hL, "BuildCommDCBW");
	p[111] = GetProcAddress(hL, "CallNamedPipeA");
	p[112] = GetProcAddress(hL, "CallNamedPipeW");
	p[113] = GetProcAddress(hL, "CallbackMayRunLong");
	p[114] = GetProcAddress(hL, "CancelDeviceWakeupRequest");
	p[115] = GetProcAddress(hL, "CancelIo");
	p[116] = GetProcAddress(hL, "CancelIoEx");
	p[117] = GetProcAddress(hL, "CancelSynchronousIo");
	p[118] = GetProcAddress(hL, "CancelThreadpoolIo");
	p[119] = GetProcAddress(hL, "CancelTimerQueueTimer");
	p[120] = GetProcAddress(hL, "CancelWaitableTimer");
	p[121] = GetProcAddress(hL, "CeipIsOptedIn");
	p[122] = GetProcAddress(hL, "ChangeTimerQueueTimer");
	p[123] = GetProcAddress(hL, "CheckAllowDecryptedRemoteDestinationPolicy");
	p[124] = GetProcAddress(hL, "CheckElevation");
	p[125] = GetProcAddress(hL, "CheckElevationEnabled");
	p[126] = GetProcAddress(hL, "CheckForReadOnlyResource");
	p[127] = GetProcAddress(hL, "CheckForReadOnlyResourceFilter");
	p[128] = GetProcAddress(hL, "CheckIsMSIXPackage");
	p[129] = GetProcAddress(hL, "CheckNameLegalDOS8Dot3A");
	p[130] = GetProcAddress(hL, "CheckNameLegalDOS8Dot3W");
	p[131] = GetProcAddress(hL, "CheckRemoteDebuggerPresent");
	p[132] = GetProcAddress(hL, "CheckTokenCapability");
	p[133] = GetProcAddress(hL, "CheckTokenMembershipEx");
	p[134] = GetProcAddress(hL, "ClearCommBreak");
	p[135] = GetProcAddress(hL, "ClearCommError");
	p[136] = GetProcAddress(hL, "CloseConsoleHandle");
	p[137] = GetProcAddress(hL, "CloseHandle");
	p[138] = GetProcAddress(hL, "ClosePackageInfo");
	p[139] = GetProcAddress(hL, "ClosePrivateNamespace");
	p[140] = GetProcAddress(hL, "CloseProfileUserMapping");
	p[141] = GetProcAddress(hL, "ClosePseudoConsole");
	p[142] = GetProcAddress(hL, "CloseState");
	p[143] = GetProcAddress(hL, "CloseThreadpool");
	p[144] = GetProcAddress(hL, "CloseThreadpoolCleanupGroup");
	p[145] = GetProcAddress(hL, "CloseThreadpoolCleanupGroupMembers");
	p[146] = GetProcAddress(hL, "CloseThreadpoolIo");
	p[147] = GetProcAddress(hL, "CloseThreadpoolTimer");
	p[148] = GetProcAddress(hL, "CloseThreadpoolWait");
	p[149] = GetProcAddress(hL, "CloseThreadpoolWork");
	p[150] = GetProcAddress(hL, "CmdBatNotification");
	p[151] = GetProcAddress(hL, "CommConfigDialogA");
	p[152] = GetProcAddress(hL, "CommConfigDialogW");
	p[153] = GetProcAddress(hL, "CompareCalendarDates");
	p[154] = GetProcAddress(hL, "CompareFileTime");
	p[155] = GetProcAddress(hL, "CompareStringA");
	p[156] = GetProcAddress(hL, "CompareStringEx");
	p[157] = GetProcAddress(hL, "CompareStringOrdinal");
	p[158] = GetProcAddress(hL, "CompareStringW");
	p[159] = GetProcAddress(hL, "ConnectNamedPipe");
	p[160] = GetProcAddress(hL, "ConsoleMenuControl");
	p[161] = GetProcAddress(hL, "ContinueDebugEvent");
	p[162] = GetProcAddress(hL, "ConvertCalDateTimeToSystemTime");
	p[163] = GetProcAddress(hL, "ConvertDefaultLocale");
	p[164] = GetProcAddress(hL, "ConvertFiberToThread");
	p[165] = GetProcAddress(hL, "ConvertNLSDayOfWeekToWin32DayOfWeek");
	p[166] = GetProcAddress(hL, "ConvertSystemTimeToCalDateTime");
	p[167] = GetProcAddress(hL, "ConvertThreadToFiber");
	p[168] = GetProcAddress(hL, "ConvertThreadToFiberEx");
	p[169] = GetProcAddress(hL, "CopyContext");
	p[170] = GetProcAddress(hL, "CopyFile2");
	p[171] = GetProcAddress(hL, "CopyFileA");
	p[172] = GetProcAddress(hL, "CopyFileExA");
	p[173] = GetProcAddress(hL, "CopyFileExW");
	p[174] = GetProcAddress(hL, "CopyFileTransactedA");
	p[175] = GetProcAddress(hL, "CopyFileTransactedW");
	p[176] = GetProcAddress(hL, "CopyFileW");
	p[177] = GetProcAddress(hL, "CopyLZFile");
	p[178] = GetProcAddress(hL, "CreateActCtxA");
	p[179] = GetProcAddress(hL, "CreateActCtxW");
	p[180] = GetProcAddress(hL, "CreateActCtxWWorker");
	p[181] = GetProcAddress(hL, "CreateBoundaryDescriptorA");
	p[182] = GetProcAddress(hL, "CreateBoundaryDescriptorW");
	p[183] = GetProcAddress(hL, "CreateConsoleScreenBuffer");
	p[184] = GetProcAddress(hL, "CreateDirectoryA");
	p[185] = GetProcAddress(hL, "CreateDirectoryExA");
	p[186] = GetProcAddress(hL, "CreateDirectoryExW");
	p[187] = GetProcAddress(hL, "CreateDirectoryTransactedA");
	p[188] = GetProcAddress(hL, "CreateDirectoryTransactedW");
	p[189] = GetProcAddress(hL, "CreateDirectoryW");
	p[190] = GetProcAddress(hL, "CreateEnclave");
	p[191] = GetProcAddress(hL, "CreateEventA");
	p[192] = GetProcAddress(hL, "CreateEventExA");
	p[193] = GetProcAddress(hL, "CreateEventExW");
	p[194] = GetProcAddress(hL, "CreateEventW");
	p[195] = GetProcAddress(hL, "CreateFiber");
	p[196] = GetProcAddress(hL, "CreateFiberEx");
	p[197] = GetProcAddress(hL, "CreateFile2");
	p[198] = GetProcAddress(hL, "CreateFileA");
	p[199] = GetProcAddress(hL, "CreateFileMappingA");
	p[200] = GetProcAddress(hL, "CreateFileMappingFromApp");
	p[201] = GetProcAddress(hL, "CreateFileMappingNumaA");
	p[202] = GetProcAddress(hL, "CreateFileMappingNumaW");
	p[203] = GetProcAddress(hL, "CreateFileMappingW");
	p[204] = GetProcAddress(hL, "CreateFileTransactedA");
	p[205] = GetProcAddress(hL, "CreateFileTransactedW");
	p[206] = GetProcAddress(hL, "CreateFileW");
	p[207] = GetProcAddress(hL, "CreateHardLinkA");
	p[208] = GetProcAddress(hL, "CreateHardLinkTransactedA");
	p[209] = GetProcAddress(hL, "CreateHardLinkTransactedW");
	p[210] = GetProcAddress(hL, "CreateHardLinkW");
	p[211] = GetProcAddress(hL, "CreateIoCompletionPort");
	p[212] = GetProcAddress(hL, "CreateJobObjectA");
	p[213] = GetProcAddress(hL, "CreateJobObjectW");
	p[214] = GetProcAddress(hL, "CreateJobSet");
	p[215] = GetProcAddress(hL, "CreateMailslotA");
	p[216] = GetProcAddress(hL, "CreateMailslotW");
	p[217] = GetProcAddress(hL, "CreateMemoryResourceNotification");
	p[218] = GetProcAddress(hL, "CreateMutexA");
	p[219] = GetProcAddress(hL, "CreateMutexExA");
	p[220] = GetProcAddress(hL, "CreateMutexExW");
	p[221] = GetProcAddress(hL, "CreateMutexW");
	p[222] = GetProcAddress(hL, "CreateNamedPipeA");
	p[223] = GetProcAddress(hL, "CreateNamedPipeW");
	p[224] = GetProcAddress(hL, "CreatePipe");
	p[225] = GetProcAddress(hL, "CreatePrivateNamespaceA");
	p[226] = GetProcAddress(hL, "CreatePrivateNamespaceW");
	p[227] = GetProcAddress(hL, "CreateProcessA");
	p[228] = GetProcAddress(hL, "CreateProcessAsUserA");
	p[229] = GetProcAddress(hL, "CreateProcessAsUserW");
	p[230] = GetProcAddress(hL, "CreateProcessInternalA");
	p[231] = GetProcAddress(hL, "CreateProcessInternalW");
	p[232] = GetProcAddress(hL, "CreateProcessW");
	p[233] = GetProcAddress(hL, "CreatePseudoConsole");
	p[234] = GetProcAddress(hL, "CreateRemoteThread");
	p[235] = GetProcAddress(hL, "CreateRemoteThreadEx");
	p[236] = GetProcAddress(hL, "CreateSemaphoreA");
	p[237] = GetProcAddress(hL, "CreateSemaphoreExA");
	p[238] = GetProcAddress(hL, "CreateSemaphoreExW");
	p[239] = GetProcAddress(hL, "CreateSemaphoreW");
	p[240] = GetProcAddress(hL, "CreateSymbolicLinkA");
	p[241] = GetProcAddress(hL, "CreateSymbolicLinkTransactedA");
	p[242] = GetProcAddress(hL, "CreateSymbolicLinkTransactedW");
	p[243] = GetProcAddress(hL, "CreateSymbolicLinkW");
	p[244] = GetProcAddress(hL, "CreateTapePartition");
	p[245] = GetProcAddress(hL, "CreateThread");
	p[246] = GetProcAddress(hL, "CreateThreadpool");
	p[247] = GetProcAddress(hL, "CreateThreadpoolCleanupGroup");
	p[248] = GetProcAddress(hL, "CreateThreadpoolIo");
	p[249] = GetProcAddress(hL, "CreateThreadpoolTimer");
	p[250] = GetProcAddress(hL, "CreateThreadpoolWait");
	p[251] = GetProcAddress(hL, "CreateThreadpoolWork");
	p[252] = GetProcAddress(hL, "CreateTimerQueue");
	p[253] = GetProcAddress(hL, "CreateTimerQueueTimer");
	p[254] = GetProcAddress(hL, "CreateToolhelp32Snapshot");
	p[255] = GetProcAddress(hL, "CreateUmsCompletionList");
	p[256] = GetProcAddress(hL, "CreateUmsThreadContext");
	p[257] = GetProcAddress(hL, "CreateWaitableTimerA");
	p[258] = GetProcAddress(hL, "CreateWaitableTimerExA");
	p[259] = GetProcAddress(hL, "CreateWaitableTimerExW");
	p[260] = GetProcAddress(hL, "CreateWaitableTimerW");
	p[261] = GetProcAddress(hL, "CtrlRoutine");
	p[262] = GetProcAddress(hL, "DeactivateActCtx");
	p[263] = GetProcAddress(hL, "DeactivateActCtxWorker");
	p[264] = GetProcAddress(hL, "DebugActiveProcess");
	p[265] = GetProcAddress(hL, "DebugActiveProcessStop");
	p[266] = GetProcAddress(hL, "DebugBreak");
	p[267] = GetProcAddress(hL, "DebugBreakProcess");
	p[268] = GetProcAddress(hL, "DebugSetProcessKillOnExit");
	p[269] = GetProcAddress(hL, "DecodePointer");
	p[270] = GetProcAddress(hL, "DecodeSystemPointer");
	p[271] = GetProcAddress(hL, "DefineDosDeviceA");
	p[272] = GetProcAddress(hL, "DefineDosDeviceW");
	p[273] = GetProcAddress(hL, "DelayLoadFailureHook");
	p[274] = GetProcAddress(hL, "DeleteAtom");
	p[275] = GetProcAddress(hL, "DeleteBoundaryDescriptor");
	p[276] = GetProcAddress(hL, "DeleteCriticalSection");
	p[277] = GetProcAddress(hL, "DeleteFiber");
	p[278] = GetProcAddress(hL, "DeleteFileA");
	p[279] = GetProcAddress(hL, "DeleteFileTransactedA");
	p[280] = GetProcAddress(hL, "DeleteFileTransactedW");
	p[281] = GetProcAddress(hL, "DeleteFileW");
	p[282] = GetProcAddress(hL, "DeleteProcThreadAttributeList");
	p[283] = GetProcAddress(hL, "DeleteSynchronizationBarrier");
	p[284] = GetProcAddress(hL, "DeleteTimerQueue");
	p[285] = GetProcAddress(hL, "DeleteTimerQueueEx");
	p[286] = GetProcAddress(hL, "DeleteTimerQueueTimer");
	p[287] = GetProcAddress(hL, "DeleteUmsCompletionList");
	p[288] = GetProcAddress(hL, "DeleteUmsThreadContext");
	p[289] = GetProcAddress(hL, "DeleteVolumeMountPointA");
	p[290] = GetProcAddress(hL, "DeleteVolumeMountPointW");
	p[291] = GetProcAddress(hL, "DequeueUmsCompletionListItems");
	p[292] = GetProcAddress(hL, "DeviceIoControl");
	p[293] = GetProcAddress(hL, "DisableThreadLibraryCalls");
	p[294] = GetProcAddress(hL, "DisableThreadProfiling");
	p[295] = GetProcAddress(hL, "DisassociateCurrentThreadFromCallback");
	p[296] = GetProcAddress(hL, "DiscardVirtualMemory");
	p[297] = GetProcAddress(hL, "DisconnectNamedPipe");
	p[298] = GetProcAddress(hL, "DnsHostnameToComputerNameA");
	p[299] = GetProcAddress(hL, "DnsHostnameToComputerNameExW");
	p[300] = GetProcAddress(hL, "DnsHostnameToComputerNameW");
	p[301] = GetProcAddress(hL, "DosDateTimeToFileTime");
	p[302] = GetProcAddress(hL, "DosPathToSessionPathA");
	p[303] = GetProcAddress(hL, "DosPathToSessionPathW");
	p[304] = GetProcAddress(hL, "DuplicateConsoleHandle");
	p[305] = GetProcAddress(hL, "DuplicateEncryptionInfoFileExt");
	p[306] = GetProcAddress(hL, "DuplicateHandle");
	p[307] = GetProcAddress(hL, "EnableThreadProfiling");
	p[308] = GetProcAddress(hL, "EncodePointer");
	p[309] = GetProcAddress(hL, "EncodeSystemPointer");
	p[310] = GetProcAddress(hL, "EndUpdateResourceA");
	p[311] = GetProcAddress(hL, "EndUpdateResourceW");
	p[312] = GetProcAddress(hL, "EnterCriticalSection");
	p[313] = GetProcAddress(hL, "EnterSynchronizationBarrier");
	p[314] = GetProcAddress(hL, "EnterUmsSchedulingMode");
	p[315] = GetProcAddress(hL, "EnumCalendarInfoA");
	p[316] = GetProcAddress(hL, "EnumCalendarInfoExA");
	p[317] = GetProcAddress(hL, "EnumCalendarInfoExEx");
	p[318] = GetProcAddress(hL, "EnumCalendarInfoExW");
	p[319] = GetProcAddress(hL, "EnumCalendarInfoW");
	p[320] = GetProcAddress(hL, "EnumDateFormatsA");
	p[321] = GetProcAddress(hL, "EnumDateFormatsExA");
	p[322] = GetProcAddress(hL, "EnumDateFormatsExEx");
	p[323] = GetProcAddress(hL, "EnumDateFormatsExW");
	p[324] = GetProcAddress(hL, "EnumDateFormatsW");
	p[325] = GetProcAddress(hL, "EnumLanguageGroupLocalesA");
	p[326] = GetProcAddress(hL, "EnumLanguageGroupLocalesW");
	p[327] = GetProcAddress(hL, "EnumResourceLanguagesA");
	p[328] = GetProcAddress(hL, "EnumResourceLanguagesExA");
	p[329] = GetProcAddress(hL, "EnumResourceLanguagesExW");
	p[330] = GetProcAddress(hL, "EnumResourceLanguagesW");
	p[331] = GetProcAddress(hL, "EnumResourceNamesA");
	p[332] = GetProcAddress(hL, "EnumResourceNamesExA");
	p[333] = GetProcAddress(hL, "EnumResourceNamesExW");
	p[334] = GetProcAddress(hL, "EnumResourceNamesW");
	p[335] = GetProcAddress(hL, "EnumResourceTypesA");
	p[336] = GetProcAddress(hL, "EnumResourceTypesExA");
	p[337] = GetProcAddress(hL, "EnumResourceTypesExW");
	p[338] = GetProcAddress(hL, "EnumResourceTypesW");
	p[339] = GetProcAddress(hL, "EnumSystemCodePagesA");
	p[340] = GetProcAddress(hL, "EnumSystemCodePagesW");
	p[341] = GetProcAddress(hL, "EnumSystemFirmwareTables");
	p[342] = GetProcAddress(hL, "EnumSystemGeoID");
	p[343] = GetProcAddress(hL, "EnumSystemGeoNames");
	p[344] = GetProcAddress(hL, "EnumSystemLanguageGroupsA");
	p[345] = GetProcAddress(hL, "EnumSystemLanguageGroupsW");
	p[346] = GetProcAddress(hL, "EnumSystemLocalesA");
	p[347] = GetProcAddress(hL, "EnumSystemLocalesEx");
	p[348] = GetProcAddress(hL, "EnumSystemLocalesW");
	p[349] = GetProcAddress(hL, "EnumTimeFormatsA");
	p[350] = GetProcAddress(hL, "EnumTimeFormatsEx");
	p[351] = GetProcAddress(hL, "EnumTimeFormatsW");
	p[352] = GetProcAddress(hL, "EnumUILanguagesA");
	p[353] = GetProcAddress(hL, "EnumUILanguagesW");
	p[354] = GetProcAddress(hL, "EnumerateLocalComputerNamesA");
	p[355] = GetProcAddress(hL, "EnumerateLocalComputerNamesW");
	p[356] = GetProcAddress(hL, "EraseTape");
	p[357] = GetProcAddress(hL, "EscapeCommFunction");
	p[358] = GetProcAddress(hL, "ExecuteUmsThread");
	p[359] = GetProcAddress(hL, "ExitProcess");
	p[360] = GetProcAddress(hL, "ExitThread");
	p[361] = GetProcAddress(hL, "ExitVDM");
	p[362] = GetProcAddress(hL, "ExpandEnvironmentStringsA");
	p[363] = GetProcAddress(hL, "ExpandEnvironmentStringsW");
	p[364] = GetProcAddress(hL, "ExpungeConsoleCommandHistoryA");
	p[365] = GetProcAddress(hL, "ExpungeConsoleCommandHistoryW");
	p[366] = GetProcAddress(hL, "FatalAppExitA");
	p[367] = GetProcAddress(hL, "FatalAppExitW");
	p[368] = GetProcAddress(hL, "FatalExit");
	p[369] = GetProcAddress(hL, "FileTimeToDosDateTime");
	p[370] = GetProcAddress(hL, "FileTimeToLocalFileTime");
	p[371] = GetProcAddress(hL, "FileTimeToSystemTime");
	p[372] = GetProcAddress(hL, "FillConsoleOutputAttribute");
	p[373] = GetProcAddress(hL, "FillConsoleOutputCharacterA");
	p[374] = GetProcAddress(hL, "FillConsoleOutputCharacterW");
	p[375] = GetProcAddress(hL, "FindActCtxSectionGuid");
	p[376] = GetProcAddress(hL, "FindActCtxSectionGuidWorker");
	p[377] = GetProcAddress(hL, "FindActCtxSectionStringA");
	p[378] = GetProcAddress(hL, "FindActCtxSectionStringW");
	p[379] = GetProcAddress(hL, "FindActCtxSectionStringWWorker");
	p[380] = GetProcAddress(hL, "FindAtomA");
	p[381] = GetProcAddress(hL, "FindAtomW");
	p[382] = GetProcAddress(hL, "FindClose");
	p[383] = GetProcAddress(hL, "FindCloseChangeNotification");
	p[384] = GetProcAddress(hL, "FindFirstChangeNotificationA");
	p[385] = GetProcAddress(hL, "FindFirstChangeNotificationW");
	p[386] = GetProcAddress(hL, "FindFirstFileA");
	p[387] = GetProcAddress(hL, "FindFirstFileExA");
	p[388] = GetProcAddress(hL, "FindFirstFileExW");
	p[389] = GetProcAddress(hL, "FindFirstFileNameTransactedW");
	p[390] = GetProcAddress(hL, "FindFirstFileNameW");
	p[391] = GetProcAddress(hL, "FindFirstFileTransactedA");
	p[392] = GetProcAddress(hL, "FindFirstFileTransactedW");
	p[393] = GetProcAddress(hL, "FindFirstFileW");
	p[394] = GetProcAddress(hL, "FindFirstStreamTransactedW");
	p[395] = GetProcAddress(hL, "FindFirstStreamW");
	p[396] = GetProcAddress(hL, "FindFirstVolumeA");
	p[397] = GetProcAddress(hL, "FindFirstVolumeMountPointA");
	p[398] = GetProcAddress(hL, "FindFirstVolumeMountPointW");
	p[399] = GetProcAddress(hL, "FindFirstVolumeW");
	p[400] = GetProcAddress(hL, "FindNLSString");
	p[401] = GetProcAddress(hL, "FindNLSStringEx");
	p[402] = GetProcAddress(hL, "FindNextChangeNotification");
	p[403] = GetProcAddress(hL, "FindNextFileA");
	p[404] = GetProcAddress(hL, "FindNextFileNameW");
	p[405] = GetProcAddress(hL, "FindNextFileW");
	p[406] = GetProcAddress(hL, "FindNextStreamW");
	p[407] = GetProcAddress(hL, "FindNextVolumeA");
	p[408] = GetProcAddress(hL, "FindNextVolumeMountPointA");
	p[409] = GetProcAddress(hL, "FindNextVolumeMountPointW");
	p[410] = GetProcAddress(hL, "FindNextVolumeW");
	p[411] = GetProcAddress(hL, "FindPackagesByPackageFamily");
	p[412] = GetProcAddress(hL, "FindResourceA");
	p[413] = GetProcAddress(hL, "FindResourceExA");
	p[414] = GetProcAddress(hL, "FindResourceExW");
	p[415] = GetProcAddress(hL, "FindResourceW");
	p[416] = GetProcAddress(hL, "FindStringOrdinal");
	p[417] = GetProcAddress(hL, "FindVolumeClose");
	p[418] = GetProcAddress(hL, "FindVolumeMountPointClose");
	p[419] = GetProcAddress(hL, "FlsAlloc");
	p[420] = GetProcAddress(hL, "FlsFree");
	p[421] = GetProcAddress(hL, "FlsGetValue");
	p[422] = GetProcAddress(hL, "FlsSetValue");
	p[423] = GetProcAddress(hL, "FlushConsoleInputBuffer");
	p[424] = GetProcAddress(hL, "FlushFileBuffers");
	p[425] = GetProcAddress(hL, "FlushInstructionCache");
	p[426] = GetProcAddress(hL, "FlushProcessWriteBuffers");
	p[427] = GetProcAddress(hL, "FlushViewOfFile");
	p[428] = GetProcAddress(hL, "FoldStringA");
	p[429] = GetProcAddress(hL, "FoldStringW");
	p[430] = GetProcAddress(hL, "FormatApplicationUserModelId");
	p[431] = GetProcAddress(hL, "FormatMessageA");
	p[432] = GetProcAddress(hL, "FormatMessageW");
	p[433] = GetProcAddress(hL, "FreeConsole");
	p[434] = GetProcAddress(hL, "FreeEnvironmentStringsA");
	p[435] = GetProcAddress(hL, "FreeEnvironmentStringsW");
	p[436] = GetProcAddress(hL, "FreeLibrary");
	p[437] = GetProcAddress(hL, "FreeLibraryAndExitThread");
	p[438] = GetProcAddress(hL, "FreeLibraryWhenCallbackReturns");
	p[439] = GetProcAddress(hL, "FreeMemoryJobObject");
	p[440] = GetProcAddress(hL, "FreeResource");
	p[441] = GetProcAddress(hL, "FreeUserPhysicalPages");
	p[442] = GetProcAddress(hL, "GenerateConsoleCtrlEvent");
	p[443] = GetProcAddress(hL, "GetACP");
	p[444] = GetProcAddress(hL, "GetActiveProcessorCount");
	p[445] = GetProcAddress(hL, "GetActiveProcessorGroupCount");
	p[446] = GetProcAddress(hL, "GetAppContainerAce");
	p[447] = GetProcAddress(hL, "GetAppContainerNamedObjectPath");
	p[448] = GetProcAddress(hL, "GetApplicationRecoveryCallback");
	p[449] = GetProcAddress(hL, "GetApplicationRecoveryCallbackWorker");
	p[450] = GetProcAddress(hL, "GetApplicationRestartSettings");
	p[451] = GetProcAddress(hL, "GetApplicationRestartSettingsWorker");
	p[452] = GetProcAddress(hL, "GetApplicationUserModelId");
	p[453] = GetProcAddress(hL, "GetAtomNameA");
	p[454] = GetProcAddress(hL, "GetAtomNameW");
	p[455] = GetProcAddress(hL, "GetBinaryType");
	p[456] = GetProcAddress(hL, "GetBinaryTypeA");
	p[457] = GetProcAddress(hL, "GetBinaryTypeW");
	p[458] = GetProcAddress(hL, "GetCPInfo");
	p[459] = GetProcAddress(hL, "GetCPInfoExA");
	p[460] = GetProcAddress(hL, "GetCPInfoExW");
	p[461] = GetProcAddress(hL, "GetCachedSigningLevel");
	p[462] = GetProcAddress(hL, "GetCalendarDateFormat");
	p[463] = GetProcAddress(hL, "GetCalendarDateFormatEx");
	p[464] = GetProcAddress(hL, "GetCalendarDaysInMonth");
	p[465] = GetProcAddress(hL, "GetCalendarDifferenceInDays");
	p[466] = GetProcAddress(hL, "GetCalendarInfoA");
	p[467] = GetProcAddress(hL, "GetCalendarInfoEx");
	p[468] = GetProcAddress(hL, "GetCalendarInfoW");
	p[469] = GetProcAddress(hL, "GetCalendarMonthsInYear");
	p[470] = GetProcAddress(hL, "GetCalendarSupportedDateRange");
	p[471] = GetProcAddress(hL, "GetCalendarWeekNumber");
	p[472] = GetProcAddress(hL, "GetComPlusPackageInstallStatus");
	p[473] = GetProcAddress(hL, "GetCommConfig");
	p[474] = GetProcAddress(hL, "GetCommMask");
	p[475] = GetProcAddress(hL, "GetCommModemStatus");
	p[476] = GetProcAddress(hL, "GetCommProperties");
	p[477] = GetProcAddress(hL, "GetCommState");
	p[478] = GetProcAddress(hL, "GetCommTimeouts");
	p[479] = GetProcAddress(hL, "GetCommandLineA");
	p[480] = GetProcAddress(hL, "GetCommandLineW");
	p[481] = GetProcAddress(hL, "GetCompressedFileSizeA");
	p[482] = GetProcAddress(hL, "GetCompressedFileSizeTransactedA");
	p[483] = GetProcAddress(hL, "GetCompressedFileSizeTransactedW");
	p[484] = GetProcAddress(hL, "GetCompressedFileSizeW");
	p[485] = GetProcAddress(hL, "GetComputerNameA");
	p[486] = GetProcAddress(hL, "GetComputerNameExA");
	p[487] = GetProcAddress(hL, "GetComputerNameExW");
	p[488] = GetProcAddress(hL, "GetComputerNameW");
	p[489] = GetProcAddress(hL, "GetConsoleAliasA");
	p[490] = GetProcAddress(hL, "GetConsoleAliasExesA");
	p[491] = GetProcAddress(hL, "GetConsoleAliasExesLengthA");
	p[492] = GetProcAddress(hL, "GetConsoleAliasExesLengthW");
	p[493] = GetProcAddress(hL, "GetConsoleAliasExesW");
	p[494] = GetProcAddress(hL, "GetConsoleAliasW");
	p[495] = GetProcAddress(hL, "GetConsoleAliasesA");
	p[496] = GetProcAddress(hL, "GetConsoleAliasesLengthA");
	p[497] = GetProcAddress(hL, "GetConsoleAliasesLengthW");
	p[498] = GetProcAddress(hL, "GetConsoleAliasesW");
	p[499] = GetProcAddress(hL, "GetConsoleCP");
	p[500] = GetProcAddress(hL, "GetConsoleCharType");
	p[501] = GetProcAddress(hL, "GetConsoleCommandHistoryA");
	p[502] = GetProcAddress(hL, "GetConsoleCommandHistoryLengthA");
	p[503] = GetProcAddress(hL, "GetConsoleCommandHistoryLengthW");
	p[504] = GetProcAddress(hL, "GetConsoleCommandHistoryW");
	p[505] = GetProcAddress(hL, "GetConsoleCursorInfo");
	p[506] = GetProcAddress(hL, "GetConsoleCursorMode");
	p[507] = GetProcAddress(hL, "GetConsoleDisplayMode");
	p[508] = GetProcAddress(hL, "GetConsoleFontInfo");
	p[509] = GetProcAddress(hL, "GetConsoleFontSize");
	p[510] = GetProcAddress(hL, "GetConsoleHardwareState");
	p[511] = GetProcAddress(hL, "GetConsoleHistoryInfo");
	p[512] = GetProcAddress(hL, "GetConsoleInputExeNameA");
	p[513] = GetProcAddress(hL, "GetConsoleInputExeNameW");
	p[514] = GetProcAddress(hL, "GetConsoleInputWaitHandle");
	p[515] = GetProcAddress(hL, "GetConsoleKeyboardLayoutNameA");
	p[516] = GetProcAddress(hL, "GetConsoleKeyboardLayoutNameW");
	p[517] = GetProcAddress(hL, "GetConsoleMode");
	p[518] = GetProcAddress(hL, "GetConsoleNlsMode");
	p[519] = GetProcAddress(hL, "GetConsoleOriginalTitleA");
	p[520] = GetProcAddress(hL, "GetConsoleOriginalTitleW");
	p[521] = GetProcAddress(hL, "GetConsoleOutputCP");
	p[522] = GetProcAddress(hL, "GetConsoleProcessList");
	p[523] = GetProcAddress(hL, "GetConsoleScreenBufferInfo");
	p[524] = GetProcAddress(hL, "GetConsoleScreenBufferInfoEx");
	p[525] = GetProcAddress(hL, "GetConsoleSelectionInfo");
	p[526] = GetProcAddress(hL, "GetConsoleTitleA");
	p[527] = GetProcAddress(hL, "GetConsoleTitleW");
	p[528] = GetProcAddress(hL, "GetConsoleWindow");
	p[529] = GetProcAddress(hL, "GetCurrencyFormatA");
	p[530] = GetProcAddress(hL, "GetCurrencyFormatEx");
	p[531] = GetProcAddress(hL, "GetCurrencyFormatW");
	p[532] = GetProcAddress(hL, "GetCurrentActCtx");
	p[533] = GetProcAddress(hL, "GetCurrentActCtxWorker");
	p[534] = GetProcAddress(hL, "GetCurrentApplicationUserModelId");
	p[535] = GetProcAddress(hL, "GetCurrentConsoleFont");
	p[536] = GetProcAddress(hL, "GetCurrentConsoleFontEx");
	p[537] = GetProcAddress(hL, "GetCurrentDirectoryA");
	p[538] = GetProcAddress(hL, "GetCurrentDirectoryW");
	p[539] = GetProcAddress(hL, "GetCurrentPackageFamilyName");
	p[540] = GetProcAddress(hL, "GetCurrentPackageFullName");
	p[541] = GetProcAddress(hL, "GetCurrentPackageId");
	p[542] = GetProcAddress(hL, "GetCurrentPackageInfo");
	p[543] = GetProcAddress(hL, "GetCurrentPackagePath");
	p[544] = GetProcAddress(hL, "GetCurrentProcess");
	p[545] = GetProcAddress(hL, "GetCurrentProcessId");
	p[546] = GetProcAddress(hL, "GetCurrentProcessorNumber");
	p[547] = GetProcAddress(hL, "GetCurrentProcessorNumberEx");
	p[548] = GetProcAddress(hL, "GetCurrentThread");
	p[549] = GetProcAddress(hL, "GetCurrentThreadId");
	p[550] = GetProcAddress(hL, "GetCurrentThreadStackLimits");
	p[551] = GetProcAddress(hL, "GetCurrentUmsThread");
	p[552] = GetProcAddress(hL, "GetDateFormatA");
	p[553] = GetProcAddress(hL, "GetDateFormatAWorker");
	p[554] = GetProcAddress(hL, "GetDateFormatEx");
	p[555] = GetProcAddress(hL, "GetDateFormatW");
	p[556] = GetProcAddress(hL, "GetDateFormatWWorker");
	p[557] = GetProcAddress(hL, "GetDefaultCommConfigA");
	p[558] = GetProcAddress(hL, "GetDefaultCommConfigW");
	p[559] = GetProcAddress(hL, "GetDevicePowerState");
	p[560] = GetProcAddress(hL, "GetDiskFreeSpaceA");
	p[561] = GetProcAddress(hL, "GetDiskFreeSpaceExA");
	p[562] = GetProcAddress(hL, "GetDiskFreeSpaceExW");
	p[563] = GetProcAddress(hL, "GetDiskFreeSpaceW");
	p[564] = GetProcAddress(hL, "GetDiskSpaceInformationA");
	p[565] = GetProcAddress(hL, "GetDiskSpaceInformationW");
	p[566] = GetProcAddress(hL, "GetDllDirectoryA");
	p[567] = GetProcAddress(hL, "GetDllDirectoryW");
	p[568] = GetProcAddress(hL, "GetDriveTypeA");
	p[569] = GetProcAddress(hL, "GetDriveTypeW");
	p[570] = GetProcAddress(hL, "GetDurationFormat");
	p[571] = GetProcAddress(hL, "GetDurationFormatEx");
	p[572] = GetProcAddress(hL, "GetDynamicTimeZoneInformation");
	p[573] = GetProcAddress(hL, "GetEnabledXStateFeatures");
	p[574] = GetProcAddress(hL, "GetEncryptedFileVersionExt");
	p[575] = GetProcAddress(hL, "GetEnvironmentStrings");
	p[576] = GetProcAddress(hL, "GetEnvironmentStringsA");
	p[577] = GetProcAddress(hL, "GetEnvironmentStringsW");
	p[578] = GetProcAddress(hL, "GetEnvironmentVariableA");
	p[579] = GetProcAddress(hL, "GetEnvironmentVariableW");
	p[580] = GetProcAddress(hL, "GetEraNameCountedString");
	p[581] = GetProcAddress(hL, "GetErrorMode");
	p[582] = GetProcAddress(hL, "GetExitCodeProcess");
	p[583] = GetProcAddress(hL, "GetExitCodeThread");
	p[584] = GetProcAddress(hL, "GetExpandedNameA");
	p[585] = GetProcAddress(hL, "GetExpandedNameW");
	p[586] = GetProcAddress(hL, "GetFileAttributesA");
	p[587] = GetProcAddress(hL, "GetFileAttributesExA");
	p[588] = GetProcAddress(hL, "GetFileAttributesExW");
	p[589] = GetProcAddress(hL, "GetFileAttributesTransactedA");
	p[590] = GetProcAddress(hL, "GetFileAttributesTransactedW");
	p[591] = GetProcAddress(hL, "GetFileAttributesW");
	p[592] = GetProcAddress(hL, "GetFileBandwidthReservation");
	p[593] = GetProcAddress(hL, "GetFileInformationByHandle");
	p[594] = GetProcAddress(hL, "GetFileInformationByHandleEx");
	p[595] = GetProcAddress(hL, "GetFileMUIInfo");
	p[596] = GetProcAddress(hL, "GetFileMUIPath");
	p[597] = GetProcAddress(hL, "GetFileSize");
	p[598] = GetProcAddress(hL, "GetFileSizeEx");
	p[599] = GetProcAddress(hL, "GetFileTime");
	p[600] = GetProcAddress(hL, "GetFileType");
	p[601] = GetProcAddress(hL, "GetFinalPathNameByHandleA");
	p[602] = GetProcAddress(hL, "GetFinalPathNameByHandleW");
	p[603] = GetProcAddress(hL, "GetFirmwareEnvironmentVariableA");
	p[604] = GetProcAddress(hL, "GetFirmwareEnvironmentVariableExA");
	p[605] = GetProcAddress(hL, "GetFirmwareEnvironmentVariableExW");
	p[606] = GetProcAddress(hL, "GetFirmwareEnvironmentVariableW");
	p[607] = GetProcAddress(hL, "GetFirmwareType");
	p[608] = GetProcAddress(hL, "GetFullPathNameA");
	p[609] = GetProcAddress(hL, "GetFullPathNameTransactedA");
	p[610] = GetProcAddress(hL, "GetFullPathNameTransactedW");
	p[611] = GetProcAddress(hL, "GetFullPathNameW");
	p[612] = GetProcAddress(hL, "GetGeoInfoA");
	p[613] = GetProcAddress(hL, "GetGeoInfoEx");
	p[614] = GetProcAddress(hL, "GetGeoInfoW");
	p[615] = GetProcAddress(hL, "GetHandleInformation");
	p[616] = GetProcAddress(hL, "GetLargePageMinimum");
	p[617] = GetProcAddress(hL, "GetLargestConsoleWindowSize");
	p[618] = GetProcAddress(hL, "GetLastError");
	p[619] = GetProcAddress(hL, "GetLocalTime");
	p[620] = GetProcAddress(hL, "GetLocaleInfoA");
	p[621] = GetProcAddress(hL, "GetLocaleInfoEx");
	p[622] = GetProcAddress(hL, "GetLocaleInfoW");
	p[623] = GetProcAddress(hL, "GetLogicalDriveStringsA");
	p[624] = GetProcAddress(hL, "GetLogicalDriveStringsW");
	p[625] = GetProcAddress(hL, "GetLogicalDrives");
	p[626] = GetProcAddress(hL, "GetLogicalProcessorInformation");
	p[627] = GetProcAddress(hL, "GetLogicalProcessorInformationEx");
	p[628] = GetProcAddress(hL, "GetLongPathNameA");
	p[629] = GetProcAddress(hL, "GetLongPathNameTransactedA");
	p[630] = GetProcAddress(hL, "GetLongPathNameTransactedW");
	p[631] = GetProcAddress(hL, "GetLongPathNameW");
	p[632] = GetProcAddress(hL, "GetMailslotInfo");
	p[633] = GetProcAddress(hL, "GetMaximumProcessorCount");
	p[634] = GetProcAddress(hL, "GetMaximumProcessorGroupCount");
	p[635] = GetProcAddress(hL, "GetMemoryErrorHandlingCapabilities");
	p[636] = GetProcAddress(hL, "GetModuleFileNameA");
	p[637] = GetProcAddress(hL, "GetModuleFileNameW");
	p[638] = GetProcAddress(hL, "GetModuleHandleA");
	p[639] = GetProcAddress(hL, "GetModuleHandleExA");
	p[640] = GetProcAddress(hL, "GetModuleHandleExW");
	p[641] = GetProcAddress(hL, "GetModuleHandleW");
	p[642] = GetProcAddress(hL, "GetNLSVersion");
	p[643] = GetProcAddress(hL, "GetNLSVersionEx");
	p[644] = GetProcAddress(hL, "GetNamedPipeAttribute");
	p[645] = GetProcAddress(hL, "GetNamedPipeClientComputerNameA");
	p[646] = GetProcAddress(hL, "GetNamedPipeClientComputerNameW");
	p[647] = GetProcAddress(hL, "GetNamedPipeClientProcessId");
	p[648] = GetProcAddress(hL, "GetNamedPipeClientSessionId");
	p[649] = GetProcAddress(hL, "GetNamedPipeHandleStateA");
	p[650] = GetProcAddress(hL, "GetNamedPipeHandleStateW");
	p[651] = GetProcAddress(hL, "GetNamedPipeInfo");
	p[652] = GetProcAddress(hL, "GetNamedPipeServerProcessId");
	p[653] = GetProcAddress(hL, "GetNamedPipeServerSessionId");
	p[654] = GetProcAddress(hL, "GetNativeSystemInfo");
	p[655] = GetProcAddress(hL, "GetNextUmsListItem");
	p[656] = GetProcAddress(hL, "GetNextVDMCommand");
	p[657] = GetProcAddress(hL, "GetNumaAvailableMemoryNode");
	p[658] = GetProcAddress(hL, "GetNumaAvailableMemoryNodeEx");
	p[659] = GetProcAddress(hL, "GetNumaHighestNodeNumber");
	p[660] = GetProcAddress(hL, "GetNumaNodeNumberFromHandle");
	p[661] = GetProcAddress(hL, "GetNumaNodeProcessorMask");
	p[662] = GetProcAddress(hL, "GetNumaNodeProcessorMaskEx");
	p[663] = GetProcAddress(hL, "GetNumaProcessorNode");
	p[664] = GetProcAddress(hL, "GetNumaProcessorNodeEx");
	p[665] = GetProcAddress(hL, "GetNumaProximityNode");
	p[666] = GetProcAddress(hL, "GetNumaProximityNodeEx");
	p[667] = GetProcAddress(hL, "GetNumberFormatA");
	p[668] = GetProcAddress(hL, "GetNumberFormatEx");
	p[669] = GetProcAddress(hL, "GetNumberFormatW");
	p[670] = GetProcAddress(hL, "GetNumberOfConsoleFonts");
	p[671] = GetProcAddress(hL, "GetNumberOfConsoleInputEvents");
	p[672] = GetProcAddress(hL, "GetNumberOfConsoleMouseButtons");
	p[673] = GetProcAddress(hL, "GetOEMCP");
	p[674] = GetProcAddress(hL, "GetOverlappedResult");
	p[675] = GetProcAddress(hL, "GetOverlappedResultEx");
	p[676] = GetProcAddress(hL, "GetPackageApplicationIds");
	p[677] = GetProcAddress(hL, "GetPackageFamilyName");
	p[678] = GetProcAddress(hL, "GetPackageFullName");
	p[679] = GetProcAddress(hL, "GetPackageId");
	p[680] = GetProcAddress(hL, "GetPackageInfo");
	p[681] = GetProcAddress(hL, "GetPackagePath");
	p[682] = GetProcAddress(hL, "GetPackagePathByFullName");
	p[683] = GetProcAddress(hL, "GetPackagesByPackageFamily");
	p[684] = GetProcAddress(hL, "GetPhysicallyInstalledSystemMemory");
	p[685] = GetProcAddress(hL, "GetPriorityClass");
	p[686] = GetProcAddress(hL, "GetPrivateProfileIntA");
	p[687] = GetProcAddress(hL, "GetPrivateProfileIntW");
	p[688] = GetProcAddress(hL, "GetPrivateProfileSectionA");
	p[689] = GetProcAddress(hL, "GetPrivateProfileSectionNamesA");
	p[690] = GetProcAddress(hL, "GetPrivateProfileSectionNamesW");
	p[691] = GetProcAddress(hL, "GetPrivateProfileSectionW");
	p[692] = GetProcAddress(hL, "GetPrivateProfileStringA");
	p[693] = GetProcAddress(hL, "GetPrivateProfileStringW");
	p[694] = GetProcAddress(hL, "GetPrivateProfileStructA");
	p[695] = GetProcAddress(hL, "GetPrivateProfileStructW");
	p[696] = GetProcAddress(hL, "GetProcAddress");
	p[697] = GetProcAddress(hL, "GetProcessAffinityMask");
	p[698] = GetProcAddress(hL, "GetProcessDEPPolicy");
	p[699] = GetProcAddress(hL, "GetProcessDefaultCpuSets");
	p[700] = GetProcAddress(hL, "GetProcessGroupAffinity");
	p[701] = GetProcAddress(hL, "GetProcessHandleCount");
	p[702] = GetProcAddress(hL, "GetProcessHeap");
	p[703] = GetProcAddress(hL, "GetProcessHeaps");
	p[704] = GetProcAddress(hL, "GetProcessId");
	p[705] = GetProcAddress(hL, "GetProcessIdOfThread");
	p[706] = GetProcAddress(hL, "GetProcessInformation");
	p[707] = GetProcAddress(hL, "GetProcessIoCounters");
	p[708] = GetProcAddress(hL, "GetProcessMitigationPolicy");
	p[709] = GetProcAddress(hL, "GetProcessPreferredUILanguages");
	p[710] = GetProcAddress(hL, "GetProcessPriorityBoost");
	p[711] = GetProcAddress(hL, "GetProcessShutdownParameters");
	p[712] = GetProcAddress(hL, "GetProcessTimes");
	p[713] = GetProcAddress(hL, "GetProcessVersion");
	p[714] = GetProcAddress(hL, "GetProcessWorkingSetSize");
	p[715] = GetProcAddress(hL, "GetProcessWorkingSetSizeEx");
	p[716] = GetProcAddress(hL, "GetProcessorSystemCycleTime");
	p[717] = GetProcAddress(hL, "GetProductInfo");
	p[718] = GetProcAddress(hL, "GetProfileIntA");
	p[719] = GetProcAddress(hL, "GetProfileIntW");
	p[720] = GetProcAddress(hL, "GetProfileSectionA");
	p[721] = GetProcAddress(hL, "GetProfileSectionW");
	p[722] = GetProcAddress(hL, "GetProfileStringA");
	p[723] = GetProcAddress(hL, "GetProfileStringW");
	p[724] = GetProcAddress(hL, "GetQueuedCompletionStatus");
	p[725] = GetProcAddress(hL, "GetQueuedCompletionStatusEx");
	p[726] = GetProcAddress(hL, "GetShortPathNameA");
	p[727] = GetProcAddress(hL, "GetShortPathNameW");
	p[728] = GetProcAddress(hL, "GetStagedPackagePathByFullName");
	p[729] = GetProcAddress(hL, "GetStartupInfoA");
	p[730] = GetProcAddress(hL, "GetStartupInfoW");
	p[731] = GetProcAddress(hL, "GetStateFolder");
	p[732] = GetProcAddress(hL, "GetStdHandle");
	p[733] = GetProcAddress(hL, "GetStringScripts");
	p[734] = GetProcAddress(hL, "GetStringTypeA");
	p[735] = GetProcAddress(hL, "GetStringTypeExA");
	p[736] = GetProcAddress(hL, "GetStringTypeExW");
	p[737] = GetProcAddress(hL, "GetStringTypeW");
	p[738] = GetProcAddress(hL, "GetSystemAppDataKey");
	p[739] = GetProcAddress(hL, "GetSystemCpuSetInformation");
	p[740] = GetProcAddress(hL, "GetSystemDEPPolicy");
	p[741] = GetProcAddress(hL, "GetSystemDefaultLCID");
	p[742] = GetProcAddress(hL, "GetSystemDefaultLangID");
	p[743] = GetProcAddress(hL, "GetSystemDefaultLocaleName");
	p[744] = GetProcAddress(hL, "GetSystemDefaultUILanguage");
	p[745] = GetProcAddress(hL, "GetSystemDirectoryA");
	p[746] = GetProcAddress(hL, "GetSystemDirectoryW");
	p[747] = GetProcAddress(hL, "GetSystemFileCacheSize");
	p[748] = GetProcAddress(hL, "GetSystemFirmwareTable");
	p[749] = GetProcAddress(hL, "GetSystemInfo");
	p[750] = GetProcAddress(hL, "GetSystemPowerStatus");
	p[751] = GetProcAddress(hL, "GetSystemPreferredUILanguages");
	p[752] = GetProcAddress(hL, "GetSystemRegistryQuota");
	p[753] = GetProcAddress(hL, "GetSystemTime");
	p[754] = GetProcAddress(hL, "GetSystemTimeAdjustment");
	p[755] = GetProcAddress(hL, "GetSystemTimeAsFileTime");
	p[756] = GetProcAddress(hL, "GetSystemTimePreciseAsFileTime");
	p[757] = GetProcAddress(hL, "GetSystemTimes");
	p[758] = GetProcAddress(hL, "GetSystemWindowsDirectoryA");
	p[759] = GetProcAddress(hL, "GetSystemWindowsDirectoryW");
	p[760] = GetProcAddress(hL, "GetSystemWow64DirectoryA");
	p[761] = GetProcAddress(hL, "GetSystemWow64DirectoryW");
	p[762] = GetProcAddress(hL, "GetTapeParameters");
	p[763] = GetProcAddress(hL, "GetTapePosition");
	p[764] = GetProcAddress(hL, "GetTapeStatus");
	p[765] = GetProcAddress(hL, "GetTempFileNameA");
	p[766] = GetProcAddress(hL, "GetTempFileNameW");
	p[767] = GetProcAddress(hL, "GetTempPathA");
	p[768] = GetProcAddress(hL, "GetTempPathW");
	p[769] = GetProcAddress(hL, "GetThreadContext");
	p[770] = GetProcAddress(hL, "GetThreadDescription");
	p[771] = GetProcAddress(hL, "GetThreadErrorMode");
	p[772] = GetProcAddress(hL, "GetThreadGroupAffinity");
	p[773] = GetProcAddress(hL, "GetThreadIOPendingFlag");
	p[774] = GetProcAddress(hL, "GetThreadId");
	p[775] = GetProcAddress(hL, "GetThreadIdealProcessorEx");
	p[776] = GetProcAddress(hL, "GetThreadInformation");
	p[777] = GetProcAddress(hL, "GetThreadLocale");
	p[778] = GetProcAddress(hL, "GetThreadPreferredUILanguages");
	p[779] = GetProcAddress(hL, "GetThreadPriority");
	p[780] = GetProcAddress(hL, "GetThreadPriorityBoost");
	p[781] = GetProcAddress(hL, "GetThreadSelectedCpuSets");
	p[782] = GetProcAddress(hL, "GetThreadSelectorEntry");
	p[783] = GetProcAddress(hL, "GetThreadTimes");
	p[784] = GetProcAddress(hL, "GetThreadUILanguage");
	p[785] = GetProcAddress(hL, "GetTickCount");
	p[786] = GetProcAddress(hL, "GetTickCount64");
	p[787] = GetProcAddress(hL, "GetTimeFormatA");
	p[788] = GetProcAddress(hL, "GetTimeFormatAWorker");
	p[789] = GetProcAddress(hL, "GetTimeFormatEx");
	p[790] = GetProcAddress(hL, "GetTimeFormatW");
	p[791] = GetProcAddress(hL, "GetTimeFormatWWorker");
	p[792] = GetProcAddress(hL, "GetTimeZoneInformation");
	p[793] = GetProcAddress(hL, "GetTimeZoneInformationForYear");
	p[794] = GetProcAddress(hL, "GetUILanguageInfo");
	p[795] = GetProcAddress(hL, "GetUmsCompletionListEvent");
	p[796] = GetProcAddress(hL, "GetUmsSystemThreadInformation");
	p[797] = GetProcAddress(hL, "GetUserDefaultGeoName");
	p[798] = GetProcAddress(hL, "GetUserDefaultLCID");
	p[799] = GetProcAddress(hL, "GetUserDefaultLangID");
	p[800] = GetProcAddress(hL, "GetUserDefaultLocaleName");
	p[801] = GetProcAddress(hL, "GetUserDefaultUILanguage");
	p[802] = GetProcAddress(hL, "GetUserGeoID");
	p[803] = GetProcAddress(hL, "GetUserPreferredUILanguages");
	p[804] = GetProcAddress(hL, "GetVDMCurrentDirectories");
	p[805] = GetProcAddress(hL, "GetVersion");
	p[806] = GetProcAddress(hL, "GetVersionExA");
	p[807] = GetProcAddress(hL, "GetVersionExW");
	p[808] = GetProcAddress(hL, "GetVolumeInformationA");
	p[809] = GetProcAddress(hL, "GetVolumeInformationByHandleW");
	p[810] = GetProcAddress(hL, "GetVolumeInformationW");
	p[811] = GetProcAddress(hL, "GetVolumeNameForVolumeMountPointA");
	p[812] = GetProcAddress(hL, "GetVolumeNameForVolumeMountPointW");
	p[813] = GetProcAddress(hL, "GetVolumePathNameA");
	p[814] = GetProcAddress(hL, "GetVolumePathNameW");
	p[815] = GetProcAddress(hL, "GetVolumePathNamesForVolumeNameA");
	p[816] = GetProcAddress(hL, "GetVolumePathNamesForVolumeNameW");
	p[817] = GetProcAddress(hL, "GetWindowsDirectoryA");
	p[818] = GetProcAddress(hL, "GetWindowsDirectoryW");
	p[819] = GetProcAddress(hL, "GetWriteWatch");
	p[820] = GetProcAddress(hL, "GetXStateFeaturesMask");
	p[821] = GetProcAddress(hL, "GlobalAddAtomA");
	p[822] = GetProcAddress(hL, "GlobalAddAtomExA");
	p[823] = GetProcAddress(hL, "GlobalAddAtomExW");
	p[824] = GetProcAddress(hL, "GlobalAddAtomW");
	p[825] = GetProcAddress(hL, "GlobalAlloc");
	p[826] = GetProcAddress(hL, "GlobalCompact");
	p[827] = GetProcAddress(hL, "GlobalDeleteAtom");
	p[828] = GetProcAddress(hL, "GlobalFindAtomA");
	p[829] = GetProcAddress(hL, "GlobalFindAtomW");
	p[830] = GetProcAddress(hL, "GlobalFix");
	p[831] = GetProcAddress(hL, "GlobalFlags");
	p[832] = GetProcAddress(hL, "GlobalFree");
	p[833] = GetProcAddress(hL, "GlobalGetAtomNameA");
	p[834] = GetProcAddress(hL, "GlobalGetAtomNameW");
	p[835] = GetProcAddress(hL, "GlobalHandle");
	p[836] = GetProcAddress(hL, "GlobalLock");
	p[837] = GetProcAddress(hL, "GlobalMemoryStatus");
	p[838] = GetProcAddress(hL, "GlobalMemoryStatusEx");
	p[839] = GetProcAddress(hL, "GlobalReAlloc");
	p[840] = GetProcAddress(hL, "GlobalSize");
	p[841] = GetProcAddress(hL, "GlobalUnWire");
	p[842] = GetProcAddress(hL, "GlobalUnfix");
	p[843] = GetProcAddress(hL, "GlobalUnlock");
	p[844] = GetProcAddress(hL, "GlobalWire");
	p[845] = GetProcAddress(hL, "Heap32First");
	p[846] = GetProcAddress(hL, "Heap32ListFirst");
	p[847] = GetProcAddress(hL, "Heap32ListNext");
	p[848] = GetProcAddress(hL, "Heap32Next");
	p[849] = GetProcAddress(hL, "HeapAlloc");
	p[850] = GetProcAddress(hL, "HeapCompact");
	p[851] = GetProcAddress(hL, "HeapCreate");
	p[852] = GetProcAddress(hL, "HeapDestroy");
	p[853] = GetProcAddress(hL, "HeapFree");
	p[854] = GetProcAddress(hL, "HeapLock");
	p[855] = GetProcAddress(hL, "HeapQueryInformation");
	p[856] = GetProcAddress(hL, "HeapReAlloc");
	p[857] = GetProcAddress(hL, "HeapSetInformation");
	p[858] = GetProcAddress(hL, "HeapSize");
	p[859] = GetProcAddress(hL, "HeapSummary");
	p[860] = GetProcAddress(hL, "HeapUnlock");
	p[861] = GetProcAddress(hL, "HeapValidate");
	p[862] = GetProcAddress(hL, "HeapWalk");
	p[863] = GetProcAddress(hL, "IdnToAscii");
	p[864] = GetProcAddress(hL, "IdnToNameprepUnicode");
	p[865] = GetProcAddress(hL, "IdnToUnicode");
	p[866] = GetProcAddress(hL, "InitAtomTable");
	p[867] = GetProcAddress(hL, "InitOnceBeginInitialize");
	p[868] = GetProcAddress(hL, "InitOnceComplete");
	p[869] = GetProcAddress(hL, "InitOnceExecuteOnce");
	p[870] = GetProcAddress(hL, "InitOnceInitialize");
	p[871] = GetProcAddress(hL, "InitializeConditionVariable");
	p[872] = GetProcAddress(hL, "InitializeContext");
	p[873] = GetProcAddress(hL, "InitializeContext2");
	p[874] = GetProcAddress(hL, "InitializeCriticalSection");
	p[875] = GetProcAddress(hL, "InitializeCriticalSectionAndSpinCount");
	p[876] = GetProcAddress(hL, "InitializeCriticalSectionEx");
	p[877] = GetProcAddress(hL, "InitializeEnclave");
	p[878] = GetProcAddress(hL, "InitializeProcThreadAttributeList");
	p[879] = GetProcAddress(hL, "InitializeSListHead");
	p[880] = GetProcAddress(hL, "InitializeSRWLock");
	p[881] = GetProcAddress(hL, "InitializeSynchronizationBarrier");
	p[882] = GetProcAddress(hL, "InstallELAMCertificateInfo");
	p[883] = GetProcAddress(hL, "InterlockedFlushSList");
	p[884] = GetProcAddress(hL, "InterlockedPopEntrySList");
	p[885] = GetProcAddress(hL, "InterlockedPushEntrySList");
	p[886] = GetProcAddress(hL, "InterlockedPushListSList");
	p[887] = GetProcAddress(hL, "InterlockedPushListSListEx");
	p[888] = GetProcAddress(hL, "InvalidateConsoleDIBits");
	p[889] = GetProcAddress(hL, "IsBadCodePtr");
	p[890] = GetProcAddress(hL, "IsBadHugeReadPtr");
	p[891] = GetProcAddress(hL, "IsBadHugeWritePtr");
	p[892] = GetProcAddress(hL, "IsBadReadPtr");
	p[893] = GetProcAddress(hL, "IsBadStringPtrA");
	p[894] = GetProcAddress(hL, "IsBadStringPtrW");
	p[895] = GetProcAddress(hL, "IsBadWritePtr");
	p[896] = GetProcAddress(hL, "IsCalendarLeapDay");
	p[897] = GetProcAddress(hL, "IsCalendarLeapMonth");
	p[898] = GetProcAddress(hL, "IsCalendarLeapYear");
	p[899] = GetProcAddress(hL, "IsDBCSLeadByte");
	p[900] = GetProcAddress(hL, "IsDBCSLeadByteEx");
	p[901] = GetProcAddress(hL, "IsDebuggerPresent");
	p[902] = GetProcAddress(hL, "IsEnclaveTypeSupported");
	p[903] = GetProcAddress(hL, "IsNLSDefinedString");
	p[904] = GetProcAddress(hL, "IsNativeVhdBoot");
	p[905] = GetProcAddress(hL, "IsNormalizedString");
	p[906] = GetProcAddress(hL, "IsProcessCritical");
	p[907] = GetProcAddress(hL, "IsProcessInJob");
	p[908] = GetProcAddress(hL, "IsProcessorFeaturePresent");
	p[909] = GetProcAddress(hL, "IsSystemResumeAutomatic");
	p[910] = GetProcAddress(hL, "IsThreadAFiber");
	p[911] = GetProcAddress(hL, "IsThreadpoolTimerSet");
	p[912] = GetProcAddress(hL, "IsUserCetAvailableInEnvironment");
	p[913] = GetProcAddress(hL, "IsValidCalDateTime");
	p[914] = GetProcAddress(hL, "IsValidCodePage");
	p[915] = GetProcAddress(hL, "IsValidLanguageGroup");
	p[916] = GetProcAddress(hL, "IsValidLocale");
	p[917] = GetProcAddress(hL, "IsValidLocaleName");
	p[918] = GetProcAddress(hL, "IsValidNLSVersion");
	p[919] = GetProcAddress(hL, "IsWow64GuestMachineSupported");
	p[920] = GetProcAddress(hL, "IsWow64Process");
	p[921] = GetProcAddress(hL, "IsWow64Process2");
	p[922] = GetProcAddress(hL, "K32EmptyWorkingSet");
	p[923] = GetProcAddress(hL, "K32EnumDeviceDrivers");
	p[924] = GetProcAddress(hL, "K32EnumPageFilesA");
	p[925] = GetProcAddress(hL, "K32EnumPageFilesW");
	p[926] = GetProcAddress(hL, "K32EnumProcessModules");
	p[927] = GetProcAddress(hL, "K32EnumProcessModulesEx");
	p[928] = GetProcAddress(hL, "K32EnumProcesses");
	p[929] = GetProcAddress(hL, "K32GetDeviceDriverBaseNameA");
	p[930] = GetProcAddress(hL, "K32GetDeviceDriverBaseNameW");
	p[931] = GetProcAddress(hL, "K32GetDeviceDriverFileNameA");
	p[932] = GetProcAddress(hL, "K32GetDeviceDriverFileNameW");
	p[933] = GetProcAddress(hL, "K32GetMappedFileNameA");
	p[934] = GetProcAddress(hL, "K32GetMappedFileNameW");
	p[935] = GetProcAddress(hL, "K32GetModuleBaseNameA");
	p[936] = GetProcAddress(hL, "K32GetModuleBaseNameW");
	p[937] = GetProcAddress(hL, "K32GetModuleFileNameExA");
	p[938] = GetProcAddress(hL, "K32GetModuleFileNameExW");
	p[939] = GetProcAddress(hL, "K32GetModuleInformation");
	p[940] = GetProcAddress(hL, "K32GetPerformanceInfo");
	p[941] = GetProcAddress(hL, "K32GetProcessImageFileNameA");
	p[942] = GetProcAddress(hL, "K32GetProcessImageFileNameW");
	p[943] = GetProcAddress(hL, "K32GetProcessMemoryInfo");
	p[944] = GetProcAddress(hL, "K32GetWsChanges");
	p[945] = GetProcAddress(hL, "K32GetWsChangesEx");
	p[946] = GetProcAddress(hL, "K32InitializeProcessForWsWatch");
	p[947] = GetProcAddress(hL, "K32QueryWorkingSet");
	p[948] = GetProcAddress(hL, "K32QueryWorkingSetEx");
	p[949] = GetProcAddress(hL, "LCIDToLocaleName");
	p[950] = GetProcAddress(hL, "LCMapStringA");
	p[951] = GetProcAddress(hL, "LCMapStringEx");
	p[952] = GetProcAddress(hL, "LCMapStringW");
	p[953] = GetProcAddress(hL, "LZClose");
	p[954] = GetProcAddress(hL, "LZCloseFile");
	p[955] = GetProcAddress(hL, "LZCopy");
	p[956] = GetProcAddress(hL, "LZCreateFileW");
	p[957] = GetProcAddress(hL, "LZDone");
	p[958] = GetProcAddress(hL, "LZInit");
	p[959] = GetProcAddress(hL, "LZOpenFileA");
	p[960] = GetProcAddress(hL, "LZOpenFileW");
	p[961] = GetProcAddress(hL, "LZRead");
	p[962] = GetProcAddress(hL, "LZSeek");
	p[963] = GetProcAddress(hL, "LZStart");
	p[964] = GetProcAddress(hL, "LeaveCriticalSection");
	p[965] = GetProcAddress(hL, "LeaveCriticalSectionWhenCallbackReturns");
	p[966] = GetProcAddress(hL, "LoadAppInitDlls");
	p[967] = GetProcAddress(hL, "LoadEnclaveData");
	p[968] = GetProcAddress(hL, "LoadLibraryA");
	p[969] = GetProcAddress(hL, "LoadLibraryExA");
	p[970] = GetProcAddress(hL, "LoadLibraryExW");
	p[971] = GetProcAddress(hL, "LoadLibraryW");
	p[972] = GetProcAddress(hL, "LoadModule");
	p[973] = GetProcAddress(hL, "LoadPackagedLibrary");
	p[974] = GetProcAddress(hL, "LoadResource");
	p[975] = GetProcAddress(hL, "LoadStringBaseExW");
	p[976] = GetProcAddress(hL, "LoadStringBaseW");
	p[977] = GetProcAddress(hL, "LocalAlloc");
	p[978] = GetProcAddress(hL, "LocalCompact");
	p[979] = GetProcAddress(hL, "LocalFileTimeToFileTime");
	p[980] = GetProcAddress(hL, "LocalFileTimeToLocalSystemTime");
	p[981] = GetProcAddress(hL, "LocalFlags");
	p[982] = GetProcAddress(hL, "LocalFree");
	p[983] = GetProcAddress(hL, "LocalHandle");
	p[984] = GetProcAddress(hL, "LocalLock");
	p[985] = GetProcAddress(hL, "LocalReAlloc");
	p[986] = GetProcAddress(hL, "LocalShrink");
	p[987] = GetProcAddress(hL, "LocalSize");
	p[988] = GetProcAddress(hL, "LocalSystemTimeToLocalFileTime");
	p[989] = GetProcAddress(hL, "LocalUnlock");
	p[990] = GetProcAddress(hL, "LocaleNameToLCID");
	p[991] = GetProcAddress(hL, "LocateXStateFeature");
	p[992] = GetProcAddress(hL, "LockFile");
	p[993] = GetProcAddress(hL, "LockFileEx");
	p[994] = GetProcAddress(hL, "LockResource");
	p[995] = GetProcAddress(hL, "MapUserPhysicalPages");
	p[996] = GetProcAddress(hL, "MapUserPhysicalPagesScatter");
	p[997] = GetProcAddress(hL, "MapViewOfFile");
	p[998] = GetProcAddress(hL, "MapViewOfFileEx");
	p[999] = GetProcAddress(hL, "MapViewOfFileExNuma");
	p[1000] = GetProcAddress(hL, "MapViewOfFileFromApp");
	p[1001] = GetProcAddress(hL, "Module32First");
	p[1002] = GetProcAddress(hL, "Module32FirstW");
	p[1003] = GetProcAddress(hL, "Module32Next");
	p[1004] = GetProcAddress(hL, "Module32NextW");
	p[1005] = GetProcAddress(hL, "MoveFileA");
	p[1006] = GetProcAddress(hL, "MoveFileExA");
	p[1007] = GetProcAddress(hL, "MoveFileExW");
	p[1008] = GetProcAddress(hL, "MoveFileTransactedA");
	p[1009] = GetProcAddress(hL, "MoveFileTransactedW");
	p[1010] = GetProcAddress(hL, "MoveFileW");
	p[1011] = GetProcAddress(hL, "MoveFileWithProgressA");
	p[1012] = GetProcAddress(hL, "MoveFileWithProgressW");
	p[1013] = GetProcAddress(hL, "MulDiv");
	p[1014] = GetProcAddress(hL, "MultiByteToWideChar");
	p[1015] = GetProcAddress(hL, "NeedCurrentDirectoryForExePathA");
	p[1016] = GetProcAddress(hL, "NeedCurrentDirectoryForExePathW");
	p[1017] = GetProcAddress(hL, "NlsCheckPolicy");
	p[1018] = GetProcAddress(hL, "NlsGetCacheUpdateCount");
	p[1019] = GetProcAddress(hL, "NlsUpdateLocale");
	p[1020] = GetProcAddress(hL, "NlsUpdateSystemLocale");
	p[1021] = GetProcAddress(hL, "NormalizeString");
	p[1022] = GetProcAddress(hL, "NotifyMountMgr");
	p[1023] = GetProcAddress(hL, "NotifyUILanguageChange");
	p[1024] = GetProcAddress(hL, "NtVdm64CreateProcessInternalW");
	p[1025] = GetProcAddress(hL, "OOBEComplete");
	p[1026] = GetProcAddress(hL, "OfferVirtualMemory");
	p[1027] = GetProcAddress(hL, "OpenConsoleW");
	p[1028] = GetProcAddress(hL, "OpenConsoleWStub");
	p[1029] = GetProcAddress(hL, "OpenEventA");
	p[1030] = GetProcAddress(hL, "OpenEventW");
	p[1031] = GetProcAddress(hL, "OpenFile");
	p[1032] = GetProcAddress(hL, "OpenFileById");
	p[1033] = GetProcAddress(hL, "OpenFileMappingA");
	p[1034] = GetProcAddress(hL, "OpenFileMappingW");
	p[1035] = GetProcAddress(hL, "OpenJobObjectA");
	p[1036] = GetProcAddress(hL, "OpenJobObjectW");
	p[1037] = GetProcAddress(hL, "OpenMutexA");
	p[1038] = GetProcAddress(hL, "OpenMutexW");
	p[1039] = GetProcAddress(hL, "OpenPackageInfoByFullName");
	p[1040] = GetProcAddress(hL, "OpenPrivateNamespaceA");
	p[1041] = GetProcAddress(hL, "OpenPrivateNamespaceW");
	p[1042] = GetProcAddress(hL, "OpenProcess");
	p[1043] = GetProcAddress(hL, "OpenProcessToken");
	p[1044] = GetProcAddress(hL, "OpenProfileUserMapping");
	p[1045] = GetProcAddress(hL, "OpenSemaphoreA");
	p[1046] = GetProcAddress(hL, "OpenSemaphoreW");
	p[1047] = GetProcAddress(hL, "OpenState");
	p[1048] = GetProcAddress(hL, "OpenStateExplicit");
	p[1049] = GetProcAddress(hL, "OpenThread");
	p[1050] = GetProcAddress(hL, "OpenThreadToken");
	p[1051] = GetProcAddress(hL, "OpenWaitableTimerA");
	p[1052] = GetProcAddress(hL, "OpenWaitableTimerW");
	p[1053] = GetProcAddress(hL, "OutputDebugStringA");
	p[1054] = GetProcAddress(hL, "OutputDebugStringW");
	p[1055] = GetProcAddress(hL, "PackageFamilyNameFromFullName");
	p[1056] = GetProcAddress(hL, "PackageFamilyNameFromId");
	p[1057] = GetProcAddress(hL, "PackageFullNameFromId");
	p[1058] = GetProcAddress(hL, "PackageIdFromFullName");
	p[1059] = GetProcAddress(hL, "PackageNameAndPublisherIdFromFamilyName");
	p[1060] = GetProcAddress(hL, "ParseApplicationUserModelId");
	p[1061] = GetProcAddress(hL, "PeekConsoleInputA");
	p[1062] = GetProcAddress(hL, "PeekConsoleInputW");
	p[1063] = GetProcAddress(hL, "PeekNamedPipe");
	p[1064] = GetProcAddress(hL, "PostQueuedCompletionStatus");
	p[1065] = GetProcAddress(hL, "PowerClearRequest");
	p[1066] = GetProcAddress(hL, "PowerCreateRequest");
	p[1067] = GetProcAddress(hL, "PowerSetRequest");
	p[1068] = GetProcAddress(hL, "PrefetchVirtualMemory");
	p[1069] = GetProcAddress(hL, "PrepareTape");
	p[1070] = GetProcAddress(hL, "PrivCopyFileExW");
	p[1071] = GetProcAddress(hL, "PrivMoveFileIdentityW");
	p[1072] = GetProcAddress(hL, "Process32First");
	p[1073] = GetProcAddress(hL, "Process32FirstW");
	p[1074] = GetProcAddress(hL, "Process32Next");
	p[1075] = GetProcAddress(hL, "Process32NextW");
	p[1076] = GetProcAddress(hL, "ProcessIdToSessionId");
	p[1077] = GetProcAddress(hL, "PssCaptureSnapshot");
	p[1078] = GetProcAddress(hL, "PssDuplicateSnapshot");
	p[1079] = GetProcAddress(hL, "PssFreeSnapshot");
	p[1080] = GetProcAddress(hL, "PssQuerySnapshot");
	p[1081] = GetProcAddress(hL, "PssWalkMarkerCreate");
	p[1082] = GetProcAddress(hL, "PssWalkMarkerFree");
	p[1083] = GetProcAddress(hL, "PssWalkMarkerGetPosition");
	p[1084] = GetProcAddress(hL, "PssWalkMarkerRewind");
	p[1085] = GetProcAddress(hL, "PssWalkMarkerSeek");
	p[1086] = GetProcAddress(hL, "PssWalkMarkerSeekToBeginning");
	p[1087] = GetProcAddress(hL, "PssWalkMarkerSetPosition");
	p[1088] = GetProcAddress(hL, "PssWalkMarkerTell");
	p[1089] = GetProcAddress(hL, "PssWalkSnapshot");
	p[1090] = GetProcAddress(hL, "PulseEvent");
	p[1091] = GetProcAddress(hL, "PurgeComm");
	p[1092] = GetProcAddress(hL, "QueryActCtxSettingsW");
	p[1093] = GetProcAddress(hL, "QueryActCtxSettingsWWorker");
	p[1094] = GetProcAddress(hL, "QueryActCtxW");
	p[1095] = GetProcAddress(hL, "QueryActCtxWWorker");
	p[1096] = GetProcAddress(hL, "QueryDepthSList");
	p[1097] = GetProcAddress(hL, "QueryDosDeviceA");
	p[1098] = GetProcAddress(hL, "QueryDosDeviceW");
	p[1099] = GetProcAddress(hL, "QueryFullProcessImageNameA");
	p[1100] = GetProcAddress(hL, "QueryFullProcessImageNameW");
	p[1101] = GetProcAddress(hL, "QueryIdleProcessorCycleTime");
	p[1102] = GetProcAddress(hL, "QueryIdleProcessorCycleTimeEx");
	p[1103] = GetProcAddress(hL, "QueryInformationJobObject");
	p[1104] = GetProcAddress(hL, "QueryIoRateControlInformationJobObject");
	p[1105] = GetProcAddress(hL, "QueryMemoryResourceNotification");
	p[1106] = GetProcAddress(hL, "QueryPerformanceCounter");
	p[1107] = GetProcAddress(hL, "QueryPerformanceFrequency");
	p[1108] = GetProcAddress(hL, "QueryProcessAffinityUpdateMode");
	p[1109] = GetProcAddress(hL, "QueryProcessCycleTime");
	p[1110] = GetProcAddress(hL, "QueryProtectedPolicy");
	p[1111] = GetProcAddress(hL, "QueryThreadCycleTime");
	p[1112] = GetProcAddress(hL, "QueryThreadProfiling");
	p[1113] = GetProcAddress(hL, "QueryThreadpoolStackInformation");
	p[1114] = GetProcAddress(hL, "QueryUmsThreadInformation");
	p[1115] = GetProcAddress(hL, "QueryUnbiasedInterruptTime");
	p[1116] = GetProcAddress(hL, "QueueUserAPC");
	p[1117] = GetProcAddress(hL, "QueueUserWorkItem");
	p[1118] = GetProcAddress(hL, "QuirkGetData2Worker");
	p[1119] = GetProcAddress(hL, "QuirkGetDataWorker");
	p[1120] = GetProcAddress(hL, "QuirkIsEnabled2Worker");
	p[1121] = GetProcAddress(hL, "QuirkIsEnabled3Worker");
	p[1122] = GetProcAddress(hL, "QuirkIsEnabledForPackage2Worker");
	p[1123] = GetProcAddress(hL, "QuirkIsEnabledForPackage3Worker");
	p[1124] = GetProcAddress(hL, "QuirkIsEnabledForPackage4Worker");
	p[1125] = GetProcAddress(hL, "QuirkIsEnabledForPackageWorker");
	p[1126] = GetProcAddress(hL, "QuirkIsEnabledForProcessWorker");
	p[1127] = GetProcAddress(hL, "QuirkIsEnabledWorker");
	p[1128] = GetProcAddress(hL, "RaiseException");
	p[1129] = GetProcAddress(hL, "RaiseFailFastException");
	p[1130] = GetProcAddress(hL, "RaiseInvalid16BitExeError");
	p[1131] = GetProcAddress(hL, "ReOpenFile");
	p[1132] = GetProcAddress(hL, "ReadConsoleA");
	p[1133] = GetProcAddress(hL, "ReadConsoleInputA");
	p[1134] = GetProcAddress(hL, "ReadConsoleInputExA");
	p[1135] = GetProcAddress(hL, "ReadConsoleInputExW");
	p[1136] = GetProcAddress(hL, "ReadConsoleInputW");
	p[1137] = GetProcAddress(hL, "ReadConsoleOutputA");
	p[1138] = GetProcAddress(hL, "ReadConsoleOutputAttribute");
	p[1139] = GetProcAddress(hL, "ReadConsoleOutputCharacterA");
	p[1140] = GetProcAddress(hL, "ReadConsoleOutputCharacterW");
	p[1141] = GetProcAddress(hL, "ReadConsoleOutputW");
	p[1142] = GetProcAddress(hL, "ReadConsoleW");
	p[1143] = GetProcAddress(hL, "ReadDirectoryChangesExW");
	p[1144] = GetProcAddress(hL, "ReadDirectoryChangesW");
	p[1145] = GetProcAddress(hL, "ReadFile");
	p[1146] = GetProcAddress(hL, "ReadFileEx");
	p[1147] = GetProcAddress(hL, "ReadFileScatter");
	p[1148] = GetProcAddress(hL, "ReadProcessMemory");
	p[1149] = GetProcAddress(hL, "ReadThreadProfilingData");
	p[1150] = GetProcAddress(hL, "ReclaimVirtualMemory");
	p[1151] = GetProcAddress(hL, "RegCloseKey");
	p[1152] = GetProcAddress(hL, "RegCopyTreeW");
	p[1153] = GetProcAddress(hL, "RegCreateKeyExA");
	p[1154] = GetProcAddress(hL, "RegCreateKeyExW");
	p[1155] = GetProcAddress(hL, "RegDeleteKeyExA");
	p[1156] = GetProcAddress(hL, "RegDeleteKeyExW");
	p[1157] = GetProcAddress(hL, "RegDeleteTreeA");
	p[1158] = GetProcAddress(hL, "RegDeleteTreeW");
	p[1159] = GetProcAddress(hL, "RegDeleteValueA");
	p[1160] = GetProcAddress(hL, "RegDeleteValueW");
	p[1161] = GetProcAddress(hL, "RegDisablePredefinedCacheEx");
	p[1162] = GetProcAddress(hL, "RegEnumKeyExA");
	p[1163] = GetProcAddress(hL, "RegEnumKeyExW");
	p[1164] = GetProcAddress(hL, "RegEnumValueA");
	p[1165] = GetProcAddress(hL, "RegEnumValueW");
	p[1166] = GetProcAddress(hL, "RegFlushKey");
	p[1167] = GetProcAddress(hL, "RegGetKeySecurity");
	p[1168] = GetProcAddress(hL, "RegGetValueA");
	p[1169] = GetProcAddress(hL, "RegGetValueW");
	p[1170] = GetProcAddress(hL, "RegLoadKeyA");
	p[1171] = GetProcAddress(hL, "RegLoadKeyW");
	p[1172] = GetProcAddress(hL, "RegLoadMUIStringA");
	p[1173] = GetProcAddress(hL, "RegLoadMUIStringW");
	p[1174] = GetProcAddress(hL, "RegNotifyChangeKeyValue");
	p[1175] = GetProcAddress(hL, "RegOpenCurrentUser");
	p[1176] = GetProcAddress(hL, "RegOpenKeyExA");
	p[1177] = GetProcAddress(hL, "RegOpenKeyExW");
	p[1178] = GetProcAddress(hL, "RegOpenUserClassesRoot");
	p[1179] = GetProcAddress(hL, "RegQueryInfoKeyA");
	p[1180] = GetProcAddress(hL, "RegQueryInfoKeyW");
	p[1181] = GetProcAddress(hL, "RegQueryValueExA");
	p[1182] = GetProcAddress(hL, "RegQueryValueExW");
	p[1183] = GetProcAddress(hL, "RegRestoreKeyA");
	p[1184] = GetProcAddress(hL, "RegRestoreKeyW");
	p[1185] = GetProcAddress(hL, "RegSaveKeyExA");
	p[1186] = GetProcAddress(hL, "RegSaveKeyExW");
	p[1187] = GetProcAddress(hL, "RegSetKeySecurity");
	p[1188] = GetProcAddress(hL, "RegSetValueExA");
	p[1189] = GetProcAddress(hL, "RegSetValueExW");
	p[1190] = GetProcAddress(hL, "RegUnLoadKeyA");
	p[1191] = GetProcAddress(hL, "RegUnLoadKeyW");
	p[1192] = GetProcAddress(hL, "RegisterApplicationRecoveryCallback");
	p[1193] = GetProcAddress(hL, "RegisterApplicationRestart");
	p[1194] = GetProcAddress(hL, "RegisterBadMemoryNotification");
	p[1195] = GetProcAddress(hL, "RegisterConsoleIME");
	p[1196] = GetProcAddress(hL, "RegisterConsoleOS2");
	p[1197] = GetProcAddress(hL, "RegisterConsoleVDM");
	p[1198] = GetProcAddress(hL, "RegisterWaitForInputIdle");
	p[1199] = GetProcAddress(hL, "RegisterWaitForSingleObject");
	p[1200] = GetProcAddress(hL, "RegisterWaitForSingleObjectEx");
	p[1201] = GetProcAddress(hL, "RegisterWaitUntilOOBECompleted");
	p[1202] = GetProcAddress(hL, "RegisterWowBaseHandlers");
	p[1203] = GetProcAddress(hL, "RegisterWowExec");
	p[1204] = GetProcAddress(hL, "ReleaseActCtx");
	p[1205] = GetProcAddress(hL, "ReleaseActCtxWorker");
	p[1206] = GetProcAddress(hL, "ReleaseMutex");
	p[1207] = GetProcAddress(hL, "ReleaseMutexWhenCallbackReturns");
	p[1208] = GetProcAddress(hL, "ReleaseSRWLockExclusive");
	p[1209] = GetProcAddress(hL, "ReleaseSRWLockShared");
	p[1210] = GetProcAddress(hL, "ReleaseSemaphore");
	p[1211] = GetProcAddress(hL, "ReleaseSemaphoreWhenCallbackReturns");
	p[1212] = GetProcAddress(hL, "RemoveDirectoryA");
	p[1213] = GetProcAddress(hL, "RemoveDirectoryTransactedA");
	p[1214] = GetProcAddress(hL, "RemoveDirectoryTransactedW");
	p[1215] = GetProcAddress(hL, "RemoveDirectoryW");
	p[1216] = GetProcAddress(hL, "RemoveDllDirectory");
	p[1217] = GetProcAddress(hL, "RemoveLocalAlternateComputerNameA");
	p[1218] = GetProcAddress(hL, "RemoveLocalAlternateComputerNameW");
	p[1219] = GetProcAddress(hL, "RemoveSecureMemoryCacheCallback");
	p[1220] = GetProcAddress(hL, "RemoveVectoredContinueHandler");
	p[1221] = GetProcAddress(hL, "RemoveVectoredExceptionHandler");
	p[1222] = GetProcAddress(hL, "ReplaceFile");
	p[1223] = GetProcAddress(hL, "ReplaceFileA");
	p[1224] = GetProcAddress(hL, "ReplaceFileW");
	p[1225] = GetProcAddress(hL, "ReplacePartitionUnit");
	p[1226] = GetProcAddress(hL, "RequestDeviceWakeup");
	p[1227] = GetProcAddress(hL, "RequestWakeupLatency");
	p[1228] = GetProcAddress(hL, "ResetEvent");
	p[1229] = GetProcAddress(hL, "ResetWriteWatch");
	p[1230] = GetProcAddress(hL, "ResizePseudoConsole");
	p[1231] = GetProcAddress(hL, "ResolveDelayLoadedAPI");
	p[1232] = GetProcAddress(hL, "ResolveDelayLoadsFromDll");
	p[1233] = GetProcAddress(hL, "ResolveLocaleName");
	p[1234] = GetProcAddress(hL, "RestoreLastError");
	p[1235] = GetProcAddress(hL, "ResumeThread");
	p[1236] = GetProcAddress(hL, "RtlAddFunctionTable");
	p[1237] = GetProcAddress(hL, "RtlCaptureContext");
	p[1238] = GetProcAddress(hL, "RtlCaptureStackBackTrace");
	p[1239] = GetProcAddress(hL, "RtlCompareMemory");
	p[1240] = GetProcAddress(hL, "RtlCopyMemory");
	p[1241] = GetProcAddress(hL, "RtlDeleteFunctionTable");
	p[1242] = GetProcAddress(hL, "RtlFillMemory");
	p[1243] = GetProcAddress(hL, "RtlInstallFunctionTableCallback");
	p[1244] = GetProcAddress(hL, "RtlLookupFunctionEntry");
	p[1245] = GetProcAddress(hL, "RtlMoveMemory");
	p[1246] = GetProcAddress(hL, "RtlPcToFileHeader");
	p[1247] = GetProcAddress(hL, "RtlRaiseException");
	p[1248] = GetProcAddress(hL, "RtlRestoreContext");
	p[1249] = GetProcAddress(hL, "RtlUnwind");
	p[1250] = GetProcAddress(hL, "RtlUnwindEx");
	p[1251] = GetProcAddress(hL, "RtlVirtualUnwind");
	p[1252] = GetProcAddress(hL, "RtlZeroMemory");
	p[1253] = GetProcAddress(hL, "ScrollConsoleScreenBufferA");
	p[1254] = GetProcAddress(hL, "ScrollConsoleScreenBufferW");
	p[1255] = GetProcAddress(hL, "SearchPathA");
	p[1256] = GetProcAddress(hL, "SearchPathW");
	p[1257] = GetProcAddress(hL, "SetCachedSigningLevel");
	p[1258] = GetProcAddress(hL, "SetCalendarInfoA");
	p[1259] = GetProcAddress(hL, "SetCalendarInfoW");
	p[1260] = GetProcAddress(hL, "SetComPlusPackageInstallStatus");
	p[1261] = GetProcAddress(hL, "SetCommBreak");
	p[1262] = GetProcAddress(hL, "SetCommConfig");
	p[1263] = GetProcAddress(hL, "SetCommMask");
	p[1264] = GetProcAddress(hL, "SetCommState");
	p[1265] = GetProcAddress(hL, "SetCommTimeouts");
	p[1266] = GetProcAddress(hL, "SetComputerNameA");
	p[1267] = GetProcAddress(hL, "SetComputerNameEx2W");
	p[1268] = GetProcAddress(hL, "SetComputerNameExA");
	p[1269] = GetProcAddress(hL, "SetComputerNameExW");
	p[1270] = GetProcAddress(hL, "SetComputerNameW");
	p[1271] = GetProcAddress(hL, "SetConsoleActiveScreenBuffer");
	p[1272] = GetProcAddress(hL, "SetConsoleCP");
	p[1273] = GetProcAddress(hL, "SetConsoleCtrlHandler");
	p[1274] = GetProcAddress(hL, "SetConsoleCursor");
	p[1275] = GetProcAddress(hL, "SetConsoleCursorInfo");
	p[1276] = GetProcAddress(hL, "SetConsoleCursorMode");
	p[1277] = GetProcAddress(hL, "SetConsoleCursorPosition");
	p[1278] = GetProcAddress(hL, "SetConsoleDisplayMode");
	p[1279] = GetProcAddress(hL, "SetConsoleFont");
	p[1280] = GetProcAddress(hL, "SetConsoleHardwareState");
	p[1281] = GetProcAddress(hL, "SetConsoleHistoryInfo");
	p[1282] = GetProcAddress(hL, "SetConsoleIcon");
	p[1283] = GetProcAddress(hL, "SetConsoleInputExeNameA");
	p[1284] = GetProcAddress(hL, "SetConsoleInputExeNameW");
	p[1285] = GetProcAddress(hL, "SetConsoleKeyShortcuts");
	p[1286] = GetProcAddress(hL, "SetConsoleLocalEUDC");
	p[1287] = GetProcAddress(hL, "SetConsoleMaximumWindowSize");
	p[1288] = GetProcAddress(hL, "SetConsoleMenuClose");
	p[1289] = GetProcAddress(hL, "SetConsoleMode");
	p[1290] = GetProcAddress(hL, "SetConsoleNlsMode");
	p[1291] = GetProcAddress(hL, "SetConsoleNumberOfCommandsA");
	p[1292] = GetProcAddress(hL, "SetConsoleNumberOfCommandsW");
	p[1293] = GetProcAddress(hL, "SetConsoleOS2OemFormat");
	p[1294] = GetProcAddress(hL, "SetConsoleOutputCP");
	p[1295] = GetProcAddress(hL, "SetConsolePalette");
	p[1296] = GetProcAddress(hL, "SetConsoleScreenBufferInfoEx");
	p[1297] = GetProcAddress(hL, "SetConsoleScreenBufferSize");
	p[1298] = GetProcAddress(hL, "SetConsoleTextAttribute");
	p[1299] = GetProcAddress(hL, "SetConsoleTitleA");
	p[1300] = GetProcAddress(hL, "SetConsoleTitleW");
	p[1301] = GetProcAddress(hL, "SetConsoleWindowInfo");
	p[1302] = GetProcAddress(hL, "SetCriticalSectionSpinCount");
	p[1303] = GetProcAddress(hL, "SetCurrentConsoleFontEx");
	p[1304] = GetProcAddress(hL, "SetCurrentDirectoryA");
	p[1305] = GetProcAddress(hL, "SetCurrentDirectoryW");
	p[1306] = GetProcAddress(hL, "SetDefaultCommConfigA");
	p[1307] = GetProcAddress(hL, "SetDefaultCommConfigW");
	p[1308] = GetProcAddress(hL, "SetDefaultDllDirectories");
	p[1309] = GetProcAddress(hL, "SetDllDirectoryA");
	p[1310] = GetProcAddress(hL, "SetDllDirectoryW");
	p[1311] = GetProcAddress(hL, "SetDynamicTimeZoneInformation");
	p[1312] = GetProcAddress(hL, "SetEndOfFile");
	p[1313] = GetProcAddress(hL, "SetEnvironmentStringsA");
	p[1314] = GetProcAddress(hL, "SetEnvironmentStringsW");
	p[1315] = GetProcAddress(hL, "SetEnvironmentVariableA");
	p[1316] = GetProcAddress(hL, "SetEnvironmentVariableW");
	p[1317] = GetProcAddress(hL, "SetErrorMode");
	p[1318] = GetProcAddress(hL, "SetEvent");
	p[1319] = GetProcAddress(hL, "SetEventWhenCallbackReturns");
	p[1320] = GetProcAddress(hL, "SetFileApisToANSI");
	p[1321] = GetProcAddress(hL, "SetFileApisToOEM");
	p[1322] = GetProcAddress(hL, "SetFileAttributesA");
	p[1323] = GetProcAddress(hL, "SetFileAttributesTransactedA");
	p[1324] = GetProcAddress(hL, "SetFileAttributesTransactedW");
	p[1325] = GetProcAddress(hL, "SetFileAttributesW");
	p[1326] = GetProcAddress(hL, "SetFileBandwidthReservation");
	p[1327] = GetProcAddress(hL, "SetFileCompletionNotificationModes");
	p[1328] = GetProcAddress(hL, "SetFileInformationByHandle");
	p[1329] = GetProcAddress(hL, "SetFileIoOverlappedRange");
	p[1330] = GetProcAddress(hL, "SetFilePointer");
	p[1331] = GetProcAddress(hL, "SetFilePointerEx");
	p[1332] = GetProcAddress(hL, "SetFileShortNameA");
	p[1333] = GetProcAddress(hL, "SetFileShortNameW");
	p[1334] = GetProcAddress(hL, "SetFileTime");
	p[1335] = GetProcAddress(hL, "SetFileValidData");
	p[1336] = GetProcAddress(hL, "SetFirmwareEnvironmentVariableA");
	p[1337] = GetProcAddress(hL, "SetFirmwareEnvironmentVariableExA");
	p[1338] = GetProcAddress(hL, "SetFirmwareEnvironmentVariableExW");
	p[1339] = GetProcAddress(hL, "SetFirmwareEnvironmentVariableW");
	p[1340] = GetProcAddress(hL, "SetHandleCount");
	p[1341] = GetProcAddress(hL, "SetHandleInformation");
	p[1342] = GetProcAddress(hL, "SetInformationJobObject");
	p[1343] = GetProcAddress(hL, "SetIoRateControlInformationJobObject");
	p[1344] = GetProcAddress(hL, "SetLastConsoleEventActive");
	p[1345] = GetProcAddress(hL, "SetLastError");
	p[1346] = GetProcAddress(hL, "SetLocalPrimaryComputerNameA");
	p[1347] = GetProcAddress(hL, "SetLocalPrimaryComputerNameW");
	p[1348] = GetProcAddress(hL, "SetLocalTime");
	p[1349] = GetProcAddress(hL, "SetLocaleInfoA");
	p[1350] = GetProcAddress(hL, "SetLocaleInfoW");
	p[1351] = GetProcAddress(hL, "SetMailslotInfo");
	p[1352] = GetProcAddress(hL, "SetMessageWaitingIndicator");
	p[1353] = GetProcAddress(hL, "SetNamedPipeAttribute");
	p[1354] = GetProcAddress(hL, "SetNamedPipeHandleState");
	p[1355] = GetProcAddress(hL, "SetPriorityClass");
	p[1356] = GetProcAddress(hL, "SetProcessAffinityMask");
	p[1357] = GetProcAddress(hL, "SetProcessAffinityUpdateMode");
	p[1358] = GetProcAddress(hL, "SetProcessDEPPolicy");
	p[1359] = GetProcAddress(hL, "SetProcessDefaultCpuSets");
	p[1360] = GetProcAddress(hL, "SetProcessDynamicEHContinuationTargets");
	p[1361] = GetProcAddress(hL, "SetProcessDynamicEnforcedCetCompatibleRanges");
	p[1362] = GetProcAddress(hL, "SetProcessInformation");
	p[1363] = GetProcAddress(hL, "SetProcessMitigationPolicy");
	p[1364] = GetProcAddress(hL, "SetProcessPreferredUILanguages");
	p[1365] = GetProcAddress(hL, "SetProcessPriorityBoost");
	p[1366] = GetProcAddress(hL, "SetProcessShutdownParameters");
	p[1367] = GetProcAddress(hL, "SetProcessWorkingSetSize");
	p[1368] = GetProcAddress(hL, "SetProcessWorkingSetSizeEx");
	p[1369] = GetProcAddress(hL, "SetProtectedPolicy");
	p[1370] = GetProcAddress(hL, "SetSearchPathMode");
	p[1371] = GetProcAddress(hL, "SetStdHandle");
	p[1372] = GetProcAddress(hL, "SetStdHandleEx");
	p[1373] = GetProcAddress(hL, "SetSystemFileCacheSize");
	p[1374] = GetProcAddress(hL, "SetSystemPowerState");
	p[1375] = GetProcAddress(hL, "SetSystemTime");
	p[1376] = GetProcAddress(hL, "SetSystemTimeAdjustment");
	p[1377] = GetProcAddress(hL, "SetTapeParameters");
	p[1378] = GetProcAddress(hL, "SetTapePosition");
	p[1379] = GetProcAddress(hL, "SetTermsrvAppInstallMode");
	p[1380] = GetProcAddress(hL, "SetThreadAffinityMask");
	p[1381] = GetProcAddress(hL, "SetThreadContext");
	p[1382] = GetProcAddress(hL, "SetThreadDescription");
	p[1383] = GetProcAddress(hL, "SetThreadErrorMode");
	p[1384] = GetProcAddress(hL, "SetThreadExecutionState");
	p[1385] = GetProcAddress(hL, "SetThreadGroupAffinity");
	p[1386] = GetProcAddress(hL, "SetThreadIdealProcessor");
	p[1387] = GetProcAddress(hL, "SetThreadIdealProcessorEx");
	p[1388] = GetProcAddress(hL, "SetThreadInformation");
	p[1389] = GetProcAddress(hL, "SetThreadLocale");
	p[1390] = GetProcAddress(hL, "SetThreadPreferredUILanguages");
	p[1391] = GetProcAddress(hL, "SetThreadPriority");
	p[1392] = GetProcAddress(hL, "SetThreadPriorityBoost");
	p[1393] = GetProcAddress(hL, "SetThreadSelectedCpuSets");
	p[1394] = GetProcAddress(hL, "SetThreadStackGuarantee");
	p[1395] = GetProcAddress(hL, "SetThreadToken");
	p[1396] = GetProcAddress(hL, "SetThreadUILanguage");
	p[1397] = GetProcAddress(hL, "SetThreadpoolStackInformation");
	p[1398] = GetProcAddress(hL, "SetThreadpoolThreadMaximum");
	p[1399] = GetProcAddress(hL, "SetThreadpoolThreadMinimum");
	p[1400] = GetProcAddress(hL, "SetThreadpoolTimer");
	p[1401] = GetProcAddress(hL, "SetThreadpoolTimerEx");
	p[1402] = GetProcAddress(hL, "SetThreadpoolWait");
	p[1403] = GetProcAddress(hL, "SetThreadpoolWaitEx");
	p[1404] = GetProcAddress(hL, "SetTimeZoneInformation");
	p[1405] = GetProcAddress(hL, "SetTimerQueueTimer");
	p[1406] = GetProcAddress(hL, "SetUmsThreadInformation");
	p[1407] = GetProcAddress(hL, "SetUnhandledExceptionFilter");
	p[1408] = GetProcAddress(hL, "SetUserGeoID");
	p[1409] = GetProcAddress(hL, "SetUserGeoName");
	p[1410] = GetProcAddress(hL, "SetVDMCurrentDirectories");
	p[1411] = GetProcAddress(hL, "SetVolumeLabelA");
	p[1412] = GetProcAddress(hL, "SetVolumeLabelW");
	p[1413] = GetProcAddress(hL, "SetVolumeMountPointA");
	p[1414] = GetProcAddress(hL, "SetVolumeMountPointW");
	p[1415] = GetProcAddress(hL, "SetVolumeMountPointWStub");
	p[1416] = GetProcAddress(hL, "SetWaitableTimer");
	p[1417] = GetProcAddress(hL, "SetWaitableTimerEx");
	p[1418] = GetProcAddress(hL, "SetXStateFeaturesMask");
	p[1419] = GetProcAddress(hL, "SetupComm");
	p[1420] = GetProcAddress(hL, "ShowConsoleCursor");
	p[1421] = GetProcAddress(hL, "SignalObjectAndWait");
	p[1422] = GetProcAddress(hL, "SizeofResource");
	p[1423] = GetProcAddress(hL, "Sleep");
	p[1424] = GetProcAddress(hL, "SleepConditionVariableCS");
	p[1425] = GetProcAddress(hL, "SleepConditionVariableSRW");
	p[1426] = GetProcAddress(hL, "SleepEx");
	p[1427] = GetProcAddress(hL, "SortCloseHandle");
	p[1428] = GetProcAddress(hL, "SortGetHandle");
	p[1429] = GetProcAddress(hL, "StartThreadpoolIo");
	p[1430] = GetProcAddress(hL, "SubmitThreadpoolWork");
	p[1431] = GetProcAddress(hL, "SuspendThread");
	p[1432] = GetProcAddress(hL, "SwitchToFiber");
	p[1433] = GetProcAddress(hL, "SwitchToThread");
	p[1434] = GetProcAddress(hL, "SystemTimeToFileTime");
	p[1435] = GetProcAddress(hL, "SystemTimeToTzSpecificLocalTime");
	p[1436] = GetProcAddress(hL, "SystemTimeToTzSpecificLocalTimeEx");
	p[1437] = GetProcAddress(hL, "TerminateJobObject");
	p[1438] = GetProcAddress(hL, "TerminateProcess");
	p[1439] = GetProcAddress(hL, "TerminateThread");
	p[1440] = GetProcAddress(hL, "TermsrvAppInstallMode");
	p[1441] = GetProcAddress(hL, "TermsrvConvertSysRootToUserDir");
	p[1442] = GetProcAddress(hL, "TermsrvCreateRegEntry");
	p[1443] = GetProcAddress(hL, "TermsrvDeleteKey");
	p[1444] = GetProcAddress(hL, "TermsrvDeleteValue");
	p[1445] = GetProcAddress(hL, "TermsrvGetPreSetValue");
	p[1446] = GetProcAddress(hL, "TermsrvGetWindowsDirectoryA");
	p[1447] = GetProcAddress(hL, "TermsrvGetWindowsDirectoryW");
	p[1448] = GetProcAddress(hL, "TermsrvOpenRegEntry");
	p[1449] = GetProcAddress(hL, "TermsrvOpenUserClasses");
	p[1450] = GetProcAddress(hL, "TermsrvRestoreKey");
	p[1451] = GetProcAddress(hL, "TermsrvSetKeySecurity");
	p[1452] = GetProcAddress(hL, "TermsrvSetValueKey");
	p[1453] = GetProcAddress(hL, "TermsrvSyncUserIniFileExt");
	p[1454] = GetProcAddress(hL, "Thread32First");
	p[1455] = GetProcAddress(hL, "Thread32Next");
	p[1456] = GetProcAddress(hL, "TlsAlloc");
	p[1457] = GetProcAddress(hL, "TlsFree");
	p[1458] = GetProcAddress(hL, "TlsGetValue");
	p[1459] = GetProcAddress(hL, "TlsSetValue");
	p[1460] = GetProcAddress(hL, "Toolhelp32ReadProcessMemory");
	p[1461] = GetProcAddress(hL, "TransactNamedPipe");
	p[1462] = GetProcAddress(hL, "TransmitCommChar");
	p[1463] = GetProcAddress(hL, "TryAcquireSRWLockExclusive");
	p[1464] = GetProcAddress(hL, "TryAcquireSRWLockShared");
	p[1465] = GetProcAddress(hL, "TryEnterCriticalSection");
	p[1466] = GetProcAddress(hL, "TrySubmitThreadpoolCallback");
	p[1467] = GetProcAddress(hL, "TzSpecificLocalTimeToSystemTime");
	p[1468] = GetProcAddress(hL, "TzSpecificLocalTimeToSystemTimeEx");
	p[1469] = GetProcAddress(hL, "UTRegister");
	p[1470] = GetProcAddress(hL, "UTUnRegister");
	p[1471] = GetProcAddress(hL, "UmsThreadYield");
	p[1472] = GetProcAddress(hL, "UnhandledExceptionFilter");
	p[1473] = GetProcAddress(hL, "UnlockFile");
	p[1474] = GetProcAddress(hL, "UnlockFileEx");
	p[1475] = GetProcAddress(hL, "UnmapViewOfFile");
	p[1476] = GetProcAddress(hL, "UnmapViewOfFileEx");
	p[1477] = GetProcAddress(hL, "UnregisterApplicationRecoveryCallback");
	p[1478] = GetProcAddress(hL, "UnregisterApplicationRestart");
	p[1479] = GetProcAddress(hL, "UnregisterBadMemoryNotification");
	p[1480] = GetProcAddress(hL, "UnregisterConsoleIME");
	p[1481] = GetProcAddress(hL, "UnregisterWait");
	p[1482] = GetProcAddress(hL, "UnregisterWaitEx");
	p[1483] = GetProcAddress(hL, "UnregisterWaitUntilOOBECompleted");
	p[1484] = GetProcAddress(hL, "UpdateCalendarDayOfWeek");
	p[1485] = GetProcAddress(hL, "UpdateProcThreadAttribute");
	p[1486] = GetProcAddress(hL, "UpdateResourceA");
	p[1487] = GetProcAddress(hL, "UpdateResourceW");
	p[1488] = GetProcAddress(hL, "VDMConsoleOperation");
	p[1489] = GetProcAddress(hL, "VDMOperationStarted");
	p[1490] = GetProcAddress(hL, "VerLanguageNameA");
	p[1491] = GetProcAddress(hL, "VerLanguageNameW");
	p[1492] = GetProcAddress(hL, "VerSetConditionMask");
	p[1493] = GetProcAddress(hL, "VerifyConsoleIoHandle");
	p[1494] = GetProcAddress(hL, "VerifyScripts");
	p[1495] = GetProcAddress(hL, "VerifyVersionInfoA");
	p[1496] = GetProcAddress(hL, "VerifyVersionInfoW");
	p[1497] = GetProcAddress(hL, "VirtualAlloc");
	p[1498] = GetProcAddress(hL, "VirtualAllocEx");
	p[1499] = GetProcAddress(hL, "VirtualAllocExNuma");
	p[1500] = GetProcAddress(hL, "VirtualFree");
	p[1501] = GetProcAddress(hL, "VirtualFreeEx");
	p[1502] = GetProcAddress(hL, "VirtualLock");
	p[1503] = GetProcAddress(hL, "VirtualProtect");
	p[1504] = GetProcAddress(hL, "VirtualProtectEx");
	p[1505] = GetProcAddress(hL, "VirtualQuery");
	p[1506] = GetProcAddress(hL, "VirtualQueryEx");
	p[1507] = GetProcAddress(hL, "VirtualUnlock");
	p[1508] = GetProcAddress(hL, "WTSGetActiveConsoleSessionId");
	p[1509] = GetProcAddress(hL, "WaitCommEvent");
	p[1510] = GetProcAddress(hL, "WaitForDebugEvent");
	p[1511] = GetProcAddress(hL, "WaitForDebugEventEx");
	p[1512] = GetProcAddress(hL, "WaitForMultipleObjects");
	p[1513] = GetProcAddress(hL, "WaitForMultipleObjectsEx");
	p[1514] = GetProcAddress(hL, "WaitForSingleObject");
	p[1515] = GetProcAddress(hL, "WaitForSingleObjectEx");
	p[1516] = GetProcAddress(hL, "WaitForThreadpoolIoCallbacks");
	p[1517] = GetProcAddress(hL, "WaitForThreadpoolTimerCallbacks");
	p[1518] = GetProcAddress(hL, "WaitForThreadpoolWaitCallbacks");
	p[1519] = GetProcAddress(hL, "WaitForThreadpoolWorkCallbacks");
	p[1520] = GetProcAddress(hL, "WaitNamedPipeA");
	p[1521] = GetProcAddress(hL, "WaitNamedPipeW");
	p[1522] = GetProcAddress(hL, "WakeAllConditionVariable");
	p[1523] = GetProcAddress(hL, "WakeConditionVariable");
	p[1524] = GetProcAddress(hL, "WerGetFlags");
	p[1525] = GetProcAddress(hL, "WerGetFlagsWorker");
	p[1526] = GetProcAddress(hL, "WerRegisterAdditionalProcess");
	p[1527] = GetProcAddress(hL, "WerRegisterAppLocalDump");
	p[1528] = GetProcAddress(hL, "WerRegisterCustomMetadata");
	p[1529] = GetProcAddress(hL, "WerRegisterExcludedMemoryBlock");
	p[1530] = GetProcAddress(hL, "WerRegisterFile");
	p[1531] = GetProcAddress(hL, "WerRegisterFileWorker");
	p[1532] = GetProcAddress(hL, "WerRegisterMemoryBlock");
	p[1533] = GetProcAddress(hL, "WerRegisterMemoryBlockWorker");
	p[1534] = GetProcAddress(hL, "WerRegisterRuntimeExceptionModule");
	p[1535] = GetProcAddress(hL, "WerRegisterRuntimeExceptionModuleWorker");
	p[1536] = GetProcAddress(hL, "WerSetFlags");
	p[1537] = GetProcAddress(hL, "WerSetFlagsWorker");
	p[1538] = GetProcAddress(hL, "WerUnregisterAdditionalProcess");
	p[1539] = GetProcAddress(hL, "WerUnregisterAppLocalDump");
	p[1540] = GetProcAddress(hL, "WerUnregisterCustomMetadata");
	p[1541] = GetProcAddress(hL, "WerUnregisterExcludedMemoryBlock");
	p[1542] = GetProcAddress(hL, "WerUnregisterFile");
	p[1543] = GetProcAddress(hL, "WerUnregisterFileWorker");
	p[1544] = GetProcAddress(hL, "WerUnregisterMemoryBlock");
	p[1545] = GetProcAddress(hL, "WerUnregisterMemoryBlockWorker");
	p[1546] = GetProcAddress(hL, "WerUnregisterRuntimeExceptionModule");
	p[1547] = GetProcAddress(hL, "WerUnregisterRuntimeExceptionModuleWorker");
	p[1548] = GetProcAddress(hL, "WerpGetDebugger");
	p[1549] = GetProcAddress(hL, "WerpInitiateRemoteRecovery");
	p[1550] = GetProcAddress(hL, "WerpLaunchAeDebug");
	p[1551] = GetProcAddress(hL, "WerpNotifyLoadStringResourceWorker");
	p[1552] = GetProcAddress(hL, "WerpNotifyUseStringResourceWorker");
	p[1553] = GetProcAddress(hL, "WideCharToMultiByte");
	p[1554] = GetProcAddress(hL, "WinExec");
	p[1555] = GetProcAddress(hL, "Wow64DisableWow64FsRedirection");
	p[1556] = GetProcAddress(hL, "Wow64EnableWow64FsRedirection");
	p[1557] = GetProcAddress(hL, "Wow64GetThreadContext");
	p[1558] = GetProcAddress(hL, "Wow64GetThreadSelectorEntry");
	p[1559] = GetProcAddress(hL, "Wow64RevertWow64FsRedirection");
	p[1560] = GetProcAddress(hL, "Wow64SetThreadContext");
	p[1561] = GetProcAddress(hL, "Wow64SuspendThread");
	p[1562] = GetProcAddress(hL, "WriteConsoleA");
	p[1563] = GetProcAddress(hL, "WriteConsoleInputA");
	p[1564] = GetProcAddress(hL, "WriteConsoleInputVDMA");
	p[1565] = GetProcAddress(hL, "WriteConsoleInputVDMW");
	p[1566] = GetProcAddress(hL, "WriteConsoleInputW");
	p[1567] = GetProcAddress(hL, "WriteConsoleOutputA");
	p[1568] = GetProcAddress(hL, "WriteConsoleOutputAttribute");
	p[1569] = GetProcAddress(hL, "WriteConsoleOutputCharacterA");
	p[1570] = GetProcAddress(hL, "WriteConsoleOutputCharacterW");
	p[1571] = GetProcAddress(hL, "WriteConsoleOutputW");
	p[1572] = GetProcAddress(hL, "WriteConsoleW");
	p[1573] = GetProcAddress(hL, "WriteFile");
	p[1574] = GetProcAddress(hL, "WriteFileEx");
	p[1575] = GetProcAddress(hL, "WriteFileGather");
	p[1576] = GetProcAddress(hL, "WritePrivateProfileSectionA");
	p[1577] = GetProcAddress(hL, "WritePrivateProfileSectionW");
	p[1578] = GetProcAddress(hL, "WritePrivateProfileStringA");
	p[1579] = GetProcAddress(hL, "WritePrivateProfileStringW");
	p[1580] = GetProcAddress(hL, "WritePrivateProfileStructA");
	p[1581] = GetProcAddress(hL, "WritePrivateProfileStructW");
	p[1582] = GetProcAddress(hL, "WriteProcessMemory");
	p[1583] = GetProcAddress(hL, "WriteProfileSectionA");
	p[1584] = GetProcAddress(hL, "WriteProfileSectionW");
	p[1585] = GetProcAddress(hL, "WriteProfileStringA");
	p[1586] = GetProcAddress(hL, "WriteProfileStringW");
	p[1587] = GetProcAddress(hL, "WriteTapemark");
	p[1588] = GetProcAddress(hL, "ZombifyActCtx");
	p[1589] = GetProcAddress(hL, "ZombifyActCtxWorker");
	p[1590] = GetProcAddress(hL, "__C_specific_handler");
	p[1591] = GetProcAddress(hL, "__chkstk");
	p[1592] = GetProcAddress(hL, "__misaligned_access");
	p[1593] = GetProcAddress(hL, "_hread");
	p[1594] = GetProcAddress(hL, "_hwrite");
	p[1595] = GetProcAddress(hL, "_lclose");
	p[1596] = GetProcAddress(hL, "_lcreat");
	p[1597] = GetProcAddress(hL, "_llseek");
	p[1598] = GetProcAddress(hL, "_local_unwind");
	p[1599] = GetProcAddress(hL, "_lopen");
	p[1600] = GetProcAddress(hL, "_lread");
	p[1601] = GetProcAddress(hL, "_lwrite");
	p[1602] = GetProcAddress(hL, "lstrcat");
	p[1603] = GetProcAddress(hL, "lstrcatA");
	p[1604] = GetProcAddress(hL, "lstrcatW");
	p[1605] = GetProcAddress(hL, "lstrcmp");
	p[1606] = GetProcAddress(hL, "lstrcmpA");
	p[1607] = GetProcAddress(hL, "lstrcmpW");
	p[1608] = GetProcAddress(hL, "lstrcmpi");
	p[1609] = GetProcAddress(hL, "lstrcmpiA");
	p[1610] = GetProcAddress(hL, "lstrcmpiW");
	p[1611] = GetProcAddress(hL, "lstrcpy");
	p[1612] = GetProcAddress(hL, "lstrcpyA");
	p[1613] = GetProcAddress(hL, "lstrcpyW");
	p[1614] = GetProcAddress(hL, "lstrcpyn");
	p[1615] = GetProcAddress(hL, "lstrcpynA");
	p[1616] = GetProcAddress(hL, "lstrcpynW");
	p[1617] = GetProcAddress(hL, "lstrlen");
	p[1618] = GetProcAddress(hL, "lstrlenA");
	p[1619] = GetProcAddress(hL, "lstrlenW");
	p[1620] = GetProcAddress(hL, "timeBeginPeriod");
	p[1621] = GetProcAddress(hL, "timeEndPeriod");
	p[1622] = GetProcAddress(hL, "timeGetDevCaps");
	p[1623] = GetProcAddress(hL, "timeGetSystemTime");
	p[1624] = GetProcAddress(hL, "timeGetTime");
	p[1625] = GetProcAddress(hL, "uaw_lstrcmpW");
	p[1626] = GetProcAddress(hL, "uaw_lstrcmpiW");
	p[1627] = GetProcAddress(hL, "uaw_lstrlenW");
	p[1628] = GetProcAddress(hL, "uaw_wcschr");
	p[1629] = GetProcAddress(hL, "uaw_wcscpy");
	p[1630] = GetProcAddress(hL, "uaw_wcsicmp");
	p[1631] = GetProcAddress(hL, "uaw_wcslen");
	p[1632] = GetProcAddress(hL, "uaw_wcsrchr");
	if (reason == DLL_PROCESS_DETACH)
	{
		FreeLibrary(hL);
		return 1;
	}

	return 1;
}

extern "C"
{
	void PROXY_AcquireSRWLockExclusive() {
		p[0]();
		
	}
	void PROXY_AcquireSRWLockShared() {
		p[1]();
		
	}
	void PROXY_ActivateActCtx() {
		p[2]();
		
	}
	void PROXY_ActivateActCtxWorker() {
		p[3]();
		
	}
	void PROXY_AddAtomA() {
		p[4]();
		
	}
	void PROXY_AddAtomW() {
		p[5]();
		
	}
	void PROXY_AddConsoleAliasA() {
		p[6]();
		
	}
	void PROXY_AddConsoleAliasW() {
		p[7]();
		
	}
	void PROXY_AddDllDirectory() {
		p[8]();
		
	}
	void PROXY_AddIntegrityLabelToBoundaryDescriptor() {
		p[9]();
		
	}
	void PROXY_AddLocalAlternateComputerNameA() {
		p[10]();
		
	}
	void PROXY_AddLocalAlternateComputerNameW() {
		p[11]();
		
	}
	void PROXY_AddRefActCtx() {
		p[12]();
		
	}
	void PROXY_AddRefActCtxWorker() {
		p[13]();
		
	}
	void PROXY_AddResourceAttributeAce() {
		p[14]();
		
	}
	void PROXY_AddSIDToBoundaryDescriptor() {
		p[15]();
		
	}
	void PROXY_AddScopedPolicyIDAce() {
		p[16]();
		
	}
	void PROXY_AddSecureMemoryCacheCallback() {
		p[17]();
		
	}
	void PROXY_AddVectoredContinueHandler() {
		p[18]();
		
	}
	void PROXY_AddVectoredExceptionHandler() {
		p[19]();
		
	}
	void PROXY_AdjustCalendarDate() {
		p[20]();
		
	}
	void PROXY_AllocConsole() {
		p[21]();
		
	}
	void PROXY_AllocateUserPhysicalPages() {
		p[22]();
		
	}
	void PROXY_AllocateUserPhysicalPagesNuma() {
		p[23]();
		
	}
	void PROXY_AppPolicyGetClrCompat() {
		p[24]();
		
	}
	void PROXY_AppPolicyGetCreateFileAccess() {
		p[25]();
		
	}
	void PROXY_AppPolicyGetLifecycleManagement() {
		p[26]();
		
	}
	void PROXY_AppPolicyGetMediaFoundationCodecLoading() {
		p[27]();
		
	}
	void PROXY_AppPolicyGetProcessTerminationMethod() {
		p[28]();
		
	}
	void PROXY_AppPolicyGetShowDeveloperDiagnostic() {
		p[29]();
		
	}
	void PROXY_AppPolicyGetThreadInitializationType() {
		p[30]();
		
	}
	void PROXY_AppPolicyGetWindowingModel() {
		p[31]();
		
	}
	void PROXY_AppXGetOSMaxVersionTested() {
		p[32]();
		
	}
	void PROXY_ApplicationRecoveryFinished() {
		p[33]();
		
	}
	void PROXY_ApplicationRecoveryInProgress() {
		p[34]();
		
	}
	void PROXY_AreFileApisANSI() {
		p[35]();
		
	}
	void PROXY_AssignProcessToJobObject() {
		p[36]();
		
	}
	void PROXY_AttachConsole() {
		p[37]();
		
	}
	void PROXY_BackupRead() {
		p[38]();
		
	}
	void PROXY_BackupSeek() {
		p[39]();
		
	}
	void PROXY_BackupWrite() {
		p[40]();
		
	}
	void PROXY_BaseCheckAppcompatCache() {
		p[41]();
		
	}
	void PROXY_BaseCheckAppcompatCacheEx() {
		p[42]();
		
	}
	void PROXY_BaseCheckAppcompatCacheExWorker() {
		p[43]();
		
	}
	void PROXY_BaseCheckAppcompatCacheWorker() {
		p[44]();
		
	}
	void PROXY_BaseCheckElevation() {
		p[45]();
		
	}
	void PROXY_BaseCleanupAppcompatCacheSupport() {
		p[46]();
		
	}
	void PROXY_BaseCleanupAppcompatCacheSupportWorker() {
		p[47]();
		
	}
	void PROXY_BaseDestroyVDMEnvironment() {
		p[48]();
		
	}
	void PROXY_BaseDllReadWriteIniFile() {
		p[49]();
		
	}
	void PROXY_BaseDumpAppcompatCache() {
		p[50]();
		
	}
	void PROXY_BaseDumpAppcompatCacheWorker() {
		p[51]();
		
	}
	void PROXY_BaseElevationPostProcessing() {
		p[52]();
		
	}
	void PROXY_BaseFlushAppcompatCache() {
		p[53]();
		
	}
	void PROXY_BaseFlushAppcompatCacheWorker() {
		p[54]();
		
	}
	void PROXY_BaseFormatObjectAttributes() {
		p[55]();
		
	}
	void PROXY_BaseFormatTimeOut() {
		p[56]();
		
	}
	void PROXY_BaseFreeAppCompatDataForProcessWorker() {
		p[57]();
		
	}
	void PROXY_BaseGenerateAppCompatData() {
		p[58]();
		
	}
	void PROXY_BaseGetNamedObjectDirectory() {
		p[59]();
		
	}
	void PROXY_BaseInitAppcompatCacheSupport() {
		p[60]();
		
	}
	void PROXY_BaseInitAppcompatCacheSupportWorker() {
		p[61]();
		
	}
	void PROXY_BaseIsAppcompatInfrastructureDisabled() {
		p[62]();
		
	}
	void PROXY_BaseIsAppcompatInfrastructureDisabledWorker() {
		p[63]();
		
	}
	void PROXY_BaseIsDosApplication() {
		p[64]();
		
	}
	void PROXY_BaseQueryModuleData() {
		p[65]();
		
	}
	void PROXY_BaseReadAppCompatDataForProcessWorker() {
		p[66]();
		
	}
	void PROXY_BaseSetLastNTError() {
		p[67]();
		
	}
	void PROXY_BaseThreadInitThunk() {
		p[68]();
		
	}
	void PROXY_BaseUpdateAppcompatCache() {
		p[69]();
		
	}
	void PROXY_BaseUpdateAppcompatCacheWorker() {
		p[70]();
		
	}
	void PROXY_BaseUpdateVDMEntry() {
		p[71]();
		
	}
	void PROXY_BaseVerifyUnicodeString() {
		p[72]();
		
	}
	void PROXY_BaseWriteErrorElevationRequiredEvent() {
		p[73]();
		
	}
	void PROXY_Basep8BitStringToDynamicUnicodeString() {
		p[74]();
		
	}
	void PROXY_BasepAllocateActivationContextActivationBlock() {
		p[75]();
		
	}
	void PROXY_BasepAnsiStringToDynamicUnicodeString() {
		p[76]();
		
	}
	void PROXY_BasepAppContainerEnvironmentExtension() {
		p[77]();
		
	}
	void PROXY_BasepAppXExtension() {
		p[78]();
		
	}
	void PROXY_BasepCheckAppCompat() {
		p[79]();
		
	}
	void PROXY_BasepCheckWebBladeHashes() {
		p[80]();
		
	}
	void PROXY_BasepCheckWinSaferRestrictions() {
		p[81]();
		
	}
	void PROXY_BasepConstructSxsCreateProcessMessage() {
		p[82]();
		
	}
	void PROXY_BasepCopyEncryption() {
		p[83]();
		
	}
	void PROXY_BasepFinishPackageActivationForSxS() {
		p[84]();
		
	}
	void PROXY_BasepFreeActivationContextActivationBlock() {
		p[85]();
		
	}
	void PROXY_BasepFreeAppCompatData() {
		p[86]();
		
	}
	void PROXY_BasepGetAppCompatData() {
		p[87]();
		
	}
	void PROXY_BasepGetComputerNameFromNtPath() {
		p[88]();
		
	}
	void PROXY_BasepGetExeArchType() {
		p[89]();
		
	}
	void PROXY_BasepGetPackageActivationTokenForSxS() {
		p[90]();
		
	}
	void PROXY_BasepInitAppCompatData() {
		p[91]();
		
	}
	void PROXY_BasepIsProcessAllowed() {
		p[92]();
		
	}
	void PROXY_BasepMapModuleHandle() {
		p[93]();
		
	}
	void PROXY_BasepNotifyLoadStringResource() {
		p[94]();
		
	}
	void PROXY_BasepPostSuccessAppXExtension() {
		p[95]();
		
	}
	void PROXY_BasepProcessInvalidImage() {
		p[96]();
		
	}
	void PROXY_BasepQueryAppCompat() {
		p[97]();
		
	}
	void PROXY_BasepQueryModuleChpeSettings() {
		p[98]();
		
	}
	void PROXY_BasepReleaseAppXContext() {
		p[99]();
		
	}
	void PROXY_BasepReleaseSxsCreateProcessUtilityStruct() {
		p[100]();
		
	}
	void PROXY_BasepReportFault() {
		p[101]();
		
	}
	void PROXY_BasepSetFileEncryptionCompression() {
		p[102]();
		
	}
	void PROXY_Beep() {
		p[103]();
		
	}
	void PROXY_BeginUpdateResourceA() {
		p[104]();
		
	}
	void PROXY_BeginUpdateResourceW() {
		p[105]();
		
	}
	void PROXY_BindIoCompletionCallback() {
		p[106]();
		
	}
	void PROXY_BuildCommDCBA() {
		p[107]();
		
	}
	void PROXY_BuildCommDCBAndTimeoutsA() {
		p[108]();
		
	}
	void PROXY_BuildCommDCBAndTimeoutsW() {
		p[109]();
		
	}
	void PROXY_BuildCommDCBW() {
		p[110]();
		
	}
	void PROXY_CallNamedPipeA() {
		p[111]();
		
	}
	void PROXY_CallNamedPipeW() {
		p[112]();
		
	}
	void PROXY_CallbackMayRunLong() {
		p[113]();
		
	}
	void PROXY_CancelDeviceWakeupRequest() {
		p[114]();
		
	}
	void PROXY_CancelIo() {
		p[115]();
		
	}
	void PROXY_CancelIoEx() {
		p[116]();
		
	}
	void PROXY_CancelSynchronousIo() {
		p[117]();
		
	}
	void PROXY_CancelThreadpoolIo() {
		p[118]();
		
	}
	void PROXY_CancelTimerQueueTimer() {
		p[119]();
		
	}
	void PROXY_CancelWaitableTimer() {
		p[120]();
		
	}
	void PROXY_CeipIsOptedIn() {
		p[121]();
		
	}
	void PROXY_ChangeTimerQueueTimer() {
		p[122]();
		
	}
	void PROXY_CheckAllowDecryptedRemoteDestinationPolicy() {
		p[123]();
		
	}
	void PROXY_CheckElevation() {
		p[124]();
		
	}
	void PROXY_CheckElevationEnabled() {
		p[125]();
		
	}
	void PROXY_CheckForReadOnlyResource() {
		p[126]();
		
	}
	void PROXY_CheckForReadOnlyResourceFilter() {
		p[127]();
		
	}
	void PROXY_CheckIsMSIXPackage() {
		p[128]();
		
	}
	void PROXY_CheckNameLegalDOS8Dot3A() {
		p[129]();
		
	}
	void PROXY_CheckNameLegalDOS8Dot3W() {
		p[130]();
		
	}
	void PROXY_CheckRemoteDebuggerPresent() {
		p[131]();
		
	}
	void PROXY_CheckTokenCapability() {
		p[132]();
		
	}
	void PROXY_CheckTokenMembershipEx() {
		p[133]();
		
	}
	void PROXY_ClearCommBreak() {
		p[134]();
		
	}
	void PROXY_ClearCommError() {
		p[135]();
		
	}
	void PROXY_CloseConsoleHandle() {
		p[136]();
		
	}
	void PROXY_CloseHandle() {
		p[137]();
		
	}
	void PROXY_ClosePackageInfo() {
		p[138]();
		
	}
	void PROXY_ClosePrivateNamespace() {
		p[139]();
		
	}
	void PROXY_CloseProfileUserMapping() {
		p[140]();
		
	}
	void PROXY_ClosePseudoConsole() {
		p[141]();
		
	}
	void PROXY_CloseState() {
		p[142]();
		
	}
	void PROXY_CloseThreadpool() {
		p[143]();
		
	}
	void PROXY_CloseThreadpoolCleanupGroup() {
		p[144]();
		
	}
	void PROXY_CloseThreadpoolCleanupGroupMembers() {
		p[145]();
		
	}
	void PROXY_CloseThreadpoolIo() {
		p[146]();
		
	}
	void PROXY_CloseThreadpoolTimer() {
		p[147]();
		
	}
	void PROXY_CloseThreadpoolWait() {
		p[148]();
		
	}
	void PROXY_CloseThreadpoolWork() {
		p[149]();
		
	}
	void PROXY_CmdBatNotification() {
		p[150]();
		
	}
	void PROXY_CommConfigDialogA() {
		p[151]();
		
	}
	void PROXY_CommConfigDialogW() {
		p[152]();
		
	}
	void PROXY_CompareCalendarDates() {
		p[153]();
		
	}
	void PROXY_CompareFileTime() {
		p[154]();
		
	}
	void PROXY_CompareStringA() {
		p[155]();
		
	}
	void PROXY_CompareStringEx() {
		p[156]();
		
	}
	void PROXY_CompareStringOrdinal() {
		p[157]();
		
	}
	void PROXY_CompareStringW() {
		p[158]();
		
	}
	void PROXY_ConnectNamedPipe() {
		p[159]();
		
	}
	void PROXY_ConsoleMenuControl() {
		p[160]();
		
	}
	void PROXY_ContinueDebugEvent() {
		p[161]();
		
	}
	void PROXY_ConvertCalDateTimeToSystemTime() {
		p[162]();
		
	}
	void PROXY_ConvertDefaultLocale() {
		p[163]();
		
	}
	void PROXY_ConvertFiberToThread() {
		p[164]();
		
	}
	void PROXY_ConvertNLSDayOfWeekToWin32DayOfWeek() {
		p[165]();
		
	}
	void PROXY_ConvertSystemTimeToCalDateTime() {
		p[166]();
		
	}
	void PROXY_ConvertThreadToFiber() {
		p[167]();
		
	}
	void PROXY_ConvertThreadToFiberEx() {
		p[168]();
		
	}
	void PROXY_CopyContext() {
		p[169]();
		
	}
	void PROXY_CopyFile2() {
		p[170]();
		
	}
	void PROXY_CopyFileA() {
		p[171]();
		
	}
	void PROXY_CopyFileExA() {
		p[172]();
		
	}
	void PROXY_CopyFileExW() {
		p[173]();
		
	}
	void PROXY_CopyFileTransactedA() {
		p[174]();
		
	}
	void PROXY_CopyFileTransactedW() {
		p[175]();
		
	}
	void PROXY_CopyFileW() {
		p[176]();
		
	}
	void PROXY_CopyLZFile() {
		p[177]();
		
	}
	void PROXY_CreateActCtxA() {
		p[178]();
		
	}
	void PROXY_CreateActCtxW() {
		p[179]();
		
	}
	void PROXY_CreateActCtxWWorker() {
		p[180]();
		
	}
	void PROXY_CreateBoundaryDescriptorA() {
		p[181]();
		
	}
	void PROXY_CreateBoundaryDescriptorW() {
		p[182]();
		
	}
	void PROXY_CreateConsoleScreenBuffer() {
		p[183]();
		
	}
	void PROXY_CreateDirectoryA() {
		p[184]();
		
	}
	void PROXY_CreateDirectoryExA() {
		p[185]();
		
	}
	void PROXY_CreateDirectoryExW() {
		p[186]();
		
	}
	void PROXY_CreateDirectoryTransactedA() {
		p[187]();
		
	}
	void PROXY_CreateDirectoryTransactedW() {
		p[188]();
		
	}
	void PROXY_CreateDirectoryW() {
		p[189]();
		
	}
	void PROXY_CreateEnclave() {
		p[190]();
		
	}
	void PROXY_CreateEventA() {
		p[191]();
		
	}
	void PROXY_CreateEventExA() {
		p[192]();
		
	}
	void PROXY_CreateEventExW() {
		p[193]();
		
	}
	void PROXY_CreateEventW() {
		p[194]();
		
	}
	void PROXY_CreateFiber() {
		p[195]();
		
	}
	void PROXY_CreateFiberEx() {
		p[196]();
		
	}
	void PROXY_CreateFile2() {
		p[197]();
		
	}
	void PROXY_CreateFileA() {
		p[198]();
		
	}
	void PROXY_CreateFileMappingA() {
		p[199]();
		
	}
	void PROXY_CreateFileMappingFromApp() {
		p[200]();
		
	}
	void PROXY_CreateFileMappingNumaA() {
		p[201]();
		
	}
	void PROXY_CreateFileMappingNumaW() {
		p[202]();
		
	}
	void PROXY_CreateFileMappingW() {
		p[203]();
		
	}
	void PROXY_CreateFileTransactedA() {
		p[204]();
		
	}
	void PROXY_CreateFileTransactedW() {
		p[205]();
		
	}
	void PROXY_CreateFileW() {
		p[206]();
		
	}
	void PROXY_CreateHardLinkA() {
		p[207]();
		
	}
	void PROXY_CreateHardLinkTransactedA() {
		p[208]();
		
	}
	void PROXY_CreateHardLinkTransactedW() {
		p[209]();
		
	}
	void PROXY_CreateHardLinkW() {
		p[210]();
		
	}
	void PROXY_CreateIoCompletionPort() {
		p[211]();
		
	}
	void PROXY_CreateJobObjectA() {
		p[212]();
		
	}
	void PROXY_CreateJobObjectW() {
		p[213]();
		
	}
	void PROXY_CreateJobSet() {
		p[214]();
		
	}
	void PROXY_CreateMailslotA() {
		p[215]();
		
	}
	void PROXY_CreateMailslotW() {
		p[216]();
		
	}
	void PROXY_CreateMemoryResourceNotification() {
		p[217]();
		
	}
	void PROXY_CreateMutexA() {
		p[218]();
		
	}
	void PROXY_CreateMutexExA() {
		p[219]();
		
	}
	void PROXY_CreateMutexExW() {
		p[220]();
		
	}
	void PROXY_CreateMutexW() {
		p[221]();
		
	}
	void PROXY_CreateNamedPipeA() {
		p[222]();
		
	}
	void PROXY_CreateNamedPipeW() {
		p[223]();
		
	}
	void PROXY_CreatePipe() {
		p[224]();
		
	}
	void PROXY_CreatePrivateNamespaceA() {
		p[225]();
		
	}
	void PROXY_CreatePrivateNamespaceW() {
		p[226]();
		
	}
	void PROXY_CreateProcessA() {
		p[227]();
		
	}
	void PROXY_CreateProcessAsUserA() {
		p[228]();
		
	}
	void PROXY_CreateProcessAsUserW() {
		p[229]();
		
	}
	void PROXY_CreateProcessInternalA() {
		p[230]();
		
	}
	void PROXY_CreateProcessInternalW() {
		p[231]();
		
	}
	void PROXY_CreateProcessW() {
		p[232]();
		
	}
	void PROXY_CreatePseudoConsole() {
		p[233]();
		
	}
	void PROXY_CreateRemoteThread() {
		p[234]();
		
	}
	void PROXY_CreateRemoteThreadEx() {
		p[235]();
		
	}
	void PROXY_CreateSemaphoreA() {
		p[236]();
		
	}
	void PROXY_CreateSemaphoreExA() {
		p[237]();
		
	}
	void PROXY_CreateSemaphoreExW() {
		p[238]();
		
	}
	void PROXY_CreateSemaphoreW() {
		p[239]();
		
	}
	void PROXY_CreateSymbolicLinkA() {
		p[240]();
		
	}
	void PROXY_CreateSymbolicLinkTransactedA() {
		p[241]();
		
	}
	void PROXY_CreateSymbolicLinkTransactedW() {
		p[242]();
		
	}
	void PROXY_CreateSymbolicLinkW() {
		p[243]();
		
	}
	void PROXY_CreateTapePartition() {
		p[244]();
		
	}
	void PROXY_CreateThread() {
		p[245]();
		
	}
	void PROXY_CreateThreadpool() {
		p[246]();
		
	}
	void PROXY_CreateThreadpoolCleanupGroup() {
		p[247]();
		
	}
	void PROXY_CreateThreadpoolIo() {
		p[248]();
		
	}
	void PROXY_CreateThreadpoolTimer() {
		p[249]();
		
	}
	void PROXY_CreateThreadpoolWait() {
		p[250]();
		
	}
	void PROXY_CreateThreadpoolWork() {
		p[251]();
		
	}
	void PROXY_CreateTimerQueue() {
		p[252]();
		
	}
	void PROXY_CreateTimerQueueTimer() {
		p[253]();
		
	}
	void PROXY_CreateToolhelp32Snapshot() {
		p[254]();
		
	}
	void PROXY_CreateUmsCompletionList() {
		p[255]();
		
	}
	void PROXY_CreateUmsThreadContext() {
		p[256]();
		
	}
	void PROXY_CreateWaitableTimerA() {
		p[257]();
		
	}
	void PROXY_CreateWaitableTimerExA() {
		p[258]();
		
	}
	void PROXY_CreateWaitableTimerExW() {
		p[259]();
		
	}
	void PROXY_CreateWaitableTimerW() {
		p[260]();
		
	}
	void PROXY_CtrlRoutine() {
		p[261]();
		
	}
	void PROXY_DeactivateActCtx() {
		p[262]();
		
	}
	void PROXY_DeactivateActCtxWorker() {
		p[263]();
		
	}
	void PROXY_DebugActiveProcess() {
		p[264]();
		
	}
	void PROXY_DebugActiveProcessStop() {
		p[265]();
		
	}
	void PROXY_DebugBreak() {
		p[266]();
		
	}
	void PROXY_DebugBreakProcess() {
		p[267]();
		
	}
	void PROXY_DebugSetProcessKillOnExit() {
		p[268]();
		
	}
	void PROXY_DecodePointer() {
		p[269]();
		
	}
	void PROXY_DecodeSystemPointer() {
		p[270]();
		
	}
	void PROXY_DefineDosDeviceA() {
		p[271]();
		
	}
	void PROXY_DefineDosDeviceW() {
		p[272]();
		
	}
	void PROXY_DelayLoadFailureHook() {
		p[273]();
		
	}
	void PROXY_DeleteAtom() {
		p[274]();
		
	}
	void PROXY_DeleteBoundaryDescriptor() {
		p[275]();
		
	}
	void PROXY_DeleteCriticalSection() {
		p[276]();
		
	}
	void PROXY_DeleteFiber() {
		p[277]();
		
	}
	void PROXY_DeleteFileA() {
		p[278]();
		
	}
	void PROXY_DeleteFileTransactedA() {
		p[279]();
		
	}
	void PROXY_DeleteFileTransactedW() {
		p[280]();
		
	}
	void PROXY_DeleteFileW() {
		p[281]();
		
	}
	void PROXY_DeleteProcThreadAttributeList() {
		p[282]();
		
	}
	void PROXY_DeleteSynchronizationBarrier() {
		p[283]();
		
	}
	void PROXY_DeleteTimerQueue() {
		p[284]();
		
	}
	void PROXY_DeleteTimerQueueEx() {
		p[285]();
		
	}
	void PROXY_DeleteTimerQueueTimer() {
		p[286]();
		
	}
	void PROXY_DeleteUmsCompletionList() {
		p[287]();
		
	}
	void PROXY_DeleteUmsThreadContext() {
		p[288]();
		
	}
	void PROXY_DeleteVolumeMountPointA() {
		p[289]();
		
	}
	void PROXY_DeleteVolumeMountPointW() {
		p[290]();
		
	}
	void PROXY_DequeueUmsCompletionListItems() {
		p[291]();
		
	}
	void PROXY_DeviceIoControl() {
		p[292]();
		
	}
	void PROXY_DisableThreadLibraryCalls() {
		p[293]();
		
	}
	void PROXY_DisableThreadProfiling() {
		p[294]();
		
	}
	void PROXY_DisassociateCurrentThreadFromCallback() {
		p[295]();
		
	}
	void PROXY_DiscardVirtualMemory() {
		p[296]();
		
	}
	void PROXY_DisconnectNamedPipe() {
		p[297]();
		
	}
	void PROXY_DnsHostnameToComputerNameA() {
		p[298]();
		
	}
	void PROXY_DnsHostnameToComputerNameExW() {
		p[299]();
		
	}
	void PROXY_DnsHostnameToComputerNameW() {
		p[300]();
		
	}
	void PROXY_DosDateTimeToFileTime() {
		p[301]();
		
	}
	void PROXY_DosPathToSessionPathA() {
		p[302]();
		
	}
	void PROXY_DosPathToSessionPathW() {
		p[303]();
		
	}
	void PROXY_DuplicateConsoleHandle() {
		p[304]();
		
	}
	void PROXY_DuplicateEncryptionInfoFileExt() {
		p[305]();
		
	}
	void PROXY_DuplicateHandle() {
		p[306]();
		
	}
	void PROXY_EnableThreadProfiling() {
		p[307]();
		
	}
	void PROXY_EncodePointer() {
		p[308]();
		
	}
	void PROXY_EncodeSystemPointer() {
		p[309]();
		
	}
	void PROXY_EndUpdateResourceA() {
		p[310]();
		
	}
	void PROXY_EndUpdateResourceW() {
		p[311]();
		
	}
	void PROXY_EnterCriticalSection() {
		p[312]();
		
	}
	void PROXY_EnterSynchronizationBarrier() {
		p[313]();
		
	}
	void PROXY_EnterUmsSchedulingMode() {
		p[314]();
		
	}
	void PROXY_EnumCalendarInfoA() {
		p[315]();
		
	}
	void PROXY_EnumCalendarInfoExA() {
		p[316]();
		
	}
	void PROXY_EnumCalendarInfoExEx() {
		p[317]();
		
	}
	void PROXY_EnumCalendarInfoExW() {
		p[318]();
		
	}
	void PROXY_EnumCalendarInfoW() {
		p[319]();
		
	}
	void PROXY_EnumDateFormatsA() {
		p[320]();
		
	}
	void PROXY_EnumDateFormatsExA() {
		p[321]();
		
	}
	void PROXY_EnumDateFormatsExEx() {
		p[322]();
		
	}
	void PROXY_EnumDateFormatsExW() {
		p[323]();
		
	}
	void PROXY_EnumDateFormatsW() {
		p[324]();
		
	}
	void PROXY_EnumLanguageGroupLocalesA() {
		p[325]();
		
	}
	void PROXY_EnumLanguageGroupLocalesW() {
		p[326]();
		
	}
	void PROXY_EnumResourceLanguagesA() {
		p[327]();
		
	}
	void PROXY_EnumResourceLanguagesExA() {
		p[328]();
		
	}
	void PROXY_EnumResourceLanguagesExW() {
		p[329]();
		
	}
	void PROXY_EnumResourceLanguagesW() {
		p[330]();
		
	}
	void PROXY_EnumResourceNamesA() {
		p[331]();
		
	}
	void PROXY_EnumResourceNamesExA() {
		p[332]();
		
	}
	void PROXY_EnumResourceNamesExW() {
		p[333]();
		
	}
	void PROXY_EnumResourceNamesW() {
		p[334]();
		
	}
	void PROXY_EnumResourceTypesA() {
		p[335]();
		
	}
	void PROXY_EnumResourceTypesExA() {
		p[336]();
		
	}
	void PROXY_EnumResourceTypesExW() {
		p[337]();
		
	}
	void PROXY_EnumResourceTypesW() {
		p[338]();
		
	}
	void PROXY_EnumSystemCodePagesA() {
		p[339]();
		
	}
	void PROXY_EnumSystemCodePagesW() {
		p[340]();
		
	}
	void PROXY_EnumSystemFirmwareTables() {
		p[341]();
		
	}
	void PROXY_EnumSystemGeoID() {
		p[342]();
		
	}
	void PROXY_EnumSystemGeoNames() {
		p[343]();
		
	}
	void PROXY_EnumSystemLanguageGroupsA() {
		p[344]();
		
	}
	void PROXY_EnumSystemLanguageGroupsW() {
		p[345]();
		
	}
	void PROXY_EnumSystemLocalesA() {
		p[346]();
		
	}
	void PROXY_EnumSystemLocalesEx() {
		p[347]();
		
	}
	void PROXY_EnumSystemLocalesW() {
		p[348]();
		
	}
	void PROXY_EnumTimeFormatsA() {
		p[349]();
		
	}
	void PROXY_EnumTimeFormatsEx() {
		p[350]();
		
	}
	void PROXY_EnumTimeFormatsW() {
		p[351]();
		
	}
	void PROXY_EnumUILanguagesA() {
		p[352]();
		
	}
	void PROXY_EnumUILanguagesW() {
		p[353]();
		
	}
	void PROXY_EnumerateLocalComputerNamesA() {
		p[354]();
		
	}
	void PROXY_EnumerateLocalComputerNamesW() {
		p[355]();
		
	}
	void PROXY_EraseTape() {
		p[356]();
		
	}
	void PROXY_EscapeCommFunction() {
		p[357]();
		
	}
	void PROXY_ExecuteUmsThread() {
		p[358]();
		
	}
	void PROXY_ExitProcess() {
		p[359]();
		
	}
	void PROXY_ExitThread() {
		p[360]();
		
	}
	void PROXY_ExitVDM() {
		p[361]();
		
	}
	void PROXY_ExpandEnvironmentStringsA() {
		p[362]();
		
	}
	void PROXY_ExpandEnvironmentStringsW() {
		p[363]();
		
	}
	void PROXY_ExpungeConsoleCommandHistoryA() {
		p[364]();
		
	}
	void PROXY_ExpungeConsoleCommandHistoryW() {
		p[365]();
		
	}
	void PROXY_FatalAppExitA() {
		p[366]();
		
	}
	void PROXY_FatalAppExitW() {
		p[367]();
		
	}
	void PROXY_FatalExit() {
		p[368]();
		
	}
	void PROXY_FileTimeToDosDateTime() {
		p[369]();
		
	}
	void PROXY_FileTimeToLocalFileTime() {
		p[370]();
		
	}
	void PROXY_FileTimeToSystemTime() {
		p[371]();
		
	}
	void PROXY_FillConsoleOutputAttribute() {
		p[372]();
		
	}
	void PROXY_FillConsoleOutputCharacterA() {
		p[373]();
		
	}
	void PROXY_FillConsoleOutputCharacterW() {
		p[374]();
		
	}
	void PROXY_FindActCtxSectionGuid() {
		p[375]();
		
	}
	void PROXY_FindActCtxSectionGuidWorker() {
		p[376]();
		
	}
	void PROXY_FindActCtxSectionStringA() {
		p[377]();
		
	}
	void PROXY_FindActCtxSectionStringW() {
		p[378]();
		
	}
	void PROXY_FindActCtxSectionStringWWorker() {
		p[379]();
		
	}
	void PROXY_FindAtomA() {
		p[380]();
		
	}
	void PROXY_FindAtomW() {
		p[381]();
		
	}
	void PROXY_FindClose() {
		p[382]();
		
	}
	void PROXY_FindCloseChangeNotification() {
		p[383]();
		
	}
	void PROXY_FindFirstChangeNotificationA() {
		p[384]();
		
	}
	void PROXY_FindFirstChangeNotificationW() {
		p[385]();
		
	}
	void PROXY_FindFirstFileA() {
		p[386]();
		
	}
	void PROXY_FindFirstFileExA() {
		p[387]();
		
	}
	void PROXY_FindFirstFileExW() {
		p[388]();
		
	}
	void PROXY_FindFirstFileNameTransactedW() {
		p[389]();
		
	}
	void PROXY_FindFirstFileNameW() {
		p[390]();
		
	}
	void PROXY_FindFirstFileTransactedA() {
		p[391]();
		
	}
	void PROXY_FindFirstFileTransactedW() {
		p[392]();
		
	}
	void PROXY_FindFirstFileW() {
		p[393]();
		
	}
	void PROXY_FindFirstStreamTransactedW() {
		p[394]();
		
	}
	void PROXY_FindFirstStreamW() {
		p[395]();
		
	}
	void PROXY_FindFirstVolumeA() {
		p[396]();
		
	}
	void PROXY_FindFirstVolumeMountPointA() {
		p[397]();
		
	}
	void PROXY_FindFirstVolumeMountPointW() {
		p[398]();
		
	}
	void PROXY_FindFirstVolumeW() {
		p[399]();
		
	}
	void PROXY_FindNLSString() {
		p[400]();
		
	}
	void PROXY_FindNLSStringEx() {
		p[401]();
		
	}
	void PROXY_FindNextChangeNotification() {
		p[402]();
		
	}
	void PROXY_FindNextFileA() {
		p[403]();
		
	}
	void PROXY_FindNextFileNameW() {
		p[404]();
		
	}
	void PROXY_FindNextFileW() {
		p[405]();
		
	}
	void PROXY_FindNextStreamW() {
		p[406]();
		
	}
	void PROXY_FindNextVolumeA() {
		p[407]();
		
	}
	void PROXY_FindNextVolumeMountPointA() {
		p[408]();
		
	}
	void PROXY_FindNextVolumeMountPointW() {
		p[409]();
		
	}
	void PROXY_FindNextVolumeW() {
		p[410]();
		
	}
	void PROXY_FindPackagesByPackageFamily() {
		p[411]();
		
	}
	void PROXY_FindResourceA() {
		p[412]();
		
	}
	void PROXY_FindResourceExA() {
		p[413]();
		
	}
	void PROXY_FindResourceExW() {
		p[414]();
		
	}
	void PROXY_FindResourceW() {
		p[415]();
		
	}
	void PROXY_FindStringOrdinal() {
		p[416]();
		
	}
	void PROXY_FindVolumeClose() {
		p[417]();
		
	}
	void PROXY_FindVolumeMountPointClose() {
		p[418]();
		
	}
	void PROXY_FlsAlloc() {
		p[419]();
		
	}
	void PROXY_FlsFree() {
		p[420]();
		
	}
	void PROXY_FlsGetValue() {
		p[421]();
		
	}
	void PROXY_FlsSetValue() {
		p[422]();
		
	}
	void PROXY_FlushConsoleInputBuffer() {
		p[423]();
		
	}
	void PROXY_FlushFileBuffers() {
		p[424]();
		
	}
	void PROXY_FlushInstructionCache() {
		p[425]();
		
	}
	void PROXY_FlushProcessWriteBuffers() {
		p[426]();
		
	}
	void PROXY_FlushViewOfFile() {
		p[427]();
		
	}
	void PROXY_FoldStringA() {
		p[428]();
		
	}
	void PROXY_FoldStringW() {
		p[429]();
		
	}
	void PROXY_FormatApplicationUserModelId() {
		p[430]();
		
	}
	void PROXY_FormatMessageA() {
		p[431]();
		
	}
	void PROXY_FormatMessageW() {
		p[432]();
		
	}
	void PROXY_FreeConsole() {
		p[433]();
		
	}
	void PROXY_FreeEnvironmentStringsA() {
		p[434]();
		
	}
	void PROXY_FreeEnvironmentStringsW() {
		p[435]();
		
	}
	void PROXY_FreeLibrary() {
		p[436]();
		
	}
	void PROXY_FreeLibraryAndExitThread() {
		p[437]();
		
	}
	void PROXY_FreeLibraryWhenCallbackReturns() {
		p[438]();
		
	}
	void PROXY_FreeMemoryJobObject() {
		p[439]();
		
	}
	void PROXY_FreeResource() {
		p[440]();
		
	}
	void PROXY_FreeUserPhysicalPages() {
		p[441]();
		
	}
	void PROXY_GenerateConsoleCtrlEvent() {
		p[442]();
		
	}
	void PROXY_GetACP() {
		p[443]();
		
	}
	void PROXY_GetActiveProcessorCount() {
		p[444]();
		
	}
	void PROXY_GetActiveProcessorGroupCount() {
		p[445]();
		
	}
	void PROXY_GetAppContainerAce() {
		p[446]();
		
	}
	void PROXY_GetAppContainerNamedObjectPath() {
		p[447]();
		
	}
	void PROXY_GetApplicationRecoveryCallback() {
		p[448]();
		
	}
	void PROXY_GetApplicationRecoveryCallbackWorker() {
		p[449]();
		
	}
	void PROXY_GetApplicationRestartSettings() {
		p[450]();
		
	}
	void PROXY_GetApplicationRestartSettingsWorker() {
		p[451]();
		
	}
	void PROXY_GetApplicationUserModelId() {
		p[452]();
		
	}
	void PROXY_GetAtomNameA() {
		p[453]();
		
	}
	void PROXY_GetAtomNameW() {
		p[454]();
		
	}
	void PROXY_GetBinaryType() {
		p[455]();
		
	}
	void PROXY_GetBinaryTypeA() {
		p[456]();
		
	}
	void PROXY_GetBinaryTypeW() {
		p[457]();
		
	}
	void PROXY_GetCPInfo() {
		p[458]();
		
	}
	void PROXY_GetCPInfoExA() {
		p[459]();
		
	}
	void PROXY_GetCPInfoExW() {
		p[460]();
		
	}
	void PROXY_GetCachedSigningLevel() {
		p[461]();
		
	}
	void PROXY_GetCalendarDateFormat() {
		p[462]();
		
	}
	void PROXY_GetCalendarDateFormatEx() {
		p[463]();
		
	}
	void PROXY_GetCalendarDaysInMonth() {
		p[464]();
		
	}
	void PROXY_GetCalendarDifferenceInDays() {
		p[465]();
		
	}
	void PROXY_GetCalendarInfoA() {
		p[466]();
		
	}
	void PROXY_GetCalendarInfoEx() {
		p[467]();
		
	}
	void PROXY_GetCalendarInfoW() {
		p[468]();
		
	}
	void PROXY_GetCalendarMonthsInYear() {
		p[469]();
		
	}
	void PROXY_GetCalendarSupportedDateRange() {
		p[470]();
		
	}
	void PROXY_GetCalendarWeekNumber() {
		p[471]();
		
	}
	void PROXY_GetComPlusPackageInstallStatus() {
		p[472]();
		
	}
	void PROXY_GetCommConfig() {
		p[473]();
		
	}
	void PROXY_GetCommMask() {
		p[474]();
		
	}
	void PROXY_GetCommModemStatus() {
		p[475]();
		
	}
	void PROXY_GetCommProperties() {
		p[476]();
		
	}
	void PROXY_GetCommState() {
		p[477]();
		
	}
	void PROXY_GetCommTimeouts() {
		p[478]();
		
	}
	void PROXY_GetCommandLineA() {
		p[479]();
		
	}
	void PROXY_GetCommandLineW() {
		p[480]();
		
	}
	void PROXY_GetCompressedFileSizeA() {
		p[481]();
		
	}
	void PROXY_GetCompressedFileSizeTransactedA() {
		p[482]();
		
	}
	void PROXY_GetCompressedFileSizeTransactedW() {
		p[483]();
		
	}
	void PROXY_GetCompressedFileSizeW() {
		p[484]();
		
	}
	void PROXY_GetComputerNameA() {
		p[485]();
		
	}
	void PROXY_GetComputerNameExA() {
		p[486]();
		
	}
	void PROXY_GetComputerNameExW() {
		p[487]();
		
	}
	void PROXY_GetComputerNameW() {
		p[488]();
		
	}
	void PROXY_GetConsoleAliasA() {
		p[489]();
		
	}
	void PROXY_GetConsoleAliasExesA() {
		p[490]();
		
	}
	void PROXY_GetConsoleAliasExesLengthA() {
		p[491]();
		
	}
	void PROXY_GetConsoleAliasExesLengthW() {
		p[492]();
		
	}
	void PROXY_GetConsoleAliasExesW() {
		p[493]();
		
	}
	void PROXY_GetConsoleAliasW() {
		p[494]();
		
	}
	void PROXY_GetConsoleAliasesA() {
		p[495]();
		
	}
	void PROXY_GetConsoleAliasesLengthA() {
		p[496]();
		
	}
	void PROXY_GetConsoleAliasesLengthW() {
		p[497]();
		
	}
	void PROXY_GetConsoleAliasesW() {
		p[498]();
		
	}
	void PROXY_GetConsoleCP() {
		p[499]();
		
	}
	void PROXY_GetConsoleCharType() {
		p[500]();
		
	}
	void PROXY_GetConsoleCommandHistoryA() {
		p[501]();
		
	}
	void PROXY_GetConsoleCommandHistoryLengthA() {
		p[502]();
		
	}
	void PROXY_GetConsoleCommandHistoryLengthW() {
		p[503]();
		
	}
	void PROXY_GetConsoleCommandHistoryW() {
		p[504]();
		
	}
	void PROXY_GetConsoleCursorInfo() {
		p[505]();
		
	}
	void PROXY_GetConsoleCursorMode() {
		p[506]();
		
	}
	void PROXY_GetConsoleDisplayMode() {
		p[507]();
		
	}
	void PROXY_GetConsoleFontInfo() {
		p[508]();
		
	}
	void PROXY_GetConsoleFontSize() {
		p[509]();
		
	}
	void PROXY_GetConsoleHardwareState() {
		p[510]();
		
	}
	void PROXY_GetConsoleHistoryInfo() {
		p[511]();
		
	}
	void PROXY_GetConsoleInputExeNameA() {
		p[512]();
		
	}
	void PROXY_GetConsoleInputExeNameW() {
		p[513]();
		
	}
	void PROXY_GetConsoleInputWaitHandle() {
		p[514]();
		
	}
	void PROXY_GetConsoleKeyboardLayoutNameA() {
		p[515]();
		
	}
	void PROXY_GetConsoleKeyboardLayoutNameW() {
		p[516]();
		
	}
	void PROXY_GetConsoleMode() {
		p[517]();
		
	}
	void PROXY_GetConsoleNlsMode() {
		p[518]();
		
	}
	void PROXY_GetConsoleOriginalTitleA() {
		p[519]();
		
	}
	void PROXY_GetConsoleOriginalTitleW() {
		p[520]();
		
	}
	void PROXY_GetConsoleOutputCP() {
		p[521]();
		
	}
	void PROXY_GetConsoleProcessList() {
		p[522]();
		
	}
	void PROXY_GetConsoleScreenBufferInfo() {
		p[523]();
		
	}
	void PROXY_GetConsoleScreenBufferInfoEx() {
		p[524]();
		
	}
	void PROXY_GetConsoleSelectionInfo() {
		p[525]();
		
	}
	void PROXY_GetConsoleTitleA() {
		p[526]();
		
	}
	void PROXY_GetConsoleTitleW() {
		p[527]();
		
	}
	void PROXY_GetConsoleWindow() {
		p[528]();
		
	}
	void PROXY_GetCurrencyFormatA() {
		p[529]();
		
	}
	void PROXY_GetCurrencyFormatEx() {
		p[530]();
		
	}
	void PROXY_GetCurrencyFormatW() {
		p[531]();
		
	}
	void PROXY_GetCurrentActCtx() {
		p[532]();
		
	}
	void PROXY_GetCurrentActCtxWorker() {
		p[533]();
		
	}
	void PROXY_GetCurrentApplicationUserModelId() {
		p[534]();
		
	}
	void PROXY_GetCurrentConsoleFont() {
		p[535]();
		
	}
	void PROXY_GetCurrentConsoleFontEx() {
		p[536]();
		
	}
	void PROXY_GetCurrentDirectoryA() {
		p[537]();
		
	}
	void PROXY_GetCurrentDirectoryW() {
		p[538]();
		
	}
	void PROXY_GetCurrentPackageFamilyName() {
		p[539]();
		
	}
	void PROXY_GetCurrentPackageFullName() {
		p[540]();
		
	}
	void PROXY_GetCurrentPackageId() {
		p[541]();
		
	}
	void PROXY_GetCurrentPackageInfo() {
		p[542]();
		
	}
	void PROXY_GetCurrentPackagePath() {
		p[543]();
		
	}
	void PROXY_GetCurrentProcess() {
		p[544]();
		
	}
	void PROXY_GetCurrentProcessId() {
		p[545]();
		
	}
	void PROXY_GetCurrentProcessorNumber() {
		p[546]();
		
	}
	void PROXY_GetCurrentProcessorNumberEx() {
		p[547]();
		
	}
	void PROXY_GetCurrentThread() {
		p[548]();
		
	}
	void PROXY_GetCurrentThreadId() {
		p[549]();
		
	}
	void PROXY_GetCurrentThreadStackLimits() {
		p[550]();
		
	}
	void PROXY_GetCurrentUmsThread() {
		p[551]();
		
	}
	void PROXY_GetDateFormatA() {
		p[552]();
		
	}
	void PROXY_GetDateFormatAWorker() {
		p[553]();
		
	}
	void PROXY_GetDateFormatEx() {
		p[554]();
		
	}
	void PROXY_GetDateFormatW() {
		p[555]();
		
	}
	void PROXY_GetDateFormatWWorker() {
		p[556]();
		
	}
	void PROXY_GetDefaultCommConfigA() {
		p[557]();
		
	}
	void PROXY_GetDefaultCommConfigW() {
		p[558]();
		
	}
	void PROXY_GetDevicePowerState() {
		p[559]();
		
	}
	void PROXY_GetDiskFreeSpaceA() {
		p[560]();
		
	}
	void PROXY_GetDiskFreeSpaceExA() {
		p[561]();
		
	}
	void PROXY_GetDiskFreeSpaceExW() {
		p[562]();
		
	}
	void PROXY_GetDiskFreeSpaceW() {
		p[563]();
		
	}
	void PROXY_GetDiskSpaceInformationA() {
		p[564]();
		
	}
	void PROXY_GetDiskSpaceInformationW() {
		p[565]();
		
	}
	void PROXY_GetDllDirectoryA() {
		p[566]();
		
	}
	void PROXY_GetDllDirectoryW() {
		p[567]();
		
	}
	void PROXY_GetDriveTypeA() {
		p[568]();
		
	}
	void PROXY_GetDriveTypeW() {
		p[569]();
		
	}
	void PROXY_GetDurationFormat() {
		p[570]();
		
	}
	void PROXY_GetDurationFormatEx() {
		p[571]();
		
	}
	void PROXY_GetDynamicTimeZoneInformation() {
		p[572]();
		
	}
	void PROXY_GetEnabledXStateFeatures() {
		p[573]();
		
	}
	void PROXY_GetEncryptedFileVersionExt() {
		p[574]();
		
	}
	void PROXY_GetEnvironmentStrings() {
		p[575]();
		
	}
	void PROXY_GetEnvironmentStringsA() {
		p[576]();
		
	}
	void PROXY_GetEnvironmentStringsW() {
		p[577]();
		
	}
	void PROXY_GetEnvironmentVariableA() {
		p[578]();
		
	}
	void PROXY_GetEnvironmentVariableW() {
		p[579]();
		
	}
	void PROXY_GetEraNameCountedString() {
		p[580]();
		
	}
	void PROXY_GetErrorMode() {
		p[581]();
		
	}
	void PROXY_GetExitCodeProcess() {
		p[582]();
		
	}
	void PROXY_GetExitCodeThread() {
		p[583]();
		
	}
	void PROXY_GetExpandedNameA() {
		p[584]();
		
	}
	void PROXY_GetExpandedNameW() {
		p[585]();
		
	}
	void PROXY_GetFileAttributesA() {
		p[586]();
		
	}
	void PROXY_GetFileAttributesExA() {
		p[587]();
		
	}
	void PROXY_GetFileAttributesExW() {
		p[588]();
		
	}
	void PROXY_GetFileAttributesTransactedA() {
		p[589]();
		
	}
	void PROXY_GetFileAttributesTransactedW() {
		p[590]();
		
	}
	void PROXY_GetFileAttributesW() {
		p[591]();
		
	}
	void PROXY_GetFileBandwidthReservation() {
		p[592]();
		
	}
	void PROXY_GetFileInformationByHandle() {
		p[593]();
		
	}
	void PROXY_GetFileInformationByHandleEx() {
		p[594]();
		
	}
	void PROXY_GetFileMUIInfo() {
		p[595]();
		
	}
	void PROXY_GetFileMUIPath() {
		p[596]();
		
	}
	void PROXY_GetFileSize() {
		p[597]();
		
	}
	void PROXY_GetFileSizeEx() {
		p[598]();
		
	}
	void PROXY_GetFileTime() {
		p[599]();
		
	}
	void PROXY_GetFileType() {
		p[600]();
		
	}
	void PROXY_GetFinalPathNameByHandleA() {
		p[601]();
		
	}
	void PROXY_GetFinalPathNameByHandleW() {
		p[602]();
		
	}
	void PROXY_GetFirmwareEnvironmentVariableA() {
		p[603]();
		
	}
	void PROXY_GetFirmwareEnvironmentVariableExA() {
		p[604]();
		
	}
	void PROXY_GetFirmwareEnvironmentVariableExW() {
		p[605]();
		
	}
	void PROXY_GetFirmwareEnvironmentVariableW() {
		p[606]();
		
	}
	void PROXY_GetFirmwareType() {
		p[607]();
		
	}
	void PROXY_GetFullPathNameA() {
		p[608]();
		
	}
	void PROXY_GetFullPathNameTransactedA() {
		p[609]();
		
	}
	void PROXY_GetFullPathNameTransactedW() {
		p[610]();
		
	}
	void PROXY_GetFullPathNameW() {
		p[611]();
		
	}
	void PROXY_GetGeoInfoA() {
		p[612]();
		
	}
	void PROXY_GetGeoInfoEx() {
		p[613]();
		
	}
	void PROXY_GetGeoInfoW() {
		p[614]();
		
	}
	void PROXY_GetHandleInformation() {
		p[615]();
		
	}
	void PROXY_GetLargePageMinimum() {
		p[616]();
		
	}
	void PROXY_GetLargestConsoleWindowSize() {
		p[617]();
		
	}
	void PROXY_GetLastError() {
		p[618]();
		
	}
	void PROXY_GetLocalTime() {
		p[619]();
		
	}
	void PROXY_GetLocaleInfoA() {
		p[620]();
		
	}
	void PROXY_GetLocaleInfoEx() {
		p[621]();
		
	}
	void PROXY_GetLocaleInfoW() {
		p[622]();
		
	}
	void PROXY_GetLogicalDriveStringsA() {
		p[623]();
		
	}
	void PROXY_GetLogicalDriveStringsW() {
		p[624]();
		
	}
	void PROXY_GetLogicalDrives() {
		p[625]();
		
	}
	void PROXY_GetLogicalProcessorInformation() {
		p[626]();
		
	}
	void PROXY_GetLogicalProcessorInformationEx() {
		p[627]();
		
	}
	void PROXY_GetLongPathNameA() {
		p[628]();
		
	}
	void PROXY_GetLongPathNameTransactedA() {
		p[629]();
		
	}
	void PROXY_GetLongPathNameTransactedW() {
		p[630]();
		
	}
	void PROXY_GetLongPathNameW() {
		p[631]();
		
	}
	void PROXY_GetMailslotInfo() {
		p[632]();
		
	}
	void PROXY_GetMaximumProcessorCount() {
		p[633]();
		
	}
	void PROXY_GetMaximumProcessorGroupCount() {
		p[634]();
		
	}
	void PROXY_GetMemoryErrorHandlingCapabilities() {
		p[635]();
		
	}
	void PROXY_GetModuleFileNameA() {
		p[636]();
		
	}
	void PROXY_GetModuleFileNameW() {
		p[637]();
		
	}
	void PROXY_GetModuleHandleA() {
		p[638]();
		
	}
	void PROXY_GetModuleHandleExA() {
		p[639]();
		
	}
	void PROXY_GetModuleHandleExW() {
		p[640]();
		
	}
	void PROXY_GetModuleHandleW() {
		p[641]();
		
	}
	void PROXY_GetNLSVersion() {
		p[642]();
		
	}
	void PROXY_GetNLSVersionEx() {
		p[643]();
		
	}
	void PROXY_GetNamedPipeAttribute() {
		p[644]();
		
	}
	void PROXY_GetNamedPipeClientComputerNameA() {
		p[645]();
		
	}
	void PROXY_GetNamedPipeClientComputerNameW() {
		p[646]();
		
	}
	void PROXY_GetNamedPipeClientProcessId() {
		p[647]();
		
	}
	void PROXY_GetNamedPipeClientSessionId() {
		p[648]();
		
	}
	void PROXY_GetNamedPipeHandleStateA() {
		p[649]();
		
	}
	void PROXY_GetNamedPipeHandleStateW() {
		p[650]();
		
	}
	void PROXY_GetNamedPipeInfo() {
		p[651]();
		
	}
	void PROXY_GetNamedPipeServerProcessId() {
		p[652]();
		
	}
	void PROXY_GetNamedPipeServerSessionId() {
		p[653]();
		
	}
	void PROXY_GetNativeSystemInfo() {
		p[654]();
		
	}
	void PROXY_GetNextUmsListItem() {
		p[655]();
		
	}
	void PROXY_GetNextVDMCommand() {
		p[656]();
		
	}
	void PROXY_GetNumaAvailableMemoryNode() {
		p[657]();
		
	}
	void PROXY_GetNumaAvailableMemoryNodeEx() {
		p[658]();
		
	}
	void PROXY_GetNumaHighestNodeNumber() {
		p[659]();
		
	}
	void PROXY_GetNumaNodeNumberFromHandle() {
		p[660]();
		
	}
	void PROXY_GetNumaNodeProcessorMask() {
		p[661]();
		
	}
	void PROXY_GetNumaNodeProcessorMaskEx() {
		p[662]();
		
	}
	void PROXY_GetNumaProcessorNode() {
		p[663]();
		
	}
	void PROXY_GetNumaProcessorNodeEx() {
		p[664]();
		
	}
	void PROXY_GetNumaProximityNode() {
		p[665]();
		
	}
	void PROXY_GetNumaProximityNodeEx() {
		p[666]();
		
	}
	void PROXY_GetNumberFormatA() {
		p[667]();
		
	}
	void PROXY_GetNumberFormatEx() {
		p[668]();
		
	}
	void PROXY_GetNumberFormatW() {
		p[669]();
		
	}
	void PROXY_GetNumberOfConsoleFonts() {
		p[670]();
		
	}
	void PROXY_GetNumberOfConsoleInputEvents() {
		p[671]();
		
	}
	void PROXY_GetNumberOfConsoleMouseButtons() {
		p[672]();
		
	}
	void PROXY_GetOEMCP() {
		p[673]();
		
	}
	void PROXY_GetOverlappedResult() {
		p[674]();
		
	}
	void PROXY_GetOverlappedResultEx() {
		p[675]();
		
	}
	void PROXY_GetPackageApplicationIds() {
		p[676]();
		
	}
	void PROXY_GetPackageFamilyName() {
		p[677]();
		
	}
	void PROXY_GetPackageFullName() {
		p[678]();
		
	}
	void PROXY_GetPackageId() {
		p[679]();
		
	}
	void PROXY_GetPackageInfo() {
		p[680]();
		
	}
	void PROXY_GetPackagePath() {
		p[681]();
		
	}
	void PROXY_GetPackagePathByFullName() {
		p[682]();
		
	}
	void PROXY_GetPackagesByPackageFamily() {
		p[683]();
		
	}
	void PROXY_GetPhysicallyInstalledSystemMemory() {
		p[684]();
		
	}
	void PROXY_GetPriorityClass() {
		p[685]();
		
	}
	void PROXY_GetPrivateProfileIntA() {
		p[686]();
		
	}
	void PROXY_GetPrivateProfileIntW() {
		p[687]();
		
	}
	void PROXY_GetPrivateProfileSectionA() {
		p[688]();
		
	}
	void PROXY_GetPrivateProfileSectionNamesA() {
		p[689]();
		
	}
	void PROXY_GetPrivateProfileSectionNamesW() {
		p[690]();
		
	}
	void PROXY_GetPrivateProfileSectionW() {
		p[691]();
		
	}
	void PROXY_GetPrivateProfileStringA() {
		p[692]();
		
	}
	void PROXY_GetPrivateProfileStringW() {
		p[693]();
		
	}
	void PROXY_GetPrivateProfileStructA() {
		p[694]();
		
	}
	void PROXY_GetPrivateProfileStructW() {
		p[695]();
		
	}
	void PROXY_GetProcAddress() {
		p[696]();
		
	}
	void PROXY_GetProcessAffinityMask() {
		p[697]();
		
	}
	void PROXY_GetProcessDEPPolicy() {
		p[698]();
		
	}
	void PROXY_GetProcessDefaultCpuSets() {
		p[699]();
		
	}
	void PROXY_GetProcessGroupAffinity() {
		p[700]();
		
	}
	void PROXY_GetProcessHandleCount() {
		p[701]();
		
	}
	void PROXY_GetProcessHeap() {
		p[702]();
		
	}
	void PROXY_GetProcessHeaps() {
		p[703]();
		
	}
	void PROXY_GetProcessId() {
		p[704]();
		
	}
	void PROXY_GetProcessIdOfThread() {
		p[705]();
		
	}
	void PROXY_GetProcessInformation() {
		p[706]();
		
	}
	void PROXY_GetProcessIoCounters() {
		p[707]();
		
	}
	void PROXY_GetProcessMitigationPolicy() {
		p[708]();
		
	}
	void PROXY_GetProcessPreferredUILanguages() {
		p[709]();
		
	}
	void PROXY_GetProcessPriorityBoost() {
		p[710]();
		
	}
	void PROXY_GetProcessShutdownParameters() {
		p[711]();
		
	}
	void PROXY_GetProcessTimes() {
		p[712]();
		
	}
	void PROXY_GetProcessVersion() {
		p[713]();
		
	}
	void PROXY_GetProcessWorkingSetSize() {
		p[714]();
		
	}
	void PROXY_GetProcessWorkingSetSizeEx() {
		p[715]();
		
	}
	void PROXY_GetProcessorSystemCycleTime() {
		p[716]();
		
	}
	void PROXY_GetProductInfo() {
		p[717]();
		
	}
	void PROXY_GetProfileIntA() {
		p[718]();
		
	}
	void PROXY_GetProfileIntW() {
		p[719]();
		
	}
	void PROXY_GetProfileSectionA() {
		p[720]();
		
	}
	void PROXY_GetProfileSectionW() {
		p[721]();
		
	}
	void PROXY_GetProfileStringA() {
		p[722]();
		
	}
	void PROXY_GetProfileStringW() {
		p[723]();
		
	}
	void PROXY_GetQueuedCompletionStatus() {
		p[724]();
		
	}
	void PROXY_GetQueuedCompletionStatusEx() {
		p[725]();
		
	}
	void PROXY_GetShortPathNameA() {
		p[726]();
		
	}
	void PROXY_GetShortPathNameW() {
		p[727]();
		
	}
	void PROXY_GetStagedPackagePathByFullName() {
		p[728]();
		
	}
	void PROXY_GetStartupInfoA() {
		p[729]();
		
	}
	void PROXY_GetStartupInfoW() {
		p[730]();
		
	}
	void PROXY_GetStateFolder() {
		p[731]();
		
	}
	void PROXY_GetStdHandle() {
		p[732]();
		
	}
	void PROXY_GetStringScripts() {
		p[733]();
		
	}
	void PROXY_GetStringTypeA() {
		p[734]();
		
	}
	void PROXY_GetStringTypeExA() {
		p[735]();
		
	}
	void PROXY_GetStringTypeExW() {
		p[736]();
		
	}
	void PROXY_GetStringTypeW() {
		p[737]();
		
	}
	void PROXY_GetSystemAppDataKey() {
		p[738]();
		
	}
	void PROXY_GetSystemCpuSetInformation() {
		p[739]();
		
	}
	void PROXY_GetSystemDEPPolicy() {
		p[740]();
		
	}
	void PROXY_GetSystemDefaultLCID() {
		p[741]();
		
	}
	void PROXY_GetSystemDefaultLangID() {
		p[742]();
		
	}
	void PROXY_GetSystemDefaultLocaleName() {
		p[743]();
		
	}
	void PROXY_GetSystemDefaultUILanguage() {
		p[744]();
		
	}
	void PROXY_GetSystemDirectoryA() {
		p[745]();
		
	}
	void PROXY_GetSystemDirectoryW() {
		p[746]();
		
	}
	void PROXY_GetSystemFileCacheSize() {
		p[747]();
		
	}
	void PROXY_GetSystemFirmwareTable() {
		p[748]();
		
	}
	void PROXY_GetSystemInfo() {
		p[749]();
		
	}
	void PROXY_GetSystemPowerStatus() {
		p[750]();
		
	}
	void PROXY_GetSystemPreferredUILanguages() {
		p[751]();
		
	}
	void PROXY_GetSystemRegistryQuota() {
		p[752]();
		
	}
	void PROXY_GetSystemTime() {
		p[753]();
		
	}
	void PROXY_GetSystemTimeAdjustment() {
		p[754]();
		
	}
	void PROXY_GetSystemTimeAsFileTime() {
		p[755]();
		
	}
	void PROXY_GetSystemTimePreciseAsFileTime() {
		p[756]();
		
	}
	void PROXY_GetSystemTimes() {
		p[757]();
		
	}
	void PROXY_GetSystemWindowsDirectoryA() {
		p[758]();
		
	}
	void PROXY_GetSystemWindowsDirectoryW() {
		p[759]();
		
	}
	void PROXY_GetSystemWow64DirectoryA() {
		p[760]();
		
	}
	void PROXY_GetSystemWow64DirectoryW() {
		p[761]();
		
	}
	void PROXY_GetTapeParameters() {
		p[762]();
		
	}
	void PROXY_GetTapePosition() {
		p[763]();
		
	}
	void PROXY_GetTapeStatus() {
		p[764]();
		
	}
	void PROXY_GetTempFileNameA() {
		p[765]();
		
	}
	void PROXY_GetTempFileNameW() {
		p[766]();
		
	}
	void PROXY_GetTempPathA() {
		p[767]();
		
	}
	void PROXY_GetTempPathW() {
		p[768]();
		
	}
	void PROXY_GetThreadContext() {
		p[769]();
		
	}
	void PROXY_GetThreadDescription() {
		p[770]();
		
	}
	void PROXY_GetThreadErrorMode() {
		p[771]();
		
	}
	void PROXY_GetThreadGroupAffinity() {
		p[772]();
		
	}
	void PROXY_GetThreadIOPendingFlag() {
		p[773]();
		
	}
	void PROXY_GetThreadId() {
		p[774]();
		
	}
	void PROXY_GetThreadIdealProcessorEx() {
		p[775]();
		
	}
	void PROXY_GetThreadInformation() {
		p[776]();
		
	}
	void PROXY_GetThreadLocale() {
		p[777]();
		
	}
	void PROXY_GetThreadPreferredUILanguages() {
		p[778]();
		
	}
	void PROXY_GetThreadPriority() {
		p[779]();
		
	}
	void PROXY_GetThreadPriorityBoost() {
		p[780]();
		
	}
	void PROXY_GetThreadSelectedCpuSets() {
		p[781]();
		
	}
	void PROXY_GetThreadSelectorEntry() {
		p[782]();
		
	}
	void PROXY_GetThreadTimes() {
		p[783]();
		
	}
	void PROXY_GetThreadUILanguage() {
		p[784]();
		
	}
	void PROXY_GetTickCount() {
		p[785]();
		
	}
	void PROXY_GetTickCount64() {
		p[786]();
		
	}
	void PROXY_GetTimeFormatA() {
		p[787]();
		
	}
	void PROXY_GetTimeFormatAWorker() {
		p[788]();
		
	}
	void PROXY_GetTimeFormatEx() {
		p[789]();
		
	}
	void PROXY_GetTimeFormatW() {
		p[790]();
		
	}
	void PROXY_GetTimeFormatWWorker() {
		p[791]();
		
	}
	void PROXY_GetTimeZoneInformation() {
		p[792]();
		
	}
	void PROXY_GetTimeZoneInformationForYear() {
		p[793]();
		
	}
	void PROXY_GetUILanguageInfo() {
		p[794]();
		
	}
	void PROXY_GetUmsCompletionListEvent() {
		p[795]();
		
	}
	void PROXY_GetUmsSystemThreadInformation() {
		p[796]();
		
	}
	void PROXY_GetUserDefaultGeoName() {
		p[797]();
		
	}
	void PROXY_GetUserDefaultLCID() {
		p[798]();
		
	}
	void PROXY_GetUserDefaultLangID() {
		p[799]();
		
	}
	void PROXY_GetUserDefaultLocaleName() {
		p[800]();
		
	}
	void PROXY_GetUserDefaultUILanguage() {
		p[801]();
		
	}
	void PROXY_GetUserGeoID() {
		p[802]();
		
	}
	void PROXY_GetUserPreferredUILanguages() {
		p[803]();
		
	}
	void PROXY_GetVDMCurrentDirectories() {
		p[804]();
		
	}
	void PROXY_GetVersion() {
		p[805]();
		
	}
	void PROXY_GetVersionExA() {
		p[806]();
		
	}
	void PROXY_GetVersionExW() {
		p[807]();
		
	}
	void PROXY_GetVolumeInformationA() {
		p[808]();
		
	}
	void PROXY_GetVolumeInformationByHandleW() {
		p[809]();
		
	}
	void PROXY_GetVolumeInformationW() {
		p[810]();
		
	}
	void PROXY_GetVolumeNameForVolumeMountPointA() {
		p[811]();
		
	}
	void PROXY_GetVolumeNameForVolumeMountPointW() {
		p[812]();
		
	}
	void PROXY_GetVolumePathNameA() {
		p[813]();
		
	}
	void PROXY_GetVolumePathNameW() {
		p[814]();
		
	}
	void PROXY_GetVolumePathNamesForVolumeNameA() {
		p[815]();
		
	}
	void PROXY_GetVolumePathNamesForVolumeNameW() {
		p[816]();
		
	}
	void PROXY_GetWindowsDirectoryA() {
		p[817]();
		
	}
	void PROXY_GetWindowsDirectoryW() {
		p[818]();
		
	}
	void PROXY_GetWriteWatch() {
		p[819]();
		
	}
	void PROXY_GetXStateFeaturesMask() {
		p[820]();
		
	}
	void PROXY_GlobalAddAtomA() {
		p[821]();
		
	}
	void PROXY_GlobalAddAtomExA() {
		p[822]();
		
	}
	void PROXY_GlobalAddAtomExW() {
		p[823]();
		
	}
	void PROXY_GlobalAddAtomW() {
		p[824]();
		
	}
	void PROXY_GlobalAlloc() {
		p[825]();
		
	}
	void PROXY_GlobalCompact() {
		p[826]();
		
	}
	void PROXY_GlobalDeleteAtom() {
		p[827]();
		
	}
	void PROXY_GlobalFindAtomA() {
		p[828]();
		
	}
	void PROXY_GlobalFindAtomW() {
		p[829]();
		
	}
	void PROXY_GlobalFix() {
		p[830]();
		
	}
	void PROXY_GlobalFlags() {
		p[831]();
		
	}
	void PROXY_GlobalFree() {
		p[832]();
		
	}
	void PROXY_GlobalGetAtomNameA() {
		p[833]();
		
	}
	void PROXY_GlobalGetAtomNameW() {
		p[834]();
		
	}
	void PROXY_GlobalHandle() {
		p[835]();
		
	}
	void PROXY_GlobalLock() {
		p[836]();
		
	}
	void PROXY_GlobalMemoryStatus() {
		p[837]();
		
	}
	void PROXY_GlobalMemoryStatusEx() {
		p[838]();
		
	}
	void PROXY_GlobalReAlloc() {
		p[839]();
		
	}
	void PROXY_GlobalSize() {
		p[840]();
		
	}
	void PROXY_GlobalUnWire() {
		p[841]();
		
	}
	void PROXY_GlobalUnfix() {
		p[842]();
		
	}
	void PROXY_GlobalUnlock() {
		p[843]();
		
	}
	void PROXY_GlobalWire() {
		p[844]();
		
	}
	void PROXY_Heap32First() {
		p[845]();
		
	}
	void PROXY_Heap32ListFirst() {
		p[846]();
		
	}
	void PROXY_Heap32ListNext() {
		p[847]();
		
	}
	void PROXY_Heap32Next() {
		p[848]();
		
	}
	void PROXY_HeapAlloc() {
		p[849]();
		
	}
	void PROXY_HeapCompact() {
		p[850]();
		
	}
	void PROXY_HeapCreate() {
		p[851]();
		
	}
	void PROXY_HeapDestroy() {
		p[852]();
		
	}
	void PROXY_HeapFree() {
		p[853]();
		
	}
	void PROXY_HeapLock() {
		p[854]();
		
	}
	void PROXY_HeapQueryInformation() {
		p[855]();
		
	}
	void PROXY_HeapReAlloc() {
		p[856]();
		
	}
	void PROXY_HeapSetInformation() {
		p[857]();
		
	}
	void PROXY_HeapSize() {
		p[858]();
		
	}
	void PROXY_HeapSummary() {
		p[859]();
		
	}
	void PROXY_HeapUnlock() {
		p[860]();
		
	}
	void PROXY_HeapValidate() {
		p[861]();
		
	}
	void PROXY_HeapWalk() {
		p[862]();
		
	}
	void PROXY_IdnToAscii() {
		p[863]();
		
	}
	void PROXY_IdnToNameprepUnicode() {
		p[864]();
		
	}
	void PROXY_IdnToUnicode() {
		p[865]();
		
	}
	void PROXY_InitAtomTable() {
		p[866]();
		
	}
	void PROXY_InitOnceBeginInitialize() {
		p[867]();
		
	}
	void PROXY_InitOnceComplete() {
		p[868]();
		
	}
	void PROXY_InitOnceExecuteOnce() {
		p[869]();
		
	}
	void PROXY_InitOnceInitialize() {
		p[870]();
		
	}
	void PROXY_InitializeConditionVariable() {
		p[871]();
		
	}
	void PROXY_InitializeContext() {
		p[872]();
		
	}
	void PROXY_InitializeContext2() {
		p[873]();
		
	}
	void PROXY_InitializeCriticalSection() {
		p[874]();
		
	}
	void PROXY_InitializeCriticalSectionAndSpinCount() {
		p[875]();
		
	}
	void PROXY_InitializeCriticalSectionEx() {
		p[876]();
		
	}
	void PROXY_InitializeEnclave() {
		p[877]();
		
	}
	void PROXY_InitializeProcThreadAttributeList() {
		p[878]();
		
	}
	void PROXY_InitializeSListHead() {
		p[879]();
		
	}
	void PROXY_InitializeSRWLock() {
		p[880]();
		
	}
	void PROXY_InitializeSynchronizationBarrier() {
		p[881]();
		
	}
	void PROXY_InstallELAMCertificateInfo() {
		p[882]();
		
	}
	void PROXY_InterlockedFlushSList() {
		p[883]();
		
	}
	void PROXY_InterlockedPopEntrySList() {
		p[884]();
		
	}
	void PROXY_InterlockedPushEntrySList() {
		p[885]();
		
	}
	void PROXY_InterlockedPushListSList() {
		p[886]();
		
	}
	void PROXY_InterlockedPushListSListEx() {
		p[887]();
		
	}
	void PROXY_InvalidateConsoleDIBits() {
		p[888]();
		
	}
	void PROXY_IsBadCodePtr() {
		p[889]();
		
	}
	void PROXY_IsBadHugeReadPtr() {
		p[890]();
		
	}
	void PROXY_IsBadHugeWritePtr() {
		p[891]();
		
	}
	void PROXY_IsBadReadPtr() {
		p[892]();
		
	}
	void PROXY_IsBadStringPtrA() {
		p[893]();
		
	}
	void PROXY_IsBadStringPtrW() {
		p[894]();
		
	}
	void PROXY_IsBadWritePtr() {
		p[895]();
		
	}
	void PROXY_IsCalendarLeapDay() {
		p[896]();
		
	}
	void PROXY_IsCalendarLeapMonth() {
		p[897]();
		
	}
	void PROXY_IsCalendarLeapYear() {
		p[898]();
		
	}
	void PROXY_IsDBCSLeadByte() {
		p[899]();
		
	}
	void PROXY_IsDBCSLeadByteEx() {
		p[900]();
		
	}
	void PROXY_IsDebuggerPresent() {
		p[901]();
		
	}
	void PROXY_IsEnclaveTypeSupported() {
		p[902]();
		
	}
	void PROXY_IsNLSDefinedString() {
		p[903]();
		
	}
	void PROXY_IsNativeVhdBoot() {
		p[904]();
		
	}
	void PROXY_IsNormalizedString() {
		p[905]();
		
	}
	void PROXY_IsProcessCritical() {
		p[906]();
		
	}
	void PROXY_IsProcessInJob() {
		p[907]();
		
	}
	void PROXY_IsProcessorFeaturePresent() {
		p[908]();
		
	}
	void PROXY_IsSystemResumeAutomatic() {
		p[909]();
		
	}
	void PROXY_IsThreadAFiber() {
		p[910]();
		
	}
	void PROXY_IsThreadpoolTimerSet() {
		p[911]();
		
	}
	void PROXY_IsUserCetAvailableInEnvironment() {
		p[912]();
		
	}
	void PROXY_IsValidCalDateTime() {
		p[913]();
		
	}
	void PROXY_IsValidCodePage() {
		p[914]();
		
	}
	void PROXY_IsValidLanguageGroup() {
		p[915]();
		
	}
	void PROXY_IsValidLocale() {
		p[916]();
		
	}
	void PROXY_IsValidLocaleName() {
		p[917]();
		
	}
	void PROXY_IsValidNLSVersion() {
		p[918]();
		
	}
	void PROXY_IsWow64GuestMachineSupported() {
		p[919]();
		
	}
	void PROXY_IsWow64Process() {
		p[920]();
		
	}
	void PROXY_IsWow64Process2() {
		p[921]();
		
	}
	void PROXY_K32EmptyWorkingSet() {
		p[922]();
		
	}
	void PROXY_K32EnumDeviceDrivers() {
		p[923]();
		
	}
	void PROXY_K32EnumPageFilesA() {
		p[924]();
		
	}
	void PROXY_K32EnumPageFilesW() {
		p[925]();
		
	}
	void PROXY_K32EnumProcessModules() {
		p[926]();
		
	}
	void PROXY_K32EnumProcessModulesEx() {
		p[927]();
		
	}
	void PROXY_K32EnumProcesses() {
		p[928]();
		
	}
	void PROXY_K32GetDeviceDriverBaseNameA() {
		p[929]();
		
	}
	void PROXY_K32GetDeviceDriverBaseNameW() {
		p[930]();
		
	}
	void PROXY_K32GetDeviceDriverFileNameA() {
		p[931]();
		
	}
	void PROXY_K32GetDeviceDriverFileNameW() {
		p[932]();
		
	}
	void PROXY_K32GetMappedFileNameA() {
		p[933]();
		
	}
	void PROXY_K32GetMappedFileNameW() {
		p[934]();
		
	}
	void PROXY_K32GetModuleBaseNameA() {
		p[935]();
		
	}
	void PROXY_K32GetModuleBaseNameW() {
		p[936]();
		
	}
	void PROXY_K32GetModuleFileNameExA() {
		p[937]();
		
	}
	void PROXY_K32GetModuleFileNameExW() {
		p[938]();
		
	}
	void PROXY_K32GetModuleInformation() {
		p[939]();
		
	}
	void PROXY_K32GetPerformanceInfo() {
		p[940]();
		
	}
	void PROXY_K32GetProcessImageFileNameA() {
		p[941]();
		
	}
	void PROXY_K32GetProcessImageFileNameW() {
		p[942]();
		
	}
	void PROXY_K32GetProcessMemoryInfo() {
		p[943]();
		
	}
	void PROXY_K32GetWsChanges() {
		p[944]();
		
	}
	void PROXY_K32GetWsChangesEx() {
		p[945]();
		
	}
	void PROXY_K32InitializeProcessForWsWatch() {
		p[946]();
		
	}
	void PROXY_K32QueryWorkingSet() {
		p[947]();
		
	}
	void PROXY_K32QueryWorkingSetEx() {
		p[948]();
		
	}
	void PROXY_LCIDToLocaleName() {
		p[949]();
		
	}
	void PROXY_LCMapStringA() {
		p[950]();
		
	}
	void PROXY_LCMapStringEx() {
		p[951]();
		
	}
	void PROXY_LCMapStringW() {
		p[952]();
		
	}
	void PROXY_LZClose() {
		p[953]();
		
	}
	void PROXY_LZCloseFile() {
		p[954]();
		
	}
	void PROXY_LZCopy() {
		p[955]();
		
	}
	void PROXY_LZCreateFileW() {
		p[956]();
		
	}
	void PROXY_LZDone() {
		p[957]();
		
	}
	void PROXY_LZInit() {
		p[958]();
		
	}
	void PROXY_LZOpenFileA() {
		p[959]();
		
	}
	void PROXY_LZOpenFileW() {
		p[960]();
		
	}
	void PROXY_LZRead() {
		p[961]();
		
	}
	void PROXY_LZSeek() {
		p[962]();
		
	}
	void PROXY_LZStart() {
		p[963]();
		
	}
	void PROXY_LeaveCriticalSection() {
		p[964]();
		
	}
	void PROXY_LeaveCriticalSectionWhenCallbackReturns() {
		p[965]();
		
	}
	void PROXY_LoadAppInitDlls() {
		p[966]();
		
	}
	void PROXY_LoadEnclaveData() {
		p[967]();
		
	}
	void PROXY_LoadLibraryA() {
		p[968]();
		
	}
	void PROXY_LoadLibraryExA() {
		p[969]();
		
	}
	void PROXY_LoadLibraryExW() {
		p[970]();
		
	}
	void PROXY_LoadLibraryW() {
		p[971]();
		
	}
	void PROXY_LoadModule() {
		p[972]();
		
	}
	void PROXY_LoadPackagedLibrary() {
		p[973]();
		
	}
	void PROXY_LoadResource() {
		p[974]();
		
	}
	void PROXY_LoadStringBaseExW() {
		p[975]();
		
	}
	void PROXY_LoadStringBaseW() {
		p[976]();
		
	}
	void PROXY_LocalAlloc() {
		p[977]();
		
	}
	void PROXY_LocalCompact() {
		p[978]();
		
	}
	void PROXY_LocalFileTimeToFileTime() {
		p[979]();
		
	}
	void PROXY_LocalFileTimeToLocalSystemTime() {
		p[980]();
		
	}
	void PROXY_LocalFlags() {
		p[981]();
		
	}
	void PROXY_LocalFree() {
		p[982]();
		
	}
	void PROXY_LocalHandle() {
		p[983]();
		
	}
	void PROXY_LocalLock() {
		p[984]();
		
	}
	void PROXY_LocalReAlloc() {
		p[985]();
		
	}
	void PROXY_LocalShrink() {
		p[986]();
		
	}
	void PROXY_LocalSize() {
		p[987]();
		
	}
	void PROXY_LocalSystemTimeToLocalFileTime() {
		p[988]();
		
	}
	void PROXY_LocalUnlock() {
		p[989]();
		
	}
	void PROXY_LocaleNameToLCID() {
		p[990]();
		
	}
	void PROXY_LocateXStateFeature() {
		p[991]();
		
	}
	void PROXY_LockFile() {
		p[992]();
		
	}
	void PROXY_LockFileEx() {
		p[993]();
		
	}
	void PROXY_LockResource() {
		p[994]();
		
	}
	void PROXY_MapUserPhysicalPages() {
		p[995]();
		
	}
	void PROXY_MapUserPhysicalPagesScatter() {
		p[996]();
		
	}
	void PROXY_MapViewOfFile() {
		p[997]();
		
	}
	void PROXY_MapViewOfFileEx() {
		p[998]();
		
	}
	void PROXY_MapViewOfFileExNuma() {
		p[999]();
		
	}
	void PROXY_MapViewOfFileFromApp() {
		p[1000]();
		
	}
	void PROXY_Module32First() {
		p[1001]();
		
	}
	void PROXY_Module32FirstW() {
		p[1002]();
		
	}
	void PROXY_Module32Next() {
		p[1003]();
		
	}
	void PROXY_Module32NextW() {
		p[1004]();
		
	}
	void PROXY_MoveFileA() {
		p[1005]();
		
	}
	void PROXY_MoveFileExA() {
		p[1006]();
		
	}
	void PROXY_MoveFileExW() {
		p[1007]();
		
	}
	void PROXY_MoveFileTransactedA() {
		p[1008]();
		
	}
	void PROXY_MoveFileTransactedW() {
		p[1009]();
		
	}
	void PROXY_MoveFileW() {
		p[1010]();
		
	}
	void PROXY_MoveFileWithProgressA() {
		p[1011]();
		
	}
	void PROXY_MoveFileWithProgressW() {
		p[1012]();
		
	}
	void PROXY_MulDiv() {
		p[1013]();
		
	}
	void PROXY_MultiByteToWideChar() {
		p[1014]();
		
	}
	void PROXY_NeedCurrentDirectoryForExePathA() {
		p[1015]();
		
	}
	void PROXY_NeedCurrentDirectoryForExePathW() {
		p[1016]();
		
	}
	void PROXY_NlsCheckPolicy() {
		p[1017]();
		
	}
	void PROXY_NlsGetCacheUpdateCount() {
		p[1018]();
		
	}
	void PROXY_NlsUpdateLocale() {
		p[1019]();
		
	}
	void PROXY_NlsUpdateSystemLocale() {
		p[1020]();
		
	}
	void PROXY_NormalizeString() {
		p[1021]();
		
	}
	void PROXY_NotifyMountMgr() {
		p[1022]();
		
	}
	void PROXY_NotifyUILanguageChange() {
		p[1023]();
		
	}
	void PROXY_NtVdm64CreateProcessInternalW() {
		p[1024]();
		
	}
	void PROXY_OOBEComplete() {
		p[1025]();
		
	}
	void PROXY_OfferVirtualMemory() {
		p[1026]();
		
	}
	void PROXY_OpenConsoleW() {
		p[1027]();
		
	}
	void PROXY_OpenConsoleWStub() {
		p[1028]();
		
	}
	void PROXY_OpenEventA() {
		p[1029]();
		
	}
	void PROXY_OpenEventW() {
		p[1030]();
		
	}
	void PROXY_OpenFile() {
		p[1031]();
		
	}
	void PROXY_OpenFileById() {
		p[1032]();
		
	}
	void PROXY_OpenFileMappingA() {
		p[1033]();
		
	}
	void PROXY_OpenFileMappingW() {
		p[1034]();
		
	}
	void PROXY_OpenJobObjectA() {
		p[1035]();
		
	}
	void PROXY_OpenJobObjectW() {
		p[1036]();
		
	}
	void PROXY_OpenMutexA() {
		p[1037]();
		
	}
	void PROXY_OpenMutexW() {
		p[1038]();
		
	}
	void PROXY_OpenPackageInfoByFullName() {
		p[1039]();
		
	}
	void PROXY_OpenPrivateNamespaceA() {
		p[1040]();
		
	}
	void PROXY_OpenPrivateNamespaceW() {
		p[1041]();
		
	}
	void PROXY_OpenProcess() {
		p[1042]();
		
	}
	void PROXY_OpenProcessToken() {
		p[1043]();
		
	}
	void PROXY_OpenProfileUserMapping() {
		p[1044]();
		
	}
	void PROXY_OpenSemaphoreA() {
		p[1045]();
		
	}
	void PROXY_OpenSemaphoreW() {
		p[1046]();
		
	}
	void PROXY_OpenState() {
		p[1047]();
		
	}
	void PROXY_OpenStateExplicit() {
		p[1048]();
		
	}
	void PROXY_OpenThread() {
		p[1049]();
		
	}
	void PROXY_OpenThreadToken() {
		p[1050]();
		
	}
	void PROXY_OpenWaitableTimerA() {
		p[1051]();
		
	}
	void PROXY_OpenWaitableTimerW() {
		p[1052]();
		
	}
	void PROXY_OutputDebugStringA() {
		p[1053]();
		
	}
	void PROXY_OutputDebugStringW() {
		p[1054]();
		
	}
	void PROXY_PackageFamilyNameFromFullName() {
		p[1055]();
		
	}
	void PROXY_PackageFamilyNameFromId() {
		p[1056]();
		
	}
	void PROXY_PackageFullNameFromId() {
		p[1057]();
		
	}
	void PROXY_PackageIdFromFullName() {
		p[1058]();
		
	}
	void PROXY_PackageNameAndPublisherIdFromFamilyName() {
		p[1059]();
		
	}
	void PROXY_ParseApplicationUserModelId() {
		p[1060]();
		
	}
	void PROXY_PeekConsoleInputA() {
		p[1061]();
		
	}
	void PROXY_PeekConsoleInputW() {
		p[1062]();
		
	}
	void PROXY_PeekNamedPipe() {
		p[1063]();
		
	}
	void PROXY_PostQueuedCompletionStatus() {
		p[1064]();
		
	}
	void PROXY_PowerClearRequest() {
		p[1065]();
		
	}
	void PROXY_PowerCreateRequest() {
		p[1066]();
		
	}
	void PROXY_PowerSetRequest() {
		p[1067]();
		
	}
	void PROXY_PrefetchVirtualMemory() {
		p[1068]();
		
	}
	void PROXY_PrepareTape() {
		p[1069]();
		
	}
	void PROXY_PrivCopyFileExW() {
		p[1070]();
		
	}
	void PROXY_PrivMoveFileIdentityW() {
		p[1071]();
		
	}
	void PROXY_Process32First() {
		p[1072]();
		
	}
	void PROXY_Process32FirstW() {
		p[1073]();
		
	}
	void PROXY_Process32Next() {
		p[1074]();
		
	}
	void PROXY_Process32NextW() {
		p[1075]();
		
	}
	void PROXY_ProcessIdToSessionId() {
		p[1076]();
		
	}
	void PROXY_PssCaptureSnapshot() {
		p[1077]();
		
	}
	void PROXY_PssDuplicateSnapshot() {
		p[1078]();
		
	}
	void PROXY_PssFreeSnapshot() {
		p[1079]();
		
	}
	void PROXY_PssQuerySnapshot() {
		p[1080]();
		
	}
	void PROXY_PssWalkMarkerCreate() {
		p[1081]();
		
	}
	void PROXY_PssWalkMarkerFree() {
		p[1082]();
		
	}
	void PROXY_PssWalkMarkerGetPosition() {
		p[1083]();
		
	}
	void PROXY_PssWalkMarkerRewind() {
		p[1084]();
		
	}
	void PROXY_PssWalkMarkerSeek() {
		p[1085]();
		
	}
	void PROXY_PssWalkMarkerSeekToBeginning() {
		p[1086]();
		
	}
	void PROXY_PssWalkMarkerSetPosition() {
		p[1087]();
		
	}
	void PROXY_PssWalkMarkerTell() {
		p[1088]();
		
	}
	void PROXY_PssWalkSnapshot() {
		p[1089]();
		
	}
	void PROXY_PulseEvent() {
		p[1090]();
		
	}
	void PROXY_PurgeComm() {
		p[1091]();
		
	}
	void PROXY_QueryActCtxSettingsW() {
		p[1092]();
		
	}
	void PROXY_QueryActCtxSettingsWWorker() {
		p[1093]();
		
	}
	void PROXY_QueryActCtxW() {
		p[1094]();
		
	}
	void PROXY_QueryActCtxWWorker() {
		p[1095]();
		
	}
	void PROXY_QueryDepthSList() {
		p[1096]();
		
	}
	void PROXY_QueryDosDeviceA() {
		p[1097]();
		
	}
	void PROXY_QueryDosDeviceW() {
		p[1098]();
		
	}
	void PROXY_QueryFullProcessImageNameA() {
		p[1099]();
		
	}
	void PROXY_QueryFullProcessImageNameW() {
		p[1100]();
		
	}
	void PROXY_QueryIdleProcessorCycleTime() {
		p[1101]();
		
	}
	void PROXY_QueryIdleProcessorCycleTimeEx() {
		p[1102]();
		
	}
	void PROXY_QueryInformationJobObject() {
		p[1103]();
		
	}
	void PROXY_QueryIoRateControlInformationJobObject() {
		p[1104]();
		
	}
	void PROXY_QueryMemoryResourceNotification() {
		p[1105]();
		
	}
	void PROXY_QueryPerformanceCounter() {
		p[1106]();
		
	}
	void PROXY_QueryPerformanceFrequency() {
		p[1107]();
		
	}
	void PROXY_QueryProcessAffinityUpdateMode() {
		p[1108]();
		
	}
	void PROXY_QueryProcessCycleTime() {
		p[1109]();
		
	}
	void PROXY_QueryProtectedPolicy() {
		p[1110]();
		
	}
	void PROXY_QueryThreadCycleTime() {
		p[1111]();
		
	}
	void PROXY_QueryThreadProfiling() {
		p[1112]();
		
	}
	void PROXY_QueryThreadpoolStackInformation() {
		p[1113]();
		
	}
	void PROXY_QueryUmsThreadInformation() {
		p[1114]();
		
	}
	void PROXY_QueryUnbiasedInterruptTime() {
		p[1115]();
		
	}
	void PROXY_QueueUserAPC() {
		p[1116]();
		
	}
	void PROXY_QueueUserWorkItem() {
		p[1117]();
		
	}
	void PROXY_QuirkGetData2Worker() {
		p[1118]();
		
	}
	void PROXY_QuirkGetDataWorker() {
		p[1119]();
		
	}
	void PROXY_QuirkIsEnabled2Worker() {
		p[1120]();
		
	}
	void PROXY_QuirkIsEnabled3Worker() {
		p[1121]();
		
	}
	void PROXY_QuirkIsEnabledForPackage2Worker() {
		p[1122]();
		
	}
	void PROXY_QuirkIsEnabledForPackage3Worker() {
		p[1123]();
		
	}
	void PROXY_QuirkIsEnabledForPackage4Worker() {
		p[1124]();
		
	}
	void PROXY_QuirkIsEnabledForPackageWorker() {
		p[1125]();
		
	}
	void PROXY_QuirkIsEnabledForProcessWorker() {
		p[1126]();
		
	}
	void PROXY_QuirkIsEnabledWorker() {
		p[1127]();
		
	}
	void PROXY_RaiseException() {
		p[1128]();
		
	}
	void PROXY_RaiseFailFastException() {
		p[1129]();
		
	}
	void PROXY_RaiseInvalid16BitExeError() {
		p[1130]();
		
	}
	void PROXY_ReOpenFile() {
		p[1131]();
		
	}
	void PROXY_ReadConsoleA() {
		p[1132]();
		
	}
	void PROXY_ReadConsoleInputA() {
		p[1133]();
		
	}
	void PROXY_ReadConsoleInputExA() {
		p[1134]();
		
	}
	void PROXY_ReadConsoleInputExW() {
		p[1135]();
		
	}
	void PROXY_ReadConsoleInputW() {
		p[1136]();
		
	}
	void PROXY_ReadConsoleOutputA() {
		p[1137]();
		
	}
	void PROXY_ReadConsoleOutputAttribute() {
		p[1138]();
		
	}
	void PROXY_ReadConsoleOutputCharacterA() {
		p[1139]();
		
	}
	void PROXY_ReadConsoleOutputCharacterW() {
		p[1140]();
		
	}
	void PROXY_ReadConsoleOutputW() {
		p[1141]();
		
	}
	void PROXY_ReadConsoleW() {
		p[1142]();
		
	}
	void PROXY_ReadDirectoryChangesExW() {
		p[1143]();
		
	}
	void PROXY_ReadDirectoryChangesW() {
		p[1144]();
		
	}
	void PROXY_ReadFile() {
		p[1145]();
		
	}
	void PROXY_ReadFileEx() {
		p[1146]();
		
	}
	void PROXY_ReadFileScatter() {
		p[1147]();
		
	}
	void PROXY_ReadProcessMemory() {
		p[1148]();
		
	}
	void PROXY_ReadThreadProfilingData() {
		p[1149]();
		
	}
	void PROXY_ReclaimVirtualMemory() {
		p[1150]();
		
	}
	void PROXY_RegCloseKey() {
		p[1151]();
		
	}
	void PROXY_RegCopyTreeW() {
		p[1152]();
		
	}
	void PROXY_RegCreateKeyExA() {
		p[1153]();
		
	}
	void PROXY_RegCreateKeyExW() {
		p[1154]();
		
	}
	void PROXY_RegDeleteKeyExA() {
		p[1155]();
		
	}
	void PROXY_RegDeleteKeyExW() {
		p[1156]();
		
	}
	void PROXY_RegDeleteTreeA() {
		p[1157]();
		
	}
	void PROXY_RegDeleteTreeW() {
		p[1158]();
		
	}
	void PROXY_RegDeleteValueA() {
		p[1159]();
		
	}
	void PROXY_RegDeleteValueW() {
		p[1160]();
		
	}
	void PROXY_RegDisablePredefinedCacheEx() {
		p[1161]();
		
	}
	void PROXY_RegEnumKeyExA() {
		p[1162]();
		
	}
	void PROXY_RegEnumKeyExW() {
		p[1163]();
		
	}
	void PROXY_RegEnumValueA() {
		p[1164]();
		
	}
	void PROXY_RegEnumValueW() {
		p[1165]();
		
	}
	void PROXY_RegFlushKey() {
		p[1166]();
		
	}
	void PROXY_RegGetKeySecurity() {
		p[1167]();
		
	}
	void PROXY_RegGetValueA() {
		p[1168]();
		
	}
	void PROXY_RegGetValueW() {
		p[1169]();
		
	}
	void PROXY_RegLoadKeyA() {
		p[1170]();
		
	}
	void PROXY_RegLoadKeyW() {
		p[1171]();
		
	}
	void PROXY_RegLoadMUIStringA() {
		p[1172]();
		
	}
	void PROXY_RegLoadMUIStringW() {
		p[1173]();
		
	}
	void PROXY_RegNotifyChangeKeyValue() {
		p[1174]();
		
	}
	void PROXY_RegOpenCurrentUser() {
		p[1175]();
		
	}
	void PROXY_RegOpenKeyExA() {
		p[1176]();
		
	}
	void PROXY_RegOpenKeyExW() {
		p[1177]();
		
	}
	void PROXY_RegOpenUserClassesRoot() {
		p[1178]();
		
	}
	void PROXY_RegQueryInfoKeyA() {
		p[1179]();
		
	}
	void PROXY_RegQueryInfoKeyW() {
		p[1180]();
		
	}
	void PROXY_RegQueryValueExA() {
		p[1181]();
		
	}
	void PROXY_RegQueryValueExW() {
		p[1182]();
		
	}
	void PROXY_RegRestoreKeyA() {
		p[1183]();
		
	}
	void PROXY_RegRestoreKeyW() {
		p[1184]();
		
	}
	void PROXY_RegSaveKeyExA() {
		p[1185]();
		
	}
	void PROXY_RegSaveKeyExW() {
		p[1186]();
		
	}
	void PROXY_RegSetKeySecurity() {
		p[1187]();
		
	}
	void PROXY_RegSetValueExA() {
		p[1188]();
		
	}
	void PROXY_RegSetValueExW() {
		p[1189]();
		
	}
	void PROXY_RegUnLoadKeyA() {
		p[1190]();
		
	}
	void PROXY_RegUnLoadKeyW() {
		p[1191]();
		
	}
	void PROXY_RegisterApplicationRecoveryCallback() {
		p[1192]();
		
	}
	void PROXY_RegisterApplicationRestart() {
		p[1193]();
		
	}
	void PROXY_RegisterBadMemoryNotification() {
		p[1194]();
		
	}
	void PROXY_RegisterConsoleIME() {
		p[1195]();
		
	}
	void PROXY_RegisterConsoleOS2() {
		p[1196]();
		
	}
	void PROXY_RegisterConsoleVDM() {
		p[1197]();
		
	}
	void PROXY_RegisterWaitForInputIdle() {
		p[1198]();
		
	}
	void PROXY_RegisterWaitForSingleObject() {
		p[1199]();
		
	}
	void PROXY_RegisterWaitForSingleObjectEx() {
		p[1200]();
		
	}
	void PROXY_RegisterWaitUntilOOBECompleted() {
		p[1201]();
		
	}
	void PROXY_RegisterWowBaseHandlers() {
		p[1202]();
		
	}
	void PROXY_RegisterWowExec() {
		p[1203]();
		
	}
	void PROXY_ReleaseActCtx() {
		p[1204]();
		
	}
	void PROXY_ReleaseActCtxWorker() {
		p[1205]();
		
	}
	void PROXY_ReleaseMutex() {
		p[1206]();
		
	}
	void PROXY_ReleaseMutexWhenCallbackReturns() {
		p[1207]();
		
	}
	void PROXY_ReleaseSRWLockExclusive() {
		p[1208]();
		
	}
	void PROXY_ReleaseSRWLockShared() {
		p[1209]();
		
	}
	void PROXY_ReleaseSemaphore() {
		p[1210]();
		
	}
	void PROXY_ReleaseSemaphoreWhenCallbackReturns() {
		p[1211]();
		
	}
	void PROXY_RemoveDirectoryA() {
		p[1212]();
		
	}
	void PROXY_RemoveDirectoryTransactedA() {
		p[1213]();
		
	}
	void PROXY_RemoveDirectoryTransactedW() {
		p[1214]();
		
	}
	void PROXY_RemoveDirectoryW() {
		p[1215]();
		
	}
	void PROXY_RemoveDllDirectory() {
		p[1216]();
		
	}
	void PROXY_RemoveLocalAlternateComputerNameA() {
		p[1217]();
		
	}
	void PROXY_RemoveLocalAlternateComputerNameW() {
		p[1218]();
		
	}
	void PROXY_RemoveSecureMemoryCacheCallback() {
		p[1219]();
		
	}
	void PROXY_RemoveVectoredContinueHandler() {
		p[1220]();
		
	}
	void PROXY_RemoveVectoredExceptionHandler() {
		p[1221]();
		
	}
	void PROXY_ReplaceFile() {
		p[1222]();
		
	}
	void PROXY_ReplaceFileA() {
		p[1223]();
		
	}
	void PROXY_ReplaceFileW() {
		p[1224]();
		
	}
	void PROXY_ReplacePartitionUnit() {
		p[1225]();
		
	}
	void PROXY_RequestDeviceWakeup() {
		p[1226]();
		
	}
	void PROXY_RequestWakeupLatency() {
		p[1227]();
		
	}
	void PROXY_ResetEvent() {
		p[1228]();
		
	}
	void PROXY_ResetWriteWatch() {
		p[1229]();
		
	}
	void PROXY_ResizePseudoConsole() {
		p[1230]();
		
	}
	void PROXY_ResolveDelayLoadedAPI() {
		p[1231]();
		
	}
	void PROXY_ResolveDelayLoadsFromDll() {
		p[1232]();
		
	}
	void PROXY_ResolveLocaleName() {
		p[1233]();
		
	}
	void PROXY_RestoreLastError() {
		p[1234]();
		
	}
	void PROXY_ResumeThread() {
		p[1235]();
		
	}
	void PROXY_RtlAddFunctionTable() {
		p[1236]();
		
	}
	void PROXY_RtlCaptureContext() {
		p[1237]();
		
	}
	void PROXY_RtlCaptureStackBackTrace() {
		p[1238]();
		
	}
	void PROXY_RtlCompareMemory() {
		p[1239]();
		
	}
	void PROXY_RtlCopyMemory() {
		p[1240]();
		
	}
	void PROXY_RtlDeleteFunctionTable() {
		p[1241]();
		
	}
	void PROXY_RtlFillMemory() {
		p[1242]();
		
	}
	void PROXY_RtlInstallFunctionTableCallback() {
		p[1243]();
		
	}
	void PROXY_RtlLookupFunctionEntry() {
		p[1244]();
		
	}
	void PROXY_RtlMoveMemory() {
		p[1245]();
		
	}
	void PROXY_RtlPcToFileHeader() {
		p[1246]();
		
	}
	void PROXY_RtlRaiseException() {
		p[1247]();
		
	}
	void PROXY_RtlRestoreContext() {
		p[1248]();
		
	}
	void PROXY_RtlUnwind() {
		p[1249]();
		
	}
	void PROXY_RtlUnwindEx() {
		p[1250]();
		
	}
	void PROXY_RtlVirtualUnwind() {
		p[1251]();
		
	}
	void PROXY_RtlZeroMemory() {
		p[1252]();
		
	}
	void PROXY_ScrollConsoleScreenBufferA() {
		p[1253]();
		
	}
	void PROXY_ScrollConsoleScreenBufferW() {
		p[1254]();
		
	}
	void PROXY_SearchPathA() {
		p[1255]();
		
	}
	void PROXY_SearchPathW() {
		p[1256]();
		
	}
	void PROXY_SetCachedSigningLevel() {
		p[1257]();
		
	}
	void PROXY_SetCalendarInfoA() {
		p[1258]();
		
	}
	void PROXY_SetCalendarInfoW() {
		p[1259]();
		
	}
	void PROXY_SetComPlusPackageInstallStatus() {
		p[1260]();
		
	}
	void PROXY_SetCommBreak() {
		p[1261]();
		
	}
	void PROXY_SetCommConfig() {
		p[1262]();
		
	}
	void PROXY_SetCommMask() {
		p[1263]();
		
	}
	void PROXY_SetCommState() {
		p[1264]();
		
	}
	void PROXY_SetCommTimeouts() {
		p[1265]();
		
	}
	void PROXY_SetComputerNameA() {
		p[1266]();
		
	}
	void PROXY_SetComputerNameEx2W() {
		p[1267]();
		
	}
	void PROXY_SetComputerNameExA() {
		p[1268]();
		
	}
	void PROXY_SetComputerNameExW() {
		p[1269]();
		
	}
	void PROXY_SetComputerNameW() {
		p[1270]();
		
	}
	void PROXY_SetConsoleActiveScreenBuffer() {
		p[1271]();
		
	}
	void PROXY_SetConsoleCP() {
		p[1272]();
		
	}
	void PROXY_SetConsoleCtrlHandler() {
		p[1273]();
		
	}
	void PROXY_SetConsoleCursor() {
		p[1274]();
		
	}
	void PROXY_SetConsoleCursorInfo() {
		p[1275]();
		
	}
	void PROXY_SetConsoleCursorMode() {
		p[1276]();
		
	}
	void PROXY_SetConsoleCursorPosition() {
		p[1277]();
		
	}
	void PROXY_SetConsoleDisplayMode() {
		p[1278]();
		
	}
	void PROXY_SetConsoleFont() {
		p[1279]();
		
	}
	void PROXY_SetConsoleHardwareState() {
		p[1280]();
		
	}
	void PROXY_SetConsoleHistoryInfo() {
		p[1281]();
		
	}
	void PROXY_SetConsoleIcon() {
		p[1282]();
		
	}
	void PROXY_SetConsoleInputExeNameA() {
		p[1283]();
		
	}
	void PROXY_SetConsoleInputExeNameW() {
		p[1284]();
		
	}
	void PROXY_SetConsoleKeyShortcuts() {
		p[1285]();
		
	}
	void PROXY_SetConsoleLocalEUDC() {
		p[1286]();
		
	}
	void PROXY_SetConsoleMaximumWindowSize() {
		p[1287]();
		
	}
	void PROXY_SetConsoleMenuClose() {
		p[1288]();
		
	}
	void PROXY_SetConsoleMode() {
		p[1289]();
		
	}
	void PROXY_SetConsoleNlsMode() {
		p[1290]();
		
	}
	void PROXY_SetConsoleNumberOfCommandsA() {
		p[1291]();
		
	}
	void PROXY_SetConsoleNumberOfCommandsW() {
		p[1292]();
		
	}
	void PROXY_SetConsoleOS2OemFormat() {
		p[1293]();
		
	}
	void PROXY_SetConsoleOutputCP() {
		p[1294]();
		
	}
	void PROXY_SetConsolePalette() {
		p[1295]();
		
	}
	void PROXY_SetConsoleScreenBufferInfoEx() {
		p[1296]();
		
	}
	void PROXY_SetConsoleScreenBufferSize() {
		p[1297]();
		
	}
	void PROXY_SetConsoleTextAttribute() {
		p[1298]();
		
	}
	void PROXY_SetConsoleTitleA() {
		p[1299]();
		
	}
	void PROXY_SetConsoleTitleW() {
		p[1300]();
		
	}
	void PROXY_SetConsoleWindowInfo() {
		p[1301]();
		
	}
	void PROXY_SetCriticalSectionSpinCount() {
		p[1302]();
		
	}
	void PROXY_SetCurrentConsoleFontEx() {
		p[1303]();
		
	}
	void PROXY_SetCurrentDirectoryA() {
		p[1304]();
		
	}
	void PROXY_SetCurrentDirectoryW() {
		p[1305]();
		
	}
	void PROXY_SetDefaultCommConfigA() {
		p[1306]();
		
	}
	void PROXY_SetDefaultCommConfigW() {
		p[1307]();
		
	}
	void PROXY_SetDefaultDllDirectories() {
		p[1308]();
		
	}
	void PROXY_SetDllDirectoryA() {
		p[1309]();
		
	}
	void PROXY_SetDllDirectoryW() {
		p[1310]();
		
	}
	void PROXY_SetDynamicTimeZoneInformation() {
		p[1311]();
		
	}
	void PROXY_SetEndOfFile() {
		p[1312]();
		
	}
	void PROXY_SetEnvironmentStringsA() {
		p[1313]();
		
	}
	void PROXY_SetEnvironmentStringsW() {
		p[1314]();
		
	}
	void PROXY_SetEnvironmentVariableA() {
		p[1315]();
		
	}
	void PROXY_SetEnvironmentVariableW() {
		p[1316]();
		
	}
	void PROXY_SetErrorMode() {
		p[1317]();
		
	}
	void PROXY_SetEvent() {
		p[1318]();
		
	}
	void PROXY_SetEventWhenCallbackReturns() {
		p[1319]();
		
	}
	void PROXY_SetFileApisToANSI() {
		p[1320]();
		
	}
	void PROXY_SetFileApisToOEM() {
		p[1321]();
		
	}
	void PROXY_SetFileAttributesA() {
		p[1322]();
		
	}
	void PROXY_SetFileAttributesTransactedA() {
		p[1323]();
		
	}
	void PROXY_SetFileAttributesTransactedW() {
		p[1324]();
		
	}
	void PROXY_SetFileAttributesW() {
		p[1325]();
		
	}
	void PROXY_SetFileBandwidthReservation() {
		p[1326]();
		
	}
	void PROXY_SetFileCompletionNotificationModes() {
		p[1327]();
		
	}
	void PROXY_SetFileInformationByHandle() {
		p[1328]();
		
	}
	void PROXY_SetFileIoOverlappedRange() {
		p[1329]();
		
	}
	void PROXY_SetFilePointer() {
		p[1330]();
		
	}
	void PROXY_SetFilePointerEx() {
		p[1331]();
		
	}
	void PROXY_SetFileShortNameA() {
		p[1332]();
		
	}
	void PROXY_SetFileShortNameW() {
		p[1333]();
		
	}
	void PROXY_SetFileTime() {
		p[1334]();
		
	}
	void PROXY_SetFileValidData() {
		p[1335]();
		
	}
	void PROXY_SetFirmwareEnvironmentVariableA() {
		p[1336]();
		
	}
	void PROXY_SetFirmwareEnvironmentVariableExA() {
		p[1337]();
		
	}
	void PROXY_SetFirmwareEnvironmentVariableExW() {
		p[1338]();
		
	}
	void PROXY_SetFirmwareEnvironmentVariableW() {
		p[1339]();
		
	}
	void PROXY_SetHandleCount() {
		p[1340]();
		
	}
	void PROXY_SetHandleInformation() {
		p[1341]();
		
	}
	void PROXY_SetInformationJobObject() {
		p[1342]();
		
	}
	void PROXY_SetIoRateControlInformationJobObject() {
		p[1343]();
		
	}
	void PROXY_SetLastConsoleEventActive() {
		p[1344]();
		
	}
	void PROXY_SetLastError() {
		p[1345]();
		
	}
	void PROXY_SetLocalPrimaryComputerNameA() {
		p[1346]();
		
	}
	void PROXY_SetLocalPrimaryComputerNameW() {
		p[1347]();
		
	}
	void PROXY_SetLocalTime() {
		p[1348]();
		
	}
	void PROXY_SetLocaleInfoA() {
		p[1349]();
		
	}
	void PROXY_SetLocaleInfoW() {
		p[1350]();
		
	}
	void PROXY_SetMailslotInfo() {
		p[1351]();
		
	}
	void PROXY_SetMessageWaitingIndicator() {
		p[1352]();
		
	}
	void PROXY_SetNamedPipeAttribute() {
		p[1353]();
		
	}
	void PROXY_SetNamedPipeHandleState() {
		p[1354]();
		
	}
	void PROXY_SetPriorityClass() {
		p[1355]();
		
	}
	void PROXY_SetProcessAffinityMask() {
		p[1356]();
		
	}
	void PROXY_SetProcessAffinityUpdateMode() {
		p[1357]();
		
	}
	void PROXY_SetProcessDEPPolicy() {
		p[1358]();
		
	}
	void PROXY_SetProcessDefaultCpuSets() {
		p[1359]();
		
	}
	void PROXY_SetProcessDynamicEHContinuationTargets() {
		p[1360]();
		
	}
	void PROXY_SetProcessDynamicEnforcedCetCompatibleRanges() {
		p[1361]();
		
	}
	void PROXY_SetProcessInformation() {
		p[1362]();
		
	}
	void PROXY_SetProcessMitigationPolicy() {
		p[1363]();
		
	}
	void PROXY_SetProcessPreferredUILanguages() {
		p[1364]();
		
	}
	void PROXY_SetProcessPriorityBoost() {
		p[1365]();
		
	}
	void PROXY_SetProcessShutdownParameters() {
		p[1366]();
		
	}
	void PROXY_SetProcessWorkingSetSize() {
		p[1367]();
		
	}
	void PROXY_SetProcessWorkingSetSizeEx() {
		p[1368]();
		
	}
	void PROXY_SetProtectedPolicy() {
		p[1369]();
		
	}
	void PROXY_SetSearchPathMode() {
		p[1370]();
		
	}
	void PROXY_SetStdHandle() {
		p[1371]();
		
	}
	void PROXY_SetStdHandleEx() {
		p[1372]();
		
	}
	void PROXY_SetSystemFileCacheSize() {
		p[1373]();
		
	}
	void PROXY_SetSystemPowerState() {
		p[1374]();
		
	}
	void PROXY_SetSystemTime() {
		p[1375]();
		
	}
	void PROXY_SetSystemTimeAdjustment() {
		p[1376]();
		
	}
	void PROXY_SetTapeParameters() {
		p[1377]();
		
	}
	void PROXY_SetTapePosition() {
		p[1378]();
		
	}
	void PROXY_SetTermsrvAppInstallMode() {
		p[1379]();
		
	}
	void PROXY_SetThreadAffinityMask() {
		p[1380]();
		
	}
	void PROXY_SetThreadContext() {
		p[1381]();
		
	}
	void PROXY_SetThreadDescription() {
		p[1382]();
		
	}
	void PROXY_SetThreadErrorMode() {
		p[1383]();
		
	}
	void PROXY_SetThreadExecutionState() {
		p[1384]();
		
	}
	void PROXY_SetThreadGroupAffinity() {
		p[1385]();
		
	}
	void PROXY_SetThreadIdealProcessor() {
		p[1386]();
		
	}
	void PROXY_SetThreadIdealProcessorEx() {
		p[1387]();
		
	}
	void PROXY_SetThreadInformation() {
		p[1388]();
		
	}
	void PROXY_SetThreadLocale() {
		p[1389]();
		
	}
	void PROXY_SetThreadPreferredUILanguages() {
		p[1390]();
		
	}
	void PROXY_SetThreadPriority() {
		p[1391]();
		
	}
	void PROXY_SetThreadPriorityBoost() {
		p[1392]();
		
	}
	void PROXY_SetThreadSelectedCpuSets() {
		p[1393]();
		
	}
	void PROXY_SetThreadStackGuarantee() {
		p[1394]();
		
	}
	void PROXY_SetThreadToken() {
		p[1395]();
		
	}
	void PROXY_SetThreadUILanguage() {
		p[1396]();
		
	}
	void PROXY_SetThreadpoolStackInformation() {
		p[1397]();
		
	}
	void PROXY_SetThreadpoolThreadMaximum() {
		p[1398]();
		
	}
	void PROXY_SetThreadpoolThreadMinimum() {
		p[1399]();
		
	}
	void PROXY_SetThreadpoolTimer() {
		p[1400]();
		
	}
	void PROXY_SetThreadpoolTimerEx() {
		p[1401]();
		
	}
	void PROXY_SetThreadpoolWait() {
		p[1402]();
		
	}
	void PROXY_SetThreadpoolWaitEx() {
		p[1403]();
		
	}
	void PROXY_SetTimeZoneInformation() {
		p[1404]();
		
	}
	void PROXY_SetTimerQueueTimer() {
		p[1405]();
		
	}
	void PROXY_SetUmsThreadInformation() {
		p[1406]();
		
	}
	void PROXY_SetUnhandledExceptionFilter() {
		p[1407]();
		
	}
	void PROXY_SetUserGeoID() {
		p[1408]();
		
	}
	void PROXY_SetUserGeoName() {
		p[1409]();
		
	}
	void PROXY_SetVDMCurrentDirectories() {
		p[1410]();
		
	}
	void PROXY_SetVolumeLabelA() {
		p[1411]();
		
	}
	void PROXY_SetVolumeLabelW() {
		p[1412]();
		
	}
	void PROXY_SetVolumeMountPointA() {
		p[1413]();
		
	}
	void PROXY_SetVolumeMountPointW() {
		p[1414]();
		
	}
	void PROXY_SetVolumeMountPointWStub() {
		p[1415]();
		
	}
	void PROXY_SetWaitableTimer() {
		p[1416]();
		
	}
	void PROXY_SetWaitableTimerEx() {
		p[1417]();
		
	}
	void PROXY_SetXStateFeaturesMask() {
		p[1418]();
		
	}
	void PROXY_SetupComm() {
		p[1419]();
		
	}
	void PROXY_ShowConsoleCursor() {
		p[1420]();
		
	}
	void PROXY_SignalObjectAndWait() {
		p[1421]();
		
	}
	void PROXY_SizeofResource() {
		p[1422]();
		
	}
	void PROXY_Sleep(int32_t x) {
		// Change the amount to sleep from 0 to 1
		((SleepFunc_t)p[1423])(x == 0 ? 1 : x);
	}
	void PROXY_SleepConditionVariableCS() {
		p[1424]();
		
	}
	void PROXY_SleepConditionVariableSRW() {
		p[1425]();
		
	}
	void PROXY_SleepEx() {
		p[1426]();
		
	}
	void PROXY_SortCloseHandle() {
		p[1427]();
		
	}
	void PROXY_SortGetHandle() {
		p[1428]();
		
	}
	void PROXY_StartThreadpoolIo() {
		p[1429]();
		
	}
	void PROXY_SubmitThreadpoolWork() {
		p[1430]();
		
	}
	void PROXY_SuspendThread() {
		p[1431]();
		
	}
	void PROXY_SwitchToFiber() {
		p[1432]();
		
	}
	void PROXY_SwitchToThread() {
		p[1433]();
		
	}
	void PROXY_SystemTimeToFileTime() {
		p[1434]();
		
	}
	void PROXY_SystemTimeToTzSpecificLocalTime() {
		p[1435]();
		
	}
	void PROXY_SystemTimeToTzSpecificLocalTimeEx() {
		p[1436]();
		
	}
	void PROXY_TerminateJobObject() {
		p[1437]();
		
	}
	void PROXY_TerminateProcess() {
		p[1438]();
		
	}
	void PROXY_TerminateThread() {
		p[1439]();
		
	}
	void PROXY_TermsrvAppInstallMode() {
		p[1440]();
		
	}
	void PROXY_TermsrvConvertSysRootToUserDir() {
		p[1441]();
		
	}
	void PROXY_TermsrvCreateRegEntry() {
		p[1442]();
		
	}
	void PROXY_TermsrvDeleteKey() {
		p[1443]();
		
	}
	void PROXY_TermsrvDeleteValue() {
		p[1444]();
		
	}
	void PROXY_TermsrvGetPreSetValue() {
		p[1445]();
		
	}
	void PROXY_TermsrvGetWindowsDirectoryA() {
		p[1446]();
		
	}
	void PROXY_TermsrvGetWindowsDirectoryW() {
		p[1447]();
		
	}
	void PROXY_TermsrvOpenRegEntry() {
		p[1448]();
		
	}
	void PROXY_TermsrvOpenUserClasses() {
		p[1449]();
		
	}
	void PROXY_TermsrvRestoreKey() {
		p[1450]();
		
	}
	void PROXY_TermsrvSetKeySecurity() {
		p[1451]();
		
	}
	void PROXY_TermsrvSetValueKey() {
		p[1452]();
		
	}
	void PROXY_TermsrvSyncUserIniFileExt() {
		p[1453]();
		
	}
	void PROXY_Thread32First() {
		p[1454]();
		
	}
	void PROXY_Thread32Next() {
		p[1455]();
		
	}
	void PROXY_TlsAlloc() {
		p[1456]();
		
	}
	void PROXY_TlsFree() {
		p[1457]();
		
	}
	void PROXY_TlsGetValue() {
		p[1458]();
		
	}
	void PROXY_TlsSetValue() {
		p[1459]();
		
	}
	void PROXY_Toolhelp32ReadProcessMemory() {
		p[1460]();
		
	}
	void PROXY_TransactNamedPipe() {
		p[1461]();
		
	}
	void PROXY_TransmitCommChar() {
		p[1462]();
		
	}
	void PROXY_TryAcquireSRWLockExclusive() {
		p[1463]();
		
	}
	void PROXY_TryAcquireSRWLockShared() {
		p[1464]();
		
	}
	void PROXY_TryEnterCriticalSection() {
		p[1465]();
		
	}
	void PROXY_TrySubmitThreadpoolCallback() {
		p[1466]();
		
	}
	void PROXY_TzSpecificLocalTimeToSystemTime() {
		p[1467]();
		
	}
	void PROXY_TzSpecificLocalTimeToSystemTimeEx() {
		p[1468]();
		
	}
	void PROXY_UTRegister() {
		p[1469]();
		
	}
	void PROXY_UTUnRegister() {
		p[1470]();
		
	}
	void PROXY_UmsThreadYield() {
		p[1471]();
		
	}
	void PROXY_UnhandledExceptionFilter() {
		p[1472]();
		
	}
	void PROXY_UnlockFile() {
		p[1473]();
		
	}
	void PROXY_UnlockFileEx() {
		p[1474]();
		
	}
	void PROXY_UnmapViewOfFile() {
		p[1475]();
		
	}
	void PROXY_UnmapViewOfFileEx() {
		p[1476]();
		
	}
	void PROXY_UnregisterApplicationRecoveryCallback() {
		p[1477]();
		
	}
	void PROXY_UnregisterApplicationRestart() {
		p[1478]();
		
	}
	void PROXY_UnregisterBadMemoryNotification() {
		p[1479]();
		
	}
	void PROXY_UnregisterConsoleIME() {
		p[1480]();
		
	}
	void PROXY_UnregisterWait() {
		p[1481]();
		
	}
	void PROXY_UnregisterWaitEx() {
		p[1482]();
		
	}
	void PROXY_UnregisterWaitUntilOOBECompleted() {
		p[1483]();
		
	}
	void PROXY_UpdateCalendarDayOfWeek() {
		p[1484]();
		
	}
	void PROXY_UpdateProcThreadAttribute() {
		p[1485]();
		
	}
	void PROXY_UpdateResourceA() {
		p[1486]();
		
	}
	void PROXY_UpdateResourceW() {
		p[1487]();
		
	}
	void PROXY_VDMConsoleOperation() {
		p[1488]();
		
	}
	void PROXY_VDMOperationStarted() {
		p[1489]();
		
	}
	void PROXY_VerLanguageNameA() {
		p[1490]();
		
	}
	void PROXY_VerLanguageNameW() {
		p[1491]();
		
	}
	void PROXY_VerSetConditionMask() {
		p[1492]();
		
	}
	void PROXY_VerifyConsoleIoHandle() {
		p[1493]();
		
	}
	void PROXY_VerifyScripts() {
		p[1494]();
		
	}
	void PROXY_VerifyVersionInfoA() {
		p[1495]();
		
	}
	void PROXY_VerifyVersionInfoW() {
		p[1496]();
		
	}
	void PROXY_VirtualAlloc() {
		p[1497]();
		
	}
	void PROXY_VirtualAllocEx() {
		p[1498]();
		
	}
	void PROXY_VirtualAllocExNuma() {
		p[1499]();
		
	}
	void PROXY_VirtualFree() {
		p[1500]();
		
	}
	void PROXY_VirtualFreeEx() {
		p[1501]();
		
	}
	void PROXY_VirtualLock() {
		p[1502]();
		
	}
	void PROXY_VirtualProtect() {
		p[1503]();
		
	}
	void PROXY_VirtualProtectEx() {
		p[1504]();
		
	}
	void PROXY_VirtualQuery() {
		p[1505]();
		
	}
	void PROXY_VirtualQueryEx() {
		p[1506]();
		
	}
	void PROXY_VirtualUnlock() {
		p[1507]();
		
	}
	void PROXY_WTSGetActiveConsoleSessionId() {
		p[1508]();
		
	}
	void PROXY_WaitCommEvent() {
		p[1509]();
		
	}
	void PROXY_WaitForDebugEvent() {
		p[1510]();
		
	}
	void PROXY_WaitForDebugEventEx() {
		p[1511]();
		
	}
	void PROXY_WaitForMultipleObjects() {
		p[1512]();
		
	}
	void PROXY_WaitForMultipleObjectsEx() {
		p[1513]();
		
	}
	void PROXY_WaitForSingleObject() {
		p[1514]();
		
	}
	void PROXY_WaitForSingleObjectEx() {
		p[1515]();
		
	}
	void PROXY_WaitForThreadpoolIoCallbacks() {
		p[1516]();
		
	}
	void PROXY_WaitForThreadpoolTimerCallbacks() {
		p[1517]();
		
	}
	void PROXY_WaitForThreadpoolWaitCallbacks() {
		p[1518]();
		
	}
	void PROXY_WaitForThreadpoolWorkCallbacks() {
		p[1519]();
		
	}
	void PROXY_WaitNamedPipeA() {
		p[1520]();
		
	}
	void PROXY_WaitNamedPipeW() {
		p[1521]();
		
	}
	void PROXY_WakeAllConditionVariable() {
		p[1522]();
		
	}
	void PROXY_WakeConditionVariable() {
		p[1523]();
		
	}
	void PROXY_WerGetFlags() {
		p[1524]();
		
	}
	void PROXY_WerGetFlagsWorker() {
		p[1525]();
		
	}
	void PROXY_WerRegisterAdditionalProcess() {
		p[1526]();
		
	}
	void PROXY_WerRegisterAppLocalDump() {
		p[1527]();
		
	}
	void PROXY_WerRegisterCustomMetadata() {
		p[1528]();
		
	}
	void PROXY_WerRegisterExcludedMemoryBlock() {
		p[1529]();
		
	}
	void PROXY_WerRegisterFile() {
		p[1530]();
		
	}
	void PROXY_WerRegisterFileWorker() {
		p[1531]();
		
	}
	void PROXY_WerRegisterMemoryBlock() {
		p[1532]();
		
	}
	void PROXY_WerRegisterMemoryBlockWorker() {
		p[1533]();
		
	}
	void PROXY_WerRegisterRuntimeExceptionModule() {
		p[1534]();
		
	}
	void PROXY_WerRegisterRuntimeExceptionModuleWorker() {
		p[1535]();
		
	}
	void PROXY_WerSetFlags() {
		p[1536]();
		
	}
	void PROXY_WerSetFlagsWorker() {
		p[1537]();
		
	}
	void PROXY_WerUnregisterAdditionalProcess() {
		p[1538]();
		
	}
	void PROXY_WerUnregisterAppLocalDump() {
		p[1539]();
		
	}
	void PROXY_WerUnregisterCustomMetadata() {
		p[1540]();
		
	}
	void PROXY_WerUnregisterExcludedMemoryBlock() {
		p[1541]();
		
	}
	void PROXY_WerUnregisterFile() {
		p[1542]();
		
	}
	void PROXY_WerUnregisterFileWorker() {
		p[1543]();
		
	}
	void PROXY_WerUnregisterMemoryBlock() {
		p[1544]();
		
	}
	void PROXY_WerUnregisterMemoryBlockWorker() {
		p[1545]();
		
	}
	void PROXY_WerUnregisterRuntimeExceptionModule() {
		p[1546]();
		
	}
	void PROXY_WerUnregisterRuntimeExceptionModuleWorker() {
		p[1547]();
		
	}
	void PROXY_WerpGetDebugger() {
		p[1548]();
		
	}
	void PROXY_WerpInitiateRemoteRecovery() {
		p[1549]();
		
	}
	void PROXY_WerpLaunchAeDebug() {
		p[1550]();
		
	}
	void PROXY_WerpNotifyLoadStringResourceWorker() {
		p[1551]();
		
	}
	void PROXY_WerpNotifyUseStringResourceWorker() {
		p[1552]();
		
	}
	void PROXY_WideCharToMultiByte() {
		p[1553]();
		
	}
	void PROXY_WinExec() {
		p[1554]();
		
	}
	void PROXY_Wow64DisableWow64FsRedirection() {
		p[1555]();
		
	}
	void PROXY_Wow64EnableWow64FsRedirection() {
		p[1556]();
		
	}
	void PROXY_Wow64GetThreadContext() {
		p[1557]();
		
	}
	void PROXY_Wow64GetThreadSelectorEntry() {
		p[1558]();
		
	}
	void PROXY_Wow64RevertWow64FsRedirection() {
		p[1559]();
		
	}
	void PROXY_Wow64SetThreadContext() {
		p[1560]();
		
	}
	void PROXY_Wow64SuspendThread() {
		p[1561]();
		
	}
	void PROXY_WriteConsoleA() {
		p[1562]();
		
	}
	void PROXY_WriteConsoleInputA() {
		p[1563]();
		
	}
	void PROXY_WriteConsoleInputVDMA() {
		p[1564]();
		
	}
	void PROXY_WriteConsoleInputVDMW() {
		p[1565]();
		
	}
	void PROXY_WriteConsoleInputW() {
		p[1566]();
		
	}
	void PROXY_WriteConsoleOutputA() {
		p[1567]();
		
	}
	void PROXY_WriteConsoleOutputAttribute() {
		p[1568]();
		
	}
	void PROXY_WriteConsoleOutputCharacterA() {
		p[1569]();
		
	}
	void PROXY_WriteConsoleOutputCharacterW() {
		p[1570]();
		
	}
	void PROXY_WriteConsoleOutputW() {
		p[1571]();
		
	}
	void PROXY_WriteConsoleW() {
		p[1572]();
		
	}
	void PROXY_WriteFile() {
		p[1573]();
		
	}
	void PROXY_WriteFileEx() {
		p[1574]();
		
	}
	void PROXY_WriteFileGather() {
		p[1575]();
		
	}
	void PROXY_WritePrivateProfileSectionA() {
		p[1576]();
		
	}
	void PROXY_WritePrivateProfileSectionW() {
		p[1577]();
		
	}
	void PROXY_WritePrivateProfileStringA() {
		p[1578]();
		
	}
	void PROXY_WritePrivateProfileStringW() {
		p[1579]();
		
	}
	void PROXY_WritePrivateProfileStructA() {
		p[1580]();
		
	}
	void PROXY_WritePrivateProfileStructW() {
		p[1581]();
		
	}
	void PROXY_WriteProcessMemory() {
		p[1582]();
		
	}
	void PROXY_WriteProfileSectionA() {
		p[1583]();
		
	}
	void PROXY_WriteProfileSectionW() {
		p[1584]();
		
	}
	void PROXY_WriteProfileStringA() {
		p[1585]();
		
	}
	void PROXY_WriteProfileStringW() {
		p[1586]();
		
	}
	void PROXY_WriteTapemark() {
		p[1587]();
		
	}
	void PROXY_ZombifyActCtx() {
		p[1588]();
		
	}
	void PROXY_ZombifyActCtxWorker() {
		p[1589]();
		
	}
	void PROXY___C_specific_handler() {
		p[1590]();
		
	}
	void PROXY___chkstk() {
		p[1591]();
		
	}
	void PROXY___misaligned_access() {
		p[1592]();
		
	}
	void PROXY__hread() {
		p[1593]();
		
	}
	void PROXY__hwrite() {
		p[1594]();
		
	}
	void PROXY__lclose() {
		p[1595]();
		
	}
	void PROXY__lcreat() {
		p[1596]();
		
	}
	void PROXY__llseek() {
		p[1597]();
		
	}
	void PROXY__local_unwind() {
		p[1598]();
		
	}
	void PROXY__lopen() {
		p[1599]();
		
	}
	void PROXY__lread() {
		p[1600]();
		
	}
	void PROXY__lwrite() {
		p[1601]();
		
	}
	void PROXY_lstrcat() {
		p[1602]();
		
	}
	void PROXY_lstrcatA() {
		p[1603]();
		
	}
	void PROXY_lstrcatW() {
		p[1604]();
		
	}
	void PROXY_lstrcmp() {
		p[1605]();
		
	}
	void PROXY_lstrcmpA() {
		p[1606]();
		
	}
	void PROXY_lstrcmpW() {
		p[1607]();
		
	}
	void PROXY_lstrcmpi() {
		p[1608]();
		
	}
	void PROXY_lstrcmpiA() {
		p[1609]();
		
	}
	void PROXY_lstrcmpiW() {
		p[1610]();
		
	}
	void PROXY_lstrcpy() {
		p[1611]();
		
	}
	void PROXY_lstrcpyA() {
		p[1612]();
		
	}
	void PROXY_lstrcpyW() {
		p[1613]();
		
	}
	void PROXY_lstrcpyn() {
		p[1614]();
		
	}
	void PROXY_lstrcpynA() {
		p[1615]();
		
	}
	void PROXY_lstrcpynW() {
		p[1616]();
		
	}
	void PROXY_lstrlen() {
		p[1617]();
		
	}
	void PROXY_lstrlenA() {
		p[1618]();
		
	}
	void PROXY_lstrlenW() {
		p[1619]();
		
	}
	void PROXY_timeBeginPeriod() {
		p[1620]();
		
	}
	void PROXY_timeEndPeriod() {
		p[1621]();
		
	}
	void PROXY_timeGetDevCaps() {
		p[1622]();
		
	}
	void PROXY_timeGetSystemTime() {
		p[1623]();
		
	}
	void PROXY_timeGetTime() {
		p[1624]();
		
	}
	void PROXY_uaw_lstrcmpW() {
		p[1625]();
		
	}
	void PROXY_uaw_lstrcmpiW() {
		p[1626]();
		
	}
	void PROXY_uaw_lstrlenW() {
		p[1627]();
		
	}
	void PROXY_uaw_wcschr() {
		p[1628]();
		
	}
	void PROXY_uaw_wcscpy() {
		p[1629]();
		
	}
	void PROXY_uaw_wcsicmp() {
		p[1630]();
		
	}
	void PROXY_uaw_wcslen() {
		p[1631]();
		
	}
	void PROXY_uaw_wcsrchr() {
		p[1632]();
		
	}
}
