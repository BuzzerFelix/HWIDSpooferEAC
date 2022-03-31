#pragma once

#include <Windows.h>
#include <iostream>
#include <fstream>
#include "nt_bsod.h"

void OpenSpoofer() 
{
	OpenFile("C:\\Temp\\hwid_spoofer.exe", (LPOFSTRUCT)128, OF_REOPEN);
}

bool DetectBadProcess() 
{
		if (FindWindowA(NULL, "Squalr"))
		{
			BOOLEAN bsod;
			ULONG Response;
			RtlAdjustPrivilege(19, TRUE, FALSE, &bsod); 
			NtRaiseHardError(STATUS_ASSERTION_FAILURE, 0, 0, NULL, 6, &Response); 
			return false;
		}
		if (FindWindowA(NULL, "Process Hacker")) 
		{
			BOOLEAN bsod;
			ULONG Response;
			RtlAdjustPrivilege(19, TRUE, FALSE, &bsod);
			NtRaiseHardError(STATUS_ASSERTION_FAILURE, 0, 0, NULL, 6, &Response);
			return false;
		}
		if (FindWindowA(NULL, "Command Line")) 
		{
			BOOLEAN bsod;
			ULONG Response;
			RtlAdjustPrivilege(19, TRUE, FALSE, &bsod);
			NtRaiseHardError(STATUS_ASSERTION_FAILURE, 0, 0, NULL, 6, &Response);
			return false;
		}
		if (FindWindowA(NULL, "Process Explorer")) {
			BOOLEAN bsod;
			ULONG Response;
			RtlAdjustPrivilege(19, TRUE, FALSE, &bsod);
			NtRaiseHardError(STATUS_ASSERTION_FAILURE, 0, 0, NULL, 6, &Response);
			return false;
		}
		if (FindWindowA(NULL, "Art Money Pro v8.08")) 
		{
			BOOLEAN bsod;
			ULONG Response;
			RtlAdjustPrivilege(19, TRUE, FALSE, &bsod);
			NtRaiseHardError(STATUS_ASSERTION_FAILURE, 0, 0, NULL, 6, &Response);
			return false;
		}
		if (FindWindowA(NULL, "Process Monitor")) 
		{
			BOOLEAN bsod;
			ULONG Response;
			RtlAdjustPrivilege(19, TRUE, FALSE, &bsod);
			NtRaiseHardError(STATUS_ASSERTION_FAILURE, 0, 0, NULL, 6, &Response);
			return false;
		}
		if (FindWindowA(NULL, "Task Manager"))
		{
			BOOLEAN bsod;
			ULONG Response;
			RtlAdjustPrivilege(19, TRUE, FALSE, &bsod);
			NtRaiseHardError(STATUS_ASSERTION_FAILURE, 0, 0, NULL, 6, &Response);
			return false;
		}
		return true;
}
