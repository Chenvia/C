// UACBypass.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <string>
#include <Windows.h>

using namespace std;

/*Set constants necessary for running exploit*/

string const CMD = "C:\\Windows\\System32\\cmd.exe";
string const FOD_HELPER ="C:\\Windows\\System32\\fodhelper.exe";
string const PYTHON_CMD = "C:\\Users\\User\\AppData\\Local\\Programs\\Python\\Python37\\python.exe";
string const REG_PATH = "Software\\Classes\\ms-settings\\shell\\open\\command";
string const DELEGATE_EXEC_REG_KEY = "DelegateExecute";

/*
Uses getTokenInformation to enumerate privileges
returns 0 for False and 1 for True
*/
BOOL IsUserElevated() {

	BOOL fRet = FALSE;
	HANDLE hToken = NULL;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
		TOKEN_ELEVATION Elevation;
		DWORD cbSize = sizeof(TOKEN_ELEVATION);
		if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) {
			fRet = Elevation.TokenIsElevated;
		}
	}
	if (hToken) {
		CloseHandle(hToken);
	}

	return fRet;

}

//HKEY CreateRegistryKey(string key, string value) 
//{
//	LONG openRes = RegCreateKeyEx(
//		HKEY_LOCAL_MACHINE,
//		sk,
//		0,
//		NULL,
//		REG_OPTION_BACKUP_RESTORE,
//		KEY_ALL_ACCESS,
//		NULL,
//		&hKey,
//		NULL);
//}

HKEY OpenKey(HKEY hRootKey, wchar_t*  strKey)
{
	HKEY hKey;
	LONG nError = RegOpenKeyEx(hRootKey, strKey, NULL, KEY_ALL_ACCESS, &hKey);

	if (nError == ERROR_FILE_NOT_FOUND)
	{
		cout << "Creating registry key: " << strKey << endl;
		nError = RegCreateKeyEx(hRootKey, strKey, NULL, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, NULL);
	}

	if (nError)
		cout << "Error: " << nError << " Could not find or create " << strKey << endl;

	return hKey;
}

void SetVal(HKEY hKey, LPCTSTR lpValue, DWORD data)
{
	LONG nError = RegSetValueEx(hKey, lpValue, NULL, REG_DWORD, (LPBYTE)& data, sizeof(DWORD));

	if (nError)
		cout << "Error: " << nError << " Could not set registry value: " << (char*)lpValue << endl;
}

DWORD GetVal(HKEY hKey, LPCTSTR lpValue)
{
	DWORD data;		DWORD size = sizeof(data);	DWORD type = REG_DWORD;
	LONG nError = RegQueryValueEx(hKey, lpValue, NULL, &type, (LPBYTE)& data, &size);

	if (nError == ERROR_FILE_NOT_FOUND)
		data = 0; // The value will be created and set to data next time SetVal() is called.
	else if (nError)
		cout << "Error: " << nError << " Could not get registry value " << (char*)lpValue << endl;

	return data;
}

int main()
{
	std::cout << "Admin Privilege: " << IsUserElevated() << "\n";

	static DWORD v1, v2;

	WCHAR* szText = L"SOFTWARE\\MyCompany";

	HKEY hKey = OpenKey(HKEY_LOCAL_MACHINE, L"SOFTWARE\\MyCompany");

	v1 = GetVal(hKey, L"Value1");
	v2 = GetVal(hKey, L"Value2");

	v1 += 5;
	v2 += 2;

	SetVal(hKey, L"Value1", v1);
	SetVal(hKey, L"Value2", v2);

	RegCloseKey(hKey);

	return 0;
}


// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
