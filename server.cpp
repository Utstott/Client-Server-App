#define _CRT_SECURE_NO_WARNINGS
//#define _D_SCL_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS
//#pragma warning(disable : 4996)
#define SXS_MANIFEST_RESOURCE_ID = 1
#define SXS_MANIFEST = foo.manifest
#define SXS_ASSEMBLY_NAME = Microsoft.Windows.Foo
#define SXS_ASSEMBLY_VERSION = 1.0
#define SXS_ASSEMBLY_LANGUAGE_INDEPENDENT = 1
#define SXS_MANIFEST_IN_RESOURCES = 1

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <fileapi.h>
#include <wchar.h>
#include <iostream>
#include <time.h> 
#include <aclapi.h>
#include <mswsock.h>  
#include <string>
#include <Wincrypt.h>
#include <Sddl.h>
#include <sstream>
#include <iomanip>
#include <atlstr.h>
#include <VersionHelpers.h>
using namespace std;
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "mswsock.lib")
#define MAX_CLIENTS (100)
#define WIN32_LEAN_AND_MEAN
struct client_ctx//структура контекста клиента
{
	int socket;
	CHAR buf_recv[512]; // Буфер приема
	CHAR buf_send[2048]; // Буфер отправки
	unsigned int sz_recv; // Принято данных
	unsigned int sz_send_total; // Данных в буфере отправки
	unsigned int sz_send; // Данных отправлено
	 // Структуры OVERLAPPED для уведомлений озавершении
	OVERLAPPED overlap_recv;
	OVERLAPPED overlap_send;
	OVERLAPPED overlap_cancel;
	DWORD flags_recv; // Флаги для WSARecv
	HCRYPTKEY Public_key;
	HCRYPTKEY  hKey;
	bool flag = false;
	int Port;
};
// Прослушивающий сокет и все сокеты подключения хранятся
// в массиве структур (вместе с overlapped и буферами)
struct client_ctx g_ctxs[1 + MAX_CLIENTS];
HCRYPTPROV hProv;
int g_accepted_socket;//номер принятого сокета
HANDLE g_io_port;//хэндл порта по которому соеденение
// Функция стартует операцию чтения из сокета
void InitCrypto()
{
	if (!CryptAcquireContext(&hProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, 0))
	{
		if (!CryptAcquireContext(&hProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, (CRYPT_NEWKEYSET)))
			cout << "Error building crypto context" << endl << GetLastError();
	}

	else 
	{cout << "Crypto context initialised" << endl;}

}
string GetOsVersionName()
{
	if (IsWindows10OrGreater())
	{return "10";}
	if (IsWindows8Point1OrGreater())
	{return "8.1";}
	if (IsWindows8OrGreater())
	{return "8";}
	if (IsWindows7OrGreater())
	{return "7";}
	if (IsWindowsVistaOrGreater())
	{return "Vista";}
	if (IsWindowsXPOrGreater())
	{return "XP";}
	return "Unknown";
}

void Current_time()
{
	SYSTEMTIME sm;
	GetSystemTime(&sm);

	cout << sm.wDay << ":";
	cout << sm.wMonth << ":";
	cout << sm.wYear << endl;

	cout << sm.wHour << ":";
	cout << sm.wMinute << ":";
	cout << sm.wSecond << endl;
}
//публичный приватный     нужно      открытый закрытый
void crypto_key(int idx)
{
	InitCrypto();
	Sleep(10);
	if (!CryptImportKey(hProv, (BYTE*)(g_ctxs[idx].buf_recv + 4), g_ctxs[idx].sz_recv - 8, NULL, NULL, &g_ctxs[idx].Public_key))//прием ключа от клиента открытого
	{
		cout << GetLastError() << endl;
		cout << "False" << endl;
	}

	if (CryptGenKey(hProv, CALG_RC4, (CRYPT_EXPORTABLE | CRYPT_ENCRYPT | CRYPT_DECRYPT), &g_ctxs[idx].hKey) == 0)//создаём сеансовый ключ
		printf("ERROR, %x", GetLastError());
	DWORD pubLen = 0;

	if (!CryptExportKey(g_ctxs[idx].hKey, g_ctxs[idx].Public_key, SIMPLEBLOB, 0, NULL, &pubLen))//узнаем размер данных передаваемых
	{
		cout << GetLastError() << endl;
		cout << "Error getting export size of session key" << endl;
	}
	BYTE* pubdata = static_cast<BYTE*>(malloc(pubLen));
	ZeroMemory(pubdata, pubLen);
	if (!CryptExportKey(g_ctxs[idx].hKey, g_ctxs[idx].Public_key, SIMPLEBLOB, 0, (BYTE*)pubdata, &pubLen))//передаем сеансовый ключ клиенту в зашифр виде
	{
		cout << GetLastError() << endl;
		cout << "Error exporting public key" << endl;
	}

	pubdata = static_cast <BYTE*>(realloc(pubdata, pubLen + 4));
	pubdata[pubLen] = '\r';
	pubdata[pubLen + 1] = '\n';
	pubdata[pubLen + 2] = '\r';
	pubdata[pubLen + 3] = '\n';
	memcpy(g_ctxs[idx].buf_send, pubdata, pubLen + 4);

	g_ctxs[idx].sz_send_total = pubLen + 4;
	g_ctxs[idx].sz_send = 0;
	cout << pubLen + 4 << endl;
	g_ctxs[idx].flag = true;
}
void find_disk(char(&disks)[26][3])//находим имена дисков
{
	int n;
	int count = 0;

	DWORD dr = GetLogicalDrives();
	for (int i = 0; i < 26; i++)
	{
		n = ((dr >> i) & 0x00000001);

		if (n == 1)
		{
			disks[count][0] = char(65 + i);
			disks[count][1] = ':';
			count++;
		}
	}
}

void schedule_read(DWORD idx)// чтение ...
{
	WSABUF buf;
	buf.buf = g_ctxs[idx].buf_recv + g_ctxs[idx].sz_recv;
	buf.len = sizeof(g_ctxs[idx].buf_recv) - g_ctxs[idx].sz_recv;
	memset(&g_ctxs[idx].overlap_recv, 0, sizeof(OVERLAPPED));
	g_ctxs[idx].flags_recv = 0;
	WSARecv(g_ctxs[idx].socket, &buf, 1, NULL, &g_ctxs[idx].flags_recv, &g_ctxs[idx].overlap_recv, NULL);
}
// Функция стартует операцию отправки подготовленных данных в сокет
void schedule_write(DWORD idx)
{
	WSABUF buf; buf.buf = g_ctxs[idx].buf_send + g_ctxs[idx].sz_send;
	buf.len = g_ctxs[idx].sz_send_total - g_ctxs[idx].sz_send;
	memset(&g_ctxs[idx].overlap_send, 0, sizeof(OVERLAPPED));
	WSASend(g_ctxs[idx].socket, &buf, 1, NULL, 0, &g_ctxs[idx].overlap_send, NULL);
}
// Функция добавляет новое принятое подключение клиента
void add_accepted_connection()
{
	DWORD i; // Поиск места в массиве g_ctxs для вставки нового подключения
	unsigned int ip = 0;
	struct sockaddr_in* local_addr = 0, * remote_addr = 0;
	int local_addr_sz, remote_addr_sz;
	GetAcceptExSockaddrs(g_ctxs[0].buf_recv, g_ctxs[0].sz_recv, sizeof(struct sockaddr_in) + 16,
		sizeof(struct sockaddr_in) + 16, (struct sockaddr**) & local_addr, &local_addr_sz, (struct sockaddr**) & remote_addr,
		&remote_addr_sz);
	if (remote_addr) ip = ntohl(remote_addr->sin_addr.s_addr);
	for (i = 0; i < sizeof(g_ctxs) / sizeof(g_ctxs[0]); i++)
	{
		if (g_ctxs[i].socket == 0 || remote_addr->sin_port == g_ctxs[i].Port)
		{

			printf(" connection %u created, remote IP: %u.%u.%u.%u\n", i, (ip >> 24) & 0xff, (ip >> 16) & 0xff,
				(ip >> 8) & 0xff, (ip) & 0xff);
			g_ctxs[i].socket = g_accepted_socket;
			// Связь сокета с портом IOCP, в качестве key используется индекс массива
			if (NULL == CreateIoCompletionPort((HANDLE)g_ctxs[i].socket, g_io_port, i, 0))
			{
				printf("CreateIoCompletionPort error: %x\n", GetLastError());
				return;
			}
			// Ожидание данных от сокета
			g_ctxs[i].Port = remote_addr->sin_port;
			schedule_read(i);
			return;
		}
	}
	// Место не найдено => нет ресурсов для принятия соединения
	closesocket(g_accepted_socket);
	g_accepted_socket = 0;
}
// Функция стартует операцию приема соединения
void schedule_accept()
{
	// Создание сокета для принятия подключения (AcceptEx не создает сокетов)
	g_accepted_socket = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
	memset(&g_ctxs[0].overlap_recv, 0, sizeof(OVERLAPPED));
	// Принятие подключения.
	// Как только операция будет завершена - порт завершения пришлет уведомление. // Размеры буферов должны быть на 16 байт больше размера адреса согласно документации разработчика ОС
	AcceptEx(g_ctxs[0].socket, g_accepted_socket, g_ctxs[0].buf_recv, 0, sizeof(struct sockaddr_in) + 16, sizeof(struct
		sockaddr_in) + 16, NULL, &g_ctxs[0].overlap_recv);
}
int is_string_received(DWORD idx, int* len)//была ли принята строка
{
	DWORD i;
	for (i = 3; i < g_ctxs[idx].sz_recv; i++)
	{
		if (g_ctxs[idx].buf_recv[i] == '\n' && g_ctxs[idx].buf_recv[i - 1] == '\r' && g_ctxs[idx].buf_recv[i - 2] == '\n' && g_ctxs[idx].buf_recv[i - 3] == '\r')
		{
			*len = (int)(i + 1 - 4);
			return 1;
		}
	}
	if (g_ctxs[idx].sz_recv == sizeof(g_ctxs[idx].buf_recv))
	{
		*len = sizeof(g_ctxs[idx].buf_recv);
		return 1;
	}
	return 0;
}
void io_serv()
{
	WSADATA wsa_data;
	if (WSAStartup(MAKEWORD(2, 2), &wsa_data) == 0)
	{printf("WSAStartup ok\n");}
	else
	{printf("WSAStartup error\n");}
	struct sockaddr_in addr;
	// Создание сокета прослушивания
	SOCKET s = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
	// Создание порта завершения
	g_io_port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
	if (NULL == g_io_port)
	{
		printf("CreateIoCompletionPort error: %x\n", GetLastError());
		return;
	}
	// Обнуление структуры данных для хранения входящих соединений
	memset(g_ctxs, 0, sizeof(g_ctxs));
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(9000);
	if (bind(s, (struct sockaddr*) & addr, sizeof(addr)) < 0 || listen(s, 1) < 0) { printf("error bind() or listen()\n"); return; }
	printf("Listening: %hu\n", ntohs(addr.sin_port));
	// Присоединение существующего сокета s к порту io_port.
	// В качестве ключа для прослушивающего сокета используется 0
	if (NULL == CreateIoCompletionPort((HANDLE)s, g_io_port, 0, 0))
	{
		printf("CreateIoCompletionPort error: %x\n", GetLastError());
		return;
	}
	g_ctxs[0].socket = s;
	// Старт операции принятия подключения.
	schedule_accept();
	// Бесконечный цикл принятия событий о завершенных операциях
	while (1)
	{
		DWORD transferred;
		ULONG_PTR key;
		OVERLAPPED* lp_overlap;
		// Ожидание событий в течение 1 секунды
		BOOL b = GetQueuedCompletionStatus(g_io_port, &transferred, &key, &lp_overlap, 1000);
		if (b)
		{
			// Поступило уведомление о завершении операции
			if (key == 0) // ключ 0 - для прослушивающего сокета
			{
				g_ctxs[0].sz_recv += transferred;
				// Принятие подключения и начало принятия следующего
				add_accepted_connection();
				schedule_accept();
			}
			else
			{
				// Иначе поступило событие по завершению операции от клиента. // Ключ key - индекс в массиве g_ctxs
				if (&g_ctxs[key].overlap_recv == lp_overlap)
				{
					int len;
					// Данные приняты:
					if (transferred == 0)
					{
						// Соединение разорвано
						CancelIo((HANDLE)g_ctxs[key].socket);
						PostQueuedCompletionStatus(g_io_port, 0, key,
							&g_ctxs[key].overlap_cancel);
						continue;
					}
					g_ctxs[key].sz_recv += transferred;
					if (is_string_received(key, &len))
					{
						int nomer;
						if (g_ctxs[key].flag == TRUE)
						{
							DWORD count = g_ctxs[key].sz_recv - 4;
							if (!CryptDecrypt(g_ctxs[key].hKey, NULL, TRUE, NULL, (BYTE*)g_ctxs[key].buf_recv, &count))
							{
								cout << GetLastError() << endl;
								cout << "Error decript" << endl;
							}
						}
						cout << g_ctxs[key].sz_recv << endl;

						memcpy(&nomer, g_ctxs[key].buf_recv, 4);
						nomer = ntohl(nomer);
						cout << "Number=" << nomer << endl;
						if (nomer == 1)
						{
							crypto_key(key);
							schedule_write(key);
						}
						if (nomer == 2)
						{
							string osVersionName = GetOsVersionName();
							DWORD len = 16;
							char temp[16];
							strcpy(temp, osVersionName.c_str());
							if (!(CryptEncrypt(g_ctxs[key].hKey, NULL, true, 0, (BYTE*)temp, &len, len)))
							{
								cout << GetLastError() << endl;
								cout << "Error encrypt" << endl;
							}
							temp[len - 4] = '\r';
							temp[len - 3] = '\n';
							temp[len - 2] = '\r';
							temp[len - 1] = '\n';
							memcpy(g_ctxs[key].buf_send, temp, len);
							//Sleep(100);

							g_ctxs[key].sz_send_total = len;
							g_ctxs[key].sz_send = 0;
							schedule_write(key);

						}

						if (nomer == 3)
						{
							SYSTEMTIME st;
							GetSystemTime(&st);
							CString cstrMessage;

							cstrMessage.Format("%d-%02d-%02d %02d:%02d:%02d.%03d",
								st.wYear,
								st.wMonth,
								st.wDay,
								st.wHour,
								st.wMinute,
								st.wSecond,
								st.wMilliseconds);
							string Time((LPCTSTR)cstrMessage);
							DWORD len = 64;
							char temp[64];
							strcpy(temp, Time.c_str());
							if (!(CryptEncrypt(g_ctxs[key].hKey, NULL, true, 0, (BYTE*)temp, &len, len)))
							{
								cout << GetLastError() << endl;
								cout << "Error encrypt" << endl;
							}
							temp[len - 4] = '\r';
							temp[len - 3] = '\n';
							temp[len - 2] = '\r';
							temp[len - 1] = '\n';
							memcpy(g_ctxs[key].buf_send, temp, len);

							g_ctxs[key].sz_send_total = len;
							g_ctxs[key].sz_send = 0;
							schedule_write(key);
						}
						if (nomer == 4)
						{
							CString cstrMessage;
							int hour, min, sec, msec = GetTickCount();
							hour = msec / (1000 * 60 * 60);
							min = msec / (1000 * 60) - hour * 60;
							sec = (msec / 1000) - (hour * 60 * 60) - min * 60;
							cstrMessage.Format("%d:%d:%d", hour, min, sec);
							string Time((LPCTSTR)cstrMessage);
							DWORD len = 64;
							char temp[64];
							strcpy(temp, Time.c_str());
							if (!(CryptEncrypt(g_ctxs[key].hKey, NULL, true, 0, (BYTE*)temp, &len, len)))
							{
								cout << GetLastError() << endl;
								cout << "Error encrypt" << endl;
							}
							temp[len - 4] = '\r';
							temp[len - 3] = '\n';
							temp[len - 2] = '\r';
							temp[len - 1] = '\n';
							memcpy(g_ctxs[key].buf_send, temp, len);
							//Sleep(100);

							g_ctxs[key].sz_send_total = len;
							g_ctxs[key].sz_send = 0;
							schedule_write(key);
						}
						if (nomer == 5)
						{
							MEMORYSTATUS stat;
							GlobalMemoryStatus(&stat);
							CString cstrMessage;
							cstrMessage.Format("Structure length=%d,Percent memory load=%d , maximum amount of physical memory=%d,free amount of physical memory=%d,maximum amount of memory for programs=%d,free memory for programs=%d,maximum amount of virtual memory=%d,free amount of virtual memory=%d", stat.dwLength,
								stat.dwMemoryLoad,
								stat.dwTotalPhys,
								stat.dwAvailPhys,
								stat.dwTotalPageFile,
								stat.dwAvailPageFile,
								stat.dwTotalVirtual,
								stat.dwAvailVirtual
							);
							string Time((LPCTSTR)cstrMessage);
							DWORD len = 512;
							char temp[512];
							strcpy(temp, Time.c_str());
							if (!(CryptEncrypt(g_ctxs[key].hKey, NULL, true, 0, (BYTE*)temp, &len, len)))
							{
								cout << GetLastError() << endl;
								cout << "Error encrypt" << endl;
							}
							temp[len - 4] = '\r';
							temp[len - 3] = '\n';
							temp[len - 2] = '\r';
							temp[len - 1] = '\n';
							memcpy(g_ctxs[key].buf_send, temp, len);

							g_ctxs[key].sz_send_total = len;
							g_ctxs[key].sz_send = 0;
							schedule_write(key);

						}
						if (nomer == 6)
						{
							string Text;
							char disks[26][3] = { 0 };
							find_disk(disks);
							CString cstrMessage;
							double freeSp[26];
							for (int i = 0; i < 26; i++)
							{
								freeSp[i] = -1;
								if (GetDriveTypeA(disks[i]) == DRIVE_FIXED)
								{
									unsigned __int64 s, b, f, c;
									GetDiskFreeSpaceEx(disks[i], (PULARGE_INTEGER)&s, (PULARGE_INTEGER)&b, (PULARGE_INTEGER)&f);
									double freeSpace = (double)f / 1024.0 / 1024.0 / 1024.0;
									freeSp[i] = freeSpace;
									cout << disks[i][0] << ":" << freeSpace << endl;
									cstrMessage.Format("%c:%e\n", disks[i][0], freeSpace);
									Text += ((LPCTSTR)cstrMessage);
								}
							}
							//			
							cout << Text << endl;
							DWORD len = 512;
							char temp[512];
							strcpy(temp, Text.c_str());
							if (!(CryptEncrypt(g_ctxs[key].hKey, NULL, true, 0, (BYTE*)temp, &len, len)))
							{
								cout << GetLastError() << endl;
								cout << "Error encrypt" << endl;
							}
							temp[len - 4] = '\r';
							temp[len - 3] = '\n';
							temp[len - 2] = '\r';
							temp[len - 1] = '\n';
							memcpy(g_ctxs[key].buf_send, temp, len);
							//Sleep(100);

							g_ctxs[key].sz_send_total = len;
							g_ctxs[key].sz_send = 0;
							schedule_write(key);
						}
						// Если строка полностью пришла, то сформировать ответ и начать его отправлять
						if (nomer == 7)
						{
 							char* path = new char[g_ctxs[key].sz_recv - 8];
							int flag;
							memcpy(&flag, g_ctxs[key].buf_recv + 4, 4);
							memcpy((path), g_ctxs[key].buf_recv + 8, g_ctxs[key].sz_recv - 8);
							flag = ntohl(flag);
							cout << flag << endl;
							cout << path << endl;
							PSECURITY_DESCRIPTOR pSD;
							PACL a;
							if (flag == 1)
							{
								GetNamedSecurityInfo(path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &a, NULL, &pSD);
							}
							else
							{
								GetNamedSecurityInfo(path, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION, NULL, NULL, &a, NULL, &pSD);
							}
							ACCESS_ALLOWED_ACE* pAce;
							ACL_SIZE_INFORMATION aclSize;
							PSID pSid;
							string info;

							GetAclInformation(a, &aclSize, sizeof(aclSize), AclSizeInformation);
							for (int i = 0; i < a->AceCount; i++)
							{
								GetAce(a, i, (LPVOID*)&pAce);
								pSid = (PSID)(&(pAce->SidStart));
								char lpName[MAX_PATH];
								char lpDomain[MAX_PATH];

								DWORD dwNameLen = sizeof(lpName);
								DWORD dwDomainNameLen = sizeof(lpDomain);
								SID_NAME_USE sidName;
								SID_NAME_USE Type;
								if (LookupAccountSid(NULL, pSid, lpName, &dwNameLen, lpDomain, &dwDomainNameLen, &sidName))//меняются имя и домен владельцев
								{
									LPSTR strSid;

									info += "User: ";
									info += lpDomain;
									info += '\\';
									info += lpName;
									info += '\n';
									info += " SID: ";
									ConvertSidToStringSidA(pSid, &strSid);
									info += strSid;
									info += '\n';
									info += " ACE: \n";

									if (DELETE & pAce->Mask)
									{info += " DELETE,\n";}
									if (FILE_GENERIC_READ & pAce->Mask)
									{info += " FILE_GENERIC_READ,\n";}
									if (FILE_GENERIC_WRITE & pAce->Mask) 
									{info += " FILE_GENERIC_WRITE,\n";}
									if (FILE_GENERIC_EXECUTE & pAce->Mask)
									{info += " FILE_GENERIC_EXECUTE,\n";}
									if (GENERIC_READ & pAce->Mask) {
										info += " GENERIC_READ,\n";
									}
									if (GENERIC_WRITE & pAce->Mask) {
										info += " GENERIC_WRITE,\n";
									}
									if (GENERIC_EXECUTE & pAce->Mask) {
										info += " GENERIC_EXECUTE,\n";
									}
									if (GENERIC_ALL & pAce->Mask) {
										info += " GENERIC_ALL,\n";
									}
									if (READ_CONTROL & pAce->Mask) {
										info += " READ_CONTROL,\n";
									}
									if (WRITE_DAC & pAce->Mask) {
										info += " WRITE_DAC,\n";
									}
									if (WRITE_OWNER & pAce->Mask) {
										info += " WRITE_OWNER,\n";
									}
									if (SYNCHRONIZE & pAce->Mask) {
										info += " SYNCHRONIZE,\n";
									}
									info += "\n\n";
								}
							}
							cout << info << endl;
							DWORD len = 2048;
							char temp[2048];
							strcpy(temp, info.c_str());
							//cout << temp << endl;
							if (!(CryptEncrypt(g_ctxs[key].hKey, NULL, false, 0, (BYTE*)temp, &len, len)))
							{
								cout << GetLastError() << endl;
								cout << "Error encrypt" << endl;
							}
							temp[len - 4] = '\r';
							temp[len - 3] = '\n';
							temp[len - 2] = '\r';
							temp[len - 1] = '\n';
							memcpy(g_ctxs[key].buf_send, temp, len);

							g_ctxs[key].sz_send_total = len;
							g_ctxs[key].sz_send = 0;
							schedule_write(key);
						}
						if (nomer == 8)
						{
							char* path = new char[g_ctxs[key].sz_recv - 8];
							int flag;
							memcpy(&flag, g_ctxs[key].buf_recv + 4, 4);
							memcpy((path), g_ctxs[key].buf_recv + 8, g_ctxs[key].sz_recv - 8);
							flag = ntohl(flag);
							cout << flag << endl;
							cout << path << endl;
							PSID pOwnerSid;
							SID_NAME_USE use;
							PSECURITY_DESCRIPTOR pSecDescr;
							if (flag == 1)
							{GetNamedSecurityInfo(path, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, &pOwnerSid, NULL, NULL, NULL, &pSecDescr);}
							else
							{GetNamedSecurityInfo(path, SE_REGISTRY_KEY, OWNER_SECURITY_INFORMATION, &pOwnerSid, NULL, NULL, NULL, &pSecDescr);}
							char lpName[MAX_PATH];
							char lpDomain[MAX_PATH];
							DWORD dwNameLen = sizeof(lpName);
							DWORD dwDomainNameLen = sizeof(lpDomain);
							DWORD res;

							res = LookupAccountSidA(NULL, pOwnerSid, lpName, &dwNameLen, lpDomain, &dwDomainNameLen, &use);

							string info;
							info = lpDomain;
							info += "\\";
							info += lpName;
							cout << info << endl;
							DWORD len = 2048;
							char temp[2048];
							strcpy(temp, info.c_str());
							cout << temp << endl;
							if (!(CryptEncrypt(g_ctxs[key].hKey, NULL, false, 0, (BYTE*)temp, &len, len)))
							{
								cout << GetLastError() << endl;
								cout << "Error encrypt" << endl;
							}
							temp[len - 4] = '\r';
							temp[len - 3] = '\n';
							temp[len - 2] = '\r';
							temp[len - 1] = '\n';
							memcpy(g_ctxs[key].buf_send, temp, len);

							g_ctxs[key].sz_send_total = len;
							g_ctxs[key].sz_send = 0;
							schedule_write(key);
						}
						if (nomer == 9)
						{
							g_ctxs[key].Public_key = 0;
							g_ctxs[key].hKey = 0;

							if (!CryptAcquireContext(&hProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_DELETEKEYSET))
							{
								cout << GetLastError() << endl;
								cout << "Error destroying keys" << endl;
							}
						}
					}
					else
					{
						// Иначе - ждем данные дальше
						schedule_read(key);
					}
				}
				else if (&g_ctxs[key].overlap_send == lp_overlap)
				{
					// Данные отправлены
					g_ctxs[key].sz_send += transferred;
					if (g_ctxs[key].sz_send < g_ctxs[key].sz_send_total && transferred > 0)
					{
						// Если данные отправлены не полностью - продолжить отправлять
						schedule_write(key);
					}
					else
					{
						// Данные отправлены полностью, прервать все коммуникации,
						// добавить в порт событие на завершение работы
						CancelIo((HANDLE)g_ctxs[key].socket);
						PostQueuedCompletionStatus(g_io_port, 0, key,
							&g_ctxs[key].overlap_cancel);
					}
				}
				else if (&g_ctxs[key].overlap_cancel == lp_overlap)
				{
					// Все коммуникации завершены, сокет может быть закрыт
					closesocket(g_ctxs[key].socket);
					g_ctxs[key].socket = 0;
					memset(&g_ctxs[key].overlap_cancel, 0, sizeof(OVERLAPPED));
					memset(&g_ctxs[key].overlap_send, 0, sizeof(OVERLAPPED));
					memset(&g_ctxs[key].overlap_recv, 0, sizeof(OVERLAPPED));
					HCRYPTKEY Pub, Session;
					CryptDuplicateKey(g_ctxs[key].hKey, NULL, 0, &Session);
					memset(&g_ctxs[key], 0, sizeof(g_ctxs[key]));
					CryptDuplicateKey(Session, NULL, 0, &g_ctxs[key].hKey);
					g_ctxs[key].flag = TRUE;
					printf(" connection %u closed\n", key);
				}
			}
		}
		else
		{}
	}
}
int main()
{
	setlocale(LC_ALL, "");
	io_serv();
	return 0;
}