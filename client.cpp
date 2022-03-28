#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <iostream>
#include <winsock2.h>
#include <locale>
#include <ws2tcpip.h>
#include <Wincrypt.h>
#include <mswsock.h> 
#pragma comment(lib, "ws2_32.lib") 
#pragma comment(lib, "mswsock.lib") 
using namespace std;
struct destination//структура получения
{
	int port;//порт
	char* ip;
	int Socket;//сокет
	DWORD pubLen;//размер передаваемых данных
	HCRYPTKEY SessionKey;//ключ сессии
	HCRYPTKEY  hPubKey;//публичный ключ
	HCRYPTKEY  hPrivKey;//привилегированный ключ
	BYTE* Session_key;
};
HCRYPTPROV hProv;
HCRYPTPROV hKey;
int set_non_block_mode(int s)
{
#ifdef _WIN32
	unsigned long mode = 1;
	return ioctlsocket(s, FIONBIO, &mode);
#else
	int fl = fcntl(s, F_GETFL, 0);
	return fcntl(s, F_SETFL, fl | O_NONBLOCK);
#endif
}

void InitCrypto()
{
	if (!CryptAcquireContext(&hProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, 0))//Функция CryptAcquireContext используется для получения дескриптора к конкретному контейнеру ключей
	{
		if (!CryptAcquireContext(&hProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, (CRYPT_NEWKEYSET)))
		{cout << "Error building crypto context" << endl << GetLastError();}
	}

	else 
	{cout << "Crypto context initialised" << endl;}
}
void GeneratePublicKey(destination& dest)
{
	if (!CryptGenKey(hProv, AT_KEYEXCHANGE, 1024 << 16, &hKey))
	{cout << "Error generating RSA key for exchange" << endl;}

	if (!CryptGetUserKey(hProv, AT_KEYEXCHANGE, &dest.hPubKey))
	{cout << "Error getting public key from container" << endl;}
	if (!CryptGetUserKey(hProv, AT_KEYEXCHANGE, &dest.hPrivKey))
	{printf("CryptGetUserKey err\n");}

	DWORD pubLen = 0;

	if (!CryptExportKey(dest.hPubKey, 0, PUBLICKEYBLOB, 0, NULL, &pubLen))
	{cout << "Error getting export size of public key" << endl;}

	BYTE* pubdata = static_cast<BYTE*>(malloc(pubLen + 8));
	ZeroMemory(pubdata, pubLen);

	if (!CryptExportKey(dest.hPubKey, 0, PUBLICKEYBLOB, 0, (BYTE*)(pubdata + 4), &pubLen))
	{cout << "Error exporting public key" << endl;}
	int nomer = 1;
	nomer = htonl(nomer);
	memcpy(pubdata, &nomer, 4);
	dest.pubLen = pubLen;
	pubdata[4 + pubLen] = '\r';
	pubdata[4 + pubLen + 1] = '\n';
	pubdata[4 + pubLen + 2] = '\r';
	pubdata[4 + pubLen + 3] = '\n';
	cout << pubLen << endl;
	send(dest.Socket, (char*)pubdata, pubLen + 8, 0);//отправка ключа на сервер

}
int init()
{
	// Для Windows следует вызвать WSAStartup перед началом использования сокетов
	WSADATA wsa_data;
	return (0 == WSAStartup(MAKEWORD(2, 2), &wsa_data));
}
void deinit()
{
	// Для Windows следует вызвать WSACleanup в конце работы
	WSACleanup();
}
int sock_err(const char* function, int s)
{
	int err;
	err = WSAGetLastError();
	fprintf(stderr, "%s: socket error: %d\n", function, err);
	return -1;
}
void s_close(int s)
{
	closesocket(s);
}
unsigned int get_host_ipn(const char* name)//получение адреса для сервера
{
	struct addrinfo* addr = 0;
	unsigned int ip4addr = 0;
	// Функция возвращает все адреса указанного хоста
	// в виде динамического однонаправленного списка
	if (0 == getaddrinfo(name, 0, 0, &addr))
	{
		struct addrinfo* cur = addr;
		while (cur)
		{
			// Интересует только IPv4 адрес, если их несколько - то первый
			if (cur->ai_family == AF_INET)
			{
				ip4addr = ((struct sockaddr_in*) cur->ai_addr)->sin_addr.s_addr;
				break;
			}
			cur = cur->ai_next;
		}
		freeaddrinfo(addr);
	}
	return ip4addr;
}

int con(int s, struct sockaddr_in addr)//добавление нового сокета
{
	for (int rec = 0; rec < 10; rec++)
	{
		if (connect(s, (struct sockaddr*) & addr, sizeof(addr)) == 0)
			return 0;
		else
		{
			fprintf(stdout, "%i time failed to connect to server\n", (rec + 1));
			Sleep(100);
		}
	}
	return 1;
}
int Server_con(destination& Server)//подключение к указаннаму серверу
{
	struct sockaddr_in addr;
	Server.Socket = socket(AF_INET, SOCK_STREAM, 0);

	if (Server.Socket < 0)
		return sock_err("socket", Server.Socket);
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(Server.port);
	addr.sin_addr.s_addr = get_host_ipn(Server.ip);
	if (con(Server.Socket, addr) != 0)	//если за 10 раз с задержкой в 100мс так и не подкл. к серверу - ошибка
	{
		deinit();
		fprintf(stdout, "connect");
		s_close(Server.Socket);
		Server.ip = NULL;
		Server.port = 0;
		return -1;
	}
	return 0;
}

int send_request(destination s, int number)//запрос выполнения команды
{
	BYTE* letter;
	DWORD len;
	if (number == 7 || number == 8)
	{
		cout << "Enter the path:";
		string path;
		cin >> path;
		cout << "Choose the flag:";
		int flag;
		cin >> flag;
		int byte = htonl(number);
		letter = new BYTE[64];

		ZeroMemory(letter, 64);
		len = 64;
		flag = htonl(flag);
		memcpy(letter, &byte, sizeof(byte));
		memcpy(letter + 4, &flag, sizeof(flag));
		memcpy(letter + 8, path.c_str(), path.length());
	}
	else
	{
		int byte = htonl(number);
		letter = new BYTE[16];
		ZeroMemory(letter, 16);
		len = 16;
		memcpy(letter, &byte, sizeof(byte));
	}
	int crypt = 0;
	try
	{
		if (!(crypt = CryptEncrypt(s.SessionKey, NULL, true, 0, letter, &len, len)))
		{
			cout << GetLastError() << endl;
			cout << "Error encrypt" << endl;
		}

		char* mem = new char[len];
		ZeroMemory(mem, len);
		memcpy(mem, letter, len);
		mem[len - 4] = '\r';
		mem[len - 3] = '\n';
		mem[len - 2] = '\r';
		mem[len - 1] = '\n';
		if (send(s.Socket, mem, len, 0) < 0)
			return sock_err("send", s.Socket);
		return 0;
	}
	catch (exception)
	{
		cout << GetLastError() << endl;
		cout << "Error encrypt" << endl;
		return 0;
	}
}
int recv_response(destination& s)//получение ответа от сервера
{
	char buffer[512] = { 0 };
	int res;
	DWORD Position = 0;
	s.Session_key = new BYTE[512];
	// Принятие очередного блока данных.
	// Если соединение будет разорвано удаленным узлом recv вернет 0
	Sleep(1000);

	while (Position < 4 || !(s.Session_key[Position - 4] == '\r' && s.Session_key[Position - 3] == '\n' && s.Session_key[Position - 2] == '\r' && s.Session_key[Position - 1] == '\n'))
	{
		if ((res = recv(s.Socket, buffer, sizeof(buffer), 0)) > 0)
		{
			memcpy(&s.Session_key[Position], &buffer, res);
			Position += res;
		}
	}
	if (!(CryptImportKey(hProv, s.Session_key, Position - 4, s.hPrivKey, CRYPT_EXPORTABLE, &s.SessionKey)))
	{
		cout << GetLastError() << endl;
		cout << "Error Decrypt" << endl;
	}
	return 0;
}

int recv_message(destination& s)//получение сообщения 
{
	char buffer[2048] = { 0 };
	int Position = 0;
	int res;
	char message[2048] = { 0 };
	while (Position < 4 || !(message[Position - 4] == '\r' && message[Position - 3] == '\n' && message[Position - 2] == '\r' && message[Position - 1] == '\n'))
	{
		if ((res = recv(s.Socket, buffer, sizeof(buffer), 0)) > 0)
		{
			memcpy(&message[Position], &buffer, res);
			Position += res;
		}
	}
	DWORD count = Position - 4;
	if (!CryptDecrypt(s.SessionKey, NULL, TRUE, NULL, (BYTE*)message, &count))
	{
		cout << GetLastError() << endl;
		cout << "Error Decrypt" << endl;
	}
	cout << message << endl;
	return 0;
}
int menu()
{
	destination Server[100];
	char* ip = NULL; 
	int port;
	int s;
	int i = 0;
	init();
	ip = new char[15];
	struct sockaddr_in addr;
	do {
		int N;
		int number;
		cout << "1-Set connection " << endl;//установить связь новый пользователь
		cout << "2-Set request type" << endl;//тип запроса вывести версию ос
		cout << "3-Get current time" << endl;//текущее время
		cout << "4-Get time elapsed since OS startup" << endl;//Получите время, прошедшее с момента запуска ОС
		cout << "5-Get types of mapped drives" << endl;//Получить данные типы подключенных дисков
		cout << "6-Get free space on local drives" << endl;//Получите свободное место на локальных дисках
		cout << "7-Get permissions" << endl;//Получить разрешения на доступ к файла или ключ реестра
		cout << "8-Get owner of the file / folder / registry key" << endl;//Получить владельца файла / папки / ключа реестра
		cout << "9-Exit" << endl;//выход
		cout << "Choose command:";
		cin >> N;
		switch (N)
		{
		case 1:
			cin >> ip;
			cin >> port;
			Server[i].ip = new char[15];
			strcpy(Server[i].ip, ip);
			Server[i].port = port;
			Server[i].Socket = socket(AF_INET, SOCK_STREAM, 0);//IPv4,Потоковый сокет,протокол

			if (Server[i].Socket < 0)
				return sock_err("socket", Server[i].Socket);
			memset(&addr, 0, sizeof(addr));
			addr.sin_family = AF_INET;
			addr.sin_port = htons(Server[i].port);
			addr.sin_addr.s_addr = get_host_ipn(Server[i].ip);
			InitCrypto();
			if (con(Server[i].Socket, addr) != 0)	//если за 10 раз с задержкой в 100мс так и не подкл. к серверу - ошибка
			{
				deinit();
				fprintf(stdout, "connect");
				s_close(Server[i].Socket);
				Server[i].ip = NULL;
				Server[i].port = 0;
				return -1;
			}
			GeneratePublicKey(Server[i]);
			recv_response(Server[i]);
			s_close(Server[i].Socket);
			i++;
			break;
		case 2:
			cout << "Choose number_of_server(from 0 to " << i << "):";
			cin >> number;
			Server_con(Server[number]);
			send_request(Server[number], N);
			recv_message(Server[number]);
			s_close(Server[number].Socket);
			break;
		case 3:
			cout << "Choose number_of_server(from 0 to " << i << "):";
			cin >> number;
			Server_con(Server[number]);
			send_request(Server[number], N);
			recv_message(Server[number]);
			s_close(Server[number].Socket);
			break;
		case 4:
			cout << "Choose number_of_server(from 0 to " << i << "):";
			cin >> number;
			Server_con(Server[number]);
			send_request(Server[number], N);
			recv_message(Server[number]);
			s_close(Server[number].Socket);
			break;
		case 5:
			cout << "Choose number_of_server(from 0 to " << i << "):";
			cin >> number;
			Server_con(Server[number]);
			send_request(Server[number], N);
			recv_message(Server[number]);
			s_close(Server[number].Socket);
			break;
		case 6:
			cout << "Choose number_of_server(from 0 to " << i << "):";
			cin >> number;
			Server_con(Server[number]);
			send_request(Server[number], N);
			recv_message(Server[number]);
			s_close(Server[number].Socket);
			break;
		case 7:
			cout << "Choose number_of_server(from 0 to " << i << "):";
			cin >> number;
			Server_con(Server[number]);
			send_request(Server[number], N);
			recv_message(Server[number]);
			s_close(Server[number].Socket);
			break;
		case 8:
			cout << "Choose number_of_server(from 0 to " << i << "):";
			cin >> number;
			Server_con(Server[number]);
			send_request(Server[number], N);
			recv_message(Server[number]);
			s_close(Server[number].Socket);
			break;
		case 9:
			for (number = 0; number < i; number++)
			{
				Server_con(Server[number]);
				send_request(Server[number], N);
				s_close(Server[number].Socket);
				CryptDestroyKey(Server[number].hPrivKey);
				CryptDestroyKey(Server[number].hPubKey);
				CryptDestroyKey(Server[number].SessionKey);
				Server[number].SessionKey = 0;
				Server[number].hPrivKey = 0;
				Server[number].hPubKey = 0;
			}
			i = 0;
			if (!CryptAcquireContext(&hProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_DELETEKEYSET))
			{cout << "Error destroying keys" << endl;}
			break;
		default:
			break;
		}
	} while (1);
}
int main()
{
	setlocale(LC_ALL, "");
	string addr;
	menu();
	return 0;
}