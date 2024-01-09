#include "AES.h"
#include "Deco.h"
#include "OS.h"
#include "sm4.h"
#include <algorithm>
#include <conio.h>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
using namespace std;
typedef std::vector<unsigned char> bytes;

//public:
OS::OS()
{
	//seting
	wrtislim = 3;
	datlenlim = 25;
	op1 = op2 = op3 = 0;
	Fname0 = "data/pass";
	Fname1 = "data/data1";
	Fname2 = "data/data2";
	Fname3 = "data/data3";
	filecheck();
	readSCpass();
}

void OS::gate()
{
	Hub(1);

	savedb1(dbase1);
	savedb2(dbase2);
	savedb3(dbase3);

	system("cls");
	cout << "Bye!\n";
}

//private:
using Funpt = void (OS::*)();
using OSfunpt = void (OS::*)(vector<OS::bk>&);

string OS::getoken(const string sign, const int mxw)
{
	cout << sign;
	string token;
	while(1)
	{
		char get = _getch();
		if(get == '\r' || get == '\0')
			break;
		if(get == 8)
		{
			if(!token.empty())
				token.pop_back();
			system("cls");
			cout << sign;
			int len = (int)token.size();
			while(len--)cout << '*';
			continue;
		}
		if(token.length() < mxw)
		{
			cout << '*';
			token.push_back(get);
		}
	}
	system("cls");
	return token;
}

void OS::Hub(int to)
{
	while(1)
	{
		if(to == 0)
			break;
		else if(to == 1)
			to = _gate();
		else if(to == 2)
			to = Hallway1();
		else if(to == 4)
			to = Hallway2();
		else if(to == 6)
			to = Hallway3();
	}
}

int OS::_gate()
{
	showps(1);

	int to = 1;
	while(1)
	{
		char get = _getch() - '0';
		if(get == 0)return 0;
		if(get == 2)
		{
			to = get;
			break;
		}
		else
			cout << "Access Denied!\n";
	}
	system("cls");
	if(to == 2)
	{
		if(Securitycheck1())
			return 2;
	}
	return 0;
}

int OS::Hallway1()
{
	showps(2);

	int to = 1;
	while(1)
	{
		char get = _getch() - '0';
		if(get == 0)return 0;
		if(get == 1 || get == 3 || get == 4)
		{
			to = get;
			break;
		}
		else
			cout << "Access Denied!\n";
	}
	system("cls");
	if(to == 1)
		return 1;
	else if(to == 3)
	{
		Room(dbase1, &OS::opendb1, &OS::savedb1);
		return 2;
	}
	else if(to == 4)
	{
		if(Securitycheck2())
			return 4;
		system("pause");
		system("cls");
	}
	return 1;
}

int OS::Hallway2()
{
	showps(4);

	int to = 1;
	while(1)
	{
		char get = _getch() - '0';
		if(get == 0)return 0;
		if(get == 1 || get == 2 || get == 5 || get == 6)
		{
			to = get;
			break;
		}
		else
			cout << "Access Denied!\n";
	}
	system("cls");
	if(to == 1)
		return 1;
	else if(to == 2)
		return 2;
	else if(to == 5)
	{
		Room(dbase2, &OS::opendb2, &OS::savedb2);
		return 4;
	}
	else if(to == 6)
	{
		if(Securitycheck3())
			return 6;
		system("pause");
		system("cls");
	}
	return 1;
}

int OS::Hallway3()
{
	showps(6);

	int to = 1;
	while(1)
	{
		char get = _getch() - '0';
		if(get == 0)return 0;
		if(get == 1 || get == 2 || get == 4 || get == 7)
		{
			to = get;
			break;
		}
		else if(get == -45)
		{
			system("cls");
			PasswordChange();
			return 1;
		}
		else
			cout << "Access Denied!\n";
	}
	system("cls");
	if(to == 1)
		return 1;
	else if(to == 2)
		return 2;
	else if(to == 4)
		return 4;
	else if(to == 7)
	{
		Room(dbase3, &OS::opendb3, &OS::savedb3);
		return 6;
	}
	return 1;
}

bool OS::Securitycheck1()
{
	using namespace Deco;
	int wtimes = 0;
	bool pass = 0, pass1 = 0;
	string note = "password:";
	string token, tkb, ki, salt = "BPS";
	token = getoken(note, datlenlim) + salt;
	note = "wrong password!\nTry again:";
	while(1)
	{
		if(pass1)
		{
			if(token == salt)
			{
				lkey1 = sha256(byte_hex(lkey1) + ki);
				pass = 1;
				break;
			}
			else
				pass1 = 0;
		}
		tkb = byte_hex(sha512(token));
		key1 = sha256(token);
		ki.resize(0);
		for(int i = 0; i < 3; i++)
		{
			if(token.size() > i)
				ki += token[i];
			else
				ki += '0' + i;
		}
		token.resize(0);
		if(tkb == SCpass1)pass1 = 1;
		if(++wtimes >= wrtislim)
		{
			cout << "Access Denied!\n";
			pass = 0;
			break;
		}
		token = getoken(note, datlenlim) + salt;
	}
	return pass;
}

bool OS::Securitycheck2()
{
	using namespace Deco;
	int wtimes = 0;
	bool pass = 0;
	string note = "password2:";
	string token, tkb, salt;
	for(int i = 0; i < 5; i++)
		salt.push_back(key1[i] % 128);
	token = getoken(note, datlenlim) + salt;
	note = "wrong password!\nTry again:";
	while(1)
	{
		cout << "Verifying password...\n";
		tkb = byte_hex(sha512WF(token, 100, 100));
		key2 = sha256(token);
		token.resize(0);
		system("cls");
		if(tkb == SCpass2)
		{
			lkey2 = sha256(byte_hex(lkey1) + byte_hex(key1));
			sm4 Sm4;
			Sm4.setType(sm4::CBC);
			Sm4.setKey(md5(byte_hex(key2)));
			Sm4.setIv(md5(byte_hex(lkey2)));
			SCpass3 = Sm4.decrypt(hex_byte(SCpass3.c_str(), SCpass3.length()));
			pass = 1;
			break;
		}
		if(++wtimes >= wrtislim)
		{
			cout << "Access Denied!\n";
			pass = 0;
			break;
		}
		token = getoken(note, datlenlim) + salt;
	}
	return pass;
}

bool OS::Securitycheck3()
{
	using namespace Deco;
	string token1, token2;

	string note = "password3:";
	token1 = getoken(note, 30);

	note = "password4:";
	token2 = getoken(note, 30);

	cout << "Verifying password...\n";
	string token = token1 + token2;
	string Hash = byte_hex(sha512WF(token, 1000, 30));
	if(Hash == SCpass3)
	{
		key4 = sha256(byte_hex(sha512WF(token1, 5, 3)));
		key3 = sha512WF(token2, 50, 300);
		system("cls");
		return 1;
	}
	system("cls");
	cout << "Access Denied!\n";
	return 0;
}

void OS::showps(const int p)
{
	cout << "Now you're in ";

	string s1 = "|0 - exit | 3 - R1 | 5 - R2 | 7 - R3 |\n";
	string s2 = "|1 - gate | 2 - H1 | 4 - H2 | 6 - H3 |\n";

	if(p == 1)
	{
		cout << "gate\n\n";
		s2 = "|* - gate | 2 - H1 | 4 - H2 | 6 - H3 |\n";
	}
	else if(p == 2)
	{
		cout << "H1\n\n";
		s2 = "|1 - gate | * - H1 | 4 - H2 | 6 - H3 |\n";
	}
	else if(p == 3)
	{
		cout << "R1\n\n";
		s1 = "|0 - exit | * - R1 | 5 - R2 | 7 - R3 |\n";
	}
	else if(p == 4)
	{
		cout << "H2\n\n";
		s2 = "|1 - gate | 2 - H1 | * - H2 | 6 - H3 |\n";
	}
	else if(p == 5)
	{
		cout << "R2\n\n";
		s1 = "|0 - exit | 3 - R1 | * - R2 | 7 - R3 |\n";
	}
	else if(p == 6)
	{
		cout << "H3\n\n";
		s2 = "|1 - gate | 2 - H1 | 4 - H2 | * - H3 |\n";
	}
	else if(p == 7)
	{
		cout << "R3\n\n";
		s1 = "|0 - exit | 3 - R1 | 5 - R2 | * - R3 |\n";
	}

	cout << s1 << s2;
	cout << "\nWhere do you want to go ?\n";
}

void OS::Room(auto& dbase, OSfunpt open, OSfunpt save)
{
	run(open, dbase);
	while(1)
	{
		int ctd = (int)dbase.size();
		cout << ctd << " data streams are loaded\n";
		cout << "Press\n'a' to add, 'd' to del, 'm' to mod\n'q' to query, 's' to sort, 'b' to back.\n";
		while(1)
		{
			char get = _getch();
			if(get == 19)
			{
				run(save, dbase);
				run(open, dbase);
				continue;
			}
			if(get == 'A' || get == 'a')
			{
				system("cls");
				string x, y;
				string t1 = "enter label:";
				string t2 = "enter data:";
				cout << t1;
				cin >> x;
				system("cls");
				y = getoken(t1 + x + '\n' + t2, datlenlim);
				if(x.length() <= datlenlim)
				{
					dbase.push_back({ x, y });
					ctd++;
				}
				break;
			}
			else if(get == 'D' || get == 'd')
			{
				system("cls");
				if(showdb(dbase))
				{
					system("pause");
					break;
				}
				int qn;
				cout << "enter number:";
				cin >> qn;
				if(qn >= 1 && qn <= ctd)
				{
					auto pt = dbase.begin();
					for(int i = 1; i < qn; i++)pt++;
					dbase.erase(pt);
					ctd--;
				}
				break;
			}
			else if(get == 'M' || get == 'm')
			{
				system("cls");
				if(showdb(dbase))
				{
					system("pause");
					break;
				}
				int qn;
				cout << "enter number:";
				cin >> qn;
				system("cls");
				if(qn >= 1 && qn <= ctd)
				{
					system("cls");
					string x, y;
					string t1 = "enter label:";
					string t2 = "enter data:";
					cout << t1;
					cin >> x;
					system("cls");
					y = getoken(t1 + x + '\n' + t2, datlenlim);
					if(x.length() <= datlenlim)
					{
						auto pt = dbase.begin();
						for(int i = 1; i < qn; i++)pt++;
						(*pt).lable = x, (*pt).data = y;
					}
				}
				break;
			}
			else if(get == 'Q' || get == 'q')
			{
				system("cls");
				if(showdb(dbase))
				{
					system("pause");
					break;
				}
				int qn;
				cout << "enter number:";
				cin >> qn;
				system("cls");
				if(qn >= 1 && qn <= ctd)
				{
					cout << "No." << qn << "\n";
					cout << "lable:" << dbase[qn - 1].lable << "\n";
					cout << " data:" << dbase[qn - 1].data << "\n";
					system("pause");
				}
				break;
			}
			else if(get == 'S' || get == 's')
			{
				system("cls");
				system("cls");
				if(showdb(dbase))
				{
					system("pause");
					break;
				}
				cout << "enter number:";
				int ctvn = 0;
				vector<int>nq;
				while(ctvn < ctd)
				{
					int x;
					cin >> x;
					if(x >= 1 && x <= ctd && find(nq.begin(), nq.end(), x) == nq.end())
					{
						ctvn++;
						nq.push_back(x);
					}
				}
				vector<bk> New;
				for(auto& i : nq)
				{
					New.push_back(dbase[i - 1]);
				}
				dbase = New;
				break;
			}
			else if(get == 'B' || get == 'b')
			{
				system("cls");
				run(save, dbase);
				return;
			}
		}
		system("cls");
	}
	run(save, dbase);
}

//protected:
void OS::run(Funpt ptr)
{
	(this->*ptr)();
}

void OS::run(OSfunpt ptr, auto& dbase)
{
	(this->*ptr)(dbase);
}

void OS::_exit(int code)
{
	system("cls");

	switch(code)
	{
	case 1:
		cout << "Error 1: Data file not found\n";
		break;
	case 2:
		cout << "Error 2: Data file is corrupted\n";
		break;
	default:
		cout << "Unexpected error encountered\n";
		break;
	}

	system("pause");
	exit(code);
}

void OS::filecheck()
{
	string folderName = "data";

	if(!filesystem::exists(folderName))
		filesystem::create_directory(folderName);

	fstream file;

	file.open(Fname1);
	if(!file.is_open())
		file.open(Fname1, ios::out);
	file.close();

	file.open(Fname2);
	if(!file.is_open())
		file.open(Fname2, ios::out);
	file.close();

	file.open(Fname3);
	if(!file.is_open())
		file.open(Fname3, ios::out);
	file.close();

	file.open(Fname0);
	if(!file.is_open())
	{
		file.open(Fname0, ios::out);
		file << "8c50a7a2fbfac67d74188c23b80716a9154eb8566b250f8a55da8608fe36373807ff27a41bf7dc4f322d2d8d77871a4704a912060c7656681050f868d486cb31\n";
		file << "1d488a627c2c8246bb70465e4a49790012db4196da5e2e4d9a803d3e35806ea6e3ebfb97237d667bb8bc2e8d396934c45e67144d8950b7dd9adca9ea7898794a\n";
		file << "aa86e21f613575425a12b57b22f88184ae7b9bdeeb9546ad79b0cdc2f78bcac11c581fb9c816dee70a521fc98d6e9cd34910701c42f469ac8867b59a97fef57e83dea93a7b02e8b4def66dc0c1ff41839d1c244926a5fd3769d56029181c3ad4409601a8d79f02acf2b7212f76a373bafccc3cdd2c8680e221fdbe3e0506c7357045ce2a65c685dab8472bd4c42c5cca\n";
		file << "MD5: ba11ddd605088dcfe9d4908b5e711484";
	}
	file.close();
}

void OS::readSCpass()
{
	fstream ps(Fname0);
	if(ps.is_open())
	{
		using namespace Deco;
		ps >> SCpass1;
		ps >> SCpass2;
		ps >> SCpass3;
		string Hash;
		ps >> Hash;
		ps >> Hash;
		ps.close();
		string pass = SCpass1 + SCpass2 + SCpass3;
		lkey1 = sha256("Stay hungry Stay foolish");
		string Hash2 = byte_hex(md5(byte_hex(sha256(pass))));
		if(Hash != Hash2)
			_exit(2);
	}
	else
		_exit(1);
}

void OS::PasswordChange()
{
	using namespace Deco;
	if(lkey1.empty() || key1.empty() || lkey2.empty()
	        || key2.empty() || key3.empty() || key4.empty())
		return;

	string nkey1 = getoken("New password1:", datlenlim);
	string nkey2 = getoken("New password2:", datlenlim);
	string nkey4 = getoken("New password3:", 30);
	string nkey3 = getoken("New password4:", 30);

	cout << "wait a minute...\n";

	opendb1(dbase1);
	opendb2(dbase2);
	opendb3(dbase3);

	string Hash1, Hash2, Hash3, Hash4;

	string salt = "BPS";
	string token = nkey1 + salt;
	Hash1 = byte_hex(sha512(token));
	salt.resize(0);
	for(int i = 0; i < 3; i++)
	{
		if(token.size() > i)
			salt += token[i];
		else
			salt += '0' + i;
	}
	lkey1 = sha256("Stay hungry Stay foolish");
	lkey1 = sha256(byte_hex(lkey1) + salt);
	key1 = sha256(token);

	salt.resize(0);
	token.resize(0);

	for(int i = 0; i < 5; i++)
		salt.push_back(key1[i] % 128);
	token = nkey2 + salt;
	Hash2 = byte_hex(sha512WF(token, 100, 100));
	lkey2 = sha256(byte_hex(lkey1) + byte_hex(key1));
	key2 = sha256(token);

	salt.resize(0);
	token.resize(0);

	token = nkey4 + nkey3;
	string H3 = byte_hex(sha512WF(token, 1000, 30));
	sm4 Sm4;
	Sm4.setType(sm4::CBC);
	Sm4.setKey(md5(byte_hex(key2)));
	Sm4.setIv(md5(byte_hex(lkey2)));
	Hash3 = byte_hex(Sm4.encrypt(H3));
	key3 = sha512WF(nkey3, 50, 300);
	key4 = sha256(byte_hex(sha512WF(nkey4, 5, 3)));

	string H4 = Hash1 + Hash2 + Hash3;
	Hash4 = byte_hex(md5(byte_hex(sha256(H4))));

	savedb1(dbase1);
	savedb2(dbase2);
	savedb3(dbase3);

	ofstream file(Fname0);
	if(!file.is_open())_exit(1);
	file << Hash1;
	file << '\n';
	file << Hash2;
	file << '\n';
	file << Hash3;
	file << "\nMD5: ";
	file << Hash4;
	file.close();

	lkey1.clear(), key1.clear();
	lkey2.clear(), key2.clear();
	key3.clear(), key4.clear();

	readSCpass();

	system("cls");
	cout << "Password has been successfully changed!\n";
	system("pause");
	system("cls");
}

string OS::gethash(const auto& dbase, int type)
{
	using namespace Deco;
	string data;
	for(auto& i : dbase)
	{
		data += i.lable;
		data += i.data;
	}
	string ret;
	if(type == 0)
		ret = byte_hex(md5(data));
	else if(type == 1)
		ret = byte_hex(md5(byte_hex(md5(byte_hex(md5(data))))));
	else if(type == 2)
		ret = byte_hex(md5(byte_hex(sha512WF(data, 10, 100))));
	else if(type == 3)
		ret = byte_hex(sha256(data));
	else if(type == 4)
		ret = byte_hex(sha512(data));
	else if(type == 5)
		ret = byte_hex(sha256(byte_hex(sha512WF(data, 5, 3))));
	else if(type == 6)
		ret = byte_hex(sha512WF(data, 10, 100));
	else if(type == 7)
		ret = byte_hex(sha512WF(data, 1000, 100));
	return ret;
}

bool OS::showdb(auto& dbase)
{
	if(dbase.empty())
	{
		cout << "NULL!\n";
		return 1;
	}
	int cti = 1;
	for(auto& i : dbase)
	{
		int fb = 10 - (int)strlen(i.lable.c_str());
		cout << "| " << cti << " - ";
		int fb1 = fb / 2, fb2 = fb - fb1;
		for(int j = 0; j < fb1; j++)cout << ' ';
		cout << i.lable;
		for(int j = 0; j < fb2; j++)cout << ' ';
		if(cti++ % 3 == 0)cout << "|\n";
	}
	if(cti % 3 != 1)cout << "|\n";
	return 0;
}

void OS::opendb1(auto& dbase)
{
	dbase.clear();
	using namespace Deco;
	ifstream file(Fname1);
	if(!file.is_open())_exit(1);
	unsigned char outext[32];
	bytes rkey = key1;
	while(!file.eof())
	{
		string x, y;
		file >> x >> y;
		if(x.empty() || y.empty())
			continue;
		if(x == "Hash:")
		{
			if(y == gethash(dbase, 1))
				break;
			else
				_exit(2);
		}

		bytes inbytes = hex_byte(x.c_str(), x.length());
		AES::ecb_decrypt(inbytes.data(), lkey1.data(), (int)lkey1.size() * 8, outext, inbytes.size());
		x.resize(0);
		for(int i = 0; i < 32; i++)
		{
			if(outext[i] == '\0')
				break;
			x += outext[i];
		}

		inbytes = hex_byte(y.c_str(), y.length());
		AES::ecb_decrypt(inbytes.data(), key1.data(), (int)key1.size() * 8, outext, inbytes.size());
		y.resize(0);
		for(int i = 0; i < 32; i++)
		{
			if(outext[i] == '\0')
				break;
			y += outext[i];
		}

		key1 = sha256(y);

		x.pop_back();
		y.pop_back();
		dbase.push_back({ x, y });
	}
	file.close();
	key1 = rkey;
	op1 = 1;
}

void OS::savedb1(auto& dbase)
{
	if(!op1)return;
	string Hash = gethash(dbase, 1);
	using namespace Deco;
	ofstream file(Fname1);
	if(!file.is_open())_exit(1);
	unsigned char outext[32];
	int ctd = (int)dbase.size();
	if(!ctd)
	{
		file.close();
		op1 = 0;
		return;
	}

	for(int i = 0; i < ctd; i++)
	{
		int salt = i % 26;
		dbase[i].lable.push_back('a' + 26 - salt);
		dbase[i].data.push_back('a' + salt);
	}

	for(int i = ctd - 1; i >= 0; i--)
	{
		string x = dbase[i].lable, y = dbase[i].data;

		int pti = 0;
		char instr[32];
		memset(instr, 0, sizeof(instr));
		for(auto& j : x)
			instr[pti++] = j;
		AES::ecb_encrypt((unsigned char*)instr, lkey1.data(), (int)lkey1.size() * 8, outext, sizeof(instr));
		x = byte_hex(outext, sizeof(outext));

		pti = 0;
		memset(instr, 0, sizeof(instr));
		for(auto& j : y)
			instr[pti++] = j;
		bytes key = i == 0 ? key1 : sha256(dbase[i - 1].data);
		AES::ecb_encrypt((unsigned char*)instr, key.data(), (int)key.size() * 8, outext, sizeof(instr));
		y = byte_hex(outext, sizeof(outext));

		dbase[i].lable = x, dbase[i].data = y;
	}

	for(auto& i : dbase)
	{
		file << i.lable << ' ' << i.data << '\n';
	}

	file << "Hash: " << Hash;

	dbase.clear();
	file.close();
	op1 = 0;
}

void OS::opendb2(auto& dbase)
{
	dbase.clear();
	using namespace Deco;
	ifstream file(Fname2);
	if(!file.is_open())_exit(1);
	unsigned char outext[32];
	bytes iv = sha512(byte_hex(lkey2) + byte_hex(key2));
	for(int i = 1; i <= 5; i++)
		iv = md5(byte_hex(iv));
	while(!file.eof())
	{
		string x, y;
		file >> x >> y;
		if(x.empty() || y.empty())
			continue;
		if(x == "Hash:")
		{
			if(y == gethash(dbase, 5))
				break;
			else
				_exit(2);
		}

		bytes ivv = iv;
		bytes inbytes = hex_byte(x.c_str(), x.length());
		AES::cbc_decrypt(inbytes.data(), lkey2.data(), ivv.data(), (int)lkey2.size() * 8, outext, inbytes.size());
		x.resize(0);
		for(int i = 0; i < 32; i++)
		{
			if(outext[i] == '\0')
				break;
			x += outext[i];
		}

		ivv = iv;
		bytes key = key2;
		inbytes = hex_byte(y.c_str(), y.length());
		AES::cbc_decrypt(inbytes.data(), key.data(), ivv.data(), (int)key.size() * 8, outext, inbytes.size());
		y.resize(0);
		for(int i = 0; i < 32; i++)
		{
			if(outext[i] == '\0')
				break;
			y += outext[i];
		}

		iv = sha512(byte_hex(iv) + y);
		for(int i = 1; i <= 10; i++)
			iv = md5(byte_hex(iv));

		x.pop_back();
		y.pop_back();
		y.pop_back();
		y.pop_back();
		dbase.push_back({ x, y });
	}
	file.close();
	op2 = 1;
}

void OS::savedb2(auto& dbase)
{
	if(!op2)return;
	string Hash = gethash(dbase, 5);
	using namespace Deco;
	ofstream file(Fname2);
	if(!file.is_open())_exit(1);
	unsigned char outext[32];
	int ctd = (int)dbase.size();
	if(!ctd)
	{
		file.close();
		op2 = 0;
		return;
	}

	for(int i = 0; i < ctd; i++)
	{
		int salt = i % 26;
		dbase[i].lable.push_back('a' + salt);
		string lable = byte_hex(sha512(dbase[i].lable));
		for(int j = 0; j < 3; j++)
			dbase[i].data.push_back(lable[j]);
	}

	bytes iv = sha512(byte_hex(lkey2) + byte_hex(key2));
	for(int i = 1; i <= 5; i++)
		iv = md5(byte_hex(iv));

	for(int i = 0; i < ctd; i++)
	{
		string x = dbase[i].lable, y = dbase[i].data;

		int pti = 0;
		char instr[32];
		memset(instr, 0, sizeof(instr));
		for(auto& j : x)
			instr[pti++] = j;
		bytes ivv = iv;
		AES::cbc_encrypt((unsigned char*)instr, lkey2.data(), ivv.data(), (int)lkey2.size() * 8, outext, sizeof(instr));
		x = byte_hex(outext, sizeof(outext));

		pti = 0;
		ivv = iv;
		memset(instr, 0, sizeof(instr));
		for(auto& j : y)
			instr[pti++] = j;
		bytes key = key2;
		AES::cbc_encrypt((unsigned char*)instr, key.data(), ivv.data(), (int)key.size() * 8, outext, sizeof(instr));
		y = byte_hex(outext, sizeof(outext));

		iv = sha512(byte_hex(iv) + dbase[i].data);
		for(int i = 1; i <= 10; i++)
			iv = md5(byte_hex(iv));

		file << x << ' ' << y << '\n';
	}

	file << "Hash: " << Hash;

	dbase.clear();
	file.close();
	op2 = 0;
}

void OS::opendb3(auto& dbase)
{
	dbase.clear();
	using namespace Deco;
	ifstream file(Fname3);
	if(!file.is_open())_exit(1);
	unsigned char outext[64];

	sm4 Sm4;
	Sm4.setType(sm4::CBC);

	string Hash2;
	bytes nkey3 = key3, nkey4 = key4;
	string token0 = byte_hex(key3) + byte_hex(key4);
	string token1 = byte_hex(sha512WF(token0, 4, 3));
	string token2 = byte_hex(sha256(byte_hex(sha512WF(token1, 3, 4))));

	while(!file.eof())
	{
		string x;
		file >> x;
		if(x.empty())
			continue;
		if(x == "Hash1:")
		{
			if(!file.eof())
			{
				file >> x;
				if(x == gethash(dbase, 2))
				{
					if(!file.eof())
					{
						file >> x;
						if(!file.eof())
						{
							file >> x;
							if(x == Hash2)
								break;
						}
					}
				}
			}
			_exit(2);
		}

		Hash2 += x;
		Hash2 = byte_hex(sha512(Hash2));

		bytes a_iv, a_key;
		bytes b_iv, b_key;
		size_t len = nkey3.size();
		for(size_t i = 0; i < len - 1; i += 2)
		{
			a_iv.push_back(nkey3[i]);
			a_key.push_back(nkey3[i + 1]);
		}
		len = nkey4.size();
		for(size_t i = 0; i < len - 1; i += 2)
		{
			b_iv.push_back(nkey4[i]);
			b_key.push_back(nkey4[i + 1]);
		}

		Sm4.setIv(b_iv);
		Sm4.setKey(b_key);
		bytes inbytes = hex_byte(x.c_str(), x.length());
		int sx = (inbytes[0] % 30) + 2;
		int sy = (inbytes[1] % 30) + 2;
		string y = Sm4.decrypt(inbytes);
		inbytes = hex_byte(y.c_str(), y.length());
		AES::cbc_decrypt(inbytes.data(), a_key.data(), a_iv.data(), (int)a_key.size() * 8, outext, inbytes.size());

		int sts = 0;
		x.resize(0), y.resize(0);
		for(int i = 0; i < 64; i++)
		{
			if(outext[i] == '\0')
			{
				if(sts == 0)
					sts = 1;
				else
					break;
			}
			else
			{
				if(sts == 0)
					x.push_back(outext[i]);
				else
					y.push_back(outext[i]);
			}
		}

		dbase.push_back({ x, y });

		token1 += x;
		token2 += y;
		nkey3 = sha512WF(token1, sx, sy);
		nkey4 = sha256(byte_hex(sha512WF(token2, sy, sx)));
		token1 = byte_hex(nkey3);
		token2 = byte_hex(nkey4);

	}
	file.close();
	op3 = 1;
}

void OS::savedb3(auto& dbase)
{
	if(!op3)return;
	string Hash1 = gethash(dbase, 2);
	using namespace Deco;
	ofstream file(Fname3);
	if(!file.is_open())_exit(1);
	unsigned char outext[64];
	int ctd = (int)dbase.size();
	if(!ctd)
	{
		file.close();
		op3 = 0;
		return;
	}

	sm4 Sm4;
	Sm4.setType(sm4::CBC);

	bytes nkey3 = key3;
	bytes nkey4 = key4;

	string Hash2;
	string token0 = byte_hex(key3) + byte_hex(key4);
	string token1 = byte_hex(sha512WF(token0, 4, 3));
	string token2 = byte_hex(sha256(byte_hex(sha512WF(token1, 3, 4))));

	char instr[64];
	for(int i = 0; i < ctd; i++)
	{
		token1 += dbase[i].lable;
		token2 += dbase[i].data;

		dbase[i].lable += '\0';
		dbase[i].lable += dbase[i].data;

		int pti = 0;
		string x = dbase[i].lable;
		memset(instr, 0, sizeof(instr));
		memset(outext, 0, sizeof(outext));
		for(auto& j : x)
			instr[pti++] = j;

		bytes a_key, a_iv;
		size_t len = nkey3.size();
		for(size_t i = 0; i < len - 1; i += 2)
		{
			a_iv.push_back(nkey3[i]);
			a_key.push_back(nkey3[i + 1]);
		}

		bytes b_key, b_iv;
		len = nkey4.size();
		for(size_t i = 0; i < len - 1; i += 2)
		{
			b_iv.push_back(nkey4[i]);
			b_key.push_back(nkey4[i + 1]);
		}

		AES::cbc_encrypt((unsigned char*)instr, a_key.data(), a_iv.data(), (int)a_key.size() * 8, outext, sizeof(instr));
		string y = byte_hex(outext, sizeof(outext));

		Sm4.setIv(b_iv);
		Sm4.setKey(b_key);
		bytes data = Sm4.encrypt(y);
		dbase[i].data = byte_hex(data);
		file << dbase[i].data << '\n';

		Hash2 += dbase[i].data;
		Hash2 = byte_hex(sha512(Hash2));

		int sx = (data[0] % 30) + 2;
		int sy = (data[1] % 30) + 2;
		nkey3 = sha512WF(token1, sx, sy);
		nkey4 = sha256(byte_hex(sha512WF(token2, sy, sx)));
		token1 = byte_hex(nkey3);
		token2 = byte_hex(nkey4);

	}

	file << "Hash1: " << Hash1;
	file << '\n';
	file << "Hash2: " << Hash2;

	dbase.clear();
	file.close();
	op3 = 0;
}