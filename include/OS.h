#pragma once
#include <string>
#include <vector>

class OS
{
public:

	OS();

	struct bk
	{
		std::string lable;
		std::string data;
	};

	void gate();

	static std::string getoken(const std::string sign, const int mxw);

private:

	using Funpt = void (OS::*)();
	using OSfunpt = void (OS::*)(std::vector<bk>&);

	void Hub(int to);

	int _gate();

	int Hallway1();

	int Hallway2();

	int Hallway3();

	bool Securitycheck1();

	bool Securitycheck2();

	bool Securitycheck3();

	void showps(const int p);

	void Room(auto& dbase, OSfunpt open, OSfunpt save);

protected:

	bool op1, op2, op3;
	int wrtislim, datlenlim;
	std::string Fname0, Fname1, Fname2, Fname3;

	std::string SCpass1, SCpass2, SCpass3;
	std::vector<bk> dbase1, dbase2, dbase3;
	std::vector<unsigned char> lkey1, key1, lkey2, key2, key3, key4;

	void run(Funpt ptr);

	void run(OSfunpt ptr, auto& dbase);

	void _exit(int code);

	void filecheck();

	void readSCpass();

	void PasswordChange();

	std::string gethash(const auto& dbase, int type);

	bool showdb(auto& dbase);

	void opendb1(auto& dbase);

	void savedb1(auto& dbase);

	void opendb2(auto& dbase);

	void savedb2(auto& dbase);

	void opendb3(auto& dbase);

	void savedb3(auto& dbase);

};