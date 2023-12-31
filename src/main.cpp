#include "OS.h"
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>
using namespace std;
typedef std::vector<unsigned char> bytes;

OS os;

int main()
{
	//while(1)
	//{
	//	char get = _getch();
	//	//system("cls");
	//	cout << (int)get << endl;
	//}
	
	os.gate();

	system("pause");
    return 0;
}