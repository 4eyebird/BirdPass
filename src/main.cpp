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
	os.gate();
	system("pause");
    return 0;
}