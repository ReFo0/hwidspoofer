#include <iostream>
#include "driver/driver.h"
#include "utils/print/print.h"
#include "utils/xor.h"


SOCKET sock0;
auto spoof_computer() -> bool {
	driver::clean_cachetable(sock0);
	driver::clean_unloaddrivers(sock0);
	driver::spoof_computer(sock0);
	print::set_text(_xor_("kernel driver: spoof operation completed\n").c_str(), LightGreen);
	driver::disconnect(sock0);
	driver::deinit();
	return 1;
}





auto socket_setup() -> void
{
	driver::init();
	Sleep(3);
	sock0 = driver::connect();
	if (sock0 == socket_failed)
	{
		print::set_text(_xor_("user mode: driver failed to connect\n").c_str(), Red);
		std::cin.get();
	}
	else if (socket_connected)
	{
		print::set_text(_xor_("kernel driver: user connected\n").c_str(), LightGreen);
		Sleep(1000);
		system(_xor_("cls").c_str());
		spoof_computer();
	}
    
}

auto menu() -> int
{
	int choice;

	while (true)
	{
		system(_xor_("cls").c_str());




		while (true)
		{

			system(_xor_("cls").c_str());


			print::set_text(_xor_("[1] kernel mode spoof\n").c_str(), LightBlue);
			print::set_text(_xor_("[3] quit\n").c_str(), LightBlue);
			std::cin >> choice;

			switch (choice)
			{
	
			case 1:
			{
				socket_setup();
			}
			break;
			case 2:
			{
				exit(1);
			}
			break;
			}
		}
	}

	system(_xor_("Pause").c_str());
}

int main()
{
	SetConsoleTitle(_xor_("refo").c_str());
	menu();

}
