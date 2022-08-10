#include <iostream>
#include "driver/driver.h"
#include "utils/print/print.h"
#include "utils/xor.h"


SOCKET sock0;
void spoof_computer() {
	driver::clean_cachetable(sock0);
	driver::clean_unloaddrivers(sock0);
	driver::spoof_computer(sock0);
	print::set_text(_xor_("kernel driver: spoof operation completed\n").c_str(), LightGreen);
	Sleep(1200);
	driver::disconnect(sock0);
	driver::deinit();
}





void socket_setup();

void socket_retry() {
	system(_xor_("cls").c_str());
	socket_setup();
}
void socket_setup()
{
	driver::init();
	Sleep(3);
	sock0 = driver::connect();
	if (sock0 == socket_failed)
	{
		print::set_text(_xor_("user mode: driver failed to connect\n").c_str(), Red);
		socket_retry();
	}
	else if (socket_connected)
	{
		print::set_text(_xor_("kernel driver: user connected\n").c_str(), LightGreen);
		Sleep(2000);
		system(_xor_("cls").c_str());
		spoof_computer();
	
	}
    
}

int menus()
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

	menus();

}
