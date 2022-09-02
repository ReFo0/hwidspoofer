#include <windows.h>
#include "print.h"

void print::set_color(const int forg_col)
{
	const auto h_std_out = GetStdHandle(STD_OUTPUT_HANDLE);
	CONSOLE_SCREEN_BUFFER_INFO csbi;
	if (GetConsoleScreenBufferInfo(h_std_out, &csbi))
	{
		const WORD w_color = (csbi.wAttributes & 0xF0) + (forg_col & 0x0F);
		SetConsoleTextAttribute(h_std_out, w_color);
	}
}

void print::set_text(const char* text, const int color)
{
	set_color(color);
	printf(static_cast<const char*>(text));
	set_color(White);
}

void print::set_error(const char* text)
{
	set_color(Red);
	printf(static_cast<const char*>(text));
	set_color(White);
}

void print::set_warning(const char* text)
{
	set_color(Yellow);
	printf(static_cast<const char*>(text));
	set_color(White);
}

void print::set_ok(const char* text)
{
	set_color(Green);
	printf(static_cast<const char*>(text));
	set_color(White);
}