#pragma once
#include <windows.h>
#include <cstdio>

enum console_color
{
	Black = 0,
	Blue,
	Green,
	Cyan,
	Red,
	Magenta,
	Brown,
	LightGray,
	DarkGray,
	LightBlue,
	LightGreen,
	LightCyan,
	LightRed,
	LightMagenta,
	Yellow,
	White,
};
class print
{
public:
	static void set_color(const int forg_col);
	static void set_text(const char* text, const int color);
	static void set_error(const char* text);
	static void set_warning(const char* text);
	static void set_ok(const char* text);
};
