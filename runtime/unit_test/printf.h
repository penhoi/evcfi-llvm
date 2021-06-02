/**
 * Some funtions specific for unit-testing
 */

#ifndef __UNITTEST_PRINTF_H__
#define __UNITTEST_PRINTF_H__

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define COLORIZE true

/*
 * Colorize a format string.
 */
static const char *
vloom_log_colorize(const char *format, char *buf, ssize_t size)
{
	size_t i, j;
	for (i = 0, j = 0; format[i] != '\0' && i < size - 2 && j < size - 2; i++)
	{
		if (format[i] != '%')
		{
			buf[j++] = format[i];
			continue;
		}
		const char *code;
		switch (format[i + 1])
		{
		case 'R':
			code = "31";
			break;
		case 'G':
			code = "32";
			break;
		case 'B':
			code = "34";
			break;
		case 'Y':
			code = "33";
			break;
		case 'M':
			code = "35";
			break;
		case 'C':
			code = "36";
			break;
		case 'D':
			code = "0";
			break;
			break;
		default:
			buf[j++] = format[i];
			continue;
		}
		i++;
		if (!COLORIZE)
			continue;
		if (j >= size - 10)
			break;
		buf[j++] = '\33';
		buf[j++] = '[';
		buf[j++] = code[0];
		if (code[1] != '\0')
			buf[j++] = code[1];
		buf[j++] = 'm';
	}
	buf[j++] = '\0';
	return buf;
}

/* Because some messages are cutomized with colour, so we need this version of printf to support them*/
static void utest_printf(const char *format, ...)
{
	va_list ap;
	va_start(ap, format);

	char buf[BUFSIZ];
	format = vloom_log_colorize(format, buf, sizeof(buf));
	vprintf(format, ap);
	puts("");

	va_end(ap);
}

#endif // __UNITTEST_PRINTF_H__