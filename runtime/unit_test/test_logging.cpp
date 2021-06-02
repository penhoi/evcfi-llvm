#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <map>

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

#undef VLOOM_UTEST
#include "../config.h"
#include "../logging.h"

TEST_GROUP(test_Logging){

};

void do_logging(const char *msg[], int loglevel, const char *prompt)
{
    for (const char **p = msg; *p != NULL; p++)
    {
        VLOOM_LOG(loglevel, "%s", *p);
    }

    /* log to delme.log */
    const char *logfile = "del.log";
    EnvConfig *config = new EnvConfig();

    // config->szLogFile = strdup(logfile); nasty thing happends
    config->szLogFile = utils_strdup(logfile);
    config->nLogLevel = loglevel;

    vloom_LogInit(config);

    for (const char **p = msg; *p != NULL; p++)
    {
        VLOOM_LOG(loglevel, "%s", *p);
    }
    vloom_LogFini();

    /* read in del.log for checking */
    FILE *flog = fopen(logfile, "r");
    CHECK_TRUE(flog != NULL);

    size_t size = BUFSIZ;
    char *buf = (char *)malloc(size);
    int res, cnt, i;
    for (i = 0; (cnt = getline(&buf, &size, flog)) != -1; i++)
    {
        char *p = buf + strlen(prompt);
        buf[cnt - 1] = '\0';
        res = strcmp(p, msg[i]);
        CHECK_EQUAL(0, res);
    }
    CHECK_TRUE(msg[i] == NULL);
    free(buf);

    /* remove the delme.log  */
    // unlink(logfile);
    delete config;
}

TEST(test_Logging, LogFuncs)
{
    /* log to stdout */
    const char *msg[] = {
        "This is the first line",
        "This is the second line",
        "This is the third line",
        NULL,
    };

    do_logging(msg, VLL_TRACE, "VLOOM TRACE: ");
    do_logging(msg, VLL_INFO, "VLOOM INFO: ");
}

int main(int ac, char **av)
{
    return CommandLineTestRunner::RunAllTests(ac, av);
}