#include <map>

#include "../vloom.h"
#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

TEST_GROUP(test_vloom){};

TEST(test_vloom, workflow)
{
    vloom_vcfi_init();

    vloom_vcfi_fini();
}

int main(int ac, char **av)
{
    return CommandLineTestRunner::RunAllTests(ac, av);
}