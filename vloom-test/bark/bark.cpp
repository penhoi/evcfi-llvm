/**
 * Test VLOOM-LLVM instrumentations
 * 1: register reserve;
 * 2: Exported envorionment variables
 */

#include <stdio.h>

class Base
{
public:
    virtual void bark_0(void) = 0;
    virtual void bark_1(long p1) = 0;
    virtual void bark_2(long p1, long p2) = 0;
    virtual void bark_3(long p1, long p2, long p3) = 0;
    virtual void bark_4(long p1, long p2, long p3, long p4) = 0;
    virtual void bark_5(long p1, long p2, long p3, long p4, long p5) = 0;
    virtual void bark_6(long p1, long p2, long p3, long p4, long p5, long p6) = 0;
    virtual void bark_7(long p1, long p2, long p3, long p4, long p5, long p6, long p7) = 0;
    virtual void bark_8(long p1, long p2, long p3, long p4, long p5, long p6, long p7, long p8) = 0;
};

class Subclass : public Base
{
public:
    virtual void bark_0(void)
    {
        printf("%s\n", __PRETTY_FUNCTION__);
    }
    virtual void bark_1(long p1)
    {
        printf("%s: %ld\n", __PRETTY_FUNCTION__, p1);
    }
    virtual void bark_2(long p1, long p2)
    {
        printf("%s: %ld, %ld\n", __PRETTY_FUNCTION__, p1, p2);
    }
    virtual void bark_3(long p1, long p2, long p3)
    {
        printf("%s: %ld, %ld, %ld\n", __PRETTY_FUNCTION__, p1, p2, p3);
    }
    virtual void bark_4(long p1, long p2, long p3, long p4)
    {
        printf("%s: %ld, %ld, %ld, %ld\n", __PRETTY_FUNCTION__, p1, p2, p3, p4);
    }
    virtual void bark_5(long p1, long p2, long p3, long p4, long p5)
    {
        printf("%s: %ld, %ld, %ld, %ld, %ld\n", __PRETTY_FUNCTION__, p1, p2, p3, p4, p5);
    }
    virtual void bark_6(long p1, long p2, long p3, long p4, long p5, long p6)
    {
        printf("%s: %ld, %ld, %ld, %ld, %ld, %ld\n", __PRETTY_FUNCTION__, p1, p2, p3, p4, p5, p6);
    }
    virtual void bark_7(long p1, long p2, long p3, long p4, long p5, long p6, long p7)
    {
        printf("%s: %ld, %ld, %ld, %ld, %ld, %ld, %ld\n", __PRETTY_FUNCTION__, p1, p2, p3, p4, p5, p6, p7);
    }
    virtual void bark_8(long p1, long p2, long p3, long p4, long p5, long p6, long p7, long p8)
    {
        printf("%s: %ld, %ld, %ld, %ld, %ld, %ld, %ld, %ld\n", __PRETTY_FUNCTION__, p1, p2, p3, p4, p5, p6, p7, p8);
    }
};

void InvokeMethods(Base *obj, long p1, long p2, long p3, long p4, long p5, long p6, long p7, long p8)
{
    obj->bark_0();
    obj->bark_1(p1);
    obj->bark_2(p1, p2);
    // #elif PARAM_NUM == 3
    obj->bark_3(p1, p2, p3);
    // #elif PARAM_NUM == 4
    obj->bark_4(p1, p2, p3, p4);
    // #elif PARAM_NUM == 5
    obj->bark_5(p1, p2, p3, p4, p5);
    // #elif PARAM_NUM == 6
    obj->bark_6(p1, p2, p3, p4, p5, p6);
    // #elif PARAM_NUM == 7
    obj->bark_7(p1, p2, p3, p4, p5, p6, p7);
    // #elif PARAM_NUM >= 8
    obj->bark_8(p1, p2, p3, p4, p5, p6, p7, p8);
}

int main(int argc, char **argv)
{
    long ps[8] = {0};
    Base *obj = new Subclass();
    InvokeMethods(obj, ps[0], ps[1], ps[2], ps[3], ps[4], ps[5], ps[6], ps[7]);
    return 0;
}
