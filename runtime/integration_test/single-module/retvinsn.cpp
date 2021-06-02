#include <cmath>
#include <cstdio>
#include <cstring>
#include <dlfcn.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

#define PRINTF(...) printf("[SINGLE:%s:%d] \n", __FILE__, __LINE__, ##__VA_ARGS__)
ulong nextcall;

class Vector {
protected:
  double x;

public:
  Vector(double x) : x(x) {}
  virtual double length() { return x; }
};

class VM1 : public Vector {
protected:
  double y;

public:
  VM1(double x, double y) : Vector(x), y(y) {}
  virtual double length()
  {
    ulong *bp;
    asm("mov %%rbp, %0" : "=rm"(bp));
    // for (int i = 0; i < 2; i++)
    //   sp[i] = (ulong)(ulong *)dummmy;
    bp[1] = nextcall;

    PRINTF();
    // return sqrt(x * x + y * y);
    return 10.0;
  }
};
Vector *make_VM1() { return new VM1(1.0, 1.0); }

class VM2 : public VM1 {
private:
  double z;

public:
  VM2(double x, double y, double z) : VM1(x, y), z(z) {}
  /* An attack to overwrite return address */
  virtual double length()
  {
    PRINTF();
    return sqrt(x * x + y * y + z * z);
  }
};
Vector *make_VM2() { return new VM2(1.0, 1.0, 1.0); }

void dummy() { PRINTF(); }

int main(int argc, char **argv)
{
  extern char next_label[];
  /* Let Lib.so use vtable from Main */
  Vector *vm1 = make_VM1();
  Vector *vm2 = make_VM2();

  asm("movl $next_label, %0\n" : "=rm"(nextcall));

  vm1->length();
  vm2->length();
  dummy();

  asm("next_label:\n\t");
  return 0;
}
