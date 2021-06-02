#include "Main.h"
#include <cmath>
#include <cstdio>
#include <cstring>
#include <dlfcn.h>
#include <signal.h>
#include <unistd.h>

typedef void (*Printer)(const char *, Vector *);
typedef Vector *(*Maker)();

class VM1 : public Vector {
protected:
  double y;

public:
  VM1(double x, double y) : Vector(x), y(y) {}
  virtual double length() { return sqrt(x * x + y * y); }
};

class VM2 : public VM1 {
private:
  double z;

public:
  VM2(double x, double y, double z) : VM1(x, y), z(z) {}
  virtual double length() { return sqrt(x * x + y * y + z * z); }
};

Vector *make_VM1() { return new VM1(1.0, 1.0); }
Vector *make_VM2() { return new VM2(1.0, 1.0, 1.0); }

class Fake {
private:
  double x;

public:
  Fake(double x) : x(x) {}
  virtual double length() { return x; }
};

int main(int argc, char **argv)
{
  void *handle = dlopen("./libVector.so", RTLD_LAZY);
  if (handle == NULL) {
    fprintf(stderr, "failed to load library \"libVector.so\"\n");
    return 1;
  }

  Printer printer = (Printer)dlsym(handle, "printer");
  if (printer == NULL) {
    fprintf(stderr, "failed to find function \"printer\"\n");
    return 1;
  }
  Maker make_VL1 = (Maker)dlsym(handle, "make_VL1");
  if (make_VL1 == NULL) {
    fprintf(stderr, "failed to find function \"make_VL1\"\n");
    return 1;
  }
  Maker make_VL2 = (Maker)dlsym(handle, "make_VL2");
  if (make_VL2 == NULL) {
    fprintf(stderr, "failed to find function \"make_VL2\"\n");
    return 1;
  }

  /* Let Lib.so use vtable from Main */
  Vector *vm1 = make_VM1();
  Vector *vm2 = make_VM2();

  printer("VM1", vm1);
  printer("VM2", vm2);

  /* Let Main use vtable from Lib.so */
  Vector *u = make_VL1();
  Vector *w = make_VL2();

  PRINTF("|VL1| = %f\n", u->length());
  PRINTF("|VL2| = %f\n", w->length());

  /* Type confusion Attacks! */
  Fake *f = new Fake(777.0);
  printer("type confusion attack: f", (Vector *)f);

  return 0;
}
