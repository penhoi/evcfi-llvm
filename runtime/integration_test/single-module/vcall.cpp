#include <cmath>
#include <cstdio>
#include <cstring>
#include <dlfcn.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

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
  virtual double length() { return sqrt(x * x + y * y); }
};

class VM2 : public VM1 {
private:
  double z;

public:
  VM2(double x, double y, double z) : VM1(x, y), z(z) {}
  virtual double length() { return sqrt(x * x + y * y + z * z); }
};

class Fake {
private:
  double x;

public:
  Fake(double x) : x(x) {}
  virtual double length() { return x; }
};

Vector *make_VM1() { return new VM1(1.0, 1.0); }
Vector *make_VM2() { return new VM2(1.0, 1.0, 1.0); }

#define PRINTF(fmt, ...) printf("[SINGLE:%s:%d] \t-> " fmt, __FILE__, __LINE__, ##__VA_ARGS__)
void printer(const char *name, Vector *v) { PRINTF("|%s| = %f\n", name, v->length()); }

int main(int argc, char **argv)
{
  /* Let Lib.so use vtable from Main */
  Vector *vm1 = make_VM1();
  Vector *vm2 = make_VM2();
  printer("VM1", vm1);
  printer("VM2", vm1);

  /* Type confusion attack! */
  Fake *f = new Fake(777.0);
  printer("type confusion attack: f", (Vector *)f);

  return 0;
}
