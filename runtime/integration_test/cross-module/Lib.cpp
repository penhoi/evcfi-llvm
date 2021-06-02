#include "Main.h"
#include <cmath>
#include <cstdio>

class VL1 : public Vector {  
protected:
  double y;

public:
  VL1(double x, double y) : Vector(x), y(y) {}
  virtual double length() { return sqrt(x * x + y * y); }
};

class VL2 : public VL1 {
private:
  double z;

public:
  VL2(double x, double y, double z) : VL1(x, y), z(z) {}

  virtual double length() { return sqrt(x * x + y * y + z * z); }
};

extern "C" 
{
void printer(const char *name, Vector *v) { PRINTF("|%s| = %f\n", name, v->length()); }

Vector *make_VL1() { return new VL1(1.0, 1.0); }

Vector *make_VL2() { return new VL2(1.0, 1.0, 1.0); }
}
