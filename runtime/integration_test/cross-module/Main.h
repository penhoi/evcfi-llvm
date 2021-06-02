#ifndef __MAIN_H
#define __MAIN_H

class Vector {
protected:
  double x;

public:
  Vector(double x) : x(x) {}
  virtual double length() { return x; }
};

#include <stdio.h>
#define PRINTF(fmt, ...) printf("[MULTIPLE:%s:%d] \t-> " fmt, __FILE__, __LINE__, ##__VA_ARGS__)

#endif
