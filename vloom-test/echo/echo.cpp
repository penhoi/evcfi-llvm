#include <stdio.h>
#include <stdlib.h>

class Vector {

public:
  virtual void echo() = 0;
};

class VM1 : public Vector {
  char *ID;

public:
  virtual void echo(void);
};

__attribute_noinline__ void VM1::echo(void) { printf("%s%d, ID=%p\n", __FUNCTION__, __LINE__, &ID); }

class VM2 : public Vector {
  char *ID;

public:
  virtual void echo(void);
};

__attribute_noinline__ void VM2::echo(void) { printf("%s%d, ID=%p\n", __FUNCTION__, __LINE__, &ID); }


int main(int argc, char **argv) {
  Vector *vm;

  vm = new VM1();
  vm->echo();

  vm = new VM2();
  vm->echo();

  return 0;
}
