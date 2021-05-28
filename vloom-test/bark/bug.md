## Bypass bug

VLOOM-LLVM has a bug, such that it fail to emit ``__VLOOM_SANITIZE_xxx'' symbols. As a result, there are compiling errors like ``undefined reference to `__VLOOM_SANITIZE__ZTV4Base'''.

We use conditional macros in source code to avoid this problem. Consistently, a shell script name "run_test.sh", which defines conditions, is used to drive the compilation.
