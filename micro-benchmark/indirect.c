#include <stdio.h>
#include <stdlib.h>

int foo(const char* argv[]) {
  printf("Hello! we are in foo\n");
  return argv[1][0];
}

int bar(const char* argv[]) {
  printf("Hello! we are in bar\n");
  return argv[2][0];
}

int baz(const char* argv[]) {
  printf("Hello! we are in baz\n");
  return argv[3][0];
}

int main(int argc, const char* argv[])
{
  int a;
  switch (argc) {
    case 1:
      a = foo(argv);
      break;
    case 2:
      a = bar(argv);
      break;
    case 5:
      a = foo(argv);
      break;
    case 10:
      a = bar(argv);
      break;
    case 42:
      a = foo(argv);
      break;
   default:
      a = baz(argv);
      break;
  }
  printf("a = %d\n", a);
  return 0;
}

