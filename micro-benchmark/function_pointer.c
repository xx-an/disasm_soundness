#include<stdio.h> 
#include<stdlib.h> 
#include<math.h> 
  
void* pick_function (int i) {
  switch (i) {
     case 0: return sin;
     case 1: return cos;
     case 2: return tan;
     default: return cos;
  }
} 

int main(int argc) 
{ 
    double x = acos(-1);
    printf("%+f\n", x);
    x = ((double (*) (double)) pick_function(argc))(x);
    printf("%+f\n", x);

   return 0; 
} 
