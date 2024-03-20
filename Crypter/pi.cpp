#include "pi.h"
#include <stdlib.h>
#include <stdio.h>

void spigot() { //https://craftofcoding.wordpress.com/tag/spigot-algorithm/
   int i, j, k, q, x;
   int len, nines=0, predigit=0;
   int N=20000; //you can actually go way up but it makes the calculation slow
 
   len = (10*N/3)+1;
   int* a = (int *)malloc(len * sizeof(int));
   if (a == 0) {
       printf("Error allocating memory.\n");
       return;
   }
 
   // Initialize A to (2,2,2,2,2,...,2)
   for (i=0; i<len; i=i+1)
      a[i] = 2;
 
   // Repeat n times
   for (j=1; j<=N; j=j+1) {
      q = 0;
      for (i=len; i>0; i=i-1) {
         x = 10 * a[i-1] + q*i;
         a[i-1] = x % (2*i-1);
         q = x / (2*i-1);
      }
      a[0] = q % 10;
      q = q / 10;
      if (q == 9)
         nines = nines + 1;
      else if (q == 10) {
         printf("%d", predigit+1);
         for (k=0; k<nines; k=k+1)
            printf("%d",0);
         predigit = 0;
         nines = 0;
      }
      else {
         printf("%d", predigit);
         predigit = q;
         if (nines != 0) {
            for (k=0; k<nines; k=k+1)
               printf("%d",9);
            nines = 0;
         }
     }
  }
  printf("%d\n", predigit);

  free(a);
}