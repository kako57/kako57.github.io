---
title: S01den's cube - Writeup
slug: s01den-cube
published: 2022-08-29
author: kako57
description: Reversing a 2x2 Rubik's cube implementation
---

## Challenge Details

Challenge Author: S01den

Language: C/C++\
Platform: Unix/linux etc.\
Architecture: x86-64

Difficulty: 4.3\
Quality: 4.0

**Description**

Find a correct flag!\
This one might be pretty fun.\
Good luck!

[Link to the challenge](https://crackmes.one/crackme/62d08a7a33c5d44a934e97bb)

---

## Initial Exploration

After downloading and inflating the zip, I found the challenge binary named `cm_rb_easy`.
I checked for any interesting pieces of text using `strings`, and got this output:

```txt
$ strings cm_rb_easy
...
[!] Usage: ./cmRubiks flag
[!] The flag is too long...
[!] Bad flag!
[*] G00d flag!
;*3$"
  oobvbbjBrorvjBvrjBrvjBobGCC: (GNU) 12.1.0
...
```

\
The string that shows how to use the program gives the hint that the challenge has
something to do with Rubik's cubes.\
There is also a string that may be printed when the given input to the program is too long.

## Decompiling the Binary

The program basically has a 2x2 Rubik's cube that is scrambled,
and we need to give it an algorithm (a sequence of rotations) that will solve it.

I loaded the binary in IDA. I decompiled the binary and tried to make a ~~readable~~ and compilable C program from it.

```c
#include <stdio.h>
#include <string.h>

char cube[24] = "oobvbbjBrorvjBvrjBrvjBob";

//----- (0000000000001169) ----------------------------------------------------
// At first I thought it was just shuffling chars, but it actually rotates the stickers of a face clockwise.
void rotate_face(char face[4])
{
  char v2; // [rsp+16h] [rbp-Ah]
  char v3; // [rsp+16h] [rbp-Ah]
  char v4; // [rsp+17h] [rbp-9h]

  v2 = *face;
  v4 = face[1];
  *face = face[2];
  face[1] = v2;
  v3 = face[3];
  face[3] = v4;
  face[2] = v3;
}

//----- (00000000000011FC) ----------------------------------------------------
// This function is actually not used by main, but it hints what rotate_face does.
void rotate_face_three_times(char a1[4])
{
  rotate_face(a1);
  rotate_face(a1);
  rotate_face(a1);
}

//----- (000000000000122F) ----------------------------------------------------
int main(int argc, char **argv, char **envp)
{
  int i; // [rsp+1Ch] [rbp-94h]
  int jj; // [rsp+20h] [rbp-90h]
  int m; // [rsp+20h] [rbp-90h]
  int ii; // [rsp+20h] [rbp-90h]
  int n; // [rsp+20h] [rbp-90h]
  int j; // [rsp+20h] [rbp-90h]
  int k; // [rsp+20h] [rbp-90h]
  int v11; // [rsp+24h] [rbp-8Ch]
  int mm; // [rsp+24h] [rbp-8Ch]
  int i1; // [rsp+24h] [rbp-8Ch]
  int i3; // [rsp+24h] [rbp-8Ch]
  int i5; // [rsp+24h] [rbp-8Ch]
  int i7; // [rsp+24h] [rbp-8Ch]
  int kk; // [rsp+28h] [rbp-88h]
  int nn; // [rsp+28h] [rbp-88h]
  int i2; // [rsp+28h] [rbp-88h]
  int i4; // [rsp+28h] [rbp-88h]
  int i6; // [rsp+28h] [rbp-88h]
  int i8; // [rsp+28h] [rbp-88h]
  char v23; // [rsp+2Eh] [rbp-82h]
  char v24; // [rsp+2Eh] [rbp-82h]
  char v25; // [rsp+2Eh] [rbp-82h]
  char v26; // [rsp+2Eh] [rbp-82h]
  char v27; // [rsp+2Eh] [rbp-82h]
  char v28; // [rsp+2Eh] [rbp-82h]
  char v29; // [rsp+2Eh] [rbp-82h]
  char v30; // [rsp+2Eh] [rbp-82h]
  char v31; // [rsp+2Eh] [rbp-82h]
  char v32; // [rsp+2Eh] [rbp-82h]
  char v33; // [rsp+2Eh] [rbp-82h]
  char v34; // [rsp+2Eh] [rbp-82h]
  char v35; // [rsp+2Fh] [rbp-81h]
  char v36; // [rsp+2Fh] [rbp-81h]
  char v37; // [rsp+2Fh] [rbp-81h]
  char v38; // [rsp+2Fh] [rbp-81h]
  char v39; // [rsp+2Fh] [rbp-81h]
  char v40; // [rsp+2Fh] [rbp-81h]
  char v41; // [rsp+2Fh] [rbp-81h]
  char v42; // [rsp+2Fh] [rbp-81h]
  char v43; // [rsp+2Fh] [rbp-81h]
  char v44; // [rsp+2Fh] [rbp-81h]
  char v45; // [rsp+2Fh] [rbp-81h]
  char v46; // [rsp+2Fh] [rbp-81h]
  char flag[104]; // [rsp+30h] [rbp-80h] BYREF

  if ( argc > 1 )
  {
    // Check if flag length is at most 100 chars
    if ( strlen(argv[1]) <= 99 )
    {
      strcpy(flag, argv[1]);
      // iterate over flag chars
      for ( i = 0; i < strlen(flag); ++i )
      {
        // check for specific char values.
        switch ( flag[i] )
        {
          // The first six cases are for clockwise rotations
          case 'B':
            // permute the stickers adjacent to the face,
            // then rotate the stickers of the face
            v31 = cube[0];
            v43 = cube[1];
            cube[1] = cube[23];
            cube[0] = cube[21];
            cube[21] = cube[15];
            cube[23] = cube[14];
            cube[15] = cube[18];
            cube[14] = cube[16];
            cube[18] = v31;
            cube[16] = v43;
            rotate_face(&cube[4]);
            break;
          case 'D':
            v33 = cube[10];
            v45 = cube[11];
            cube[10] = cube[18];
            cube[11] = cube[19];
            cube[18] = cube[6];
            cube[19] = cube[7];
            cube[7] = cube[23];
            cube[6] = cube[22];
            cube[23] = v45;
            cube[22] = v33;
            rotate_face(&cube[12]);
            break;
          case 'F':
            v25 = cube[2];
            v37 = cube[3];
            cube[3] = cube[17];
            cube[2] = cube[19];
            cube[17] = cube[12];
            cube[19] = cube[13];
            cube[12] = cube[22];
            cube[13] = cube[20];
            cube[22] = v37;
            cube[20] = v25;
            rotate_face(&cube[8]);
            break;
          case 'L':
            v29 = cube[8];
            v41 = cube[10];
            cube[8] = cube[0];
            cube[10] = cube[2];
            cube[0] = cube[7];
            cube[2] = cube[5];
            cube[7] = cube[12];
            cube[5] = cube[14];
            cube[12] = v29;
            cube[14] = v41;
            rotate_face(&cube[16]);
            break;
          case 'R':
            v27 = cube[1];
            v39 = cube[3];
            cube[3] = cube[11];
            cube[1] = cube[9];
            cube[9] = cube[13];
            cube[11] = cube[15];
            cube[15] = cube[4];
            cube[13] = cube[6];
            cube[6] = v27;
            cube[4] = v39;
            rotate_face(&cube[20]);
            break;
          case 'U':
            v23 = cube[8];
            v35 = cube[9];
            cube[8] = cube[20];
            cube[9] = cube[21];
            cube[20] = cube[4];
            cube[21] = cube[5];
            cube[4] = cube[16];
            cube[5] = cube[17];
            cube[17] = v35;
            cube[16] = v23;
            rotate_face(cube);
            break;
          // The following cases are lowercase counterparts of the first six cases
          // and they correspond to the counter-clockwise rotations.
          case 'b':
            // They do the same clockwise rotation, but 3 times,
            // so the result is a counter-clockwise rotation. ("BBB" == "b")
            for ( j = 0; j <= 2; ++j )
            {
              v32 = cube[0];
              v44 = cube[1];
              cube[1] = cube[23];
              cube[0] = cube[21];
              cube[21] = cube[15];
              cube[23] = cube[14];
              cube[15] = cube[18];
              cube[14] = cube[16];
              cube[18] = v32;
              cube[16] = v44;
              rotate_face(&cube[4]);
            }
            break;
          case 'd':
            for ( k = 0; k <= 2; ++k )
            {
              v34 = cube[10];
              v46 = cube[11];
              cube[10] = cube[18];
              cube[11] = cube[19];
              cube[18] = cube[6];
              cube[19] = cube[7];
              cube[7] = cube[23];
              cube[6] = cube[22];
              cube[23] = v46;
              cube[22] = v34;
              rotate_face(&cube[12]);
            }
            break;
          case 'f':
            for ( m = 0; m <= 2; ++m )
            {
              v26 = cube[2];
              v38 = cube[3];
              cube[3] = cube[17];
              cube[2] = cube[19];
              cube[17] = cube[12];
              cube[19] = cube[13];
              cube[12] = cube[22];
              cube[13] = cube[20];
              cube[22] = v38;
              cube[20] = v26;
              rotate_face(&cube[8]);
            }
            break;
          case 'l':
            for ( n = 0; n <= 2; ++n )
            {
              v30 = cube[8];
              v42 = cube[10];
              cube[8] = cube[0];
              cube[10] = cube[2];
              cube[0] = cube[7];
              cube[2] = cube[5];
              cube[7] = cube[12];
              cube[5] = cube[14];
              cube[12] = v30;
              cube[14] = v42;
              rotate_face(&cube[16]);
            }
            break;
          case 'r':
            for ( ii = 0; ii <= 2; ++ii )
            {
              v28 = cube[1];
              v40 = cube[3];
              cube[3] = cube[11];
              cube[1] = cube[9];
              cube[9] = cube[13];
              cube[11] = cube[15];
              cube[15] = cube[4];
              cube[13] = cube[6];
              cube[6] = v28;
              cube[4] = v40;
              rotate_face(&cube[20]);
            }
            break;
          case 'u':
            for ( jj = 0; jj <= 2; ++jj )
            {
              v24 = cube[8];
              v36 = cube[9];
              cube[8] = cube[20];
              cube[9] = cube[21];
              cube[20] = cube[4];
              cube[21] = cube[5];
              cube[4] = cube[16];
              cube[5] = cube[17];
              cube[17] = v36;
              cube[16] = v24;
              rotate_face(cube);
            }
            break;
          default:
            continue;
        }
      }
      // Check if the cube is solved.
      // Every face is four bytes, so the program checks if all four contains the same byte value for every face.
      v11 = 0;
LABEL_45:
      if ( v11 <= 1 )
      {
        for ( kk = 0; ; ++kk )
        {
          if ( kk > 1 )
          {
            ++v11;
            goto LABEL_45;
          }
          if ( cube[8] != cube[2 * v11 + 8 + kk] )
            break;
        }
LABEL_78:
        puts("[!] Bad flag!");
        return 0LL;
      }
      else
      {
        for ( mm = 0; mm <= 1; ++mm )
        {
          for ( nn = 0; nn <= 1; ++nn )
          {
            if ( cube[0] != cube[2 * mm + nn] )
              goto LABEL_78;
          }
        }
        for ( i1 = 0; i1 <= 1; ++i1 )
        {
          for ( i2 = 0; i2 <= 1; ++i2 )
          {
            if ( cube[4] != cube[2 * i1 + 4 + i2] )
              goto LABEL_78;
          }
        }
        for ( i3 = 0; i3 <= 1; ++i3 )
        {
          for ( i4 = 0; i4 <= 1; ++i4 )
          {
            if ( cube[12] != cube[2 * i3 + 12 + i4] )
              goto LABEL_78;
          }
        }
        for ( i5 = 0; i5 <= 1; ++i5 )
        {
          for ( i6 = 0; i6 <= 1; ++i6 )
          {
            if ( cube[16] != cube[2 * i5 + 16 + i6] )
              goto LABEL_78;
          }
        }
        for ( i7 = 0; i7 <= 1; ++i7 )
        {
          for ( i8 = 0; i8 <= 1; ++i8 )
          {
            if ( cube[20] != cube[2 * i7 + 20 + i8] )
              goto LABEL_78;
          }
        }
        puts("[*] G00d flag!");
        return 0;
      }
    }
    else
    {
      puts("[!] The flag is too long...");
      return 0;
    }
  }
  else
  {
    puts("[!] Usage: ./cmRubiks flag");
    return 0;
  }
}
```

## Strategies and Ideas

Before we go to actually solving the problem, here are some useful information:

- For any scramble of a 2x2 Rubik's cube, the most efficient solution would be at most 14 quarter turns.
  This is known as the **God's number** for the 2x2 Rubik's cube.
- There exist cube solvers online for 2x2 that have precomputed solutions, as there are about 3674160 comibinations only that need to be exhausted.

\
I thought of two ways of solving the cube.

One way is a brute force solution where I try every possible algorithm until I find a solution.
Since we were given the recognized characters, we can try all the possible character sequences
without having to figure out how the array representation of the cube maps to a
more intuitive cube model. This might take way too long, though (because 12 ^ 14 is very big).

The other one is to recreate the model of the cube.
In this method, I had to do the following:

1. Figure out which group of indices represent which face.
2. Figure out the actual mapping of index to location in cube using the permutation of adjacent stickers in rotations as a reference.
3. Map the indices in a flattened cube representation.
4. Assign each byte value in the array to a color in the flattened cube.
5. Feed the representation in an online cube solver.
6. Convert the solution given as the flag.

## Reversing the Cube Implementation

My goal is that by step 3, I get a flattened cube representation that looks like this:

```
       -----
      | U U |
      | U U |
 ----- ----- ----- -----
| L L | F F | R R | B B |
| L L | F F | R R | B B |
 ----- ----- ----- -----
      | D D |
      | D D |
       -----
```

Above, every sticker is represented by a char that shows which face it belongs to.\
After several minutes of working from step 1 to step 3, I have the indices filled:

```
         -------
        |  0  1 |
        |  2  3 |
 ------- ------- ------- -------
| 16 17 |  8  9 | 20 21 |  4  5 |
| 18 19 | 10 11 | 22 23 |  6  7 |
 ------- ------- ------- -------
        | 12 13 |
        | 14 15 |
         -------
```

Then I replaced each index with their given byte values

```
       -----
      | o o |
      | b v |
 ----- ----- ----- -----
| j B | r o | j B | b b |
| r v | r v | o b | j B |
 ----- ----- ----- -----
      | j B |
      | v r |
       -----
```

I went to an [online cube solver](https://rubiks-cube-solver.com/2x2/) and I edited the cube with the byte values converted to colors. I clicked Solve and it gave me the solution instantly.

![Cube Solution](/images/s01den-cube-solution.jpg "Cube Solution")

The solution given by the online solver is not understood by the program,
so we have to convert it first.
R2 just means an R rotation but twice (a half-turn)
and the primes (the apostrophes) indicate
counter-clockwise rotation, so we change F' to f, and U' to u.

Applying those changes, the solution becomes `URRfRUfu`.

```txt
$ ./cm_rb_easy URRfRUfu
[*] G00d flag!
```

## Brute-force Solution

I wanted to see how long will the brute-force approach take to find a solution.

For this, I reused the decompiled code, and tweaked it
so the cube implementation can give a good response
on whether the input flag is a valid solution.
The brute-force approach uses depth-first search to find a solution.

```c
const char flag_chars[12] = "FRUDBLfrudbl";
char flag[15] = ""; // limit the flag to allow 14 quarter turns only

int dfs(int depth) {
  // check_solution is a tweaked version of the decompiled program's main function
  // it returns 1 when the flag is a solution, and 0 otherwise
  if (check_solution(flag))
    return 1;
  for (int i = 0; i < 12; i++) {
    flag[depth] = flag_chars[i];
    if (depth < 14 && dfs(depth + 1))
        return 1;
    flag[depth] = '\0';
  }
  return 0;
}

int main() {
  dfs(0);
  printf("Flag: %s\n", flag);
}
```

NOTE: I did not put the implementation for `check_solution` here;
define it on your own as an exercise. It shouldn't be that hard, anyway.

\
The brute-force approach found a solution very quickly.

```txt
$ ./solve
Flag: FFFFFFFRFURfRf
```

\
This solution works, but notice that the 7 F turns can be reduced to an f,
because FFFF is the same as no rotation at all, and FFF is the same as f.

And now we reduced the algorithm to eight quarter turns: `fRFURfRf`.

```txt
$ ./cm_rb_easy fRFURfRf
[*] G00d flag!
```
