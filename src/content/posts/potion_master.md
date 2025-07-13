---
title: Potion Master - Writeup
slug: potion-master
published: 2022-12-16
author: kako57
description: Reversing a chunky Haskell program
---

## Challenge Details

This challenge is in the Hack the Box University CTF 2022.

We are not given a binary, but a source code written in Haskell

---

## Code

```hs
import Data.Char (ord)
import Data.Bits (xor)

-- Complete the incantation...
flag = "HTB{XXX}"

-- validates flag format and extracts the flag
extractFlag :: String -> String
extractFlag (s:rest)
  | s == 'H' ||  s == 'T' ||  s == 'B'
  = extractFlag rest
  | s == '{' && last rest == '}'
  = init rest
  | otherwise = error ("Invalid format")

-- creates a list of chunks of n elements from a list
chunks :: Int -> [a] -> [[a]]
chunks n l
  | n == 0 = []
  | n == 1 = [[x] | x <- l]
  | length l <= n = [l]
  | otherwise = [take n l] ++ (chunks n (drop n l))

-- takes the last n characters of an array
takeLast :: Int -> [a] -> [a]
takeLast n = reverse . take n . reverse

a = [-43, 61, 58, 5, -4, -11, 64, -40, -43, 61, 62, -51, 46, 15, -49, -44, 47, 4, 6, -7, 47, 7, -59, 52, -15, 11, 7, 61, 0]
b = [6, 106, 10, 0, 119, 52, 51, 101, 0, 0, 15, 48, 116, 22, 10, 58, 125, 100, 102, 33]
c = [304, 357, 303, 320, 304, 307, 349, 305, 257, 337, 340, 309, 428, 270, 66]
d = [52, 52, 95, 95, 110, 49, 51, 51, 95, 110, 110, 53]

checkFlag :: String -> Bool
checkFlag flag =
  length content == 58 &&
  all (==True) (map (\ (l,r) -> l == r) (zip one a)) &&
  all (==True) (map (\ (l,r) -> l == r) (zip two b)) &&
  all (==True) (map (\ (l,r) -> l == r) (zip three c)) &&
  all (==True) (map (\ (l,r) -> l == r) (zip four d))
  where content = map ord (extractFlag flag)
        one     = map (\ [l, r] -> (l - r)) (chunks 2 content)
        two     = map (foldr xor 0) (chunks 3 content)
        three     = map (foldr (+) 0) (chunks 4 content)
        four     = map head (chunks 5 content)

main = putStrLn (if (checkFlag flag)
    then "The spell went off without a hitch!"
    else "You disappear in a puff of smoke!"
  )
```

## Understanding the program

### `main`
In Haskell, `main` is a special function that is the entry point of the program.
It is the function that is executed when the program is run.
In this code, `main` is defined as a function that outputs a message
depending on the result of `checkFlag` applied to the `flag` string.
If `checkFlag` returns `True`, then `main` outputs
the string "The spell went off without a hitch!".
If checkFlag returns False, then `main`
outputs the string "You disappear in a puff of smoke!".

### `chunks`

`chunks` is a function that divides a list into
sublists of a specified length.
It returns a list of these sublists.
If the length of the original list is not a
multiple of the specified length,
the last sublist will contain the remaining elements.

### extractFlag

extractFlag is a function that takes the contents of the flag, following the flag format.

```
extractFlag "HTB{this_is_the_flag}"
```

would return

```
"this_is_the_flag
```

Side note: some strings are accepted by `extractFlag`, but are not necessarily in the correct format:

```
extractFlag "T{yet_another_flag}"
extractFlag "B{one_more_flag}"
```


### `checkFlag`

`checkFlag` is a function that takes a string as input and
returns a boolean value indicating whether the
input string satisfies certain conditions.
The function first extracts the contents of the `flag`
string using the `extractFlag` function and converts
each character in the extracted string to its
ASCII code using the `ord` function from the `Data.Char` module.
Then it defines four lists, `one`, `two`, `three`, and `four`,
using list comprehension and the helper function `chunks`.

The `one` list is created by applying the function `\ (l,r) -> l == r`
to a list of pairs obtained by dividing the content
list into pairs of two elements using `chunks 2`.
This function compares each pair of elements and
returns `True` if they are equal, `False` otherwise.

The `two` list is created by applying the function `foldr xor 0`
to a list of lists obtained by dividing the content
list into lists of three elements using `chunks 3`.
This function performs a bitwise exclusive-or operation
on each list of three elements and returns the result.

The `three` list is created in a similar way,
but using the function `foldr (+) 0` instead of `foldr xor 0`.
This function adds the elements of each list of four elements and returns the result.

Finally, the `four` list is created by applying the function `head`
to a list of lists obtained by dividing the content list into
lists of five elements using `chunks 5`.
This function returns the first element of each list.

The `checkFlag` function then checks that the length of content is 58
and that all elements in the lists `one`, `two`, `three`, and `four`
are equal to the corresponding elements in the
lists `a`, `b`, `c`, and `d` respectively.
If all these conditions are met, `checkFlag`
returns `True`, otherwise it returns `False`.

## Solution

Brute-forcing may be an efficient solution,
but you would need to consider some special cases.

My solution is to use Z3.

```py
#!/usr/bin/env python3

from z3 import *
import functools

def chunks(l, n):
    return [l[i:i+n] for i in range(0, len(l), n)]

def xor_chunk(e):
    return functools.reduce(lambda x,y: x^y, e)

# Create a solver
s = Solver()

# Create a list of 58 bitvectors of size 8
x = [BitVec('x%d' % i, 8) for i in range(58)]

one = list(map(lambda e: e[0] - e[1], chunks(x, 2)))
two = list(map(lambda e: xor_chunk(e), chunks(x, 3)))
three = list(map(sum, chunks(x, 4)))
four = list(map(lambda e: e[0], chunks(x, 5)))

a = [-43, 61, 58, 5, -4, -11, 64, -40, -43, 61, 62, -51, 46, 15, -49, -44, 47, 4, 6, -7, 47, 7, -59, 52, -15, 11, 7, 61, 0]
b = [6, 106, 10, 0, 119, 52, 51, 101, 0, 0, 15, 48, 116, 22, 10, 58, 125, 100, 102, 33]
c = [304, 357, 303, 320, 304, 307, 349, 305, 257, 337, 340, 309, 428, 270, 66]
d = [52, 52, 95, 95, 110, 49, 51, 51, 95, 110, 110, 53]

for i, j in zip(one, a):
    s.add(i == j)
for i, j in zip(two, b):
    s.add(i == j)
for i, j in zip(three, c):
    s.add(i == j)
for i, j in zip(four, d):
    s.add(i == j)

# make sure chars are printable
for i in x:
    s.add(i >= 32)
    s.add(i <= 126)

# Check if the constraints are satisfiable
if s.check() == sat:
    # Get the model
    m = s.model()
    # Print the value
    print('HTB{' + ''.join([chr(m[x[i]].as_long()) for i in range(58)]) + '}')
else:
    print('No solution found')
```
