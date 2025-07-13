---
title: PlaidCTF 2025 - rev/prospectin' - Writeup
slug: plaid-2025-prospectin
published: 2025-04-20
tags: [rev, genetic algorithm, CTF]
category: CTF writeups
description: Bred flags to solve a reverse engineering challenge
---

## Introduction

Hello, I'm 「」, and I played PlaidCTF 2025 with team \[:\]. I will share to you the details on our solve on Prospectin', a two-part reverse engineering challenge.

## About the binaries

For the two challenges, we were given two binaries: *prospectors_claim* and *the_motherlode*. These are Linux ELF dynamically linked binaries built for aarch64.

## I came in late and part one got solved using AI

Turns out that they have solved the first half, and got the flag for *prospectors_claim*. The solution was with using Claude, a large language model. Claude seems to have done to solution itself, and simply wrote checks to show that the solution is indeed what it found.

Below is the code portion of the Claude output sent by ViperX7:

```javascript
// Let's analyze the code structure more carefully
// We need to understand the memory layout
// and what the local variables represent

// The code uses fgets to read input into &local_55,
// with a size of 0x41 (65 bytes)
// This means local_55 down to local_16 form our input string

// Let's continue mapping the constraints:
const values = {
  "local_16": 0x7d,      // '}'
  "local_17": 0x30,      // '0'
  "local_18": 0x30,      // '0'
  "local_19": 0x32,      // '2'
  "local_1a": 0x36,      // '6'
  "local_1b": 0x39,      // '9'
  "local_1c": 0x63,      // 'c'
  "local_1d": 0x61,      // 'a'
  "local_1e": 0x35,      // '5'
  "local_1f": 0x63,      // 'c'
  "local_20": 0x30,      // '0'
  "local_21": 0x30,      // '0'
  "local_22": 0x32,      // '2'
  "local_23": 0x31,      // '1'
  "local_24": 0x61,      // 'a'
  "local_25": 0x35,      // '5'
  "local_26": 0x65,      // 'e'
  "local_27": 0x32,      // '2'
  "local_28": 0x37,      // '7'
  "local_29": 0x64,      // 'd'
  "local_2a": 0x65,      // 'e'
  "local_2b": 0x39,      // '9'
  "local_2c": 0x33,      // '3'
  "local_2d": 0x62,      // 'b'
  "local_2e": 0x34,      // '4'
  "local_2f": 0x32,      // '2'
  "local_30": 0x33,      // '3'
  "local_31": 0x32,      // '2'
  "local_32": 0x65,      // 'e'
  "local_33": 0x61,      // 'a'
  "local_34": 0x32,      // '2'
  "local_35": 0x64,      // 'd'
  "local_36": 0x34,      // '4'
  "local_37": 0x33,      // '3'
  "local_38": 0x35,      // '5'
  "local_39": 0x35,      // '5'
  "local_3a": 0x32,      // '2'
  "local_3b": 0x31,      // '1'
  "local_3c": 0x62,      // 'b'
  "local_3d": 0x32,      // '2'
  "local_3e": 0x38,      // '8'
  "local_3f": 0x61,      // 'a'
  "local_40": 0x64,      // 'd'
  "local_41": 0x61,      // 'a'
  "local_42": 0x36,      // '6'
  "local_43": 0x64,      // 'd'
  "local_44": 0x39,      // '9'
  "local_45": 0x33,      // '3'
  "local_46": 0x37,      // '7'
  "local_47": 0x36,      // '6'
  "local_48": 0x64,      // 'd'
  "local_49": 0x36,      // '6'
  "local_4a": 0x32,      // '2'
  "local_4b": 0x31,      // '1'
  "local_4c": 0x36,      // '6'
  "local_4d": 0x31,      // '1'
  "local_4e": 0x64,      // 'd'
  "local_4f": 0x34,      // '4'
  "local_50": 0x32,      // '2'
  "local_51": 0x7b,      // '{'
  "local_52": 0x46,      // 'F'
  "local_53": 0x54,      // 'T'
  "local_54": 0x43,      // 'C'
  "local_55": 0x50,      // 'P'
};

// Now let's check the additional constraints to confirm our values:
// For example: if ((local_36 ^ local_3d) == 0xaa)
console.log(`local_36 ^ local_3d = ${values["local_36"] ^ values["local_3d"]} (should be 0xaa)`);

// if (local_36 + local_27 == -0x70)
// But we need to handle the two's complement arithmetic correctly
// -0x70 in 8-bit two's complement is 0x90
console.log(`local_36 + local_27 = ${(values["local_36"] + values["local_27"]) & 0xff} (should be ${(-0x70) & 0xff})`);

// Let's also check the equality constraints:
// if (local_39 == local_25) { bump(&score); }
console.log(`local_39 == local_25: ${values["local_39"] === values["local_25"]} (should be true)`);

// if (local_23 == local_4b) { bump(&score); }
console.log(`local_23 == local_4b: ${values["local_23"] === values["local_4b"]} (should be true)`);

// if (local_4c == local_42) { bump(&score); }
console.log(`local_4c == local_42: ${values["local_4c"] === values["local_42"]} (should be true)`);

// if (local_35 == local_48) { bump(&score); }
console.log(`local_35 == local_48: ${values["local_35"] === values["local_48"]} (should be true)`);

// if (local_27 == local_2f) { bump(&score); }
console.log(`local_27 == local_2f: ${values["local_27"] === values["local_2f"]} (should be true)`);

// Now let's build the flag from our values
// Since the memory is laid out in reverse (from local_55 down to local_16),
// we need to reverse the order to get the correct flag
let flag = '';
for (let i = 0x55; i >= 0x16; i--) {
  const key = `local_${i.toString(16)}`;
  if (values[key] !== undefined) {
    flag += String.fromCharCode(values[key]);
  }
}

console.log("Reconstructed flag:", flag);
```

For this writeup, the only thing helpful from this solution is that I made a hard read that the second binary, *the_motherlode*, will have the same flag format and charset as that of *prospectors_claim*. This helps a lot in optimizing my solution later on.

The hard read: flag format for these challenges is `PCTF{[0-9a-f]+}`

	Flag: `PCTF{24d16126d6739d6ada82b125534d2ae2324b39ed72e5a1200c5ac96200}`

## Static analysis

I mainly have amd64 machines, except for my MacBook Pro - which I didn't want to open during the CTF, so I would need to run the binary with QEMU, which is fine, but if I can tap into the program logic without needing QEMU, that would be so comfortable for my debugger and for my machines. That is why while my team was already working on some z3 optimization stuff (I came in late, remember?), I'm looking at the possibility of decompiling the binary and recompiling for the amd64 architecture.

Luckily, Ghidra gives an insanely accurate decompilation. Simply export the program to a C file and do some cleanup, and you're good to do some recompilation! Note that we're lucky here because the program doesn't abuse anything architecture specific, and no weird operations that are hard to decompile for Ghidra (which would also make it hard to write a C program for).

Below is the decompilation for *prospectors_claim*:

```c
undefined8 main(void)

{
  char local_55 [65];
  
  setvbuf(_stdout,(char *)0x0,2,0);
  printf("=== The Prospector\'s Claim ===\n");
  printf("Old Man Jenkins\' map to his modest gold claim has been floating around\n");
  printf("Fool\'s Gulch for years. Most folks think it\'s worthless, but you\'ve\n");
  printf("noticed something peculiar in the worn-out corners...\n\n");
  printf("Enter the claim sequence: ");
  fgets(local_55,0x41,_stdin);
  if (local_55[0x1b] == '2') {
    bump(&score);
  }
  if ((byte)(local_55[0x1f] ^ local_55[0x18]) == 0xaa) {
    bump(&score);
  }
  if ((char)(local_55[0x1f] + local_55[0x2e]) == -0x70) {
    bump(&score);
  }
  if ((char)(local_55[0x3b] + local_55[0x24]) == -0x7f) {
    bump(&score);
  }
  if (local_55[0xd] == -0x42) {
    bump(&score);
  }
  if (local_55[0x20] == 'd') {
    bump(&score);
  }
  if (local_55[0x1a] == '1') {
    bump(&score);
  }
  if (local_55[0x2a] == '9') {
    bump(&score);
  }
  if ((char)(local_55[0x2d] + local_55[0x3f]) == -0x6d) {
    bump(&score);
  }
// ... tons of checks; truncated for readability ...
  if (local_55[0x12] == 'd') {
    bump(&score);
  }
  if (score < DAT_00115054) {
    if (score < DAT_00115050) {
      if (score < DAT_0011504c) {
        printf("\nThat claim\'s as empty as a desert well in August.\n",
               (ulong)(uint)(score - DAT_0011504c));
        printf("Not a speck of gold to be found. Try another spot, prospector!\n");
      }
      else {
        printf("\nYou\'ve been swindled, partner! All you\'ve dug up is worthless rock.\n",
               (ulong)(uint)(score - DAT_0011504c));
        printf("The saloon erupts in laughter as you show off your \'treasure\'.\n");
        printf("Keep prospecting - or take up farming instead!\n");
      }
    }
    else {
      printf("\nA few gold flakes glimmer in your pan, but it ain\'t enough to stake a claim.\n",
             (ulong)(uint)(score - DAT_00115050));
      printf("The assayer laughs you out of his office. \"Come back when you\'ve got\n");
      printf("something worth my time, greenhorn!\"\n");
    }
  }
  else {
    printf(&DAT_00104850,(ulong)(uint)(score - DAT_00115054));
    printf("You\'ve struck a rich vein of gold! Your claim is officially recorded\n");
    printf("at the assayer\'s office, and the flag is yours: %s\n",local_55);
  }
  return 0;
}
```

What you will notice is the size the buffer for the input, which is where we would probably need to place the flag, is 0x41 bytes; however, the function for input is *fgets()*, so it will only read up to 0x40 chars, leaving the last byte to be set to a null terminator. The math checks out because ViperX7's solution (using Claude) has given us a 64-byte flag string. For *the_motherlode* the input buffer is of size 57 bytes, leaving 56 bytes of input for the flag.

After the input is a ton of if conditions. checking the properties of some characters. Note that for *the_motherlode*, the conditions are much more complex than those of *prospectors_claim*:

```c
  fgets(local_5c,0x39,_stdin);
  if ((((byte)(local_5c[3] + local_5c[0x1a] & local_5c[0x20]) <
        (byte)((local_5c[9] + local_5c[0x19]) - local_5c[0x1c])) &&
      ((byte)(local_5c[0xf] - local_5c[0x10] & local_5c[0x12]) < 0x27)) &&
     ((byte)(local_5c[0xe] + local_5c[0x17] * local_5c[2]) <
      (byte)((local_5c[0x18] + local_5c[0x19]) * local_5c[0x1a]))) {
    yeet(&scores);
  }
  if ((((byte)(local_5c[2] * local_5c[0x25] - local_5c[0x2b]) < 200) &&
      (0x3c < (byte)((local_5c[0x2f] - local_5c[0x29]) + local_5c[0xb]))) &&
     ((0x4c < (byte)((local_5c[0x31] + local_5c[0x21]) - local_5c[5]) &&
      ((byte)(local_5c[0x17] - (local_5c[8] + local_5c[0x2e])) <
       (byte)(local_5c[0xd] * local_5c[0x2e] ^ local_5c[10]))))) {
    bump(&scores);
  }
  if ((0xf0 < (byte)((local_5c[0x22] - local_5c[0x20]) * local_5c[6])) &&
     ((byte)((local_5c[0x14] + local_5c[0x37]) * local_5c[0x35]) < 0xe1)) {
    whack(&scores);
    bump(&scores);
  }
  if (((byte)((local_5c[0x26] + local_5c[0x2f]) - local_5c[0x2c]) <
       (byte)(local_5c[0x24] - local_5c[0x1d] | local_5c[4])) &&
     ((byte)((local_5c[0x18] ^ local_5c[2]) & local_5c[8]) < 0x24)) {
    boost(&scores);
  }
// ... a ton more checks; truncated for readability
```

If a condition is satisfied, a function is called, with a pointer to an integer, the *score*, as a parameter. 
Depending on the name of the function invoked, the *score* is increased by a certain amount:

- *bonk()* does nothing
- *bump()* raises the score by 0x1
- *whack()* raises the score by 0x2
- *boost()* raises the score by 0x4
- *yeet()* raises the score by 0x8
- *zoink()* raises the score by 0x10
- *kaboom()* raises the score by 0x20
- *mega_whack()* raises the score by 0x40
- *mega_boost()* raises the score by 0x80

> [!warning]
> Not all functions are used by the binaries. *prospectors_claim* only uses *bump()*, while *the_motherlode* is observed to use *bump()*, *whack()*, *boost()*, and *yeet()*. The other functions are declared for completeness, but are not necessarily used.
> 
> Also note that for *the_motherlode*, a condition may be paired with a series of these function calls in the body, unlike *prospectors_claim*, which only has one statement of *bump()* for every condition.

In both binaries, the final if cases are score checks, and they print out different kinds of messages depending on the score. If the score is high enough, the program prints back your input and states that it is the flag. For *prospectors_claim*, the goal is to reach a score of at least 0x119 (281), for *the_motherlode*, the goal is to reach a score of at least 0x5f3 (1523).

### Recompiling the program logic

Luckily, the Ghidra decompilation for *main()* is pretty neat! Recompiling gave me some benefits:
- Can now recompile for another architecture (e.g. amd64)
- Extract parts of the program logic and do some stuff with that

While recompiling does not simplify any of the conditions, we can extract all the logic stuff, do some modifications, and compile that.

A good idea I received was to carve the score calculation from the decompilation and compile that to a shared object. This can be left as an exercise to the reader (it's not that hard, I promise).

Once I had a shared object, I can now invoke the score calculation function from Python. A way to pass bytes to a C native function is with the following example:

```python
import ctypes
motherlode = ctypes.CDLL('./libmotherlode.so')
# int evaluate(char *s)
motherlode.evaluate.argtypes = [ctypes.POINTER(ctypes.c_ubyte)]
motherlode.evaluate.restype = ctypes.c_int

# bruh
payload = b'PCTF{abcdefghijlkmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789}'

ubuffer = (ctypes.c_ubyte * len(payload)).from_buffer(bytearray(payload)) return motherlode.evaluate(ubuffer)
```

## Strategy

So, we have a function that takes in an input, calculates some score, and a flag would have a sufficient score, above a defined threshold.

When I considered all that, I thought that the challenge might be a global maximization problem.

The idea is to find the best input that gives the highest score. This is a problem that can be solved with a genetic algorithm.
Or, as I like to call it, breeding.

Our genetic algorithm looks like this:
- We have individuals - inputs
- Each individual at first are randomly generated to have random genes
	- Genes in this case refer to the hex digits inside the flag prefix and suffix
		- 1 hex digit can be represented in four bits
- For each generation:
	- We evaluate the fitness of an individual, using a fitness function - the score evaluation function
	- We take a portion of the population, starting from the worst-fit to the best-fit and killing them. This is to apply the concept of natural selection, where those that are not fit end up dying early.
	- For the remaining individuals, they are randomly chosen to reproduce and form new individuals, which are slightly mutated versions of their parents. This is to apply the concept of fitness, where those that can survive *and* reproduce are fit.
		- The individuals in my implementation reproduce asexually.
- Once we find an individual to have reached the score threshold, we immediately stop breeding, and simply print the flag using the individual's genome.

## Solution script

Combining the idea of breeding and recompiling to a shared object, we end up with something like the code below, which is the solve script that found the flag first:

```python
#!/usr/bin/env python3

import random
import string
import time
import os

from Crypto.Random.random import getrandbits
from pwn import process, context

context.log_level = 'warn'

import ctypes

motherlode = ctypes.CDLL('./motherlode.so')
motherlode.run.argtypes = [ctypes.POINTER(ctypes.c_ubyte)]
motherlode.run.restype  = ctypes.c_int

# Constants
POPULATION_SIZE = 10000
MUTATION_RATE = 0.50

individual_length = 50 * 4
# charset = 'abcdef0123456789'
charset = "".join(chr(x) for x in range(0x20, 0x7f))

def generate_individual(length):
    """Generate a random individual of given length."""
    return getrandbits(individual_length)

def mutate(individual):
    """Mutate an individual by randomly flipping a bit."""
    pos = random.randint(0, individual_length - 1)
    for i in range(individual_length):
        if random.random() < MUTATION_RATE:
            if i == pos:
                individual ^= (1 << pos)
    return individual

def evaluate(individual):
    individual = hex(individual)[2:]
    payload = b'PCTF{' + individual.encode() + b'}'
    ubuffer = (ctypes.c_ubyte * len(payload)).from_buffer(bytearray(payload))
    return motherlode.run(ubuffer)

def breed(population):
    while True:
        scores = [evaluate(individual) for individual in population]
        sorted_population = sorted(zip(population, scores), key=lambda x: x[1], reverse=True)
        best_individual, best_score = sorted_population[0]

        print("Best individual: PCTF{"
                f'{hex(best_individual)[2:]}'
              "}"
              f", Score: {best_score}, Mutation Rate: {MUTATION_RATE:.2f}")
        if best_score > 0x5f2:
            print("Found a solution!")
            break
        for i in range(10):
            print(f"    Individual: {hex(sorted_population[i][0])[2:]}, Score: {sorted_population[i][1]}")
        
        survivors = [individual for individual, score in sorted_population[:POPULATION_SIZE // 4]]
        survivors = list(set(survivors))

        new_population = []
        while len(new_population) < POPULATION_SIZE:
            parent = random.choice(survivors)
            child = mutate(parent)
            new_population.append(child)
        
        population = survivors + new_population
        population = list(set(population))

def main():
    population = [generate_individual(individual_length) for _ in range(POPULATION_SIZE)]
    breed(population)

if __name__ == "__main__":
    main()
```

Credits to oh_word to recommending pulling the score evaluation. He is the last guy that touched the script above.

## Discussion

The code ends up running pretty quickly, as long as you have `motherlode.so`.

Note that while the solution script is fast enough, it's not the most efficient way of solving. the function *mutate()* can be sped up faster by not going through the for loops lol. This makes it way much faster because of reduced unnecessary calls for RNG.

A solution can be written similarly for *prospectors_claim*, and the flag would be found much faster than for *the_motherlode*.

## Conclusion

I have shown that a genetic algorithm can be good for optimization problems.
If it weren't for it, we would have otherwise needed to look into some complicated logic.

Shout-out to [gcheang](https://github.com/gcheang) for teaching me ~~how to breed~~ genetic algorithms back in Winter of 2023.

Thank you to my team, \[:\], for believing in my strategy.

「」
