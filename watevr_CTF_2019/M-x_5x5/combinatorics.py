#!/usr/bin/python2

import itertools
 
def xor(index, number):
    table= [ 
        int('00000000', 2),
        int('00000111', 2),
        int('00001110', 2),
        int('00011100', 2),
        int('00111000', 2),
        int('01110000', 2),
        int('11100000', 2),
        int('11000000', 2),
        int('10000000', 2),
        int('00000000', 2),
            ]
    number = (number ^ table[index]) % 0x100
    return number

for i in range(10):
    for j in range(10):
        for combo in itertools.combinations(range(i), j):
            #number = 0xB
            number = 0x7
            for k in combo:
                number = xor(k, number)
                if number == 0x38: 
                    print "Got'em:", combo
                    exit(1)
