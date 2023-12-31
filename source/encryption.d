module godwit.encryption;

import std.traits;
import std.parallelism;
import std.range;
import std.exception;
import std.algorithm;
import std.bitmanip;
import std.random;
import std.conv;

public:
static:
/*const int[] seed = [
    0x50a7f451, 0x5365417e, 0xc3a4171a, 0x965e273a, 0xcb6bab3b, 0xf1459d1f, 0xab58faac, 0x9303e34b, 0x55fa3020, 0xf66d76ad,
    0x9176cc88, 0x254c02f5, 0xfcd7e54f, 0xd7cb2ac5, 0x80443526, 0x8fa362b5, 0x495ab1de, 0x671bba25, 0x980eea45, 0xe1c0fe5d,
    0x02752fc3, 0x12f04c81, 0xa397468d, 0xc6f9d36b, 0xe75f8f03, 0x959c9215, 0xeb7a6dbf, 0xda595295, 0x2d83bed4, 0xd3217458,
    0x2969e049, 0x44c8c98e, 0x6a89c275, 0x78798ef4, 0x6b3e5899, 0xdd71b927, 0xb64fe1be, 0x17ad88f0, 0x66ac20c9, 0xb43ace7d
];*/
const int[] primes = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73,
    79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131
];
void btencryp(ubyte* ptr, int length, string key)
{
    if (key.length != 32)
        return;

    foreach (i, _; parallel(ptr[0..length]))
    {
        foreach (c; key)
            ptr[i] ^= c & ~i; 
    }
    
    foreach (i; 0..length)
    {
        int ii = key[primes[i % 32] % key.length] % length;
        ubyte b = ptr[ii];
        ptr[ii] = ptr[i];
        ptr[i] = b;
    }
}

void btdecryp(ubyte* ptr, int length, string key)
{
    if (key.length != 32)
        return;

    foreach_reverse (i; 0..length)
    {
        int ii = key[primes[i % 32] % key.length] % length;
        ubyte b = ptr[i];
        ptr[i] = ptr[ii];
        ptr[ii] = b;
    }

    foreach_reverse (i; 0..length)
    {
        foreach_reverse (c; key)
            ptr[i] ^= c & ~i; 
    }
}

T btencryp(T)(T val, string key)
    if (!isArray!T)
{
    btencryp(cast(ubyte*)&val, T.sizeof, key);
    return val;
}

T btdecryp(T)(T val, string key)
    if (!isArray!T)
{
    btdecryp(cast(ubyte*)&val, T.sizeof, key);
    return val;
}

T btencryp(T)(T val, string key)
    if (isArray!T)
{
    static assert(0, "Unimplemented");
}

T btdecryp(T)(T val, string key)
    if (isArray!T)
{
    static assert(0, "Unimplemented");
}