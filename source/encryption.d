module godwit.encryption;

import std.traits;
import std.parallelism;
import std.range;

public:
static:
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
        {
            if (i % 3 == 0)
                ptr[i - 1] += ptr[i];

            switch (c % 3)
            {
                case 0:
                    ptr[i] ^= c << (0x7f & i);
                    break;
                case 1:
                    ptr[i] -= c & -i;
                    break;
                case 2:
                    ptr[i] += c >> (i | 0x7f);
                    break;
                default:
                    break;
            }  
        }

        /*if ((ptr[i] & 0x80) == 0 && (cast(int)ptr[i] - 10 | 0x80) < 255 && cast(int)ptr[i + 1] + 10 < 255)
        {
            ptr[i] -= 10;
            ptr[i] |= 0x80;
            ptr[i + 1] += 10;
        }*/
    }

    foreach (i, _; parallel(ptr[0..length]))
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
        /*if ((ptr[i] & 0x80) && ptr[i + 1] > 10)
        {
            ptr[i] &= ~0x80;
            ptr[i] += 10;
            ptr[i + 1] -= 10;
        }*/

        foreach_reverse (c; key)
        {
            switch (c % 3)
            {
                case 0:
                    ptr[i] ^= c << (0x7f & i);
                    break;
                case 1:
                    ptr[i] += c & -i;
                    break;
                case 2:
                    ptr[i] -= c >> (i | 0x7f);
                    break;
                default:
                    break;
            }
            
            if (i % 3 == 0)
                ptr[i - 1] -= ptr[i];
        }
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