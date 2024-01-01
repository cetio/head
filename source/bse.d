module bse;

import std.traits;
import std.parallelism;

public:
static:
/*const int[] seed = [
    0x50a7f451, 0x5365417e, 0xc3a4171a, 0x965e273a, 0xcb6bab3b, 
    0xf1459d1f, 0xab58faac, 0x9303e34b, 0x55fa3020, 0xf66d76ad,
    0x9176cc88, 0x254c02f5, 0xfcd7e54f, 0xd7cb2ac5, 0x80443526, 
    0x8fa362b5, 0x495ab1de, 0x671bba25, 0x980eea45, 0xe1c0fe5d,
    0x02752fc3, 0x12f04c81, 0xa397468d, 0xc6f9d36b, 0xe75f8f03, 
    0x959c9215, 0xeb7a6dbf, 0xda595295, 0x2d83bed4, 0xd3217458,
    0x2969e049, 0x44c8c98e, 0x6a89c275, 0x78798ef4, 0x6b3e5899, 
    0xdd71b927, 0xb64fe1be, 0x17ad88f0, 0x66ac20c9, 0xb43ace7d
];*/
ubyte[32] rand = [
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
    0x0A, 0x0D, 0x1A, 0x1D, 0x2E, 0x2C, 0x13, 0x09,
    0x1B, 0x26, 0x7F, 0x2F, 0x12, 0x19, 0x0B, 0x22, 
    0x10, 0x01, 0x2A, 0x6F, 0x05, 0x14, 0x1E, 0x18,
];
/*void bse256ag_encrypt(ref ubyte[] bytes, string key)
{
    if (key.length != 32)
        return;

    uint len = (cast(uint)bytes.length / 8) + 4;
    if ((bytes.length + len) % 8 != 0)
        len += (8 - ((bytes.length + len) % 8));
    bytes ~= new ubyte[len];
    *cast(uint*)&bytes[$-4] = len;

    ulong a = (cast(ulong*)&key[0])[0];
    ulong b = (cast(ulong*)&key[0])[1];
    ulong c = (cast(ulong*)&key[0])[2];
    ulong d = (cast(ulong*)&key[0])[3];

    foreach (i, _; parallel(bytes))
    {
        ulong ri = ~i;
        bytes[i] ^= cast(ubyte)((c >> i) & ri); 
        bytes[i] ^= cast(ubyte)((d >> i) & ri);
        bytes[i] += ri; 
        bytes[i] ^= cast(ubyte)((a << i) & ri); 
        bytes[i] ^= cast(ubyte)((b << i) & ri); 
    }
    
    foreach (i; 0..bytes.length)
    {
        int ii = key[rand[i % 32] % key.length] % bytes.length;
        ubyte b0 = bytes[ii];
        bytes[ii] = bytes[i];
        bytes[i] = b0;
    }

    ulong numBlocks = bytes.length / 8; 
    foreach (i; 0..numBlocks) 
    {
        ulong* block1 = cast(ulong*)(bytes.ptr + (i * 8));
        ulong* block2 = cast(ulong*)(bytes.ptr + (key[rand[i % 32] % key.length] % bytes.length));

        ulong u0 = *block1;
        *block1 = *block2;
        *block2 = u0;
    }
}

void bse256ag_decrypt(ref ubyte[] bytes, string key)
{
    if (key.length != 32 || bytes.length % 8 != 0)
        return;

    ulong a = (cast(ulong*)&key[0])[0];
    ulong b = (cast(ulong*)&key[0])[1];
    ulong c = (cast(ulong*)&key[0])[2];
    ulong d = (cast(ulong*)&key[0])[3];

    ulong numBlocks = bytes.length / 8; 
    foreach_reverse (i; 0..numBlocks) 
    {
        ulong* block1 = cast(ulong*)(bytes.ptr + (i * 8));
        ulong* block2 = cast(ulong*)(bytes.ptr + (key[rand[i % 32] % key.length] % bytes.length));

        ulong u0 = *block1;
        *block1 = *block2;
        *block2 = u0;
    }

    foreach_reverse (i; 0..bytes.length)
    {
        int ii = key[rand[i % 32] % key.length] % bytes.length;
        ubyte b0 = bytes[ii];
        bytes[ii] = bytes[i];
        bytes[i] = b0;
    }

    foreach_reverse (i; 0..bytes.length)
    {
        ulong ri = ~i;
        bytes[i] ^= cast(ubyte)((b << i) & ri); 
        bytes[i] ^= cast(ubyte)((a << i) & ri); 
        bytes[i] -= ri; 
        bytes[i] ^= cast(ubyte)((d >> i) & ri); 
        bytes[i] ^= cast(ubyte)((c >> i) & ri);
    }

    import std.stdio;
    writeln(bytes);
    readln();
    bytes = bytes[0..($-*cast(uint*)&bytes[$-4])];
}*/

void bse256_encrypt(ubyte* ptr, int length, string key)
{
    if (key.length != 32)
        return;

    ulong a = (cast(ulong*)&key[0])[0];
    ulong b = (cast(ulong*)&key[0])[1];
    ulong c = (cast(ulong*)&key[0])[2];
    ulong d = (cast(ulong*)&key[0])[3];

    foreach (i, _; parallel(ptr[0..length]))
    {
        ulong ri = ~i;
        ptr[i] ^= cast(ubyte)((c >> i) & ri); 
        ptr[i] ^= cast(ubyte)((d >> i) & ri);
        ptr[i] -= ri; 
        ptr[i] ^= cast(ubyte)((a << i) & ri); 
        ptr[i] ^= cast(ubyte)((b << i) & ri); 
    }
    
    foreach (i; 0..length)
    {
        int ii = key[rand[i % 32] % key.length] % length;
        ubyte b0 = ptr[ii];
        ptr[ii] = ptr[i];
        ptr[i] = b0;
    }
}

void bse256_decrypt(ubyte* ptr, int length, string key)
{
    if (key.length != 32)
        return;

    ulong a = (cast(ulong*)&key[0])[0];
    ulong b = (cast(ulong*)&key[0])[1];
    ulong c = (cast(ulong*)&key[0])[2];
    ulong d = (cast(ulong*)&key[0])[3];

    foreach_reverse (i; 0..length)
    {
        int ii = key[rand[i % 32] % key.length] % length;
        ubyte b0 = ptr[i];
        ptr[i] = ptr[ii];
        ptr[ii] = b0;
    }

    foreach_reverse (i; 0..length)
    {
        ulong ri = ~i;
        ptr[i] ^= cast(ubyte)((b << i) & ri); 
        ptr[i] ^= cast(ubyte)((a << i) & ri); 
        ptr[i] += ri; 
        ptr[i] ^= cast(ubyte)((d >> i) & ri);
        ptr[i] ^= cast(ubyte)((c >> i) & ri); 
        
    }
}

void bse128_encrypt(ubyte* ptr, int length, string key)
{
    if (key.length != 16)
        return;

    //Encryption time:570ms
    //ulong2 vec = (cast(ulong2*)&key[0])[0];
    ulong a = (cast(ulong*)&key[0])[0];
    ulong b = (cast(ulong*)&key[0])[1];

    foreach (i, _; parallel(ptr[0..length]))
    {
        ptr[i] -= ~i; 
        ptr[i] ^= cast(ubyte)((a << i) & ~i); 
        ptr[i] ^= cast(ubyte)((b << i) & ~i); 
        //ptr[i] ^= cast(ulong2)__simd_ib(XMM.PSLLDQ, vec, 31) & ~i;
    }
    
    foreach (i; 0..length)
    {
        int ii = key[rand[i % 32] % key.length] % length;
        ubyte b0 = ptr[ii];
        ptr[ii] = ptr[i];
        ptr[i] = b0;
    }
}

void bse128_decrypt(ubyte* ptr, int length, string key)
{
    if (key.length != 16)
        return;

    ulong a = (cast(ulong*)&key[0])[0];
    ulong b = (cast(ulong*)&key[0])[1];

    foreach_reverse (i; 0..length)
    {
        int ii = key[rand[i % 32] % key.length] % length;
        ubyte b0 = ptr[i];
        ptr[i] = ptr[ii];
        ptr[ii] = b0;
    }

    foreach_reverse (i; 0..length)
    {
        ptr[i] ^= cast(ubyte)((b << i) & ~i); 
        ptr[i] ^= cast(ubyte)((a << i) & ~i); 
        ptr[i] += ~i; 
    }
}

T bse_encrypt(T)(T val, string key)
    if (!isArray!T)
{
    bse256_encrypt(cast(ubyte*)&val, T.sizeof, key);
    return val;
}

T bse_decrypt(T)(T val, string key)
    if (!isArray!T)
{
    bse256_decrypt(cast(ubyte*)&val, T.sizeof, key);
    return val;
}

T bse_encrypt(T)(T val, string key)
    if (isArray!T)
{
    bse256_encrypt(cast(ubyte*)&val[0], cast(int)(T.sizeof * val.length), key);
    return val;
}

T bse_decrypt(T)(T val, string key)
    if (isArray!T)
{
    bse256_decrypt(cast(ubyte*)&val[0], cast(int)(T.sizeof * val.length), key);
    return val;
}