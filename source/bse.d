module godwit.bse;

import std.traits;
import std.parallelism;
import core.simd;
import std.conv;

private template ElementType(T) 
{
    static if (is(T == U[], U))
        alias ElementType = ElementType!U;
    else
        alias ElementType = T;
}

public:
static:
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
        bytes[i] ^= cast(ubyte)((c << i) & ri); 
        bytes[i] ^= cast(ubyte)((d << i) & ri);
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
}*/

T bse_encrypt(int BITS, T)(T val, string key)
    if (!isArray!T)
{
    static assert(BITS == 256, "Unsupported key bitness!");
    bse256_encrypt(cast(ubyte*)&val, T.sizeof, key);
    return val;
}

T bse_decrypt(int BITS, T)(T val, string key)
    if (!isArray!T)
{
    static assert(BITS == 256, "Unsupported key bitness!");
    bse256_decrypt(cast(ubyte*)&val, T.sizeof, key);
    return val;
}

T bse_encrypt(int BITS, T)(T val, string key)
    if (isArray!T)
{
    static assert(BITS == 256, "Unsupported key bitness!");
    bse256_encrypt(cast(ubyte*)&val[0], cast(int)(ElementType!T.sizeof * val.length), key);
    return val;
}

T bse_decrypt(int BITS, T)(T val, string key)
    if (isArray!T)
{
    static assert(BITS == 256, "Unsupported key bitness!");
    bse256_decrypt(cast(ubyte*)&val[0], cast(int)(ElementType!T.sizeof * val.length), key);
    return val;
}

// TODO: fix severe plaintext weakness
private void bse256_encrypt(ubyte* ptr, int length, string key)
{
    if (key.length != 32)
        return;

    // Steps:
    // Create minikeys
    // Partition the data into blocks
    // Substitute blocks
    // Encrypt each block, using the minikeys
    // Shuffle the blocks
    // Profit

    ulong a = (cast(ulong*)&key[0])[0];
    ulong b = (cast(ulong*)&key[0])[1];
    ulong c = (cast(ulong*)&key[0])[2];
    ulong d = (cast(ulong*)&key[0])[3];

    foreach (i; 0..length)
    {
        int ii = cast(int)(((c << i) & (d << i)) % length);
        ubyte b0 = ptr[i];
        ptr[i] = ptr[ii];
        ptr[ii] = b0;
    }

    // This is on average 5ms faster than an if
    foreach (r; 0..4)
    switch (length % 16)
    {
        case 0:
            foreach (i, _; parallel(ptr[0..(length / 16)]))
            {
                ulong2* vptr = cast(ulong2*)(ptr + (i * 16));
            
                ulong ri = ~i ^ r;
                *vptr ^= (c << i) & ri;  
                *vptr ^= (d << i) & ri; 
                *vptr -= ri; 
                *vptr ^= (a << i) & ri; 
                *vptr ^= (b << i) & ri; 
            }
            break;
        case 8:
            foreach (i, _; parallel(ptr[0..(length / 8)]))
            {
                ulong* vptr = cast(ulong*)(ptr + (i * 8));
            
                ulong ri = ~i ^ r;
                *vptr ^= (c << i) & ri;  
                *vptr ^= (d << i) & ri; 
                *vptr -= ri; 
                *vptr ^= (a << i) & ri; 
                *vptr ^= (b << i) & ri; 
            }
            break;
        case 4:
            foreach (i, _; parallel(ptr[0..(length / 4)]))
            {
                uint* vptr = cast(uint*)(ptr + (i * 4));
                
                ulong ri = ~i ^ r;
                *vptr ^= (c << i) & ri;  
                *vptr ^= (d << i) & ri; 
                *vptr -= ri; 
                *vptr ^= (a << i) & ri; 
                *vptr ^= (b << i) & ri; 
            }
            break;
        case 2:
            foreach (i, _; parallel(ptr[0..(length / 2)]))
            {
                ushort* vptr = cast(ushort*)(ptr + (i * 2));
                
                ulong ri = ~i ^ r;
                *vptr ^= (c << i) & ri;  
                *vptr ^= (d << i) & ri; 
                *vptr -= ri; 
                *vptr ^= (a << i) & ri; 
                *vptr ^= (b << i) & ri; 
            }
            break;
        default:
            foreach (i, _; parallel(ptr[0..length]))
            {
                ulong ri = ~i ^ r;
                ptr[i] ^= (c << i) & ri;  
                ptr[i] ^= (d << i) & ri; 
                ptr[i] -= ri; 
                ptr[i] ^= (a << i) & ri; 
                ptr[i] ^= (b << i) & ri; 
            }
            break;
    } 

    foreach (i; 0..length)
    {
        int ii = cast(int)(((a << i) & (b << i)) % length);
        ubyte b0 = ptr[i];
        ptr[i] = ptr[ii];
        ptr[ii] = b0;
    }
}

private void bse256_decrypt(ubyte* ptr, int length, string key)
{
    if (key.length != 32)
        return;

    ulong a = (cast(ulong*)&key[0])[0];
    ulong b = (cast(ulong*)&key[0])[1];
    ulong c = (cast(ulong*)&key[0])[2];
    ulong d = (cast(ulong*)&key[0])[3];

    foreach_reverse (i; 0..length)
    {
        int ii = cast(int)(((a << i) & (b << i)) % length);
        ubyte b0 = ptr[i];
        ptr[i] = ptr[ii];
        ptr[ii] = b0;
    }

    foreach (r; 0..4)
    switch (length % 16)
    {
        case 0:
            foreach_reverse (i; 0..(length / 16))
            {
                ulong2* vptr = cast(ulong2*)(ptr + (i * 16));
            
                ulong ri = ~i ^ r;
                *vptr ^= (b << i) & ri;  
                *vptr ^= (a << i) & ri; 
                *vptr += ri; 
                *vptr ^= (d << i) & ri; 
                *vptr ^= (c << i) & ri; 
            }
            break;
        case 8:
            foreach_reverse (i; 0..(length / 8))
            {
                ulong* vptr = cast(ulong*)(ptr + (i * 8));
            
                ulong ri = ~i ^ r;
                *vptr ^= (b << i) & ri;  
                *vptr ^= (a << i) & ri; 
                *vptr += ri; 
                *vptr ^= (d << i) & ri; 
                *vptr ^= (c << i) & ri; 
            }
            break;
        case 4:
            foreach_reverse (i; 0..(length / 4))
            {
                uint* vptr = cast(uint*)(ptr + (i * 4));
                
                ulong ri = ~i ^ r;
                *vptr ^= (b << i) & ri;  
                *vptr ^= (a << i) & ri; 
                *vptr += ri; 
                *vptr ^= (d << i) & ri; 
                *vptr ^= (c << i) & ri; 
            }
            break;
        case 2:
            foreach_reverse (i; 0..(length / 2))
            {
                ushort* vptr = cast(ushort*)(ptr + (i * 2));
                
                ulong ri = ~i ^ r;
                *vptr ^= (b << i) & ri;  
                *vptr ^= (a << i) & ri; 
                *vptr += ri; 
                *vptr ^= (d << i); 
                *vptr ^= (c << i) & ri; 
            }
            break;
        default:
            foreach_reverse (i; 0..length)
            {
                ulong ri = ~i ^ r;
                ptr[i] ^= (b << i) & ri;  
                ptr[i] ^= (a << i) & ri; 
                ptr[i] += ri; 
                ptr[i] ^= (d << i) & ri; 
                ptr[i] ^= (c << i) & ri; 
            }
            break;
    } 

    foreach_reverse (i; 0..length)
    {
        int ii = cast(int)(((c << i) & (d << i)) % length);
        ubyte b0 = ptr[i];
        ptr[i] = ptr[ii];
        ptr[ii] = b0;
    }
}

/* void bse128_encrypt(ubyte* ptr, int length, string key)
{
    if (key.length != 16)
    {
        import std.conv;
        throw new Exception("Key is "~(key.length * 8).to!string~" bits, expected 128!");
    }

    // Steps:
    // Create minikeys
    // Partition the data into blocks
    // Substitute blocks
    // Encrypt each block, using the minikeys
    // Shuffle the blocks
    // Profit

    ulong a = (cast(ulong*)&key[0])[0];
    ulong b = (cast(ulong*)&key[0])[1];

    foreach (i; 0..length)
    {
        int ii = cast(int)((a << i) % length);
        ubyte b0 = ptr[i];
        ptr[i] = ptr[ii];
        ptr[ii] = b0;
    }

    // This is on average 5ms faster than an if
    foreach (r; 0..4)
    switch (length % 16)
    {
        case 0:
            foreach (i, _; parallel(ptr[0..(length / 16)]))
            {
                ulong2* vptr = cast(ulong2*)(ptr + (i * 16));
            
                ulong ri = ~i;
                *vptr -= ri; 
                *vptr ^= (a << i) & ri; 
                *vptr ^= (b << i) & ri; 
            }
            break;
        case 8:
            foreach (i, _; parallel(ptr[0..(length / 8)]))
            {
                ulong* vptr = cast(ulong*)(ptr + (i * 8));
            
                ulong ri = ~i;
                *vptr -= ri; 
                *vptr ^= (a << i) & ri; 
                *vptr ^= (b << i) & ri; 
            }
            break;
        case 4:
            foreach (i, _; parallel(ptr[0..(length / 4)]))
            {
                uint* vptr = cast(uint*)(ptr + (i * 4));
                
                ulong ri = ~i;
                *vptr -= ri; 
                *vptr ^= (a << i) & ri; 
                *vptr ^= (b << i) & ri; 
            }
            break;
        case 2:
            foreach (i, _; parallel(ptr[0..(length / 2)]))
            {
                ushort* vptr = cast(ushort*)(ptr + (i * 2));
                
                ulong ri = ~i;
                *vptr -= ri; 
                *vptr ^= (a << i) & ri; 
                *vptr ^= (b << i) & ri; 
            }
            break;
        default:
            foreach (i, _; parallel(ptr[0..length]))
            {
                ulong ri = ~i;
                ptr[i] -= ri; 
                ptr[i] ^= (a << i) & ri; 
                ptr[i] ^= (b << i) & ri; 
            }
            break;
    } 

    foreach (i; 0..length)
    {
        int ii = cast(int)((b << i) % length);
        ubyte b0 = ptr[i];
        ptr[i] = ptr[ii];
        ptr[ii] = b0;
    }
}

void bse128_decrypt(ubyte* ptr, int length, string key)
{
    if (key.length != 16)
    {
        import std.conv;
        throw new Exception("Key is "~(key.length * 8).to!string~" bits, expected 128!");
    }

    ulong a = (cast(ulong*)&key[0])[0];
    ulong b = (cast(ulong*)&key[0])[1];

    foreach_reverse (i; 0..length)
    {
        int ii = cast(int)((a << i) % length);
        ubyte b0 = ptr[i];
        ptr[i] = ptr[ii];
        ptr[ii] = b0;
    }

    foreach (r; 0..4)
    switch (length % 16)
    {
        case 0:
            foreach_reverse (i; 0..(length / 16))
            {
                ulong2* vptr = cast(ulong2*)(ptr + (i * 16));
            
                ulong ri = ~i;
                *vptr ^= (b << i) & ri;  
                *vptr ^= (a << i) & ri; 
                *vptr += ri; 
            }
            break;
        case 8:
            foreach_reverse (i; 0..(length / 8))
            {
                ulong* vptr = cast(ulong*)(ptr + (i * 8));
            
                ulong ri = ~i;
                *vptr ^= (b << i) & ri;  
                *vptr ^= (a << i) & ri; 
                *vptr += ri; 
            }
            break;
        case 4:
            foreach_reverse (i; 0..(length / 4))
            {
                uint* vptr = cast(uint*)(ptr + (i * 4));
                
                ulong ri = ~i;
                *vptr ^= (b << i) & ri;  
                *vptr ^= (a << i) & ri; 
                *vptr += ri; 
            }
            break;
        case 2:
            foreach_reverse (i; 0..(length / 2))
            {
                ushort* vptr = cast(ushort*)(ptr + (i * 2));
                
                ulong ri = ~i;
                *vptr ^= (b << i) & ri;  
                *vptr ^= (a << i) & ri; 
                *vptr += ri; 
            }
            break;
        default:
            foreach_reverse (i; 0..length)
            {
                ulong ri = ~i;
                ptr[i] ^= (b << i) & ri;  
                ptr[i] ^= (a << i) & ri; 
                ptr[i] += ri; 
            }
            break;
    } 

    foreach_reverse (i; 0..length)
    {
        int ii = cast(int)((b << i) % length);
        ubyte b0 = ptr[i];
        ptr[i] = ptr[ii];
        ptr[ii] = b0;
    }
} */