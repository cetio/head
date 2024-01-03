module godwit.bse;

import std.traits;
import std.parallelism;
import core.simd;
import std.conv;
import std.functional;

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
    if (key.len != 32)
        return;

    uint len = (cast(uint)bytes.len / 8) + 4;
    if ((bytes.len + len) % 8 != 0)
        len += (8 - ((bytes.len + len) % 8));
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
    
    foreach (i; 0..bytes.len)
    {
        int ii = key[rand[i % 32] % key.len] % bytes.len;
        ubyte b0 = bytes[ii];
        bytes[ii] = bytes[i];
        bytes[i] = b0;
    }

    ulong numBlocks = bytes.len / 8; 
    foreach (i; 0..numBlocks) 
    {
        ulong* block1 = cast(ulong*)(bytes.ptr + (i * 8));
        ulong* block2 = cast(ulong*)(bytes.ptr + (key[rand[i % 32] % key.len] % bytes.len));

        ulong u0 = *block1;
        *block1 = *block2;
        *block2 = u0;
    }
}*/

/++
    Encrypts the provided value using BSE.

    Parameters:
        BITS: The number of bits for the encryption key.
        T: The type of the value to be encrypted, expected to not be an array.

    Returns:
        The encrypted value of the same type and size as the input 'val'.

    Constraints:
        - T: The input 'val' must not be an array type.

    Example Usage:
    ```d
    ubyte[] data = [/*...*/];
    string encryptionKey = "abcdefgh12345678abcdefgh12345678"; // 32-character decryption key
    ubyte[] encryptedData = bse_encrypt!256(data, encryptionKey);
    ```
+/
T bse_encrypt(int BITS, T)(T val, string key)
    if (!isArray!T)
{
    static assert(BITS == 256, "Unsupported key bitness!");
    bse256_encrypt(cast(ubyte*)&val, T.sizeof, key);
    return val;
}

/++
    Decrypts the provided value using BSE.

    Parameters:
        BITS: The number of bits for the encryption key.
        T: The type of the value to be decrypted, expected to not be an array.

    Returns:
        The decrypted value of the same type and size as the input 'val'.

    Constraints:
        - T: The input 'val' must not be an array type.

    Example Usage:
    ```d
    ubyte[] encryptedData = [/*...*/]; // Encrypted data of type ubyte array
    string encryptionKey = "abcdefgh12345678abcdefgh12345678"; // 32-character decryption key
    ubyte[] decryptedData = bse_decrypt!256(encryptedData, encryptionKey);
    ```
+/
T bse_decrypt(int BITS, T)(T val, string key)
    if (!isArray!T)
{
    static assert(BITS == 256, "Unsupported key bitness!");
    bse256_decrypt(cast(ubyte*)&val, T.sizeof, key);
    return val;
}

/++
    Encrypts the provided value using BSE.

    Parameters:
        BITS: The number of bits for the encryption key.
        T: The type of the value to be encrypted, expected to be an array.

    Returns:
        The encrypted value of the same type and size as the input 'val'.

    Constraints:
        - T: The input 'val' must be an array type.

    Example Usage:
    ```d
    ubyte[] data = [/*...*/];
    string encryptionKey = "abcdefgh12345678abcdefgh12345678"; // 32-character decryption key
    ubyte[] encryptedData = bse_encrypt!256(data, encryptionKey);
    ```
+/
T bse_encrypt(int BITS, T)(T val, string key)
    if (isArray!T)
{
    static assert(BITS == 256, "Unsupported key bitness!");
    bse256_encrypt(cast(ubyte*)&val[0], cast(int)(ElementType!T.sizeof * val.length), key);
    return val;
}

/++
    Decrypts the provided value using BSE.

    Parameters:
        BITS: The number of bits for the encryption key.
        T: The type of the value to be decrypted, expected to be an array.

    Returns:
        The decrypted value of the same type and size as the input 'val'.

    Constraints:
        - T: The input 'val' must be an array type.

    Example Usage:
    ```d
    ubyte[] encryptedData = [/*...*/]; // Encrypted data of type ubyte array
    string encryptionKey = "abcdefgh12345678abcdefgh12345678"; // 32-character decryption key
    ubyte[] decryptedData = bse_decrypt!256(encryptedData, encryptionKey);
    ```
+/
T bse_decrypt(int BITS, T)(T val, string key)
    if (isArray!T)
{
    static assert(BITS == 256, "Unsupported key bitness!");
    bse256_decrypt(cast(ubyte*)&val[0], cast(int)(ElementType!T.sizeof * val.length), key);
    return val;
}

/++
    Encrypts the provided data using BSE256.

    Parameters:
        ptr: Pointer to the data to be encrypted, represented as an array of ubytes.
        len: Length of the data in bytes.
        key: Encryption key as a string. Must be 256 bits (32 characters in length.)

    Remarks:
        Should use `bse_encrypt` instead, unless calling this from another language.

    Returns:
        Nothing. The provided data pointed to by 'ptr' is modified in place to store the encrypted result.
        If the 'key' parameter length is not 32 characters, the function returns without performing encryption.

    Example Usage:
    ```d
    ubyte[] data = [/*...*/]; // Initialize data to be encrypted
    string encryptionKey = "abcdefgh12345678abcdefgh12345678"; // 32-character encryption key
    bse256_encrypt(&data[0], data.length, encryptionKey);
    ```
+/
extern (C) export void bse256_encrypt(ubyte* ptr, int len, string key)
{
    if (key.length != 32)
        return;

    // Steps:
    // Key expansion
    // Partition the data into blocks
    // Substitute blocks
    // Encrypt each block, using the expanded keys
    // Shuffle the blocks
    // Profit

    ulong a = (cast(ulong*)&key[0])[0];
    ulong b = (cast(ulong*)&key[0])[1];
    ulong c = (cast(ulong*)&key[0])[2];
    ulong d = (cast(ulong*)&key[0])[3];
    int rlen = (len - (len % 16));

    // Very slow! 85% of the encryption time!
    // Use blocks?
    foreach (i; 0..len)
    {
        int ii = cast(int)(((c << i) & (d << i)) % len);
        ubyte b0 = ptr[i];
        ptr[i] = ptr[ii];
        ptr[ii] = b0;
    }

    foreach (r; 0..4)
    {
        foreach (i, _; parallel(ptr[0..(rlen / 16)]))
        {
            ulong2* vptr = cast(ulong2*)(ptr + (i * 16));
            ulong ri = ~i;
            *vptr ^= (c << i) & ri;  
            *vptr ^= (d << i) & ri; 
            *vptr ^= (a << i) & ri; 
            *vptr ^= (b << i) & ri; 
        }
        foreach (i; 0..(rlen / 16))
        {
            ulong2* vptr = cast(ulong2*)(ptr + (i * 16));
            if (i != 0)
                *vptr ^= *(vptr - 1);
        }
    
        foreach (i, _; parallel(ptr[rlen..len]))
        {
            ulong ri = ~i;
            ptr[i] ^= (c << i) & ri;  
            ptr[i] ^= (d << i) & ri; 
            ptr[i] ^= (a << i) & ri; 
            ptr[i] ^= (b << i) & ri; 
        }
        foreach (i; rlen..len)
        {
            if (i != 0)
                ptr[i] ^= ptr[i - 1];
        }
    }

    // If I do this it becomes slightly faster,
    // It only happens for this one loop, none of the others.
    // I do not know why, I do not want to know why, leave it be.
    foreach (i; 0..len)
    {
        int ii = cast(int)(((a << i) & (b << i)) % len);
        ubyte b0 = ptr[i];
        ptr[i] = ptr[ii];
        ptr[ii] = b0;
    }
}

/++
    Decrypts the provided data using BSE256.

    Parameters:
        ptr: Pointer to the data to be decrypted, represented as an array of ubytes.
        len: Length of the data in bytes.
        key: Encryption key as a string. Must be 256 bits (32 characters in length.)

    Remarks:
        Should use `bse_decrypt` instead, unless calling this from another language.

    Returns:
        Nothing. The provided data pointed to by 'ptr' is modified in place to store the decrypted result.
        If the 'key' parameter length is not 32 characters, the function returns without performing decryption.

    Example Usage:
    ```d
    ubyte[] data = [/*...*/]; // Initialize data to be decrypted
    string encryptionKey = "abcdefgh12345678abcdefgh12345678"; // 32-character encryption key
    bse256_decrypt(&data[0], data.length, encryptionKey);
    ```
+/
extern (C) export void bse256_decrypt(ubyte* ptr, int len, string key)
{
    if (key.length != 32)
        return;

    ulong a = (cast(ulong*)&key[0])[0];
    ulong b = (cast(ulong*)&key[0])[1];
    ulong c = (cast(ulong*)&key[0])[2];
    ulong d = (cast(ulong*)&key[0])[3];
    int rlen = (len - (len % 16));

    foreach_reverse (i; 0..len)
    {
        int ii = cast(int)(((a << i) & (b << i)) % len);
        ubyte b0 = ptr[i];
        ptr[i] = ptr[ii];
        ptr[ii] = b0;
    }

    foreach_reverse (r; 0..4)
    {
        foreach_reverse (i; 0..(rlen / 16))
        {
            ulong2* vptr = cast(ulong2*)(ptr + (i * 16));
            if (i != 0)
                *vptr ^= *(vptr - 1);
            ulong ri = ~i;
            *vptr ^= (b << i) & ri; 
            *vptr ^= (a << i) & ri; 
            *vptr ^= (d << i) & ri;
            *vptr ^= (c << i) & ri;  
        }

        foreach_reverse (i; rlen..len)
        {
            if (i != 0)
                ptr[i] ^= ptr[i - 1];
            ulong ri = ~i;
            ptr[i] ^= (b << i) & ri;  
            ptr[i] ^= (a << i) & ri; 
            ptr[i] ^= (d << i) & ri; 
            ptr[i] ^= (c << i) & ri;  
        }
    }

    foreach_reverse (i; 0..len)
    {
        int ii = cast(int)(((c << i) & (d << i)) % len);
        ubyte b0 = ptr[i];
        ptr[i] = ptr[ii];
        ptr[ii] = b0;
    }
}

/* void bse128_encrypt(ubyte* ptr, int len, string key)
{
    if (key.len != 16)
    {
        import std.conv;
        throw new Exception("Key is "~(key.len * 8).to!string~" bits, expected 128!");
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

    foreach (i; 0..len)
    {
        int ii = cast(int)((a << i) % len);
        ubyte b0 = ptr[i];
        ptr[i] = ptr[ii];
        ptr[ii] = b0;
    }

    // This is on average 5ms faster than an if
    foreach (r; 0..4)
    switch (len % 16)
    {
        case 0:
            foreach (i, _; parallel(ptr[0..(len / 16)]))
            {
                ulong2* vptr = cast(ulong2*)(ptr + (i * 16));
            
                ulong ri = ~i;
                *vptr -= ri; 
                *vptr ^= (a << i) & ri; 
                *vptr ^= (b << i) & ri; 
            }
            break;
        case 8:
            foreach (i, _; parallel(ptr[0..(len / 8)]))
            {
                ulong* vptr = cast(ulong*)(ptr + (i * 8));
            
                ulong ri = ~i;
                *vptr -= ri; 
                *vptr ^= (a << i) & ri; 
                *vptr ^= (b << i) & ri; 
            }
            break;
        case 4:
            foreach (i, _; parallel(ptr[0..(len / 4)]))
            {
                uint* vptr = cast(uint*)(ptr + (i * 4));
                
                ulong ri = ~i;
                *vptr -= ri; 
                *vptr ^= (a << i) & ri; 
                *vptr ^= (b << i) & ri; 
            }
            break;
        case 2:
            foreach (i, _; parallel(ptr[0..(len / 2)]))
            {
                ushort* vptr = cast(ushort*)(ptr + (i * 2));
                
                ulong ri = ~i;
                *vptr -= ri; 
                *vptr ^= (a << i) & ri; 
                *vptr ^= (b << i) & ri; 
            }
            break;
        default:
            foreach (i, _; parallel(ptr[0..len]))
            {
                ulong ri = ~i;
                ptr[i] -= ri; 
                ptr[i] ^= (a << i) & ri; 
                ptr[i] ^= (b << i) & ri; 
            }
            break;
    } 

    foreach (i; 0..len)
    {
        int ii = cast(int)((b << i) % len);
        ubyte b0 = ptr[i];
        ptr[i] = ptr[ii];
        ptr[ii] = b0;
    }
}

void bse128_decrypt(ubyte* ptr, int len, string key)
{
    if (key.len != 16)
    {
        import std.conv;
        throw new Exception("Key is "~(key.len * 8).to!string~" bits, expected 128!");
    }

    ulong a = (cast(ulong*)&key[0])[0];
    ulong b = (cast(ulong*)&key[0])[1];

    foreach_reverse (i; 0..len)
    {
        int ii = cast(int)((a << i) % len);
        ubyte b0 = ptr[i];
        ptr[i] = ptr[ii];
        ptr[ii] = b0;
    }

    foreach (r; 0..4)
    switch (len % 16)
    {
        case 0:
            foreach_reverse (i; 0..(len / 16))
            {
                ulong2* vptr = cast(ulong2*)(ptr + (i * 16));
            
                ulong ri = ~i;
                *vptr ^= (b << i) & ri;  
                *vptr ^= (a << i) & ri; 
                *vptr += ri; 
            }
            break;
        case 8:
            foreach_reverse (i; 0..(len / 8))
            {
                ulong* vptr = cast(ulong*)(ptr + (i * 8));
            
                ulong ri = ~i;
                *vptr ^= (b << i) & ri;  
                *vptr ^= (a << i) & ri; 
                *vptr += ri; 
            }
            break;
        case 4:
            foreach_reverse (i; 0..(len / 4))
            {
                uint* vptr = cast(uint*)(ptr + (i * 4));
                
                ulong ri = ~i;
                *vptr ^= (b << i) & ri;  
                *vptr ^= (a << i) & ri; 
                *vptr += ri; 
            }
            break;
        case 2:
            foreach_reverse (i; 0..(len / 2))
            {
                ushort* vptr = cast(ushort*)(ptr + (i * 2));
                
                ulong ri = ~i;
                *vptr ^= (b << i) & ri;  
                *vptr ^= (a << i) & ri; 
                *vptr += ri; 
            }
            break;
        default:
            foreach_reverse (i; 0..len)
            {
                ulong ri = ~i;
                ptr[i] ^= (b << i) & ri;  
                ptr[i] ^= (a << i) & ri; 
                ptr[i] += ri; 
            }
            break;
    } 

    foreach_reverse (i; 0..len)
    {
        int ii = cast(int)((b << i) % len);
        ubyte b0 = ptr[i];
        ptr[i] = ptr[ii];
        ptr[ii] = b0;
    }
} */