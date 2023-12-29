module godwit.stream;

import std.file;
import std.conv;
import std.algorithm.mutation;
import std.traits;

public enum Endianness : ubyte
{
    Native,
    LittleEndian,
    BigEndian
}

public enum Seek
{
    Start,
    Current,
    End
}

static @nogc void bencrypt(ubyte* ptr, int length, string key)
{
    if (key.length == 0)
        return; // Enforce a minimum key length

    foreach (int i; 0..length)
    {
        ptr[i] ^= (cast(ubyte)(key[(i + 3) % key.length]) << 3) | (cast(ubyte)(key[(i + 2) % key.length]) >> 5);
        ptr[i] += cast(ubyte)((i + 1) * 0x7F);
        ptr[i] ^= getPrime(i + 1) ^ key[(i + 1) % key.length];
        ptr[i] ^= 0xAB;
        ptr[i] ^= (cast(ubyte)(key[(i + 5) % key.length]) << 2) | (cast(ubyte)(key[(i + 4) % key.length]) >> 6);
    }
}

static @nogc void bdecrypt(ubyte* ptr, int length, string key)
{
    if (key.length == 0)
        return;

    foreach (int i; 0..length)
    {
        ptr[i] ^= (cast(ubyte)(key[(i + 5) % key.length]) << 2) | (cast(ubyte)(key[(i + 4) % key.length]) >> 6);
        ptr[i] ^= 0xAB;
        ptr[i] ^= getPrime(i + 1) ^ key[(i + 1) % key.length];
        ptr[i] -= cast(ubyte)((i + 1) * 0x7F);
        ptr[i] ^= (cast(ubyte)(key[(i + 3) % key.length]) << 3) | (cast(ubyte)(key[(i + 2) % key.length]) >> 5);
    }
}

static @nogc T bencrypt(T)(T val, string key)
{
    bencrypt(cast(ubyte*)&val, T.sizeof, key);
    return val;
}

static @nogc T bdecrypt(T)(T val, string key)
{
    bdecrypt(cast(ubyte*)&val, T.sizeof, key);
    return val;
}

private @nogc int getPrime(int n)
{
    if (n < 2)
        return 2;

    int count = 1;
    int num = 3;

    while (count < n)
    {
        bool isPrime = true;
        for (int i = 2; i * i <= num; i++)
        {
            if (num % i == 0)
            {
                isPrime = false;
                break;
            }
        }

        if (isPrime)
            count++;

        num += 2;
    }

    return num - 2;
}

/**
* Swaps the endianness of the provided value, if applicable.
*
* Params:
*     val = The value to swap endianness.
*
* Returns:
*   The value with swapped endianness.
*/
private static @nogc T makeEndian(T)(T val, Endianness endianness)
{
    version (LittleEndian)
    {
        if (endianness == Endianness.BigEndian)
        {
            ubyte[] bytes = (cast(ubyte*)&val)[0..T.sizeof];
            bytes = bytes.reverse();
            val = *cast(T*)&bytes[0];
        }
    }
    else version (BigEndian)
    {
        if (endianness == Endianness.LittleEndian)
        {
            ubyte[] bytes = (cast(ubyte*)&val)[0..T.sizeof];
            bytes = bytes.reverse();
            val = *cast(T*)&bytes[0];
        }
    }

    return val;
}

template ElementType(T) 
{
    static if (is(T == U[], U))
        alias ElementType!U ElementType;
    else
        alias T ElementType;
}

public class Stream
{
protected:
    string filePath;

public:
    ubyte[] data;
    ulong position;
    Endianness endianness;
    string key;

    this(ubyte[] data, Endianness endianness = Endianness.Native)
    {
        this.data = data.dup;
        this.endianness = endianness;
    }

    this(byte[] data, Endianness endianness = Endianness.Native)
    {
        this.data = cast(ubyte[])data.dup;
        this.endianness = endianness;
    }

    this(string filePath, Endianness endianness = Endianness.Native)
    {
        this.data = cast(ubyte[])std.file.read(filePath);
        this.endianness = endianness;
        this.filePath = filePath;
    }

    @nogc bool mayRead()(int size = 1)
    {
        return position + size - 1 < data.length;
    }

    @nogc bool mayRead(T)()
    {
        return position + T.sizeof - 1 < data.length;
    }

    @nogc void encrypt(string key)
    {
        bencrypt(cast(ubyte*)&data[0], cast(int)data.length, key);
    }

    @nogc void decrypt(string key)
    {
        bdecrypt(cast(ubyte*)&data[0], cast(int)data.length, key);
    }

    /**
    * Moves the position in the stream by the size of type T.
    *
    * Params:
    *     T = The size of type to move the position by.
    */
    @nogc void step(T)()
    {
        position += T.sizeof;
    }

    /**
    * Moves the position in the stream by the size of type T * elements.
    *
    * Params:
    *     T = The size of type to move the position by.
    *     count = The number of elements.
    */
    @nogc void step(T)(int count)
    {
        position += T.sizeof * count;
    }

    /**
    * Seeks to a new position in the stream based on the provided offset and seek direction.
    * Does not work like a conventional seek, and will read type T from the stream, using that as the seek offset.
    *
    * Params:
    *     T = The offset value for seeking.
    *     SEEK = The direction of the seek operation (Start, Current, or End).
    */
    @nogc void seek(T, Seek SEEK)()
        if (isIntegral!T)
    {
        static if (SEEK == Seek.Start)
        {
            position = peek!T;
        }
        else static if (SEEK == Seek.Current)
        {
            position += peek!T;
        }
        else
        {
            position = data.length - peek!T;
        }
    }

    /**
    * Reads the next value from the stream of type T.
    *
    * Params:
    *     T = The type of data to be read.
    *
    * Returns:
    *   The value read from the stream.
    */
    @nogc T read(T)()
        if (!isArray!T)
    {
        if (data.length <= position)
            return T.init;

        scope(exit) step!T;
        T val = *cast(T*)(&data[position]);
        return bdecrypt!T(makeEndian!T(val, endianness), key);
    }

    /**
    * Peeks at the next value from the stream of type T without advancing the stream position.
    *
    * Params:
    *     T = The type of data to peek.
    *
    * Returns:
    *   The value peeked from the stream.
    */
    @nogc T peek(T)()
        if (!isArray!T)
    {
        if (data.length <= position)
            return T.init;

        T val = *cast(T*)(&data[position]);
        return bdecrypt!T(makeEndian!T(val, endianness), key);
    }

    /**
    * Reads an array of type T from the stream.
    *
    * Params:
    *     T = The type of data to be read.
    *
    * Returns:
    *   An array read from the stream.
    */
    T read(T)()
        if (isArray!T)
    {
        T items;
        foreach (ulong i; 0..read7EncodedInt())
            items ~= read!(ElementType!T);
        return items;
    }

    /**
    * Peeks an array of type T from the stream without advancing the stream position.
    *
    * Params:
    *     T = The type of data to peek.
    *
    * Returns:
    *   An array peeked from the stream.
    */
    T peek(T)()
        if (isArray!T)
    {
        ulong _position = position;
        scope(exit) position = _position;
        return read!T;
    }

    /**
    * Writes the provided value to the stream.
    *
    * Params:
    *     T = The type of data to be written.
    *     val = The value to be written to the stream.
    */
    @nogc void write(T)(T val)
    {
        if (data.length <= position)
            return;

        scope(exit) step!T;
        *cast(T*)(&data[position]) = bencrypt!T(makeEndian!T(val, endianness), key);
    }

    /**
    * Writes the provided value to the stream without advancing the stream position.
    *
    * Params:
    *     T = The type of data to be written.
    *     val = The value to be written to the stream.
    */
    @nogc void put(T)(T val)
    {
        if (data.length <= position)
            return;

        *cast(T*)(&data[position]) = bencrypt!T(makeEndian!T(val, endianness), key);
    }

    /**
    * Reads multiple values of type T from the stream.
    *
    * Params:
    *     T = The type of data to be read.
    *     count = The number of values to read from the stream.
    *
    * Returns:
    *   An array of values read from the stream.
    */
    T[] read(T)(int count)
    {
        T[] items;
        foreach (ulong i; 0..count)
            items ~= read!T;
        return items;
    }

    /**
    * Peeks at multiple values of type T from the stream without advancing the stream position.
    *
    * Params:
    *     T = The type of data to peek.
    *     count = The number of values to peek from the stream.
    *
    * Returns:
    *   An array of values peeked from the stream.
    */
    T[] peek(T)(int count)
    {
        ulong _position = position;
        scope(exit) position = _position;
        return read!T(count);
    }

    /**
    * Writes multiple values of type T to the stream.
    *
    * Params:
    *     T = The type of data to be written.
    *     items = An array of values to be written to the stream.
    */
    @nogc void write(T, bool NOPREFIX = false)(T[] items)
    {
        static if (!NOPREFIX)
            write7EncodedInt(cast(int)items.length);

        foreach (ulong i; 0..items.length)
            write!T(items[i]);
            
    }

    /**
    * Writes multiple values of type T to the stream without advancing the stream position.
    *
    * Params:
    *     T = The type of data to be written.
    *     items = An array of values to be written to the stream.
    */
    @nogc void put(T, bool NOPREFIX = false)(T[] items)
    {
        ulong _position = position;
        scope(exit) position = _position;
        write!(T, NOPREFIX)(items);
    }

    /**
    * Reads a string from the stream considering the character width and prefixing.
    *
    * Params:
    *     CHAR = The character type used for reading the string (char, wchar, or dchar).
    *     PREFIXED = Indicates whether the string is prefixed. Default is false.
    *
    * Returns:
    *   The read string from the stream.
    */
    string readString(CHAR, bool PREFIXED = false)()
        if (is(CHAR == char) || is(CHAR == dchar) || is(CHAR == wchar))
    {
        static if (PREFIXED)
        {
            import std.stdio;
            return read!(CHAR[]).to!string;
        }
            

        char[] chars;
        while (peek!CHAR != '\0')
            chars ~= read!CHAR;
        return makeEndian!string(chars.to!string, endianness);
    }

    /**
    * Reads a string from the stream considering the character width and prefixing without advancing the stream position.
    *
    * Params:
    *     CHAR = The character type used for reading the string (char, wchar, or dchar).
    *     PREFIXED = Indicates whether the string is prefixed. Default is false.
    *
    * Returns:
    *   The read string from the stream.
    */
    string peekString(CHAR, bool PREFIXED = false)()
        if (is(CHAR == char) || is(CHAR == dchar) || is(CHAR == wchar))
    {
        ulong _position = position;
        scope(exit) position = _position;
        return readString!(CHAR, PREFIXED);
    }

    /**
    * Writes a string to the stream considering the character width and prefixing.
    *
    * Params:
    *     CHAR = The character type used for writing the string (char, wchar, or dchar).
    *     PREFIXED = Indicates whether the string is prefixed. Default is false.
    *     str = The string to be written to the stream.
    */
    void writeString(CHAR, bool PREFIXED = false)(string str)
        if (is(CHAR == char) || is(CHAR == dchar) || is(CHAR == wchar))
    {
        if (!PREFIXED && str.length > 0 && str[$-1] != '\0')
            str ~= '\0';

        write!(CHAR, !PREFIXED)(str.dup.to!(CHAR[]));
    }

    /**
    * Writes a string into the stream considering the character width and prefixing without advancing the stream position.
    *
    * Params:
    *     CHAR = The character type used for writing the string (char, wchar, or dchar).
    *     PREFIXED = Indicates whether the string is prefixed. Default is false.
    *     str = The string to be put into the stream.
    */
    void putString(CHAR, bool PREFIXED = false)(string str)
        if (is(CHAR == char) || is(CHAR == dchar) || is(CHAR == wchar))
    {
        if (!PREFIXED && str.length > 0 && str[$-1] != '\0')
            str ~= '\0';
        
        put!(CHAR, !PREFIXED)(str.dup.to!(CHAR[]));
    }

    /**
    * Reads an integer value encoded in 7 bits from the stream.
    *
    * Returns:
    *   The integer value read from the stream.
    */
    @nogc int read7EncodedInt()
    {
        int result = 0;
        int shift = 0;

        foreach (int i; 0..5)
        {
            ubyte b = read!ubyte();
            result |= cast(int)(b & 0x7F) << shift;
            if ((b & 0x80) == 0)
                return result;
            shift += 7;
        }
        
        return result;
    }

    /**
    * Writes an integer value encoded in 7 bits to the stream.
    *
    * Params:
    *     val = The integer value to be written to the stream.
    */
    @nogc void write7EncodedInt(int val)
    {
        foreach (int i; 0..5)
        {
            byte b = cast(byte)(val & 0x7F);
            val >>= 7;
            if (val != 0)
                b |= 0x80;
            write!ubyte(b);
            if (val == 0)
                return;
        }
    }

    /**
    * Reads a type from the stream using optional fields.
    *
    * Params:
    *     T = The type to be read from the stream.
    *     ARGS... = The arguments for optional fields.
    *
    * Returns:
    *   The read type read from the stream.
    */
    T readPlasticized(T, ARGS...)()
        if (ARGS.length % 3 == 0)
    {
        T val;
        foreach (string field; FieldNameTuple!T)
        {
            bool cread = true;
            foreach (i, ARG; ARGS)
            {
                static if (i % 3 == 0)
                {
                    static assert(is(typeof(ARG) == string),
                        "Field name expected, found " ~ ARG.stringof);  
                }
                else static if (i % 3 == 1)
                {
                    static assert(is(typeof(ARG) == string),
                        "Conditional field name expected, found " ~ ARG.stringof);
                }
                else
                {
                    if (field == ARGS[i - 2] && __traits(getMember, val, ARGS[i - 1]) != ARG)
                        cread = false;
                }
            }
            if (cread)
                __traits(getMember, val, field) = read!(typeof(__traits(getMember, val, field)));
        }
        return val;
    }

    void flush(string filePath)
    {
        if (filePath != null)
            std.file.write(filePath, data);
    }

    void flush()
    {
        if (this.filePath != null)
            std.file.write(this.filePath, data);
    }
}