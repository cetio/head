import std.stdio;
import godwit.stream;
import godwit.formats;
import godwit.bse;
import std.datetime;
import crypto.aes;
import crypto.padding;
import std.conv;

void main()
{
	Stream stream = new Stream(r"C:\Users\stake\Downloads\test.exe");
    auto start = Clock.currTime;
    stream.encrypt("yKxPczCgvMp94Bn3NsVf28m6rjqwUD5t");
    auto end = Clock.currTime;
    writeln("BSE256 ", (end - start).split!("msecs").msecs, "ms");
    ubyte[] iv = [1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 1, 2, 3, 4];
    start = Clock.currTime;
    AESUtils.encrypt!AES256(stream.data, "yKxPczCgvMp94Bn3NsVf28m6rjqwUD5t", iv, PaddingMode.PKCS5);
    end = Clock.currTime;
    writeln("AES256 ", (end - start).split!("msecs").msecs, "ms");
}