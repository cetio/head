import std.stdio;
import godwit.stream;
import godwit.formats;
import godwit.encryption;

void main()
{
	int val = 111222333;
	//string val = "A";

	string key = "LIEiR7RTKz71x8kCiKq7VUMpqe70Zhrv";
	writeln("ENCRYPT: ", btencryp(val, key));
	writeln("DECRYPT: ", btdecryp(btencryp(val, key), key));
	auto a = btencryp(val, key);
	writeln("BYTES: ", (cast(ubyte*)&a)[0 .. 4]);

	key = "EBY5mwzN99rdieMXwVKoVqrYJGg4nmf2";
	writeln("ENCRYPT: ", btencryp(val, key));
	writeln("DECRYPT: ", btdecryp(btencryp(val, key), key));
	auto b = btencryp(val, key);
	writeln("BYTES: ", (cast(ubyte*)&b)[0 .. 4]);

	key = "sNMuh9kXFkpSAMOQZpMkiqAXVXXPF4GB";
	writeln("ENCRYPT: ", btencryp(val, key));
	writeln("DECRYPT: ", btdecryp(btencryp(val, key), key));
	auto c = btencryp(val, key);
	writeln("BYTES: ", (cast(ubyte*)&c)[0 .. 4]);

	key = "w8EAbOPYefqFtjR41xFL8C0z0UTjOl9y";
	writeln("ENCRYPT: ", btencryp(val, key));
	writeln("DECRYPT: ", btdecryp(btencryp(val, key), key));
	auto d = btencryp(val, key);
	writeln("BYTES: ", (cast(ubyte*)&d)[0 .. 4]);

	key = "uw3PxqbG4pjbKwPhwR0eSI3huFhhg04B";
	writeln("ENCRYPT: ", btencryp(val, key));
	writeln("DECRYPT: ", btdecryp(btencryp(val, key), key));
	auto e = btencryp(val, key);
	auto f = btdecryp(btencryp(val, key), key);
	writeln("EBYTES: ", (cast(ubyte*)&e)[0..4]);
	writeln("DBYTES: ", (cast(ubyte*)&f)[0..4]);
	writeln("NBYTES: ", (cast(ubyte*)&val)[0..4]);

	Stream stream = new Stream(r"C:\Users\stake\Downloads\Web_Razer_Synapse_Installer_v2.21.24.41.exe");
	import std.datetime;
	auto start = Clock.currTime();
	stream.encrypt("uw3PxqbG4pjbKwPhwR0eSI3huFhhg04B");
	auto end = Clock.currTime();
	stream.flush();
	writeln("Encryption time:", (end - start).split!("msecs").msecs, "ms");
}