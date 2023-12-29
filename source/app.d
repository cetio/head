import std.stdio;
import godwit.stream;
import godwit.formats;

void main()
{
	PE pe = PE.read(r"C:\Users\stake\source\repos\head\head.exe");
	writeln(pe.optionalImage);
}