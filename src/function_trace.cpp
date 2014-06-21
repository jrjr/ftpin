/*
 * Copyright 2014 James Ritchey
 * GNU GPLv3
 * 
 */
#include <iostream>
#include <fstream>
#include <sstream>
#include <regex>
#include "pin.H"

ofstream TraceFile;
static stringstream outfilestream;
PIN_LOCK lock;
regex needle;
bool dostacktrace=false;

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
    "o", "basic_block_trace.txt", "specify output file name");
KNOB<string> KnobRegex(KNOB_MODE_WRITEONCE, "pintool",
    "r", ".*?", "specify regex functions to trace");
KNOB<unsigned int> KnobStackTrace(KNOB_MODE_WRITEONCE, "pintool",
    "s", "0", "specify whether to attempt stack trace on function traces");

// This function is called when the application exits
VOID Fini(INT32 code, VOID *v)
{
    // Write to a file since cout and cerr maybe closed by the application
    TraceFile.close();
}

INT32 Usage()
{
    cerr << "This tool traces functions via a regex" << endl;
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

string ImgToString(IMG img)
{
	string imgname;		
	if (IMG_Valid(img))
		imgname = IMG_Name(img);
	else
		imgname = "Unknown";	
	return imgname;
}

string RtnToString(RTN rtn)
{
	string rtnname;
	if (RTN_Valid(rtn))
		rtnname = RTN_Name(rtn);
	else
		rtnname="Unknown";
	return rtnname;
}

pair<unsigned int, unsigned int> StackRange(CONTEXT *ctx)
{
	unsigned int fs = (unsigned int)PIN_GetContextReg(ctx, REG_SEG_FS_BASE);
	unsigned int topofstack = *(unsigned int *)(fs +4);
	unsigned int bottomofstack = *(unsigned int *)(fs + 8);
	return make_pair<unsigned int, unsigned int>(topofstack, bottomofstack);
}

void UnwindStack(CONTEXT *ctx)
{
	pair<unsigned int, unsigned int> stackrange = StackRange(ctx);
	unsigned int ebpframe = (unsigned int)PIN_GetContextReg(ctx, REG_EBP);
	unsigned int top = get<0>(stackrange);
	unsigned int bottom = get<1>(stackrange);
	outfilestream << "Stack Trace EBP frame: " << ebpframe<<endl;
	
	while(ebpframe)
	{
		if (ebpframe & 3)
			break; // not dword aligned
		unsigned int returnaddr = *(unsigned int *)(ebpframe + 4);
		PIN_LockClient();
		IMG frameimage = IMG_FindByAddress(returnaddr);
		RTN framertn = RTN_FindByAddress(returnaddr);
		PIN_UnlockClient();
		string imgname;
		outfilestream << "Return address: " << returnaddr<< " ";
		outfilestream << "Image: " << ImgToString(frameimage) << " ";
		outfilestream << "RTN: " << RtnToString(framertn)<<endl;
		
		unsigned int nextframe = *(unsigned int *)(ebpframe);
		if (nextframe <= ebpframe)
			break; // next frame is lower than this one
		ebpframe = nextframe;
	}
}


VOID BeforeRtn(THREADID tid, ADDRINT ip, CONTEXT *ctx, unsigned int arg0, unsigned int arg1, unsigned int arg2, unsigned int arg3, unsigned int arg4, unsigned int arg5, unsigned int arg6, unsigned int arg7, unsigned int arg8)
{
	PIN_GetLock(&lock, tid+1);

	PIN_LockClient();
	IMG img = IMG_FindByAddress(ip);
	RTN rtn = RTN_FindByAddress(ip);
	PIN_UnlockClient();
	
	if (outfilestream.rdbuf()->in_avail() != 0)
	{
		outfilestream.flush();
		TraceFile << outfilestream.str();
		TraceFile.flush();
		outfilestream.str("");
	}
	
	outfilestream << "TID: " << tid << " :IP: " << ip << " :Name: " << ImgToString(img) <<":"<<RtnToString(rtn) << " :Possible args - Arg0: " <<hex << arg0 << " :Arg1: " << arg1 << " :Arg2: " <<arg2 << " :Arg3: " << arg3 << " :Arg4: " <<arg4 << " :Arg5: " << arg5 << " :Arg6: " <<arg6<< " :Arg7: "<<arg7<< " :Arg8: " << arg8<< endl;
	if (dostacktrace)
		UnwindStack(ctx);
	
	PIN_ReleaseLock(&lock);	
}

VOID AfterRtn(THREADID tid, ADDRINT ip, ADDRINT ret)
{
	PIN_GetLock(&lock, tid+1);
	PIN_LockClient();
	IMG img = IMG_FindByAddress(ip);
	RTN rtn = RTN_FindByAddress(ip);
	PIN_UnlockClient();
	if (outfilestream.rdbuf()->in_avail() != 0)
	{
		outfilestream.flush();
		TraceFile << outfilestream.str();
		TraceFile.flush();
		outfilestream.str("");
	}
	outfilestream << "TID: " << tid << " :IP: " << ip << " :Name: " << ImgToString(img) <<":"<<RtnToString(rtn) << " :Ret: " <<hex << ret << endl;
	
	PIN_ReleaseLock(&lock);	
}

VOID Image(IMG img, VOID *v)
{
	if (IMG_Valid(img))
	{
		outfilestream <<hex<< "Image loaded: " <<IMG_Name(img) << " at "<<IMG_StartAddress(img)<<endl;
	}
	
	for (SYM sym = IMG_RegsymHead(img); SYM_Valid(sym); sym = SYM_Next(sym))
    {
        string function = PIN_UndecorateSymbolName(SYM_Name(sym), UNDECORATION_NAME_ONLY);

		stringstream haystack;
		haystack << IMG_Name(img) << ":" << function;
		if (regex_search(haystack.str(), needle))
		{
			outfilestream << KnobRegex.Value() << " matches " << haystack.str() << endl;
			RTN rtn = RTN_FindByAddress(IMG_LowAddress(img) + SYM_Value(sym));
			if (RTN_Valid(rtn))
			{
				outfilestream << RTN_Name(rtn) <<" loaded"<<endl;
				RTN_Open(rtn);
				
				RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)BeforeRtn,
											IARG_THREAD_ID,
											IARG_INST_PTR,
											IARG_CONTEXT,
											IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
											IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
											IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
											IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
											IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
											IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
											IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
											IARG_FUNCARG_ENTRYPOINT_VALUE, 7,
											IARG_FUNCARG_ENTRYPOINT_VALUE, 8,
											IARG_END);
				RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)AfterRtn,
											IARG_THREAD_ID,
											IARG_INST_PTR,
											IARG_FUNCRET_EXITPOINT_VALUE,
											IARG_END);
				
				RTN_Close(rtn);
			}
		}
		
	}
	
	if (outfilestream.rdbuf()->in_avail() != 0)
	{
		outfilestream.flush();
		TraceFile << outfilestream.str();
		TraceFile.flush();
		outfilestream.str("");
	}
}

int main(int argc, char * argv[])
{
	PIN_InitSymbols();
	
    if (PIN_Init(argc, argv)) return Usage();
	
	PIN_InitLock(&lock);
    TraceFile.open(KnobOutputFile.Value());
	needle.assign(KnobRegex.Value(), regex_constants::icase);
	
	if (KnobStackTrace.Value())
		dostacktrace=true;
		
	IMG_AddInstrumentFunction(Image, 0);
    PIN_AddFiniFunction(Fini, 0);
    
    PIN_StartProgram();
    
    return 0;
}
