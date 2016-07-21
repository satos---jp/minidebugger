#include<windows.h>
#include<cstdio>
//#pragma comment(lib,"user32.lib");
//#pragma comment(lib,"Advapi32.lib");
#define EFLAGS_TF 0x00000100 /* シングルステップモードフラグ */
#define eprintf(...) fprintf(stderr,__VA_ARGS__)
#define rep(i,n) for(int i=0;i<(int(n));i++)
#include "minidbg.h"

void debugger::init(){
		
	HANDLE ht;
	TOKEN_PRIVILEGES tp;
	OpenProcessToken(
		GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY | TOKEN_READ,
		&ht);
	LUID luid;
	LookupPrivilegeValue(NULL,SE_DEBUG_NAME,&luid);
	tp.PrivilegeCount=1;
	tp.Privileges[0].Luid=luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	AdjustTokenPrivileges(ht,FALSE,&tp,0,0,0);
	CloseHandle(ht);
	//自プロセスの権限を上げる
}

void debugger::run(LPSTR procname){
	setbs.clear();
	STARTUPINFO si = {};
	WCHAR procdir[256];
	lstrcpyn((LPSTR)procdir,procname,256);
	//256文字。
	int ls = lstrlen((LPSTR)procdir); ls--;
	while(ls>=0){
		if(procdir[ls]!='/'){
			procdir[ls]='\0';
			ls--;
		}
		else break;
	}
	if(ls<0){
		procdir[0]='/';
		procdir[1]='\0';
	}		
	
	BOOL bcre = CreateProcess(NULL,procname,NULL,NULL,FALSE,
		DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS,
		NULL,(LPSTR)procdir, &si, &pi);
	//0x401280
	//main .. 0x4013c0
	if(bcre == FALSE){
		MessageBox(NULL,"Miss to run process","notifi",MB_OK);
		exit(-1);
	}
}
	
void debugger::getmemory(LPCVOID addr,LPVOID bufs,int len){
	BOOL b = ReadProcessMemory(pi.hThread,addr,bufs,len*4,NULL);
	if(!b)eprintf("failed to read memory\n");
}
	
void debugger::outcontext(){
	CONTEXT ct = {};
	ct.ContextFlags = 
		CONTEXT_DEBUG_REGISTERS | CONTEXT_CONTROL | CONTEXT_INTEGER;
	GetThreadContext(pi.hThread,&ct);
	
	printf("eax .. %lx\n",ct.Eax);
	printf("ebx .. %lx\n",ct.Ebx);
	printf("ecx .. %lx\n",ct.Ecx);
	printf("edx .. %lx\n",ct.Edx);
	printf("esi .. %lx\n",ct.Esi);
	printf("edi .. %lx\n",ct.Edi);
	printf("codesegment .. %lx\n",ct.SegCs);
	printf("esp .. %lx\n",ct.Esp);
	printf("ebp .. %lx\n",ct.Ebp);	
	
	printf("eip .. %lx\n",ct.Eip);
}
	
void debugger::settrap(){
	//トラップフラグは、1度かかるとなくなるので再度建てること。
	CONTEXT ct = {};
	ct.ContextFlags = CONTEXT_CONTROL;
	GetThreadContext(pi.hThread,&ct);
	ct.ContextFlags = CONTEXT_CONTROL;
	ct.EFlags |= EFLAGS_TF;
	SetThreadContext(pi.hThread,&ct);
}
	
void debugger::setbreak(DWORD dwAddress,int p){
	CONTEXT ctx = { CONTEXT_DEBUG_REGISTERS };
	GetThreadContext( pi.hThread, &ctx );
	
	if(p==0)ctx.Dr0 = dwAddress;
	else if(p==1)ctx.Dr1 = dwAddress;
	else if(p==2)ctx.Dr2 = dwAddress;
	else if(p==3)ctx.Dr3 = dwAddress;
	else eprintf("invalid break number %d\n",p);
	
	ctx.Dr7 |= (0x1 << (p * 2));
	SetThreadContext( pi.hThread, &ctx );
}

void debugger::unsetbreak(int p){
	CONTEXT ctx = { CONTEXT_DEBUG_REGISTERS };
	GetThreadContext( pi.hThread, &ctx );
	ctx.Dr7 &= ~(0x1 << (p * 2));
	SetThreadContext( pi.hThread, &ctx );
	vector<int> tbs;
	rep(i,setbs.size()){
		if(setbs[i]!=p)tbs.push_back(setbs[i]);
	}
	swap(tbs,setbs);
}


void debugger::createdprocess(){
	printf("maked process\n");
	outcontext();
	//setbreak(0x4013d6);
	//setbreak(0x430450);
	//settrap();
}
	
void debugger::closedprocess(){
	//MessageBox(NULL,"closing process","notifi",MB_OK);
	printf("closing process\n");
	outcontext();
}

	
	
void debugger::debugexception(DWORD debe,void (*breaklistener)(int)){
	CONTEXT ctx = { CONTEXT_CONTROL | CONTEXT_DEBUG_REGISTERS };
	switch(debe){
	case EXCEPTION_BREAKPOINT:
		printf("exception breakpoint\n");
		outcontext();
		break;
	case EXCEPTION_SINGLE_STEP:
		printf("singl breaked\n");
		//outcontext();
		{
			GetThreadContext( pi.hThread, &ctx );
			int bln=-1;
			if( ctx.Dr6 & 0x00004000 ) { // SingleStep フラグ
				printf("EIP: 0x%08lX\n", ctx.Eip );
				rep(j,setbs.size()){
					CONTEXT ctx = { CONTEXT_DEBUG_REGISTERS };
					GetThreadContext( pi.hThread, &ctx );
					ctx.Dr7 |= (0x1 << (setbs[j] * 2));
					SetThreadContext( pi.hThread, &ctx );
				}
				setbs.clear();
				//setbreak(0x430450);
			}
			else {
				printf("BreakPoint.  Dr6: 0x%08lX\n", ctx.Dr6);
				bln=0;
				outcontext();
				ctx.Dr6 = 0x00000000; // DebugStatus はクリアされない
				rep(i,4){
					if(ctx.Dr6 & (0x1<<i)){
						bln |= (0x1<<i);
						setbs.push_back(i);
						ctx.Dr7 &= ~(0x1 << (i * 2));
					}
				}
				SetThreadContext( pi.hThread, &ctx );
				settrap();
			}
			breaklistener(bln);
		}
		break;
	case EXCEPTION_ACCESS_VIOLATION:
		break;
	default:
		printf("mistery except\n");
		break;
	}
}
	
void debugger::listen(void (*breaklistener)(int)){
	DEBUG_EVENT de = {};
		
	for(;;){
		if(!WaitForDebugEvent(&de,INFINITE)){
			MessageBox(NULL,"cant get debug event","notifi",MB_OK);
			goto Exit;
		}
		DWORD contst = DBG_CONTINUE;
		//DWORD contst = DBG_EXCEPTION_NOT_HANDLED;
		printf("debugvent ............... %lx\n",de.dwDebugEventCode);
		switch(de.dwDebugEventCode){
		case CREATE_PROCESS_DEBUG_EVENT:
			//3
			createdprocess();
			break;
		case CREATE_THREAD_DEBUG_EVENT:
			//2
			//MessageBox(NULL,"maked thread","notifi",MB_OK);
			printf("maked thread\n");
			break;
		case EXIT_PROCESS_DEBUG_EVENT:
			//5
			closedprocess();
			goto Exit;
			break;
		case EXIT_THREAD_DEBUG_EVENT:
			//4
			break;
		case LOAD_DLL_DEBUG_EVENT:
			//6
			break;
		case UNLOAD_DLL_DEBUG_EVENT:
			//7
			break;
		case OUTPUT_DEBUG_STRING_EVENT:
			//8
			break;
		case EXCEPTION_DEBUG_EVENT:
			//1
			printf("exception\n");
			debugexception(de.u.Exception.ExceptionRecord.ExceptionCode,breaklistener);
			break;
		default:
			printf("unknown break %lx\n",de.dwDebugEventCode);
			break;
		}
		
		if(!ContinueDebugEvent(de.dwProcessId,de.dwThreadId,contst)){
			printf("continue failed\n");
			break;
		}
	}
	
	Exit:;
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);	
}


void hoge(int p){
	printf("%d\n",p);
}

int main(){
	debugger de;
	de.init();
	de.run((LPSTR)"../specimen/x.exe");
	de.listen(hoge);
	MessageBox(NULL,"finis debugging","notifi",MB_OK);
	return 0;
}


