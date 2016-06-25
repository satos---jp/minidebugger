#include<windows.h>
#include<cstdio>
//#pragma comment(lib,"user32.lib");
//#pragma comment(lib,"Advapi32.lib");
#define EFLAGS_TF 0x00000100 /* シングルステップモードフラグ */


struct debugger{
	void init(){
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
		//自プロセスの権利を上げる
	}
	PROCESS_INFORMATION pi;
	void run(){
		STARTUPINFO si = {};
		BOOL bcre = CreateProcess(NULL,(LPSTR)"oe.exe",NULL,NULL,FALSE,
			DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS,
			NULL, NULL, &si, &pi);
		//0x401280
		//main .. 0x4013c0
		if(bcre == FALSE){
			MessageBox(NULL,"Miss to run process","notifi",MB_OK);
			exit(-1);
		}
		//create
	}
	
	void outcontext(){
		CONTEXT ct = {};
		ct.ContextFlags = 
			CONTEXT_DEBUG_REGISTERS | CONTEXT_CONTROL | CONTEXT_INTEGER;
		GetThreadContext(pi.hThread,&ct);
		/*
		printf("eax .. %lx\n",ct.Eax);
		printf("ebx .. %lx\n",ct.Ebx);
		printf("ecx .. %lx\n",ct.Ecx);
		printf("edx .. %lx\n",ct.Edx);
		printf("esi .. %lx\n",ct.Esi);
		printf("edi .. %lx\n",ct.Edi);
		printf("codesegment .. %lx\n",ct.SegCs);
		printf("esp .. %lx\n",ct.Esp);
		printf("ebp .. %lx\n",ct.Ebp);	
		*/
		printf("eip .. %lx\n",ct.Eip);
	}
	
	void settrap(){
		//トラップフラグは、1度かかるとなくなるので再度建てること。
		CONTEXT ct = {};
		ct.ContextFlags = CONTEXT_CONTROL;
		GetThreadContext(pi.hThread,&ct);
		ct.ContextFlags = CONTEXT_CONTROL;
		ct.EFlags |= EFLAGS_TF;
		SetThreadContext(pi.hThread,&ct);
	}
	
	void setbreak(DWORD dwAddress){
		CONTEXT ctx = { CONTEXT_DEBUG_REGISTERS };
		GetThreadContext( pi.hThread, &ctx );
		ctx.Dr0 = dwAddress;
		ctx.Dr7 |= 0x00000001;
		SetThreadContext( pi.hThread, &ctx );
	}
	
	void createdprocess(){
		printf("maked process\n");
		outcontext();
		//setbreak(0x4013d6);
		setbreak(0x4013fb);
		//settrap();
	}
	
	void closedprocess(){
		//MessageBox(NULL,"closing process","notifi",MB_OK);
		printf("closing process\n");
		outcontext();
	}
	
	void debugexception(DWORD debe){
		CONTEXT ctx = { CONTEXT_CONTROL | CONTEXT_DEBUG_REGISTERS };
		switch(debe){
		case EXCEPTION_BREAKPOINT:
			printf("exception breakpoint\n");
			outcontext();
			break;
		case EXCEPTION_SINGLE_STEP:
			printf("singl breaked\n");
			outcontext();
			GetThreadContext( pi.hThread, &ctx );
			if( ctx.Dr6 & 0x00004000 ) { // SingleStep フラグ
				printf("EIP: 0x%08lX\n", ctx.Eip );
				setbreak(0x4013fb);
			} else {
				printf("BreakPoint.  Dr6: 0x%08lX\n", ctx.Dr6);
				ctx.Dr6 = 0x00000000; // DebugStatus はクリアされない
				ctx.Dr7 = 0x00000000; // とりあえず全部クリア
				SetThreadContext( pi.hThread, &ctx );
				settrap();
			}
			
			//Sleep(100);
			//fprintf(stderr,"hoge ");
			break;
		case EXCEPTION_ACCESS_VIOLATION:
			break;
		default:
			printf("mistery except\n");
			break;
		}
	}
	
	void listen(){
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
				createdprocess();
				break;
			case CREATE_THREAD_DEBUG_EVENT:
				//MessageBox(NULL,"maked thread","notifi",MB_OK);
				printf("maked thread\n");
				break;
			case EXIT_PROCESS_DEBUG_EVENT:
				closedprocess();
				goto Exit;
				break;
			case LOAD_DLL_DEBUG_EVENT:
				break;
			case UNLOAD_DLL_DEBUG_EVENT:
				break;
			case OUTPUT_DEBUG_STRING_EVENT:
				break;
			case EXCEPTION_DEBUG_EVENT:
				printf("exception\n");
				debugexception(de.u.Exception.ExceptionRecord.ExceptionCode);
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
};

int main(){
	debugger de;
	de.init();
	de.run();
	de.listen();
	//MessageBox(NULL,"finis debugging","notifi",MB_OK);
	return 0;
}


