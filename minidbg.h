#ifndef MINIDBG_H
#define MINIDBG_H

#include<vector>
using namespace std;

typedef enum{
	EXEC = 0,
	WRITE =  1,
	RW  = 3} brktype;

typedef enum{
	LEN_BYTE = 0,
	LEN_WORD =  1,
	LEN_DWORD = 3} brklen;
	
struct breakdata{
	DWORD addr;
	brktype type; //Dr7��4bit���ɑΉ�����B
	brklen len;
	breakdata();
	void setDr7(DWORD& dr7,int idx);
	void unsetDr7(DWORD& dr7,int idx);
};

class debugger{
public:
	PROCESS_INFORMATION pi;
private:
	//PROCESS_INFORMATION pi;
	vector<int> setbs; //breakpoint�p�̂��(�ǂ̂�)
	breakdata brks[4];
	void settrap();
	void debugexception(DWORD debe,void (*breaklistener)(int));
	void createdprocess();
	void closedprocess();
	void catchbreak(void (*breaklistener)(int));
	
public:
	void init();
	void run(LPSTR procname);
	void getmemory(LPCVOID addr,LPVOID bufs,size_t len);
	void setbreak(DWORD dwAddress,int p,brktype type,brklen len); //0�`3�̂�
	void setrunbreak(DWORD dwAddress,int p); //0�`3�̂�
	void unsetbreak(int p); //0�`3�̂�
	void listen(void (*breaklistener)(int));
	//break���ɁA�d�|�����|�C���^�̒l�������Ă���B
	void outcontext();
};

#endif