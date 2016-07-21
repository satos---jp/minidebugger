#ifndef MINIDBG_H
#define MINIDBG_H

#include<vector>
using namespace std;

class debugger{
private:
	PROCESS_INFORMATION pi;
	vector<int> setbs; //breakpoint�p�̂��(�ǂ̂�)
	void settrap();
	void outcontext();
	void debugexception(DWORD debe,void (*breaklistener)(int));
	void createdprocess();
	void closedprocess();


public:
	void init();
	void run(LPSTR procname);
	void getmemory(LPCVOID addr,LPVOID bufs,int len);
	void setbreak(DWORD dwAddress,int p); //0�`3�̂�
	void unsetbreak(int p); //0�`3�̂�
	void listen(void (*breaklistener)(int));
	//break���ɁA�d�|�����|�C���^�̒l�������Ă���B
};

#endif