#pragma once
#define F_SETFL 1
#define O_NONBLOCK 1
int fcntl(int fd,int command,int flags);
