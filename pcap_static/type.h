
#ifndef __TYPE_H__
#define __TYPE_H__

#define MY_DBEUG

#ifdef MY_DBEUG
#define DEBUGPRINT(...) printf(__VA_ARGS__)
#else
#define DEBUGPRINT(...) 
#endif

#define IN 
#define OUT
#define INOUT

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif
#define ERROR_SUCCESS 0
#define ERROR_FAILED -1
//����32�ֽڣ�16�ֽڣ�8�ֽ�����
typedef unsigned int uint;
typedef unsigned short ushort;
typedef unsigned char uchar;

#endif
