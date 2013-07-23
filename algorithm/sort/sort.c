#include "sort.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>

#define TEST_SIZE	1024
#define DATA_FILE	"data"
#define INSERT_FILE	"insert.txt"
#define SELECT_FILE	"select.txt"
#define QUICK_FILE	"quick.txt"
#define BUBBLE_FILE	"bubble.txt"
#define HEAP_FILE	"heap.txt"
#define MERGE_FILE	"merge.txt"
#define MERGE_FILE2	"merge2.txt"

typedef int (*sort_func_t)(unsigned *, int , int (*cmp_cun)(unsigned *, unsigned *), int );

int cmp(unsigned *, unsigned *);
void test(sort_func_t sort_func, char *file, int sort);

unsigned int sort_data[TEST_SIZE];
unsigned int data[TEST_SIZE];
FILE *pf=NULL;

int main(int argc, char *argv[])
{
	int i=0;
	int fd;
	
	printf("start...\r\n");
	fd = open("/dev/urandom", O_RDONLY);
	if(fd < 0)
	{
		perror("random");
		return -1;
	}
	
	//初始化数据
	printf("generating the random data...\r\n");
	pf = fopen(DATA_FILE, "w");
	for(i=0; i<TEST_SIZE; i++)
	{
		read(fd, &data[i], sizeof(unsigned int));
		fprintf(pf, "%u\r\n", data[i]);
	}
	fclose(pf);
	close(fd);
	
	//insert sort
	printf("insert sorting...\r\n");
	test(insert_sort, INSERT_FILE, SORT_UP);

	//bubble sort
	printf("bubble sorting..\r\n");
	test(bubble_sort, BUBBLE_FILE, SORT_UP);

	//select sort
	puts("select sorting...");
	test(select_sort, SELECT_FILE, SORT_UP);

	//quick sort
	puts("quick sorting..");
	test(quick_sort, QUICK_FILE, SORT_UP);

	//heap sort
	puts("heap sorting...");
	test(heap_sort, HEAP_FILE, SORT_UP);

	//merger sort
	puts("merge sorting...");
	test(merge_sort, MERGE_FILE, SORT_UP);

	//merger2 sort
	puts("merge2 sorting...");
	test(merge_sort2, MERGE_FILE2, SORT_UP);

	return 0;
}

int cmp(unsigned *pi, unsigned *pj)
{
	if(*pi>*pj)
		return 1;
	if(*pi<*pj)
		return -1;
	return 0;
}
void test(sort_func_t sort_func, char *file, int sort)
{
	int i;

	assert(NULL != sort_func);
	assert(NULL != file);

	memcpy(sort_data, data, sizeof(data));
	sort_func(sort_data, TEST_SIZE, cmp, sort);
	pf = fopen(file, "w");
	if(NULL == pf)
	{
		perror("open");
		exit(-1);
	}
	for(i=0; i<TEST_SIZE; i++)
	{
		fprintf(pf, "%u\r\n", sort_data[i]);
	}
	fclose(pf);
}

int insert_sort(unsigned *data, int len,  int (*cmp_func)(unsigned *, unsigned *), int sort)
{
	int i,j;
	unsigned temp;

	assert(NULL != data);
	assert(NULL != cmp_func);
	
	for(i=1; i<len; i++)
	{
		temp = data[i];
		j=i-1;
		while(j>=0 && (sort==cmp_func(data+j, &temp)))
		{
			data[j+1] = data[j];
			j--;
		}
		data[j+1] = temp;
	}

	return 0;
}

int  shell_sort(unsigned *data, int len, int (*cmp_func)(unsigned *, unsigned *), int sort)
{
	assert(NULL != data);
	assert(NULL != cmp_func);

	return 0;
}

int bubble_sort(unsigned *data, int len, int (*cmp_func)(unsigned *, unsigned *), int sort)
{
	int i,j;
	unsigned temp;
	assert(NULL != data);
	assert(NULL != cmp_func);

	for(i=0; i<len-1;i++)
	{
		for(j=1; j<len-i; j++)
		{
			if(sort == cmp_func(data+j-1, data+j))
			{
				temp = data[j];
				data[j] = data[j-1];
				data[j-1] = temp;
			}
		}
	}
	return 0;
}

int quick_sort(unsigned *data, int len, int (*cmp_func)(unsigned *, unsigned *), int sort)
{
	int i,j;
	unsigned x;

	assert(NULL != data);
	assert(NULL != cmp_func);

	x = data[0];
	i = 0;
	j = len - 1;

	if(len<=1)
	{
		return 0;
	}
	while(i<j)
	{
		while(i<j && sort==cmp_func(data+j, &x))
		{
			j--;
		}
		if(i<j)
		{
			data[i] = data[j];
			i++;
		}

		while(i<j && sort==cmp_func(&x, data+i))
		{
			i++;
		}
		if(i<j)
		{
			data[j] = data[i];
			j--;
		}
	}
	data[i] = x;

	quick_sort(data, i, cmp_func, sort);
	quick_sort(data+i+1, len-i-1, cmp_func, sort);

	return 0;
}

int select_sort(unsigned *data, int len, int (*cmp_func)(unsigned *, unsigned *), int sort)
{
	int i,j;
	unsigned min, pos;

	assert(NULL != data);
	assert(NULL != cmp_func);
	
	for(i=0; i<len-1; i++)
	{
		pos = i;
		min = data[i];
		for(j=i+1; j<len; j++)
		{
			if(sort == cmp_func(&min, data+j))
			{
				min = data[j];
				pos = j;
			}
		}
		data[pos] = data[i];
		data[i] = min;
	}

	return 0;
}

void adjust_head(unsigned *data, int start, int len, int (*cmp_func)(unsigned *, unsigned *), int sort)
{
	unsigned temp;
	int i,j;

	assert(NULL != data);
	assert(start <= len);

	i = start;
	j = 2*i+1;			//left child
	temp = data[start];
	while(j<len)
	{
		if(j+1<len && sort == cmp_func(data+j+1, data+j))
		{
			j++;		//right child
		}
		if(sort == cmp_func(&temp, data+j))
		{
			break;
		}

		data[i] = data[j];
		i=j;
		j = 2*i + 1;
	}
	data[i] = temp;
}
int heap_sort(unsigned *data, int len, int (*cmp_func)(unsigned *, unsigned *), int sort)
{
	int i;
	unsigned temp;

	assert(NULL != data);
	assert(NULL != cmp_func);

	//adjust the whole heap
	for(i=len/2-1; i>=0; i--)
	{
		adjust_head(data, i, len, cmp_func, sort);
	}

	//sorting
	for(i=len-1; i>0; i--)
	{
		temp = data[0];
		data[0] = data[i];
		data[i] = temp;

		adjust_head(data, 0, i, cmp_func, sort);
	}

	return 0;
}

//归并
int merge(unsigned *data, int start, int mid, int end, int (*cmp_func)(unsigned *, unsigned *), int sort)
{
	int i, j, k;
	unsigned *p;

	assert(NULL != data);

	p = (unsigned *)malloc(sizeof(unsigned)*(end+1));
	if(NULL == p)
	{
		return -1;
	}
	memcpy(p, data, sizeof(unsigned)*(end+1));

	i = 0;
	j = mid;
	k = 0;
	while(i<mid && j<=end)
	{
		if(sort == cmp_func(data+i, data+j))
		{
			p[k++] = data[j++];
		}else
		{
			p[k++] = data[i++];
		}
	}

	while(i<mid)
	{
		p[k++] = data[i++];
	}

	while(j<=end)
	{
		p[k++] = data[j++];
	}

	memcpy(data, p, sizeof(unsigned)*(end+1));
	free(p);

	return 0;
}
//递归归并
int merge_sort(unsigned *data, int len, int (*cmp_func)(unsigned *, unsigned *), int sort)
{
	int mid;

	assert(NULL != data);
	assert(NULL != cmp_func);

	if(len<=1)
	{
		return 0;
	}

	mid = len/2;
	merge_sort(data, mid, cmp_func, sort);
	merge_sort(data+mid, len-mid, cmp_func, sort);
	merge(data, 0, mid, len-1, cmp_func, sort);

	return 0;
}
//自低向上归并
int merge_sort2(unsigned *data, int len, int (*cmp_func)(unsigned *, unsigned *), int sort)
{
	int s,t,i;

	assert(NULL != data);
	assert(NULL != cmp_func);

	t=1;
	while(t<len)
	{
		s = t;
		t = s * 2;

		for(i=0; i+t<=len; i+=t)
		{
			merge(data, i, i+s, i+t-1, cmp_func, sort);
		}
		//如果剩下的有一组多，那么也合并
		if(i+s<len)
		{
			merge(data, i, i+s, len-1, cmp_func, sort);
		}
	}

	return 0;
}
