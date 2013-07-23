#ifndef __SORT_H__
#define __SORT_H__

#define SORT_DESC	1
#define SORT_UP		-1
//简单的插入排序
int insert_sort(unsigned *data, int len, int (*cmp_func)(unsigned *, unsigned *), int sort);
int shell_sort (unsigned *data, int len, int (*cmp_func)(unsigned *, unsigned *), int sort);
int bubble_sort(unsigned *data, int len, int (*cmp_fuc)(unsigned *, unsigned *), int sort);
int quick_sort(unsigned *data, int len, int (*cmp_func)(unsigned *, unsigned *), int sort);
int select_sort(unsigned *data, int len, int (*cmp_func)(unsigned *, unsigned *), int sort);
int heap_sort(unsigned *data, int len, int (*cmp_func)(unsigned *, unsigned *), int sort);
int merge_sort(unsigned *data, int len, int (*cmp_func)(unsigned *, unsigned *), int sort);
int merge_sort2(unsigned *data, int len, int (*cmp_func)(unsigned *, unsigned *), int sort);

#endif
