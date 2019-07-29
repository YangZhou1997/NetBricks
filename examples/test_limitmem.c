#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <stdint.h>
#include <string.h>

#define BLOCK_SIZE (1024 * 1024)
#define MEM_LIMIT (100) // 100M

int main(int argc, char **argv)
{
	int num_block = MEM_LIMIT;
	if(argc >= 2)
	{
		num_block = atoi(argv[1]);
	}
	printf("scheduled allocated memory size: %d MB\n", num_block);
	for(int i = 0; i < num_block; i++)
	{
		void * mem_ptr = malloc(BLOCK_SIZE);
		memset((uint8_t *)mem_ptr, 0, BLOCK_SIZE);
		if(mem_ptr == NULL)
		{
			printf("Maximum memory allocated: %d MB", i);
			return 0;
		}
	}
	printf("Maximum memory allocated: %d MB\n", num_block);
	return 0;
}
