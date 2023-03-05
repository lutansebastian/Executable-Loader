/*
 * Loader Implementation
 *
 * 2022, Operating Systems
 */
#define DIE(assertion, call_description)			\
	if (assertion) {								\
		perror(call_description);					\
		exit(EXIT_FAILURE);							\
	}							
#define IGNORED 0

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <signal.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>

#include "exec_parser.h"

static so_exec_t *exec;
static int file_descriptor;

static void segv_handler(int signum, siginfo_t *info, void *context)
{	
	/* 
	* TODO - actual loader implementation.
	*/
	
	int i;
	int page_size = getpagesize();
	uintptr_t fault_address = (uintptr_t)info->si_addr;

	/* 
	* Segment traversal and data initialisation.
	*/

	for (i = 0; i < exec->segments_no; i++) {
		so_seg_t *current_segment = &exec->segments[i];

		uintptr_t segment_start_address = current_segment->vaddr;
		unsigned int segment_mem_size = current_segment->mem_size;

		/* 
		* Looking for the segment containing the fault address.
		*/

		if (fault_address >= segment_start_address && 
			fault_address < segment_start_address + segment_mem_size) {
			
			unsigned int segment_file_size = current_segment->file_size;
			unsigned int segment_offset = current_segment->offset;
			unsigned int segment_permissions = current_segment->perm;

			/*
			* Allocate the data array.
			*/

			unsigned int maximum_number_of_pages = 
				(segment_mem_size / page_size) + 1;

			if (current_segment->data == NULL)
				current_segment->data = (int *) 
					calloc (maximum_number_of_pages, sizeof(int));

			unsigned int current_page_number = 
				(fault_address - segment_start_address) / page_size;
			/*
			* Create a new mapping in the virtual address space for the current 
			* page.
			*/

			if (((int*)(current_segment->data))[current_page_number] == 0) {
				void *mmap_ret_addr = mmap(((void*)segment_start_address + 
					current_page_number * page_size), page_size, PROT_WRITE, 
					MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, IGNORED, IGNORED);
				DIE(mmap_ret_addr == MAP_FAILED, "MMAP FAILED");
				
				/*
				* Mark the page as mapped.
				*/

				((int*)(current_segment->data))[current_page_number] = 1;
				
				/*
				* Check if I am not over the file size. 
				*/

				if (current_page_number * page_size < segment_file_size) {

					/*
					* Move the cursor to the beginning of the segment and move 
					* to the current page.
					*/

					off_t lseek_return_value = lseek(file_descriptor, 
						segment_offset + current_page_number * page_size,
						SEEK_SET);
					DIE(lseek_return_value == (off_t) -1, "LSEEK FAILED");

					/*
					* Read from file
					*/

					if (segment_file_size - current_page_number * page_size < 
						page_size) {
						int read1_return_value = read(file_descriptor, 
							mmap_ret_addr, 
							segment_file_size - 
							current_page_number * page_size);
						DIE(read1_return_value == -1, "READ1 FAILED");			
					}
					else {
						int read2_return_value = read(file_descriptor, 
							mmap_ret_addr, 
							page_size);
						DIE(read2_return_value == -1, "READ2 FAILED");
					}
				}

				/*
				* Change the permissions
				*/

				int mprotect_return_value = mprotect(mmap_ret_addr, 
					page_size, 
					segment_permissions);
				DIE(mprotect_return_value == -1, "MPROTECT ERROR");
				
				return;
			}
		}
	}
	signal(SIGSEGV, NULL);
}

int so_init_loader(void)
{
	int rc;
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = segv_handler;
	sa.sa_flags = SA_SIGINFO;
	rc = sigaction(SIGSEGV, &sa, NULL);
	if (rc < 0) {
		perror("sigaction");
		return -1;
	}
	return 0;
}

int so_execute(char *path, char *argv[])
{

	/*
	* Open the file and close before end.
	*/

	file_descriptor = open(path, O_RDONLY);
	DIE(file_descriptor == -1, "FD ERROR");

	exec = so_parse_exec(path);
	if (!exec)
		return -1;

	so_start_exec(exec, argv);

	close(file_descriptor);
	return -1;
}
