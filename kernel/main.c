
/*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
                            main.c
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
                                                    Forrest Yu, 2005
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

#include "type.h"
#include "stdio.h"
#include "const.h"
#include "protect.h"
#include "string.h"
#include "fs.h"
#include "proc.h"
#include "tty.h"
#include "console.h"
#include "global.h"
#include "proto.h"
#include "animation.h"


/*****************************************************************************
 *                               kernel_main
 *****************************************************************************/
/**
 * jmp from kernel.asm::_start. 
 * 
 *****************************************************************************/
PUBLIC int kernel_main()
{
	disp_str("\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");

	int i, j, eflags, prio;
        u8  rpl;
        u8  priv; /* privilege */

	struct task * t;
	struct proc * p = proc_table;

	char * stk = task_stack + STACK_SIZE_TOTAL;

	for (i = 0; i < NR_TASKS + NR_PROCS; i++,p++,t++) {
		if (i >= NR_TASKS + NR_NATIVE_PROCS) {
			p->p_flags = FREE_SLOT;
			continue;
		}

	        if (i < NR_TASKS) {     /* TASK */
                        t	= task_table + i;
                        priv	= PRIVILEGE_TASK;
                        rpl     = RPL_TASK;
                        eflags  = 0x1202;/* IF=1, IOPL=1, bit 2 is always 1 */
			prio    = 15;
                }
                else {                  /* USER PROC */
                        t	= user_proc_table + (i - NR_TASKS);
                        priv	= PRIVILEGE_USER;
                        rpl     = RPL_USER;
                        eflags  = 0x202;	/* IF=1, bit 2 is always 1 */
			prio    = 5;
                }

		strcpy(p->name, t->name);	/* name of the process */
		p->p_parent = NO_TASK;

		if (strcmp(t->name, "INIT") != 0) {
			p->ldts[INDEX_LDT_C]  = gdt[SELECTOR_KERNEL_CS >> 3];
			p->ldts[INDEX_LDT_RW] = gdt[SELECTOR_KERNEL_DS >> 3];

			/* change the DPLs */
			p->ldts[INDEX_LDT_C].attr1  = DA_C   | priv << 5;
			p->ldts[INDEX_LDT_RW].attr1 = DA_DRW | priv << 5;
		}
		else {		/* INIT process */
			unsigned int k_base;
			unsigned int k_limit;
			int ret = get_kernel_map(&k_base, &k_limit);
			assert(ret == 0);
			init_desc(&p->ldts[INDEX_LDT_C],
				  0, /* bytes before the entry point
				      * are useless (wasted) for the
				      * INIT process, doesn't matter
				      */
				  (k_base + k_limit) >> LIMIT_4K_SHIFT,
				  DA_32 | DA_LIMIT_4K | DA_C | priv << 5);

			init_desc(&p->ldts[INDEX_LDT_RW],
				  0, /* bytes before the entry point
				      * are useless (wasted) for the
				      * INIT process, doesn't matter
				      */
				  (k_base + k_limit) >> LIMIT_4K_SHIFT,
				  DA_32 | DA_LIMIT_4K | DA_DRW | priv << 5);
		}

		p->regs.cs = INDEX_LDT_C << 3 |	SA_TIL | rpl;
		p->regs.ds =
			p->regs.es =
			p->regs.fs =
			p->regs.ss = INDEX_LDT_RW << 3 | SA_TIL | rpl;
		p->regs.gs = (SELECTOR_KERNEL_GS & SA_RPL_MASK) | rpl;
		p->regs.eip	= (u32)t->initial_eip;
		p->regs.esp	= (u32)stk;
		p->regs.eflags	= eflags;

		p->ticks = p->priority = prio;

		p->p_flags = 0;
		p->p_msg = 0;
		p->p_recvfrom = NO_TASK;
		p->p_sendto = NO_TASK;
		p->has_int_msg = 0;
		p->q_sending = 0;
		p->next_sending = 0;

		for (j = 0; j < NR_FILES; j++)
			p->filp[j] = 0;

		stk -= t->stacksize;
	}

	k_reenter = 0;
	ticks = 0;

	p_proc_ready	= proc_table;

	init_clock();
    init_keyboard();

	restart();

	while(1){}
}


/*****************************************************************************
 *                                get_ticks
 *****************************************************************************/
PUBLIC int get_ticks()
{
	MESSAGE msg;
	reset_msg(&msg);
	msg.type = GET_TICKS;
	send_recv(BOTH, TASK_SYS, &msg);
	return msg.RETVAL;
}


/**
 * @struct posix_tar_header
 * Borrowed from GNU `tar'
 */
struct posix_tar_header
{				/* byte offset */
	char name[100];		/*   0 */
	char mode[8];		/* 100 */
	char uid[8];		/* 108 */
	char gid[8];		/* 116 */
	char size[12];		/* 124 */
	char mtime[12];		/* 136 */
	char chksum[8];		/* 148 */
	char typeflag;		/* 156 */
	char linkname[100];	/* 157 */
	char magic[6];		/* 257 */
	char version[2];	/* 263 */
	char uname[32];		/* 265 */
	char gname[32];		/* 297 */
	char devmajor[8];	/* 329 */
	char devminor[8];	/* 337 */
	char prefix[155];	/* 345 */
	/* 500 */
};

/*****************************************************************************
 *                                untar
 *****************************************************************************/
/**
 * Extract the tar file and store them.
 * 
 * @param filename The tar file.
 *****************************************************************************/
void untar(const char * filename)
{
	printf("[extract `%s'\n", filename);
	int fd = open(filename, O_RDWR);
	assert(fd != -1);

	char buf[SECTOR_SIZE * 16];
	int chunk = sizeof(buf);
	int i = 0;
	int bytes = 0;

	while (1) {
		bytes = read(fd, buf, SECTOR_SIZE);
		assert(bytes == SECTOR_SIZE); /* size of a TAR file
					       * must be multiple of 512
					       */
		if (buf[0] == 0) {
			if (i == 0)
				printf("    need not unpack the file.\n");
			break;
		}
		i++;

		struct posix_tar_header * phdr = (struct posix_tar_header *)buf;

		/* calculate the file size */
		char * p = phdr->size;
		int f_len = 0;
		while (*p)
			f_len = (f_len * 8) + (*p++ - '0'); /* octal */

		int bytes_left = f_len;
		int fdout = open(phdr->name, O_CREAT | O_RDWR | O_TRUNC);
		if (fdout == -1) {
			printf("    failed to extract file: %s\n", phdr->name);
			printf(" aborted]\n");
			close(fd);
			return;
		}
		printf("    %s", phdr->name);
		while (bytes_left) {
			int iobytes = min(chunk, bytes_left);
			read(fd, buf,
			     ((iobytes - 1) / SECTOR_SIZE + 1) * SECTOR_SIZE);
			bytes = write(fdout, buf, iobytes);
			assert(bytes == iobytes);
			bytes_left -= iobytes;
			printf(".");
		}
		printf("\n");
		close(fdout);
	}

	if (i) {
		lseek(fd, 0, SEEK_SET);
		buf[0] = 0;
		bytes = write(fd, buf, 1);
		assert(bytes == 1);
	}

	close(fd);

	printf(" done, %d files extracted]\n", i);
}

/*****************************************************************************
 *                                shabby_shell
 *****************************************************************************/
/**
 * A very very simple shell.
 * 
 * @param tty_name  TTY file name.
 *****************************************************************************/
void shabby_shell(const char * tty_name)
{
	int fd_stdin  = open(tty_name, O_RDWR);
	assert(fd_stdin  == 0);
	int fd_stdout = open(tty_name, O_RDWR);
	assert(fd_stdout == 1);

	char rdbuf[128];
	
	char current_dir[512]="/";	// current directory

	while (1) {
		//write(1, "$ ", 2);
		printf("root@owls%s:~$",current_dir);
		int r = read(0, rdbuf, 70);
		rdbuf[r] = 0;

		int argc = 0;
		char * argv[PROC_ORIGIN_STACK];
		char * p = rdbuf;
		char * s;
		int word = 0;
		char ch;
		do {
			ch = *p;
			if (*p != ' ' && *p != 0 && !word) {
				s = p;
				word = 1;
			}
			if ((*p == ' ' || *p == 0) && word) {
				word = 0;
				argv[argc++] = s;
				*p = 0;
			}
			p++;
		} while(ch);
		argv[argc] = 0;

		int fd = open(argv[0], O_RDWR);
		if (fd == -1) {
			if (rdbuf[0]) {
				write(1, "{", 1);
				write(1, rdbuf, r);
				write(1, "}\n", 2);
			}
		}
		else {
			close(fd);
			int pid = fork();
			if (pid != 0) { /* parent */
				int s;
				wait(&s);
			}
			else {	/* child */
				execv(argv[0], argv);
			}
		}
	}

	close(1);
	close(0);
}

void clear() {	
    clear_screen(0, console_table[current_console].cursor);
    console_table[current_console].crtc_start = console_table[current_console].orig;
    console_table[current_console].cursor = console_table[current_console].orig;
}

void clearArr(char *arr, int length) {
    int i;
    for (i = 0; i < length; i++) {
        arr[i] = 0;
    }
}

PUBLIC void addTwoString(char *to_str, char *from_str1, char *from_str2) {
    int i = 0, j = 0;
    while (from_str1[i] != 0) {
        to_str[j++]=from_str1[i++];
    }
    i = 0;
    while (from_str2[i] != 0) {
        to_str[j++]=from_str2[i++];
    }
    to_str[j]=0;
}

void shell(char *tty_name) {
    int fd;
    //int isLogin = 0;
    char rdbuf[512];
    char cmd[512];
    char arg1[512];
    char arg2[512];
    char buf[1024];
    char temp[512];

    int fd_stdin  = open(tty_name, O_RDWR);
    assert(fd_stdin  == 0);
    int fd_stdout = open(tty_name, O_RDWR);
    assert(fd_stdout == 1);
	help();
    char current_dirr[512] = "/";
    while (1) {
        // clear the array ！
        clearArr(rdbuf, 512);
        clearArr(cmd, 512);
        clearArr(arg1, 512);
        clearArr(arg2, 512);
        clearArr(buf, 1024);
        clearArr(temp, 512);
        
        printf("root@owls%s:~$ ", current_dirr);
        int r = read(fd_stdin, rdbuf, 512);
        if (strcmp(rdbuf, "") == 0) {
            continue;
        }
        int i = 0;
        int j = 0;
        while ((rdbuf[i] != ' ') && (rdbuf[i] != 0)) {
            cmd[i] = rdbuf[i];
            i++;
        }
        i++;
        while ((rdbuf[i] != ' ') && (rdbuf[i] != 0)) {
            arg1[j] = rdbuf[i];
            i++;
            j++;
        }
        i++;
        j = 0;
        while ((rdbuf[i] != ' ') && (rdbuf[i] != 0)) {
            arg2[j] = rdbuf[i];
            i++;
            j++;
        }
        // clear
        rdbuf[r] = 0;

        // Command "help"
        if (strcmp(cmd, "help") == 0) {
            help();
        }
		// Command "clear"
        else if (strcmp(cmd, "clear") == 0) {
            clear();
        }
		// Command "touch"
		else if (strcmp(cmd, "touch") == 0) {
            if (arg1[0] != '/') {
                addTwoString(temp,current_dirr, arg1);
                memcpy(arg1, temp, 512);       
            }

            fd = open(arg1, O_CREAT | O_RDWR);
            if (fd == -1) {
                printf("touch: cannnot create file! Please check the filename!\n");
                continue ;
            }
            write(fd, buf, 1);
            printf("File created: %s (fd %d)\n", arg1, fd);
            close(fd);
        }
		 // Command "ls"
        else if (strcmp(cmd, "ls") == 0) {
            ls(current_dirr);
        }
        // Command "test"
        else if (strcmp(cmd, "test") == 0) {
            //doTest(arg1);
			
        }
        // Command not supported
        else {
            printf("Command not supported!\n");
        }
    }
}

/*****************************************************************************
 *                                Init
 *****************************************************************************/
/**
 * The hen.
 * 
 *****************************************************************************/
void Init()
{
	// int fd_stdin  = open("/dev_tty0", O_RDWR);
	// assert(fd_stdin  == 0);
	// int fd_stdout = open("/dev_tty0", O_RDWR);
	// assert(fd_stdout == 1);

	// printf("Init() is running ...\n");

	// /* extract `cmd.tar' */
	// untar("/cmd.tar");
			

	// char * tty_list[] = {"/dev_tty1", "/dev_tty2"};

	// int i;
	// for (i = 0; i < sizeof(tty_list) / sizeof(tty_list[0]); i++) {
	// 	int pid = fork();
	// 	if (pid != 0) { /* parent process */
	// 		printf("[parent is running, child pid:%d]\n", pid);
	// 	}
	// 	else {	/* child process */
	// 		printf("[child is running, pid:%d]\n", getpid());
	// 		close(fd_stdin);
	// 		close(fd_stdout);
			
	// 		shabby_shell(tty_list[i]);
	// 		assert(0);
	// 	}
	// }

	// while (1) {
	// 	int s;
	// 	int child = wait(&s);
	// 	printf("child (%d) exited with status: %d.\n", child, s);
	// }
	while(1);
	assert(0);
}



/*======================================================================*
                               TestA
 *======================================================================*/
void TestA()
{
	//animation();	
	shell("/dev_tty0");
	for(;;);
}

/*======================================================================*
                               TestB
 *======================================================================*/
void TestB()
{
	for(;;);
}

/*======================================================================*
                               TestB
 *======================================================================*/
void TestC()
{
	for(;;);
}

/*****************************************************************************
 *                                panic
 *****************************************************************************/
PUBLIC void panic(const char *fmt, ...)
{
	int i;
	char buf[256];

	/* 4 is the size of fmt in the stack */
	va_list arg = (va_list)((char*)&fmt + 4);

	i = vsprintf(buf, fmt, arg);

	printl("%c !!panic!! %s", MAG_CH_PANIC, buf);

	/* should never arrive here */
	__asm__ __volatile__("ud2");
}

/*****************************************************************************
 *                                help
 *****************************************************************************/
void help() {
    printf("================================================================================");
    printf("                                  Owl'S                                         ");
    printf("                     Authors:                                                   ");
    printf("                              Chudi LAN     1552687                             ");
    printf("                              Yulei CHEN    1650257                             ");
    printf("================================================================================");
    //printf("Usage: [command] [flags] [options]                                              ");
    printf("    help                          : display help for all instrctions            ");
	printf("    [shift]+[up/down]             : scroll up/down the screen                   ");
	printf("    clear                         : clear the screen                            ");
    printf("    ls                            : list files in current directory             ");
    printf("    touch       [filename]        : create a new file                           ");
    // printf("    cat         [filename]        : display content of the file                 ");
    // printf("    vi          [filename]        : modify the content of the file              ");
    // printf("    rm          [filename]        : delete a file                               ");
    // printf("    cp          [source] [dest]   : copy a file                                 ");
    // printf("    mv          [source] [dest]   : move a file                                 ");
    // printf("    encrypt     [filename]        : encrypt a file                              ");
    // printf("    cd          [pathname]        : change the directory                        ");
    // printf("    mkdir       [dirname]         : create a new directory                      ");
    // printf("    minesweeper                   : start the minesweeper game                  ");
    // printf("    snake                         : start the snake game                        ");
    // printf("    2048                          : start the 2048 game                         ");
    // printf("    process                       : display all process-info and manage         ");
    // printf("    about                         : display the about of system                 ");
    printf("================================================================================");
}