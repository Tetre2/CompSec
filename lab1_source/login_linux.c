/* $Header: https://svn.ita.chalmers.se/repos/security/edu/course/computer_security/trunk/lab/login_linux/login_linux.c 585 2013-01-19 10:31:04Z pk@CHALMERS.SE $ */

/* gcc -std=gnu99 -Wall -g -o mylogin login_linux.c -lcrypt */

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <string.h>
#include <signal.h>
#include <pwd.h>
#include <sys/types.h>
#include <crypt.h>
/* Uncomment next line in step 2 */
#include "pwent.h"

#define TRUE 1
#define FALSE 0
#define LENGTH 16

void sighandler() {

	/* add signalhandling routines here */
	/* see 'man 2 signal' */
}



int main(int argc, char *argv[]) {

	mypwent *passwddata; /* this has to be redefined in step 2 */
	/* see pwent.h */

	char important1[LENGTH] = "**IMPORTANT 1**";

	char user[LENGTH];

	char important2[LENGTH] = "**IMPORTANT 2**";

	//char   *c_pass; //you might want to use this variable later...
	char prompt[] = "password: ";
	char *user_pass;

	//ignoring interupts (ctrl-c)
	signal(SIGINT, sighandler);
	signal(SIGQUIT, sighandler);
	signal(SIGTERM, sighandler);
	signal(SIGTSTP, sighandler);
	signal(SIGABRT, sighandler);

	while (TRUE) {
		/* check what important variable contains - do not remove, part of buffer overflow test */
		printf("Value of variable 'important1' before input of login name: %s\n",
				important1);
		printf("Value of variable 'important2' before input of login name: %s\n",
				important2);

		printf("login: ");
		fflush(NULL); /* Flush all  output buffers */
		__fpurge(stdin); /* Purge any data in stdin buffer */

		//limited input to LENGTH size input
		if (fgets(user, LENGTH, stdin) == NULL) 
			exit(0); 
		
		// remove '\n' from fgets
		for (int i = 0; i < LENGTH; i++){
			if(user[i] == '\n')
				user[i] = '\0';
		}
		

		/* check to see if important variable is intact after input of login name - do not remove */
		printf("Value of variable 'important 1' after input of login name: %*.*s\n",
				LENGTH - 1, LENGTH - 1, important1);
		printf("Value of variable 'important 2' after input of login name: %*.*s\n",
		 		LENGTH - 1, LENGTH - 1, important2);

		user_pass = getpass(prompt);
		passwddata = mygetpwnam(user);

		if (passwddata != NULL) {
			/* You have to encrypt user_pass for this to work */
			/* Don't forget to include the salt */

			// encrypting what the user typed to then check against the cypher texts stored in the db
			if (strcmp(crypt(user_pass, passwddata->passwd_salt), passwddata->passwd) == 0) {
				
				passwddata->pwage += 1;
				passwddata->pwfailed = 0;

				printf(" You're in!\n Faild attempts: %d and account age: %d\n", passwddata->pwfailed, passwddata->pwage);
				if(passwddata->pwage > 10){ //if the age is above 10 then request a new pw and update age
					printf("Please chagne your password!\nProvide a new Password!\n");
					user_pass = getpass(prompt);
					passwddata->passwd = crypt(user_pass, passwddata->passwd_salt);
					passwddata->pwage = 0;
				}

				mysetpwent(user, passwddata);

				/*  check UID, see setuid(2) */
				setuid(passwddata->uid);
				/*  start a shell, use execve(2) */
				execve("/bin/bash", NULL, NULL);

			}else{
				passwddata->pwfailed += 1;
				mysetpwent(user, passwddata);

				// if failed more then 5 sleet to stop bruteforce
				if(passwddata->pwfailed > 5){
					printf("STOP!\n");
					fflush(stdout);
					sleep(5);
				}

			}
		}
		printf("Login Incorrect \n");
	}
	return 0;
}
