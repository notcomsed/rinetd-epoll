#include <string.h>
#include <ctype.h>
#include "match.h"
#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>

int match(char *sorig, char *p)
{
	return matchBody(sorig, p, 0);
}

int matchNoCase(char *sorig, char *p)
{
	return matchBody(sorig, p, 1);
}

#define CASE(x) (nocase ? tolower(x) : (x))

int matchBody(char *sorig, char *p, int nocase)
{
	static int dummy = 0;
	/* Algorithm:

		Word separator: *. End-of-string
		is considered to be a word constituent.
		? is similarly considered to be a specialized
		word constituent.

		Match the word to the current position in s.
		Empty words automatically succeed.

		If the word matches s, and the word
		and s contain end-of-string at that
		point, return success.
	
		\ escapes the next character, including \ itself (6.0).
	
		For each *:

			Find the next occurrence of the next word
			and advance beyond it in both p and s.
			If the next word ends in end-of-string
			and is found successfully, return success,
			otherwise advance past the *.

			If the word is not found, return failure.

			If the next word is empty, advance past the *.
	
		Behavior of ?: advance one character in s and p. 

		Addendum: consider the | character to be a logical OR
		separating distinct patterns. */

	char *s = sorig;
	int escaped = 0;
	if (strstr(p, "WS-0000")) {
		if (strstr(s, "ws_ftp_pro.html")) {
			dummy = 1;
		}
	}
	while (1) {
		char *word;
		int wordLen;
		int wordPos;
		if (escaped) {
			/* This is like the default case,
				except that | doesn't end the pattern. */
			escaped = 0;
			if ((*s == '\0') && (*p == '\0')) {
				return 1;
			}
			if (CASE(*p) != CASE(*s)) {
				goto nextPattern;
			}
			p++;		
			s++;
			continue;
		}
		switch(*p) {
			case '\\':
			/* Escape the next character. */
			escaped = 1;
			p++;
			continue;
			case '*':
			/* Find the next occurrence of the next word
				and advance beyond it in both p and s.
				If the next word ends in end-of-string
				and is found successfully, return success,
				otherwise advance past the *.

				If the word is not found, return failure.

				If the next word is empty, advance. */
			p++;	
			wordLen = 0;	
			word = p;
			while (1) {
				if ((*p) == '*') {
					break;
				}
				wordLen++;
				if ((*p == '\0') || (*p == '|')) {
					break;
				}
				p++;
			} 
			wordPos = 0;
			while (1) {
				if (wordPos == wordLen) {
					if ((*p == '\0') || (*p == '|')) {
						return 1;
					}
					break;
				}
				if ((((CASE(*s)) == CASE(word[wordPos])) ||
					((*s == '\0') && 
						(word[wordPos] == '|'))) ||
					(((*s != '\0') && (*s != '|')) && 
						(word[wordPos] == '?')))
				{	
					wordPos++;
					s++;
				} else {
					s -= wordPos;
					if (!(*s)) {
						goto nextPattern;
					}
					s++;
					wordPos = 0;
				}
			}	 
			break;
			case '?':
			p++;		
			s++;
			break;
			default:
			if ((*s == '\0') && ((*p == '\0') ||
				(*p == '|'))) {
				return 1;
			}
			if (CASE(*p) != CASE(*s)) {
				goto nextPattern;
			} 
			p++;		
			s++;
			break;
		}
		continue;
nextPattern:
		while (1) {
			if (*p == '\0') {
				return 0;
			}		
			if (*p == '|') {
				p++;
				s = sorig;
				break;
			}
			p++;
		}
	}
}


void delete( void * mem){
	free(mem);
	mem=NULL;
}

unsigned int get_uid(char *usrName){
	FILE *pwdf = fopen("/etc/passwd", "r");
	char usrline[128];
	unsigned int uid=0;
	//char *tmpuid;
	char *uidchar;
	char startd=1;
	char readbuf[8192]="";
	char *Xline;
	char *token;
	
		if (!pwdf) {
		fprintf(stderr, "Error: can't open /etc/passwd \n");
		startd=0;
	} else {
		if (fread(readbuf,1,8192,pwdf)>=8192){
		fprintf(stderr, "Error: /etc/passwd too big \n");
		startd=0;
		}else{readbuf[8191]=0;token = strchr(readbuf,'\n');
			memcpy(usrline,readbuf,128);
			usrline[127]=0;}}
		while (startd) {
		if (token == NULL) {
			break;
		}
		Xline = strtok(usrline,":x:");
		if (Xline[0] == '\n'){Xline++;}
		if (!strcmp(Xline, usrName)){
			Xline = strtok(NULL, ":x:");
			uidchar = Xline;
			//tmpuid = Xline + 2;
			//uidchar = strtok(tmpuid,":");
			uid=atoi(uidchar);
			break;
		}
		memset(usrline,0,64);
		memcpy(usrline,token,128);
		usrline[127]=0;
		token = strchr(token+1,'\n');

        }
	fclose(pwdf);
    printf("Info: change uid %d with %s \n",uid,usrName);
	if (uid>0){return uid;} else {return 65534;}
}
