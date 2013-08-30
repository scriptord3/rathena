/**
 * @file loginclif.h
 * Module purpose is to handle incoming and outgoing request with client
 * Licensed under GNU GPL
 *  For more information, see LICENCE in the main folder
 * @author Athena Dev Teams originally in login.c
 * @author rA Dev team
 */

#ifndef _LOGINCLIF_H
#define	_LOGINCLIF_H

#ifdef	__cplusplus
extern "C" {
#endif

int logclif_parse(int fd);

void do_init_loginclif(void);
void do_final_loginclif(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _LOGINCLIF_H */

