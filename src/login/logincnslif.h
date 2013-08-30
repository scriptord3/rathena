/**
 * @file logincnslif.h
 * Module purpose is to handle incoming and outgoing requests with console.
 * Licensed under GNU GPL.
 *  For more information, see LICENCE in the main folder.
 * @author Athena Dev Teams originally in login.c
 * @author rAthena Dev Team
 */

#ifndef CONSOLEIF_H
#define	CONSOLEIF_H

#ifdef	__cplusplus
extern "C" {
#endif

int cnslif_parse(const char* buf);

int logcnsl_get_options(int argc, char ** argv);
void display_helpscreen(bool do_exit);

void do_init_logincnslif(void);
void do_final_logincnslif(void);

#ifdef	__cplusplus
}
#endif

#endif	/* CONSOLEIF_H */

