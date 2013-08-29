/*
 * File:   consoleif.h
 * Author: lighta
 *
 * Created on June 15, 2013, 3:58 AM
 */

#ifndef CONSOLEIF_H
#define	CONSOLEIF_H

#ifdef	__cplusplus
extern "C" {
#endif

int chcnslif_parse(const char* buf);

void do_init_logincnslif(void);

int cnsl_get_options(int argc, char ** argv);
void display_helpscreen(bool do_exit);

#ifdef	__cplusplus
}
#endif

#endif	/* CONSOLEIF_H */

