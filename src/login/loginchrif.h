/**
 * @file loginchrif.h
 * Module purpose is to handle incoming and outgoing requests with char-server.
 * Licensed under GNU GPL.
 *  For more information, see LICENCE in the main folder.
 * @author Athena Dev Teams originally in login.c
 * @author rAthena Dev Team
 */

#ifndef LOGINCHRIF_H
#define	LOGINCHRIF_H

#ifdef	__cplusplus
extern "C" {
#endif

int logchrif_parse(int fd);

int logchrif_sendallwos(int sfd, uint8* buf, size_t len);

void do_init_loginchrif(void);
void do_shutdown_loginchrif(void);
void do_final_loginchrif(void);

#ifdef	__cplusplus
}
#endif

#endif	/* LOGINCHRIF_H */

