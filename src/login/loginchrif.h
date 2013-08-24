/*
 * File:   loginchrif.h
 * Author: lighta
 *
 * Created on June 15, 2013, 3:57 AM
 */

#ifndef LOGINCHRIF_H
#define	LOGINCHRIF_H

#ifdef	__cplusplus
extern "C" {
#endif

int parse_fromchar(int fd);

void do_init_loginchrif(void);
void do_shutdown_loginchrif(void);
void do_final_loginchrif(void);

int charif_sendallwos(int sfd, uint8* buf, size_t len);

#ifdef	__cplusplus
}
#endif

#endif	/* LOGINCHRIF_H */

