/*
 * File:   char_mapif.h
 * Author: lighta
 *
 * Created on June 15, 2013, 12:05 PM
 */

#ifndef CHAR_MAPIF_H
#define	CHAR_MAPIF_H

#ifdef	__cplusplus
extern "C" {
#endif

int chmapif_parse(int fd);

int chmapif_init(int fd);
void do_init_chmapif(void);
void chmapif_on_disconnect(int id);
void chmapif_server_reset(int id);
void do_final_chmapif(void);

int chmapif_sendall(unsigned char *buf,unsigned int len);
int chmapif_sendallwos(int fd,unsigned char *buf,unsigned int len);
int chmapif_send(int fd,unsigned char *buf,unsigned int len);

void chmapif_sendall_playercount(int users);
void chmapif_send_ackdivorce(int partner_id1, int partner_id2);



#ifdef	__cplusplus
}
#endif

#endif	/* CHAR_MAPIF_H */

