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

int parse_frommap(int fd);

int char_mapif_init(int fd);
void do_init_mapif(void);
void mapif_on_disconnect(int id);
void mapif_server_reset(int id);
void do_final_mapif(void);

int mapif_sendall(unsigned char *buf,unsigned int len);
int mapif_sendallwos(int fd,unsigned char *buf,unsigned int len);
int mapif_send(int fd,unsigned char *buf,unsigned int len);

void char_sendall_playercount(int users);
void char_send_ackdivorce(int partner_id1, int partner_id2);



#ifdef	__cplusplus
}
#endif

#endif	/* CHAR_MAPIF_H */

