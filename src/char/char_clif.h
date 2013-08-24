/*
 * File:   char_clif.h
 * Author: lighta
 *
 * Created on June 15, 2013, 12:06 PM
 */

#ifndef CHAR_CLIF_H
#define	CHAR_CLIF_H

#include "char.h"

#ifdef	__cplusplus
extern "C" {
#endif

int parse_char(int fd);

void pincode_sendstate( int fd, struct char_session_data* sd, enum pincode_state state );
void char_send_auth_result(int fd,char result);

void mmo_char_send(int fd, struct char_session_data* sd);


#ifdef	__cplusplus
}
#endif

#endif	/* CHAR_CLIF_H */

