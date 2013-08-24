/*
 * File:   char_logif.h
 * Author: lighta
 *
 * Created on June 15, 2013, 12:05 PM
 */

#ifndef CHAR_LOGIF_H
#define	CHAR_LOGIF_H

#include "char.h"

#ifdef	__cplusplus
extern "C" {
#endif

int parse_char(int fd);

void do_init_loginif(void);
void do_final_loginif(void);

int save_accreg2(unsigned char* buf, int len);
int request_accreg2(int account_id, int char_id);
int char_send_setacconline(int aid);
int char_send_setaccoffline(int fd, int aid);
void char_send_setallaccoffline(int fd);
int char_send_reqaccdata(int fd, struct char_session_data *sd);
int char_send_usercount(int users);
int pincode_notifyLoginPinError( int account_id );
int pincode_notifyLoginPinUpdate( int account_id, char* pin );

#ifdef	__cplusplus
}
#endif

#endif	/* CHAR_LOGIF_H */

