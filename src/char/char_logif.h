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

int chclif_parse(int fd);

void do_init_chlogif(void);
void do_final_chlogif(void);

int chlogif_save_accreg2(unsigned char* buf, int len);
int chlogif_request_accreg2(int account_id, int char_id);
int chlogif_send_setacconline(int aid);
int chlogif_send_setaccoffline(int fd, int aid);
void chlogif_send_setallaccoffline(int fd);
int chlogif_send_reqaccdata(int fd, struct char_session_data *sd);
int chlogif_send_usercount(int users);
int chlogif_pincode_notifyLoginPinError( int account_id );
int chlogif_pincode_notifyLoginPinUpdate( int account_id, char* pin );

#ifdef	__cplusplus
}
#endif

#endif	/* CHAR_LOGIF_H */

