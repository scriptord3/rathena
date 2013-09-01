/**
 * @file loginchrif.c
 * Module purpose is to handle incoming and outgoing requests with char-server.
 * Licensed under GNU GPL.
 *  For more information, see LICENCE in the main folder.
 * @author Athena Dev Teams originally in login.c
 * @author rAthena Dev Team
 */

#include "../common/timer.h" //difftick
#include "../common/strlib.h" //safeprint
#include "../common/showmsg.h" //show notice
#include "../common/socket.h" //wfifo session
#include "../common/malloc.h"
#include "account.h"
#include "ipban.h" //ipban_check
#include "login.h"
#include "loginlog.h"
#include "loginclif.h"
#include "loginchrif.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//early declaration
void logchrif_on_disconnect(int id);

/**
 * Packet send to all char-servers, except one. (wos: without our self)
 * @param sfd: fd to discard sending to
 * @param buf: packet to send in form of an array buffer
 * @param len: size of packet
 * @return : the number of char-serv the packet was sent to
 */
int logchrif_sendallwos(int sfd, uint8* buf, size_t len) {
	int i, c;
	for( i = 0, c = 0; i < ARRAYLENGTH(server); ++i ) {
		int fd = server[i].fd;
		if( session_isValid(fd) && fd != sfd ){
			WFIFOHEAD(fd,len);
			memcpy(WFIFOP(fd,0), buf, len);
			WFIFOSET(fd,len);
			++c;
		}
	}
	return c;
}

/**
 * Timered function to synchronize ip addresses.
 *  Requesting all char to update their registered ip and transmit their new ip.
 *  Performed each ip_sync_interval.
 * @param tid: timer id
 * @param tick: tick of execution
 * @param id: unused
 * @param data: unused
 * @return 0
 */
static int logchrif_sync_ip_addresses(int tid, unsigned int tick, int id, intptr_t data) {
	uint8 buf[2];
	ShowInfo("IP Sync in progress...\n");
	WBUFW(buf,0) = 0x2735;
	logchrif_sendallwos(-1, buf, 2);
	return 0;
}




/// Parsing handlers

/**
 * Request from char-server to authenticate an account.
 * @param fd: fd to parse from (char-serv)
 * @param id: id of char-serv
 * @param ip: char-serv ip (used for info)
 * @return 0 not enough info transmitted, 1 success
 */
int logchrif_parse_reqauth(int fd, int id,char* ip){
	if( RFIFOREST(fd) < 23 )
		return 0;
	else{
		struct auth_node* node;
		int account_id = RFIFOL(fd,2);
		uint32 login_id1 = RFIFOL(fd,6);
		uint32 login_id2 = RFIFOL(fd,10);
		uint8 sex = RFIFOB(fd,14);
		//uint32 ip_ = ntohl(RFIFOL(fd,15));
		int request_id = RFIFOL(fd,19);
		RFIFOSKIP(fd,23);

		node = (struct auth_node*)idb_get(auth_db, account_id);
		if( runflag == LOGINSERVER_ST_RUNNING &&
			node != NULL &&
			node->account_id == account_id &&
			node->login_id1  == login_id1 &&
			node->login_id2  == login_id2 &&
			node->sex        == sex_num2str(sex) /*&&
			node->ip         == ip_*/ ){// found
			//ShowStatus("Char-server '%s': authentication of the account %d accepted (ip: %s).\n", server[id].name, account_id, ip);

			// send ack
			WFIFOHEAD(fd,25);
			WFIFOW(fd,0) = 0x2713;
			WFIFOL(fd,2) = account_id;
			WFIFOL(fd,6) = login_id1;
			WFIFOL(fd,10) = login_id2;
			WFIFOB(fd,14) = sex;
			WFIFOB(fd,15) = 0;// ok
			WFIFOL(fd,16) = request_id;
			WFIFOL(fd,20) = node->version;
			WFIFOB(fd,24) = node->clienttype;
			WFIFOSET(fd,25);

			// each auth entry can only be used once
			idb_remove(auth_db, account_id);
		}else{// authentication not found
			ShowStatus("Char-server '%s': authentication of the account %d REFUSED (ip: %s).\n", server[id].name, account_id, ip);
			WFIFOHEAD(fd,25);
			WFIFOW(fd,0) = 0x2713;
			WFIFOL(fd,2) = account_id;
			WFIFOL(fd,6) = login_id1;
			WFIFOL(fd,10) = login_id2;
			WFIFOB(fd,14) = sex;
			WFIFOB(fd,15) = 1;// auth failed
			WFIFOL(fd,16) = request_id;
			WFIFOL(fd,20) = 0;
			WFIFOB(fd,24) = 0;
			WFIFOSET(fd,25);
		}
	}
	return 1;
}

/**
 * Receive a request to update user count for char-server identified by id.
 * @param fd: fd to parse from (char-serv)
 * @param id: id of char-serv
 * @return 0 not enough info transmitted, 1 success
 */
int logchrif_parse_ackusercount(int fd, int id){
	if( RFIFOREST(fd) < 6 )
		return 0;
	else{
		int users = RFIFOL(fd,2);
		RFIFOSKIP(fd,6);
		// how many users on world? (update)
		if( server[id].users != users ){
			ShowStatus("set users %s : %d\n", server[id].name, users);
			server[id].users = users;
		}
	}
	return 1;
}

/**
 * Receive a request from char-server to change e-mail from default "a@a.com".
 * @param fd: fd to parse from (char-serv)
 * @param id: id of char-serv
 * @param ip: char-serv ip (used for info)
 * @return 0 not enough info transmitted, 1 success
 */
int logchrif_parse_updmail(int fd, int id, char* ip){
	if (RFIFOREST(fd) < 46)
		return 0;
	else{
		AccountDB* accounts = login_get_accounts_db();
		struct mmo_account acc;
		char email[40];

		int account_id = RFIFOL(fd,2);
		safestrncpy(email, (char*)RFIFOP(fd,6), 40); remove_control_chars(email);
		RFIFOSKIP(fd,46);

		if( e_mail_check(email) == 0 )
			ShowNotice("Char-server '%s': Attempt to create an e-mail on an account with a default e-mail REFUSED - e-mail is invalid (account: %d, ip: %s)\n", server[id].name, account_id, ip);
		else if( !accounts->load_num(accounts, &acc, account_id) || strcmp(acc.email, "a@a.com") == 0 || acc.email[0] == '\0' )
			ShowNotice("Char-server '%s': Attempt to create an e-mail on an account with a default e-mail REFUSED - account doesn't exist or e-mail of account isn't default e-mail (account: %d, ip: %s).\n", server[id].name, account_id, ip);
		else{
			memcpy(acc.email, email, 40);
			ShowNotice("Char-server '%s': Create an e-mail on an account with a default e-mail (account: %d, new e-mail: %s, ip: %s).\n", server[id].name, account_id, email, ip);
			// Save
			accounts->save(accounts, &acc);
		}
	}
	return 1;
}

/**
 * Receive a request for account data reply by sending all mmo_account information.
 * @param fd: fd to parse from (char-serv)
 * @param id: id of char-serv
 * @param ip: char-serv ip (used for info)
 * @return 0 not enough info transmitted, 1 success
 */
int logchrif_parse_reqaccdata(int fd, int id, char *ip){
	if( RFIFOREST(fd) < 6 )
		return 0;
	else{
		struct mmo_account acc;
		AccountDB* accounts = login_get_accounts_db();
		time_t expiration_time = 0;
		char email[40] = "";
		uint8 char_slots = 0;
		int group_id = 0;
		char birthdate[10+1] = "";
		char pincode[PINCODE_LENGTH+1];
		int account_id = RFIFOL(fd,2);

		memset(pincode,0,PINCODE_LENGTH+1);

		RFIFOSKIP(fd,6);

		if( !accounts->load_num(accounts, &acc, account_id) )
			ShowNotice("Char-server '%s': account %d NOT found (ip: %s).\n", server[id].name, account_id, ip);
		else{
			safestrncpy(email, acc.email, sizeof(email));
			expiration_time = acc.expiration_time;
			group_id = acc.group_id;
			char_slots = acc.char_slots;
			safestrncpy(birthdate, acc.birthdate, sizeof(birthdate));
			safestrncpy(pincode, acc.pincode, sizeof(pincode));
		}

		WFIFOHEAD(fd,72);
		WFIFOW(fd,0) = 0x2717;
		WFIFOL(fd,2) = account_id;
		safestrncpy((char*)WFIFOP(fd,6), email, 40);
		WFIFOL(fd,46) = (uint32)expiration_time;
		WFIFOB(fd,50) = (unsigned char)group_id;
		WFIFOB(fd,51) = char_slots;
		safestrncpy((char*)WFIFOP(fd,52), birthdate, 10+1);
		safestrncpy((char*)WFIFOP(fd,63), pincode, 4+1 );
		WFIFOL(fd,68) = (uint32)acc.pincode_change;
		WFIFOSET(fd,72);
	}
	return 1;
}

/**
 * Ping request from char-server to send a reply.
 * @param fd: fd to parse from (char-serv)
 * @return 1 success
 */
int logchrif_parse_keepalive(int fd){
	RFIFOSKIP(fd,2);
	WFIFOHEAD(fd,2);
	WFIFOW(fd,0) = 0x2718;
	WFIFOSET(fd,2);
	return 1;
}

/**
 * Map server send information to change an email of an account via char-server.
 * 0x2722 <account_id>.L <actual_e-mail>.40B <new_e-mail>.40B
 * @param fd: fd to parse from (char-serv)
 * @param id: id of char-serv
 * @param ip: char-serv ip (used for info)
 * @return 0 not enough info transmitted, 1 success
 */
int logchrif_parse_reqchangemail(int fd, int id, char* ip){
	if (RFIFOREST(fd) < 86)
		return 0;
	else{
		struct mmo_account acc;
		AccountDB* accounts = login_get_accounts_db();
		char actual_email[40];
		char new_email[40];

		int account_id = RFIFOL(fd,2);
		safestrncpy(actual_email, (char*)RFIFOP(fd,6), 40);
		safestrncpy(new_email, (char*)RFIFOP(fd,46), 40);
		RFIFOSKIP(fd, 86);

		if( e_mail_check(actual_email) == 0 )
			ShowNotice("Char-server '%s': Attempt to modify an e-mail on an account (@email GM command), but actual email is invalid (account: %d, ip: %s)\n", server[id].name, account_id, ip);
		else if( e_mail_check(new_email) == 0 )
			ShowNotice("Char-server '%s': Attempt to modify an e-mail on an account (@email GM command) with a invalid new e-mail (account: %d, ip: %s)\n", server[id].name, account_id, ip);
		else if( strcmpi(new_email, "a@a.com") == 0 )
			ShowNotice("Char-server '%s': Attempt to modify an e-mail on an account (@email GM command) with a default e-mail (account: %d, ip: %s)\n", server[id].name, account_id, ip);
		else if( !accounts->load_num(accounts, &acc, account_id) )
			ShowNotice("Char-server '%s': Attempt to modify an e-mail on an account (@email GM command), but account doesn't exist (account: %d, ip: %s).\n", server[id].name, account_id, ip);
		else if( strcmpi(acc.email, actual_email) != 0 )
			ShowNotice("Char-server '%s': Attempt to modify an e-mail on an account (@email GM command), but actual e-mail is incorrect (account: %d (%s), actual e-mail: %s, proposed e-mail: %s, ip: %s).\n", server[id].name, account_id, acc.userid, acc.email, actual_email, ip);
		else{
			safestrncpy(acc.email, new_email, 40);
			ShowNotice("Char-server '%s': Modify an e-mail on an account (@email GM command) (account: %d (%s), new e-mail: %s, ip: %s).\n", server[id].name, account_id, acc.userid, new_email, ip);
			// Save
			accounts->save(accounts, &acc);
		}
	}
	return 1;
}

/**
 * Receiving an account state update request from a map-server (relayed via char-server).
 * @param fd: fd to parse from (char-serv)
 * @param id: id of char-serv
 * @param ip: char-serv ip (used for info)
 * @return 0 not enough info transmitted, 1 success
 * TODO seems pretty damn close to logchrif_parse_reqbanacc
 */
int logchrif_parse_requpdaccstate(int fd, int id, char* ip){
	if (RFIFOREST(fd) < 10)
		return 0;
	else{
		struct mmo_account acc;
		AccountDB* accounts = login_get_accounts_db();

		int account_id = RFIFOL(fd,2);
		unsigned int state = RFIFOL(fd,6);
		RFIFOSKIP(fd,10);

		if( !accounts->load_num(accounts, &acc, account_id) )
			ShowNotice("Char-server '%s': Error of Status change (account: %d not found, suggested status %d, ip: %s).\n", server[id].name, account_id, state, ip);
		else if( acc.state == state )
			ShowNotice("Char-server '%s':  Error of Status change - actual status is already the good status (account: %d, status %d, ip: %s).\n", server[id].name, account_id, state, ip);
		else{
			ShowNotice("Char-server '%s': Status change (account: %d, new status %d, ip: %s).\n", server[id].name, account_id, state, ip);

			acc.state = state;
			// Save
			accounts->save(accounts, &acc);

			// notify other servers
			if (state != 0){
				uint8 buf[11];
				WBUFW(buf,0) = 0x2731;
				WBUFL(buf,2) = account_id;
				WBUFB(buf,6) = 0; // 0: change of state, 1: ban
				WBUFL(buf,7) = state; // status or final date of a banishment
				logchrif_sendallwos(-1, buf, 11);
			}
		}
	}
	return 1;
}

/**
 * Receiving a ban request from map-server via char-server.
 * @param fd: fd to parse from (char-serv)
 * @param id: id of char-serv
 * @param ip: char-serv ip (used for info)
 * @return 0 not enough info transmitted, 1 success
 * TODO check logchrif_parse_requpdaccstate for possible merge
 */
int logchrif_parse_reqbanacc(int fd, int id, char* ip){
	if (RFIFOREST(fd) < 18)
		return 0;
	else{
		struct mmo_account acc;
		AccountDB* accounts = login_get_accounts_db();

		int account_id = RFIFOL(fd,2);
		int year = (short)RFIFOW(fd,6);
		int month = (short)RFIFOW(fd,8);
		int mday = (short)RFIFOW(fd,10);
		int hour = (short)RFIFOW(fd,12);
		int min = (short)RFIFOW(fd,14);
		int sec = (short)RFIFOW(fd,16);
		RFIFOSKIP(fd,18);

		if( !accounts->load_num(accounts, &acc, account_id) )
			ShowNotice("Char-server '%s': Error of ban request (account: %d not found, ip: %s).\n", server[id].name, account_id, ip);
		else{
			time_t timestamp;
			struct tm *tmtime;
			if (acc.unban_time == 0 || acc.unban_time < time(NULL))
				timestamp = time(NULL); // new ban
			else
				timestamp = acc.unban_time; // add to existing ban
			tmtime = localtime(&timestamp);
			tmtime->tm_year = tmtime->tm_year + year;
			tmtime->tm_mon  = tmtime->tm_mon + month;
			tmtime->tm_mday = tmtime->tm_mday + mday;
			tmtime->tm_hour = tmtime->tm_hour + hour;
			tmtime->tm_min  = tmtime->tm_min + min;
			tmtime->tm_sec  = tmtime->tm_sec + sec;
			timestamp = mktime(tmtime);
			if (timestamp == -1)
				ShowNotice("Char-server '%s': Error of ban request (account: %d, invalid date, ip: %s).\n", server[id].name, account_id, ip);
			else if( timestamp <= time(NULL) || timestamp == 0 )
				ShowNotice("Char-server '%s': Error of ban request (account: %d, new date unbans the account, ip: %s).\n", server[id].name, account_id, ip);
			else{
				uint8 buf[11];
				char tmpstr[24];
				timestamp2string(tmpstr, sizeof(tmpstr), timestamp, login_config.date_format);
				ShowNotice("Char-server '%s': Ban request (account: %d, new final date of banishment: %d (%s), ip: %s).\n", server[id].name, account_id, timestamp, tmpstr, ip);

				acc.unban_time = timestamp;

				// Save
				accounts->save(accounts, &acc);

				WBUFW(buf,0) = 0x2731;
				WBUFL(buf,2) = account_id;
				WBUFB(buf,6) = 1; // 0: change of status, 1: ban
				WBUFL(buf,7) = (uint32)timestamp; // status or final date of a banishment
				logchrif_sendallwos(-1, buf, 11);
			}
		}
	}
	return 1;
}

/**
 * Receiving a sex change request (sex is reversed).
 * @param fd: fd to parse from (char-serv)
 * @param id: id of char-serv
 * @param ip: char-serv ip (used for info)
 * @return 0 not enough info transmitted, 1 success
 */
int logchrif_parse_reqchgsex(int fd, int id, char* ip){
	if( RFIFOREST(fd) < 6 )
		return 0;
	else{
		struct mmo_account acc;
		AccountDB* accounts = login_get_accounts_db();

		int account_id = RFIFOL(fd,2);
		RFIFOSKIP(fd,6);

		if( !accounts->load_num(accounts, &acc, account_id) )
			ShowNotice("Char-server '%s': Error of sex change (account: %d not found, ip: %s).\n", server[id].name, account_id, ip);
		else if( acc.sex == 'S' )
			ShowNotice("Char-server '%s': Error of sex change - account to change is a Server account (account: %d, ip: %s).\n", server[id].name, account_id, ip);
		else{
			unsigned char buf[7];
			char sex = ( acc.sex == 'M' ) ? 'F' : 'M'; //Change gender

			ShowNotice("Char-server '%s': Sex change (account: %d, new sex %c, ip: %s).\n", server[id].name, account_id, sex, ip);

			acc.sex = sex;
			// Save
			accounts->save(accounts, &acc);

			// announce to other servers
			WBUFW(buf,0) = 0x2723;
			WBUFL(buf,2) = account_id;
			WBUFB(buf,6) = sex_str2num(sex);
			logchrif_sendallwos(-1, buf, 7);
		}
	}
	return 1;
}

/**
 * We receive account_reg2 from a char-server, and we send them to other char-servers.
 * @param fd: fd to parse from (char-serv)
 * @param id: id of char-serv
 * @param ip: char-serv ip (used for info)
 * @return 0 not enough info transmitted, 1 success
 */
int logchrif_parse_updreg2(int fd, int id, char* ip){
	int j;
	if( RFIFOREST(fd) < 4 || RFIFOREST(fd) < RFIFOW(fd,2) )
		return 0;
	else{
		struct mmo_account acc;
		AccountDB* accounts = login_get_accounts_db();
		int account_id = RFIFOL(fd,4);

		if( !accounts->load_num(accounts, &acc, account_id) )
			ShowStatus("Char-server '%s': receiving (from the char-server) of account_reg2 (account: %d not found, ip: %s).\n", server[id].name, account_id, ip);
		else{
			int len;
			int p;
			ShowNotice("char-server '%s': receiving (from the char-server) of account_reg2 (account: %d, ip: %s).\n", server[id].name, account_id, ip);
			for( j = 0, p = 13; j < ACCOUNT_REG2_NUM && p < RFIFOW(fd,2); ++j ){
				sscanf((char*)RFIFOP(fd,p), "%31c%n", acc.account_reg2[j].str, &len);
				acc.account_reg2[j].str[len]='\0';
				p +=len+1; //+1 to skip the '\0' between strings.
				sscanf((char*)RFIFOP(fd,p), "%255c%n", acc.account_reg2[j].value, &len);
				acc.account_reg2[j].value[len]='\0';
				p +=len+1;
				remove_control_chars(acc.account_reg2[j].str);
				remove_control_chars(acc.account_reg2[j].value);
			}
			acc.account_reg2_num = j;
			// Save
			accounts->save(accounts, &acc);
			// Sending information towards the other char-servers.
			RFIFOW(fd,0) = 0x2729;// reusing read buffer
			logchrif_sendallwos(fd, RFIFOP(fd,0), RFIFOW(fd,2));
		}
		RFIFOSKIP(fd,RFIFOW(fd,2));
	}
	return 1;
}

/**
 * Receiving an unban request from map-server via char-server.
 * @param fd: fd to parse from (char-serv)
 * @param id: id of char-serv
 * @param ip: char-serv ip (used for info)
 * @return 0 not enough info transmitted, 1 success
 */
int logchrif_parse_requnbanacc(int fd, int id, char* ip){
	if( RFIFOREST(fd) < 6 )
		return 0;
	else{
		struct mmo_account acc;
		AccountDB* accounts = login_get_accounts_db();

		int account_id = RFIFOL(fd,2);
		RFIFOSKIP(fd,6);

		if( !accounts->load_num(accounts, &acc, account_id) )
			ShowNotice("Char-server '%s': Error of UnBan request (account: %d not found, ip: %s).\n", server[id].name, account_id, ip);
		else if( acc.unban_time == 0 )
			ShowNotice("Char-server '%s': Error of UnBan request (account: %d, no change for unban date, ip: %s).\n", server[id].name, account_id, ip);
		else{
			ShowNotice("Char-server '%s': UnBan request (account: %d, ip: %s).\n", server[id].name, account_id, ip);
			acc.unban_time = 0;
			accounts->save(accounts, &acc);
		}
	}
	return 1;
}

/**
 * Set account_id to online.
 * @author [Wizputer]
 * @param fd: fd to parse from (char-serv)
 * @param id: id of char-serv
 * @return 0 not enough info transmitted, 1 success
 */
int logchrif_parse_setacconline(int fd, int id){
	if( RFIFOREST(fd) < 6 )
		return 0;
	login_add_online_user(id, RFIFOL(fd,2));
	RFIFOSKIP(fd,6);
	return 1;
}

/**
 * Set account_id to offline.
 * @author  [Wizputer]
 * @param fd: fd to parse from (char-serv)
 * @return 0 not enough info transmitted, 1 success
 */
int logchrif_parse_setaccoffline(int fd){
	if( RFIFOREST(fd) < 6 )
		return 0;
	login_remove_online_user(RFIFOL(fd,2));
	RFIFOSKIP(fd,6);
	return 1;
}

/**
 * Receive list of all online accounts.
 * @author  [Skotlex]
 * @param fd: fd to parse from (char-serv)
 * @param id: id of char-serv
 * @return 0 not enough info transmitted, 1 success
 */
int logchrif_parse_updonlinedb(int fd, int id){
	if (RFIFOREST(fd) < 4 || RFIFOREST(fd) < RFIFOW(fd,2))
		return 0;
	else{
		struct online_login_data *p;
		int aid;
		uint32 i, users;
		online_db->foreach(online_db, login_online_db_setoffline, id); //Set all chars from this char-server offline first
		users = RFIFOW(fd,4);
		for (i = 0; i < users; i++) {
			aid = RFIFOL(fd,6+i*4);
			p = idb_ensure(online_db, aid, login_create_online_user);
			p->char_server = id;
			if (p->waiting_disconnect != INVALID_TIMER){
				delete_timer(p->waiting_disconnect, login_waiting_disconnect_timer);
				p->waiting_disconnect = INVALID_TIMER;
			}
		}
		RFIFOSKIP(fd,RFIFOW(fd,2));
	}
	return 1;
}

/**
 * Request account_reg2 for a character.
 * @param fd: fd to parse from (char-serv)
 * @return 0 not enough info transmitted, 1 success
 */
int logchrif_parse_reqacc2reg(int fd){
	int j;
	if (RFIFOREST(fd) < 10)
		return 0;
	else{
		struct mmo_account acc;
		AccountDB* accounts = login_get_accounts_db();
		size_t off;

		int account_id = RFIFOL(fd,2);
		int char_id = RFIFOL(fd,6);
		RFIFOSKIP(fd,10);

		WFIFOHEAD(fd,ACCOUNT_REG2_NUM*sizeof(struct global_reg));
		WFIFOW(fd,0) = 0x2729;
		WFIFOL(fd,4) = account_id;
		WFIFOL(fd,8) = char_id;
		WFIFOB(fd,12) = 1; //Type 1 for Account2 registry

		off = 13;
		if( accounts->load_num(accounts, &acc, account_id) ){
			for( j = 0; j < acc.account_reg2_num; j++ ){
				if( acc.account_reg2[j].str[0] != '\0' ){
					off += sprintf((char*)WFIFOP(fd,off), "%s", acc.account_reg2[j].str)+1; //We add 1 to consider the '\0' in place.
					off += sprintf((char*)WFIFOP(fd,off), "%s", acc.account_reg2[j].value)+1;
				}
			}
		}

		WFIFOW(fd,2) = (uint16)off;
		WFIFOSET(fd,WFIFOW(fd,2));
	}
	return 1;
}

/**
 * Received new charip from char-serv, update information.
 * @param fd: char-serv file descriptor
 * @param id: char-serv id
 * @return 0 not enough info transmitted, 1 success
 */
int logchrif_parse_updcharip(int fd, int id){
	if( RFIFOREST(fd) < 6 )
		return 0;
	server[id].ip = ntohl(RFIFOL(fd,2));
	ShowInfo("Updated IP of Server #%d to %d.%d.%d.%d.\n",id, CONVIP(server[id].ip));
	RFIFOSKIP(fd,6);
	return 1;
}

/**
 * Request to set all accounts offline.
 * @param fd: fd to parse from (char-serv)
 * @param id: id of char-serv (char-serv)
 * @return 1 success
 */
int logchrif_parse_setalloffline(int fd, int id){
	ShowInfo("Setting accounts from char-server %d offline.\n", id);
	online_db->foreach(online_db, login_online_db_setoffline, id);
	RFIFOSKIP(fd,2);
	return 1;
}

/**
 * Request to change PIN Code for an account.
 * @param fd: fd to parse from (char-serv)
 * @return 0 fail (packet does not have enough data), 1 success
 */
int logchrif_parse_updpincode(int fd){
	if( RFIFOREST(fd) < 11 )
		return 0;
	else{
		struct mmo_account acc;
		AccountDB* accounts = login_get_accounts_db();

		if( accounts->load_num(accounts, &acc, RFIFOL(fd,2) ) ){
			strncpy( acc.pincode, (char*)RFIFOP(fd,6), 5 );
			acc.pincode_change = time( NULL );
			accounts->save(accounts, &acc);
		}
		RFIFOSKIP(fd,11);
	}
	return 1;
}

/**
 * PIN Code was incorrectly entered too many times.
 * @param fd: fd to parse from (char-serv)
 * @return 0 fail (packet does not have enough data), 1 success
 */
int logchrif_parse_pincode_authfail(int fd){
	if( RFIFOREST(fd) < 6 )
		return 0;
	else{
		struct mmo_account acc;
		AccountDB* accounts = login_get_accounts_db();
		if( accounts->load_num(accounts, &acc, RFIFOL(fd,2) ) ){
			struct online_login_data* ld;

			ld = (struct online_login_data*)idb_get(online_db,acc.account_id);

			if( ld == NULL )
				return 0;

			login_log( host2ip(acc.last_ip), acc.userid, 100, "PIN Code check failed" );
		}
		login_remove_online_user(acc.account_id);
		RFIFOSKIP(fd,6);
	}
	return 1;
}

/**
 * Entry point from char-server to log-server.
 * Function that checks incoming command, then splits it to the correct handler.
 * @param fd: file descriptor to parse, (link to char-serv)
 * @return 0=invalid server,marked for disconnection,unknow packet; 1=success
 */
int logchrif_parse(int fd){
	int id;
	uint32 ipl;
	char ip[16];

	ARR_FIND( 0, ARRAYLENGTH(server), id, server[id].fd == fd );
	if( id == ARRAYLENGTH(server) ){// not a char server
		ShowDebug("logchrif_parse: Disconnecting invalid session #%d (is not a char-server)\n", fd);
		set_eof(fd);
		do_close(fd);
		return 0;
	}

	if( session[fd]->flag.eof ){
		do_close(fd);
		server[id].fd = -1;
		logchrif_on_disconnect(id);
		return 0;
	}

	ipl = server[id].ip;
	ip2str(ipl, ip);

	while( RFIFOREST(fd) >= 2 ){
		uint16 command = RFIFOW(fd,0);
		switch( command ){
		case 0x2712: logchrif_parse_reqauth(fd, id, ip); break;
		case 0x2714: logchrif_parse_ackusercount(fd, id); break;
		case 0x2715: logchrif_parse_updmail(fd, id, ip); break;
		case 0x2716: logchrif_parse_reqaccdata(fd, id, ip); break;
		case 0x2719: logchrif_parse_keepalive(fd); break;
		case 0x2722: logchrif_parse_reqchangemail(fd,id,ip); break;
		case 0x2724: logchrif_parse_requpdaccstate(fd,id,ip); break;
		case 0x2725: logchrif_parse_reqbanacc(fd,id,ip); break;
		case 0x2727: logchrif_parse_reqchgsex(fd,id,ip); break;
		case 0x2728: logchrif_parse_updreg2(fd,id,ip); break;
		case 0x272a: logchrif_parse_requnbanacc(fd,id,ip); break;
		case 0x272b: logchrif_parse_setacconline(fd,id); break;
		case 0x272c: logchrif_parse_setaccoffline(fd); break;
		case 0x272d: logchrif_parse_updonlinedb(fd,id); break;
		case 0x272e: logchrif_parse_reqacc2reg(fd); break;
		case 0x2736: logchrif_parse_updcharip(fd,id); break;
		case 0x2737: logchrif_parse_setalloffline(fd,id); break;
		case 0x2738: logchrif_parse_updpincode(fd); break;
		case 0x2739: logchrif_parse_pincode_authfail(fd); break;
		default:
			ShowError("logchrif_parse: Unknown packet 0x%x from a char-server! Disconnecting!\n", command);
			set_eof(fd);
			return 0;
		} // switch
	} // while
	return 1;
}




/// Constructor destructor and signal handlers

/**
 * Initializes a server structure.
 * @param id: id of char-serv (should be >0, FIXME)
 */
void logchrif_server_init(int id) {
	memset(&server[id], 0, sizeof(server[id]));
	server[id].fd = -1;
}

/**
 * Destroys a server structure.
 * @param id: id of char-serv (should be >0, FIXME)
 */
void logchrif_server_destroy(int id){
	if( server[id].fd != -1 ) {
		do_close(server[id].fd);
		server[id].fd = -1;
	}
}

/**
 * Resets all the data related to a server.
 *  Actually destroys then recreates the struct.
 * @param id: id of char-serv (should be >0, FIXME)
 */
void logchrif_server_reset(int id) {
	online_db->foreach(online_db, login_online_db_setoffline, id); //Set all chars from this char server to offline.
	logchrif_server_destroy(id);
	logchrif_server_init(id);
}

/**
 * Called when the connection to Char Server is disconnected.
 * @param id: id of char-serv (should be >0, FIXME)
 */
void logchrif_on_disconnect(int id) {
	ShowStatus("Char-server '%s' has disconnected.\n", server[id].name);
	logchrif_server_reset(id);
}

/**
 * loginchrif constructor
 *  Initialisation, function called at start of the login-serv.
 */
void do_init_loginchrif(void){
	int i;
	for( i = 0; i < ARRAYLENGTH(server); ++i )
		logchrif_server_init(i);

	// add timer to detect ip address change and perform update
	if (login_config.ip_sync_interval) {
		add_timer_func_list(logchrif_sync_ip_addresses, "sync_ip_addresses");
		add_timer_interval(gettick() + login_config.ip_sync_interval, logchrif_sync_ip_addresses, 0, 0, login_config.ip_sync_interval);
	}
}

/**
 * Signal handler
 *  This function attempts to properly close the server when an interrupt signal is received.
 *  current signal catch : SIGTERM, SIGINT
 */
void do_shutdown_loginchrif(void){
	int id;
	for( id = 0; id < ARRAYLENGTH(server); ++id )
		logchrif_server_reset(id);
}

/**
 * loginchrif destructor
 *  dealloc..., function called at exit of the login-serv
 */
void do_final_loginchrif(void){
	int i;
	for( i = 0; i < ARRAYLENGTH(server); ++i )
		logchrif_server_destroy(i);
}