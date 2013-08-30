/**
 * @file login.h
 * Module purpose is to read configuration for login-serv and handle accounts,
 *  also synchronise all login interface: loginchrif, loginclif, logincnslif
 * Licensed under GNU GPL
 *  For more information, see LICENCE in the main folder
 * @author Athena Dev Teams < r15k
 * @author rA Dev team
 */

#ifndef _LOGIN_H_
#define _LOGIN_H_

#include "../common/mmo.h" // NAME_LENGTH,SEX_*
#include "../common/core.h" // CORE_ST_LAST
#include "account.h"

enum E_LOGINSERVER_ST {
	LOGINSERVER_ST_RUNNING = CORE_ST_LAST,
	LOGINSERVER_ST_SHUTDOWN,
	LOGINSERVER_ST_LAST
};

#define PASSWORDENC 3 ///supported encryption types: 1- passwordencrypt, 2- passwordencrypt2, 3- both

struct login_session_data {
	int account_id;
	long login_id1;
	long login_id2;
	char sex;// 'F','M','S'

	char userid[NAME_LENGTH];
	char passwd[32+1]; // 23+1 for plaintext, 32+1 for md5-ed passwords
	int passwdenc;
	char md5key[20];
	uint16 md5keylen;

	char lastlogin[24];
	uint8 group_id;
	uint8 clienttype;
	uint32 version;

	uint8 client_hash[16];
	int has_client_hash;

	int fd;
};

#define MAX_SERVERS 30 //max number of mapserv that could be attach
struct mmo_char_server {
	char name[20];
	int fd;
	uint32 ip;
	uint16 port;
	uint16 users;       // user count on this server
	uint16 type;        // 0=normal, 1=maintenance, 2=over 18, 3=paying, 4=P2P
	uint16 new_;        // should display as 'new'?
} server[MAX_SERVERS]; // char server data

struct client_hash_node {
	int group_id;
	uint8 hash[16];
	struct client_hash_node *next;
};

struct Login_Config {
	uint32 login_ip;					// the address to bind to
	uint16 login_port;					// the port to bind to
	unsigned int ipban_cleanup_interval;			// interval (in seconds) to clean up expired IP bans
	unsigned int ip_sync_interval;				// interval (in minutes) to execute a DNS/IP update (for dynamic IPs)
	bool log_login;						// whether to log login server actions or not
	char date_format[32];					// date format used in messages
	bool console;						// console input system enabled?
	bool new_account_flag,new_acc_length_limit;		// autoregistration via _M/_F ? / if yes minimum length is 4?
	int start_limited_time;					// new account expiration time (-1: unlimited)
	bool use_md5_passwds;					// work with password hashes instead of plaintext passwords?
	int group_id_to_connect;				// required group id to connect
	int min_group_id_to_connect;				// minimum group id to connect
	bool check_client_version;				// check the clientversion set in the clientinfo ?
	uint32 client_version_to_connect;			// the client version needed to connect (if checking is enabled)

	bool ipban;						// perform IP blocking (via contents of `ipbanlist`) ?
	bool dynamic_pass_failure_ban;				// automatic IP blocking due to failed login attemps ?
	unsigned int dynamic_pass_failure_ban_interval;		// how far to scan the loginlog for password failures
	unsigned int dynamic_pass_failure_ban_limit;		// number of failures needed to trigger the ipban
	unsigned int dynamic_pass_failure_ban_duration;		// duration of the ipban
	bool use_dnsbl;						// dns blacklist blocking ?
	char dnsbl_servs[1024];					// comma-separated list of dnsbl servers

	char account_engine[256];				// name of the engine to use (defaults to auto, for the first available engine)
	int allowed_regs;					//max number of registration
	int time_allowed;					//registration intervall in seconds

	int client_hash_check;					// flags for checking client md5
	struct client_hash_node *client_hash_nodes;		// linked list containg md5 hash for each gm group
	char *loginconf_name;					//name of main config file
	char *msgconf_name;					//name of msg_conf config file
	char *lanconf_name;					//name of lan config file
} login_config;

#define sex_num2str(num) ( (num ==  SEX_FEMALE  ) ? 'F' : (num ==  SEX_MALE  ) ? 'M' : 'S' )
#define sex_str2num(str) ( (str == 'F' ) ?  SEX_FEMALE  : (str == 'M' ) ?  SEX_MALE  :  SEX_SERVER  )

#define msg_config_read(cfgName) login_msg_config_read(cfgName)
#define msg_txt(msg_number) login_msg_txt(msg_number)
#define do_final_msg() login_do_final_msg()
int login_msg_config_read(char *cfgName);
const char* login_msg_txt(int msg_number);
void login_do_final_msg(void);

//-----------------------------------------------------
// Online User Database [Wizputer]
//-----------------------------------------------------
struct online_login_data {
	int account_id;
	int waiting_disconnect;
	int char_server;
};
DBMap* online_db; // int account_id -> struct online_login_data*

//-----------------------------------------------------
// Auth database
//-----------------------------------------------------
#define AUTH_TIMEOUT 30000
struct auth_node {
	int account_id;
	uint32 login_id1;
	uint32 login_id2;
	uint32 ip;
	char sex;
	uint32 version;
	uint8 clienttype;
};
DBMap* auth_db; // int account_id -> struct auth_node*


AccountDB* login_get_accounts_db(void);


bool login_check_encrypted(const char* str1, const char* str2, const char* passwd);
bool login_check_password(const char* md5key, int passwdenc, const char* passwd, const char* refpass);

int login_waiting_disconnect_timer(int tid, unsigned int tick, int id, intptr_t data);
void login_remove_online_user(int account_id);
struct online_login_data* login_add_online_user(int char_server, int account_id);
int lan_subnetcheck(uint32 ip);

int login_online_db_setoffline(DBKey key, DBData *data, va_list ap);
DBData login_create_online_user(DBKey key, va_list args);

int login_mmo_auth_new(const char* userid, const char* pass, const char sex, const char* last_ip);
int login_mmo_auth(struct login_session_data* sd, bool isServer);

#endif /* _LOGIN_H_ */
