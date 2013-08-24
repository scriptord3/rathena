// Copyright (c) Athena Dev Teams - Licensed under GNU GPL
// For more information, see LICENCE in the main folder

#include "../common/core.h"
#include "../common/db.h"
#include "../common/malloc.h"
#include "../common/md5calc.h"
#include "../common/random.h"
#include "../common/showmsg.h"
#include "../common/socket.h" //ip2str
#include "../common/strlib.h"
#include "../common/timer.h"
#include "../common/msg_conf.h"
#include "../common/utils.h"
#include "account.h"
#include "ipban.h"
#include "login.h"
#include "loginlog.h"
#include "loginclif.h"
#include "loginchrif.h"
#include "logincnslif.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LOGIN_MAX_MSG 30
static char* msg_table[LOGIN_MAX_MSG]; // Login Server messages_conf
// Account engines available
static struct{
	AccountDB* (*constructor)(void);
	AccountDB* db;
} account_engines[] = {
	{account_db_sql, NULL},
#ifdef ACCOUNTDB_ENGINE_0
	{ACCOUNTDB_CONSTRUCTOR(ACCOUNTDB_ENGINE_0), NULL},
#endif
#ifdef ACCOUNTDB_ENGINE_1
	{ACCOUNTDB_CONSTRUCTOR(ACCOUNTDB_ENGINE_1), NULL},
#endif
#ifdef ACCOUNTDB_ENGINE_2
	{ACCOUNTDB_CONSTRUCTOR(ACCOUNTDB_ENGINE_2), NULL},
#endif
#ifdef ACCOUNTDB_ENGINE_3
	{ACCOUNTDB_CONSTRUCTOR(ACCOUNTDB_ENGINE_3), NULL},
#endif
#ifdef ACCOUNTDB_ENGINE_4
	{ACCOUNTDB_CONSTRUCTOR(ACCOUNTDB_ENGINE_4), NULL},
#endif
	// end of structure
	{NULL, NULL}
};
AccountDB* accounts = NULL; // account database«
// Advanced subnet check [LuzZza]
struct s_subnet {
	uint32 mask;
	uint32 char_ip;
	uint32 map_ip;
} subnet[16];
int subnet_count = 0;

int login_fd; // login server socket

AccountDB* login_get_accounts_db(void){
	return accounts;
}

/**
 * @see DBCreateData
 */
DBData create_online_user(DBKey key, va_list args)
{
	struct online_login_data* p;
	CREATE(p, struct online_login_data, 1);
	p->account_id = key.i;
	p->char_server = -1;
	p->waiting_disconnect = INVALID_TIMER;
	return db_ptr2data(p);
}

struct online_login_data* add_online_user(int char_server, int account_id)
{
	struct online_login_data* p;
	p = idb_ensure(online_db, account_id, create_online_user);
	p->char_server = char_server;
	if( p->waiting_disconnect != INVALID_TIMER )
	{
		delete_timer(p->waiting_disconnect, waiting_disconnect_timer);
		p->waiting_disconnect = INVALID_TIMER;
	}
	return p;
}

void remove_online_user(int account_id)
{
	struct online_login_data* p;
	p = (struct online_login_data*)idb_get(online_db, account_id);
	if( p == NULL )
		return;
	if( p->waiting_disconnect != INVALID_TIMER )
		delete_timer(p->waiting_disconnect, waiting_disconnect_timer);

	idb_remove(online_db, account_id);
}

int waiting_disconnect_timer(int tid, unsigned int tick, int id, intptr_t data)
{
	struct online_login_data* p = (struct online_login_data*)idb_get(online_db, id);
	if( p != NULL && p->waiting_disconnect == tid && p->account_id == id )
	{
		p->waiting_disconnect = INVALID_TIMER;
		remove_online_user(id);
		idb_remove(auth_db, id);
	}
	return 0;
}

/**
 * Mark a char offline
 */
int online_db_setoffline(DBKey key, DBData *data, va_list ap)
{
	struct online_login_data* p = db_data2ptr(data);
	int server = va_arg(ap, int);
	if( server == -1 )
	{
		p->char_server = -1;
		if( p->waiting_disconnect != INVALID_TIMER )
		{
			delete_timer(p->waiting_disconnect, waiting_disconnect_timer);
			p->waiting_disconnect = INVALID_TIMER;
		}
	}
	else if( p->char_server == server )
		p->char_server = -2; //Char server disconnected.
	return 0;
}

/**
 * @see DBApply
 */
static int online_data_cleanup_sub(DBKey key, DBData *data, va_list ap)
{
	struct online_login_data *character= db_data2ptr(data);
	if (character->char_server == -2) //Unknown server.. set them offline
		remove_online_user(character->account_id);
	return 0;
}

static int online_data_cleanup(int tid, unsigned int tick, int id, intptr_t data)
{
	online_db->foreach(online_db, online_data_cleanup_sub);
	return 0;
}



//-------------------------------------
// Make new account
//-------------------------------------
int mmo_auth_new(const char* userid, const char* pass, const char sex, const char* last_ip) {
	static int num_regs = 0; // registration counter
	static unsigned int new_reg_tick = 0;
	unsigned int tick = gettick();
	struct mmo_account acc;

	//Account Registration Flood Protection by [Kevin]
	if( new_reg_tick == 0 )
		new_reg_tick = gettick();
	if( DIFF_TICK(tick, new_reg_tick) < 0 && num_regs >= login_config.allowed_regs ) {
		ShowNotice("Account registration denied (registration limit exceeded)\n");
		return 3;
	}

	if( login_config.new_acc_length_limit && ( strlen(userid) < 4 || strlen(pass) < 4 ) )
		return 1;

	// check for invalid inputs
	if( sex != 'M' && sex != 'F' )
		return 0; // 0 = Unregistered ID

	// check if the account doesn't exist already
	if( accounts->load_str(accounts, &acc, userid) ) {
		ShowNotice("Attempt of creation of an already existant account (account: %s_%c, pass: %s, received pass: %s)\n", userid, sex, acc.pass, pass);
		return 1; // 1 = Incorrect Password
	}

	memset(&acc, '\0', sizeof(acc));
	acc.account_id = -1; // assigned by account db
	safestrncpy(acc.userid, userid, sizeof(acc.userid));
	safestrncpy(acc.pass, pass, sizeof(acc.pass));
	acc.sex = sex;
	safestrncpy(acc.email, "a@a.com", sizeof(acc.email));
	acc.expiration_time = ( login_config.start_limited_time != -1 ) ? time(NULL) + login_config.start_limited_time : 0;
	safestrncpy(acc.lastlogin, "0000-00-00 00:00:00", sizeof(acc.lastlogin));
	safestrncpy(acc.last_ip, last_ip, sizeof(acc.last_ip));
	safestrncpy(acc.birthdate, "0000-00-00", sizeof(acc.birthdate));
	safestrncpy(acc.pincode, "", sizeof(acc.pincode));
	acc.pincode_change = 0;

	acc.char_slots = 0;

	if( !accounts->create(accounts, &acc) )
		return 0;

	ShowNotice("Account creation (account %s, id: %d, pass: %s, sex: %c)\n", acc.userid, acc.account_id, acc.pass, acc.sex);

	if( DIFF_TICK(tick, new_reg_tick) > 0 ) {// Update the registration check.
		num_regs = 0;
		new_reg_tick = tick + login_config.time_allowed*1000;
	}
	++num_regs;

	return -1;
}

//-----------------------------------------------------
// Check/authentication of a connection
//-----------------------------------------------------
int mmo_auth(struct login_session_data* sd, bool isServer) {
	struct mmo_account acc;
	int len;

	char ip[16];
	ip2str(session[sd->fd]->client_addr, ip);

	// DNS Blacklist check
	if( login_config.use_dnsbl ) {
		char r_ip[16];
		char ip_dnsbl[256];
		char* dnsbl_serv;
		uint8* sin_addr = (uint8*)&session[sd->fd]->client_addr;

		sprintf(r_ip, "%u.%u.%u.%u", sin_addr[0], sin_addr[1], sin_addr[2], sin_addr[3]);

		for( dnsbl_serv = strtok(login_config.dnsbl_servs,","); dnsbl_serv != NULL; dnsbl_serv = strtok(NULL,",") ) {
			sprintf(ip_dnsbl, "%s.%s", r_ip, trim(dnsbl_serv));
			if( host2ip(ip_dnsbl) ) {
				ShowInfo("DNSBL: (%s) Blacklisted. User Kicked.\n", r_ip);
				return 3;
			}
		}

	}

	//Client Version check
	if( login_config.check_client_version && sd->version != login_config.client_version_to_connect ){
		ShowNotice("Invalid version (account: '%s', auth_vers: '%d', received version: '%d', ip: %s)\n",
			sd->userid, login_config.client_version_to_connect, sd->version, ip);
		return 5;
	}

	len = strnlen(sd->userid, NAME_LENGTH);

	// Account creation with _M/_F
	if( login_config.new_account_flag ) {
		if( len > 2 && strnlen(sd->passwd, NAME_LENGTH) > 0 && // valid user and password lengths
			sd->passwdenc == 0 && // unencoded password
			sd->userid[len-2] == '_' && memchr("FfMm", sd->userid[len-1], 4) ) // _M/_F suffix
		{
			int result;

			// remove the _M/_F suffix
			len -= 2;
			sd->userid[len] = '\0';

			result = mmo_auth_new(sd->userid, sd->passwd, TOUPPER(sd->userid[len+1]), ip);
			if( result != -1 )
				return result;// Failed to make account. [Skotlex].
		}
	}

	if( !accounts->load_str(accounts, &acc, sd->userid) ) {
		ShowNotice("Unknown account (account: %s, received pass: %s, ip: %s)\n", sd->userid, sd->passwd, ip);
		return 0; // 0 = Unregistered ID
	}

	if( !check_password(sd->md5key, sd->passwdenc, sd->passwd, acc.pass) ) {
		ShowNotice("Invalid password (account: '%s', pass: '%s', received pass: '%s', ip: %s)\n", sd->userid, acc.pass, sd->passwd, ip);
		return 1; // 1 = Incorrect Password
	}

	if( acc.expiration_time != 0 && acc.expiration_time < time(NULL) ) {
		ShowNotice("Connection refused (account: %s, pass: %s, expired ID, ip: %s)\n", sd->userid, sd->passwd, ip);
		return 2; // 2 = This ID is expired
	}

	if( acc.unban_time != 0 && acc.unban_time > time(NULL) ) {
		char tmpstr[24];
		timestamp2string(tmpstr, sizeof(tmpstr), acc.unban_time, login_config.date_format);
		ShowNotice("Connection refused (account: %s, pass: %s, banned until %s, ip: %s)\n", sd->userid, sd->passwd, tmpstr, ip);
		return 6; // 6 = Your are Prohibited to log in until %s
	}

	if( acc.state != 0 ) {
		ShowNotice("Connection refused (account: %s, pass: %s, state: %d, ip: %s)\n", sd->userid, sd->passwd, acc.state, ip);
		return acc.state - 1;
	}

	if( login_config.client_hash_check && !isServer ) {
		struct client_hash_node *node = login_config.client_hash_nodes;
		uint8 anyhash[16];
		bool match = false;

		if( !sd->has_client_hash ) {
			ShowNotice("Client doesn't sent client hash (account: %s, pass: %s, ip: %s)\n", sd->userid, sd->passwd, acc.state, ip);
			return 5;
		}
		memset(anyhash,1,sizeof(anyhash));
		while( node ) {
			if( node->group_id <= acc.group_id && (memcmp(node->hash,anyhash,16)==0 || memcmp(node->hash, sd->client_hash, 16) == 0 ) ){
				match = true;
				break;
			}

			node = node->next;
		}

		if( !match ) {
			char smd5[33];
			int i;

			for( i = 0; i < 16; i++ )
				sprintf(&smd5[i * 2], "%02x", sd->client_hash[i]);

			ShowNotice("Invalid client hash (account: %s, pass: %s, sent md5: %d, ip: %s)\n", sd->userid, sd->passwd, smd5, ip);
			return 5;
		}
	}

	ShowNotice("Authentication accepted (account: %s, id: %d, ip: %s)\n", sd->userid, acc.account_id, ip);

	// update session data
	sd->account_id = acc.account_id;
	sd->login_id1 = rnd() + 1;
	sd->login_id2 = rnd() + 1;
	safestrncpy(sd->lastlogin, acc.lastlogin, sizeof(sd->lastlogin));
	sd->sex = acc.sex;
	sd->group_id = acc.group_id;

	// update account data
	timestamp2string(acc.lastlogin, sizeof(acc.lastlogin), time(NULL), "%Y-%m-%d %H:%M:%S");
	safestrncpy(acc.last_ip, ip, sizeof(acc.last_ip));
	acc.unban_time = 0;
	acc.logincount++;

	accounts->save(accounts, &acc);

	if( sd->sex != 'S' && sd->account_id < START_ACCOUNT_NUM )
		ShowWarning("Account %s has account id %d! Account IDs must be over %d to work properly!\n", sd->userid, sd->account_id, START_ACCOUNT_NUM);

	return -1; // account OK
}

//-----------------------------------------------------
// encrypted/unencrypted password check (from eApp)
//-----------------------------------------------------
bool check_encrypted(const char* str1, const char* str2, const char* passwd)
{
	char tmpstr[64+1], md5str[32+1];

	safesnprintf(tmpstr, sizeof(tmpstr), "%s%s", str1, str2);
	MD5_String(tmpstr, md5str);

	return (0==strcmp(passwd, md5str));
}

bool check_password(const char* md5key, int passwdenc, const char* passwd, const char* refpass)
{
	if(passwdenc == 0)
	{
		return (0==strcmp(passwd, refpass));
	}
	else
	{
		// password mode set to 1 -> md5(md5key, refpass) enable with <passwordencrypt></passwordencrypt>
		// password mode set to 2 -> md5(refpass, md5key) enable with <passwordencrypt2></passwordencrypt2>

		return ((passwdenc&0x01) && check_encrypted(md5key, refpass, passwd)) ||
		       ((passwdenc&0x02) && check_encrypted(refpass, md5key, passwd));
	}
}

//--------------------------------------------
// Test to know if an IP come from LAN or WAN.
//--------------------------------------------
int lan_subnetcheck(uint32 ip)
{
	int i;
	ARR_FIND( 0, subnet_count, i, (subnet[i].char_ip & subnet[i].mask) == (ip & subnet[i].mask) );
	return ( i < subnet_count ) ? subnet[i].char_ip : 0;
}

//----------------------------------
// Reading Lan Support configuration
//----------------------------------
int login_lan_config_read(const char *lancfgName)
{
	FILE *fp;
	int line_num = 0;
	char line[1024], w1[64], w2[64], w3[64], w4[64];

	if((fp = fopen(lancfgName, "r")) == NULL) {
		ShowWarning("LAN Support configuration file is not found: %s\n", lancfgName);
		return 1;
	}

	while(fgets(line, sizeof(line), fp))
	{
		line_num++;
		if ((line[0] == '/' && line[1] == '/') || line[0] == '\n' || line[1] == '\n')
			continue;

		if(sscanf(line,"%[^:]: %[^:]:%[^:]:%[^\r\n]", w1, w2, w3, w4) != 4)
		{
			ShowWarning("Error syntax of configuration file %s in line %d.\n", lancfgName, line_num);
			continue;
		}

		if( strcmpi(w1, "subnet") == 0 )
		{
			subnet[subnet_count].mask = str2ip(w2);
			subnet[subnet_count].char_ip = str2ip(w3);
			subnet[subnet_count].map_ip = str2ip(w4);

			if( (subnet[subnet_count].char_ip & subnet[subnet_count].mask) != (subnet[subnet_count].map_ip & subnet[subnet_count].mask) )
			{
				ShowError("%s: Configuration Error: The char server (%s) and map server (%s) belong to different subnetworks!\n", lancfgName, w3, w4);
				continue;
			}

			subnet_count++;
		}
	}

	if( subnet_count > 1 ) /* only useful if there is more than 1 available */
		ShowStatus("Read information about %d subnetworks.\n", subnet_count);

	fclose(fp);
	return 0;
}

/*
 * Init default configuration
 */
void login_set_defaults()
{
	login_config.login_ip = INADDR_ANY;
	login_config.login_port = 6900;
	login_config.ipban_cleanup_interval = 60;
	login_config.ip_sync_interval = 0;
	login_config.log_login = true;
	safestrncpy(login_config.date_format, "%Y-%m-%d %H:%M:%S", sizeof(login_config.date_format));
	login_config.console = false;
	login_config.new_account_flag = true;
	login_config.new_acc_length_limit = true;
	login_config.use_md5_passwds = false;
	login_config.group_id_to_connect = -1;
	login_config.min_group_id_to_connect = -1;
	login_config.check_client_version = false;
	login_config.client_version_to_connect = date2version(PACKETVER); //20120410 => 30
	ShowInfo("loginconfig: client_version_to_connect = %d\n",login_config.client_version_to_connect);

	login_config.ipban = true;
	login_config.dynamic_pass_failure_ban = true;
	login_config.dynamic_pass_failure_ban_interval = 5;
	login_config.dynamic_pass_failure_ban_limit = 7;
	login_config.dynamic_pass_failure_ban_duration = 5;
	login_config.use_dnsbl = false;
	safestrncpy(login_config.dnsbl_servs, "", sizeof(login_config.dnsbl_servs));
	safestrncpy(login_config.account_engine, "auto", sizeof(login_config.account_engine));
	login_config.allowed_regs = true;
	login_config.time_allowed = 10; //in second

	login_config.client_hash_check = 0;
	login_config.client_hash_nodes = NULL;

	//other default conf
	login_config.loginconf_name = "conf/login_athena.conf";
	login_config.lanconf_name = "conf/subnet_athena.conf";
	login_config.msgconf_name = "conf/msg_conf/login_msg.conf";
}

//-----------------------------------
// Reading main configuration file
//-----------------------------------
int login_config_read(const char* cfgName)
{
	char line[1024], w1[1024], w2[1024];
	FILE* fp = fopen(cfgName, "r");
	if (fp == NULL) {
		ShowError("Configuration file (%s) not found.\n", cfgName);
		return 1;
	}
	while(fgets(line, sizeof(line), fp)) {
		if (line[0] == '/' && line[1] == '/')
			continue;

		if (sscanf(line, "%[^:]: %[^\r\n]", w1, w2) < 2)
			continue;

		if(!strcmpi(w1,"timestamp_format"))
			safestrncpy(timestamp_format, w2, 20);
		else if(!strcmpi(w1,"stdout_with_ansisequence"))
			stdout_with_ansisequence = config_switch(w2);
		else if(!strcmpi(w1,"console_silent")) {
			msg_silent = atoi(w2);
			if( msg_silent ) /* only bother if we actually have this enabled */
				ShowInfo("Console Silent Setting: %d\n", atoi(w2));
		}
		else if( !strcmpi(w1, "bind_ip") ) {
			login_config.login_ip = host2ip(w2);
			if( login_config.login_ip ) {
				char ip_str[16];
				ShowStatus("Login server binding IP address : %s -> %s\n", w2, ip2str(login_config.login_ip, ip_str));
			}
		}
		else if( !strcmpi(w1, "login_port") ) {
			login_config.login_port = (uint16)atoi(w2);
		}
		else if(!strcmpi(w1, "log_login"))
			login_config.log_login = (bool)config_switch(w2);

		else if(!strcmpi(w1, "new_account"))
			login_config.new_account_flag = (bool)config_switch(w2);
		else if(!strcmpi(w1, "new_acc_length_limit"))
			login_config.new_acc_length_limit = (bool)config_switch(w2);
		else if(!strcmpi(w1, "start_limited_time"))
			login_config.start_limited_time = atoi(w2);
		else if(!strcmpi(w1, "check_client_version"))
			login_config.check_client_version = (bool)config_switch(w2);
		else if(!strcmpi(w1, "client_version_to_connect"))
			login_config.client_version_to_connect = strtoul(w2, NULL, 10);
		else if(!strcmpi(w1, "use_MD5_passwords"))
			login_config.use_md5_passwds = (bool)config_switch(w2);
		else if(!strcmpi(w1, "group_id_to_connect"))
			login_config.group_id_to_connect = atoi(w2);
		else if(!strcmpi(w1, "min_group_id_to_connect"))
			login_config.min_group_id_to_connect = atoi(w2);
		else if(!strcmpi(w1, "date_format"))
			safestrncpy(login_config.date_format, w2, sizeof(login_config.date_format));
		else if(!strcmpi(w1, "console"))
			login_config.console = (bool)config_switch(w2);
		else if(!strcmpi(w1, "allowed_regs")) //account flood protection system
			login_config.allowed_regs = atoi(w2);
		else if(!strcmpi(w1, "time_allowed"))
			login_config.time_allowed = atoi(w2);
		else if(!strcmpi(w1, "use_dnsbl"))
			login_config.use_dnsbl = (bool)config_switch(w2);
		else if(!strcmpi(w1, "dnsbl_servers"))
			safestrncpy(login_config.dnsbl_servs, w2, sizeof(login_config.dnsbl_servs));
		else if(!strcmpi(w1, "ipban_cleanup_interval"))
			login_config.ipban_cleanup_interval = (unsigned int)atoi(w2);
		else if(!strcmpi(w1, "ip_sync_interval"))
			login_config.ip_sync_interval = (unsigned int)1000*60*atoi(w2); //w2 comes in minutes.
		else if(!strcmpi(w1, "client_hash_check"))
			login_config.client_hash_check = config_switch(w2);
		else if(!strcmpi(w1, "client_hash")) {
			int group = 0;
			char md5[33];

			if (sscanf(w2, "%d, %32s", &group, md5) == 2) {
				struct client_hash_node *nnode;
				int i;
				CREATE(nnode, struct client_hash_node, 1);

				if(!strcmpi(md5,"any")){
					memset(nnode->hash,1,sizeof(nnode->hash));
				}
				else {
					for (i = 0; i < 32; i += 2) {
						char buf[3];
						unsigned int byte;

						memcpy(buf, &md5[i], 2);
						buf[2] = 0;

						sscanf(buf, "%x", &byte);
						nnode->hash[i / 2] = (uint8)(byte & 0xFF);
					}
				}

				nnode->group_id = group;
				nnode->next = login_config.client_hash_nodes;

				login_config.client_hash_nodes = nnode;
			}
		}
		else if(!strcmpi(w1, "import"))
			login_config_read(w2);
		else
		if(!strcmpi(w1, "account.engine"))
			safestrncpy(login_config.account_engine, w2, sizeof(login_config.account_engine));
		else
		{// try the account engines
			int i;
			for( i = 0; account_engines[i].constructor; ++i )
			{
				AccountDB* db = account_engines[i].db;
				if( db && db->set_property(db, w1, w2) )
					break;
			}
			// try others
			ipban_config_read(w1, w2);
			loginlog_config_read(w1, w2);
		}
	}
	fclose(fp);
	ShowInfo("Finished reading %s.\n", cfgName);
	return 0;
}

/// Get the engine selected in the config settings.
/// Updates the config setting with the selected engine if 'auto'.
static AccountDB* get_account_engine(void)
{
	int i;
	bool get_first = (strcmp(login_config.account_engine,"auto") == 0);

	for( i = 0; account_engines[i].constructor; ++i )
	{
		char name[sizeof(login_config.account_engine)];
		AccountDB* db = account_engines[i].db;
		if( db && db->get_property(db, "engine.name", name, sizeof(name)) &&
			(get_first || strcmp(name, login_config.account_engine) == 0) )
		{
			if( get_first )
				safestrncpy(login_config.account_engine, name, sizeof(login_config.account_engine));
			return db;
		}
	}
	return NULL;
}

//--------------------------------------
// Function called at exit of the server
//--------------------------------------
void do_final(void)
{
	int i;
	struct client_hash_node *hn = login_config.client_hash_nodes;

	while (hn)
	{
		struct client_hash_node *tmp = hn;
		hn = hn->next;
		aFree(tmp);
	}

	login_log(0, "login server", 100, "login server shutdown");
	ShowStatus("Terminating...\n");

	if( login_config.log_login )
		loginlog_final();

	do_final_msg();
	ipban_final();

	for( i = 0; account_engines[i].constructor; ++i )
	{// destroy all account engines
		AccountDB* db = account_engines[i].db;
		if( db )
		{
			db->destroy(db);
			account_engines[i].db = NULL;
		}
	}
	accounts = NULL; // destroyed in account_engines
	online_db->destroy(online_db, NULL);
	auth_db->destroy(auth_db, NULL);

	do_final_loginchrif();

	if( login_fd != -1 )
	{
		do_close(login_fd);
		login_fd = -1;
	}

	ShowStatus("Finished.\n");
}

//------------------------------
// Function called when the server
// has received a crash signal.
//------------------------------
void do_abort(void)
{
}

void set_server_type(void)
{
	SERVER_TYPE = ATHENA_SERVER_LOGIN;
}


/// Called when a terminate signal is received.
void do_shutdown(void)
{
	if( runflag != LOGINSERVER_ST_SHUTDOWN )
	{
		runflag = LOGINSERVER_ST_SHUTDOWN;
		ShowStatus("Shutting down...\n");
		// TODO proper shutdown procedure; kick all characters, wait for acks, ...  [FlavioJS]
		do_shutdown_loginchrif();
		flush_fifos();
		runflag = CORE_ST_STOP;
	}
}


//------------------------------
// Login server initialization
//------------------------------
int do_init(int argc, char** argv)
{
	int i;

	// intialize engines (to accept config settings)
	for( i = 0; account_engines[i].constructor; ++i )
		account_engines[i].db = account_engines[i].constructor();

	// read login-server configuration
	login_set_defaults();
	cnsl_get_options(argc,argv);

	login_config_read(login_config.loginconf_name);
	msg_config_read(login_config.msgconf_name);
	login_lan_config_read(login_config.lanconf_name);
	//end config

	rnd_init();

	do_init_loginchrif();

	// initialize logging
	if( login_config.log_login )
		loginlog_init();

	// initialize static and dynamic ipban system
	ipban_init();

	// Online user database init
	online_db = idb_alloc(DB_OPT_RELEASE_DATA);
	add_timer_func_list(waiting_disconnect_timer, "waiting_disconnect_timer");

	// Interserver auth init
	auth_db = idb_alloc(DB_OPT_RELEASE_DATA);

	// set default parser as parse_login function
	set_defaultparse(parse_login);

	// every 10 minutes cleanup online account db.
	add_timer_func_list(online_data_cleanup, "online_data_cleanup");
	add_timer_interval(gettick() + 600*1000, online_data_cleanup, 0, 0, 600*1000);

	// Account database init
	accounts = get_account_engine();
	if( accounts == NULL ) {
		ShowFatalError("do_init: account engine '%s' not found.\n", login_config.account_engine);
		exit(EXIT_FAILURE);
	} else {

		if(!accounts->init(accounts)) {
			ShowFatalError("do_init: Failed to initialize account engine '%s'.\n", login_config.account_engine);
			exit(EXIT_FAILURE);
		}
	}

	// server port open & binding
	if( (login_fd = make_listen_bind(login_config.login_ip,login_config.login_port)) == -1 ) {
		ShowFatalError("Failed to bind to port '"CL_WHITE"%d"CL_RESET"'\n",login_config.login_port);
		exit(EXIT_FAILURE);
	}

	if( runflag != CORE_ST_STOP ) {
		shutdown_callback = do_shutdown;
		runflag = LOGINSERVER_ST_RUNNING;
	}

	do_init_logincnslif();

	ShowStatus("The login-server is "CL_GREEN"ready"CL_RESET" (Server is listening on the port %u).\n\n", login_config.login_port);
	login_log(0, "login server", 100, "login server started");

	return 0;
}

int login_msg_config_read(char *cfgName){
	return _msg_config_read(cfgName,LOGIN_MAX_MSG,msg_table);
}
const char* login_msg_txt(int msg_number){
	return _msg_txt(msg_number,LOGIN_MAX_MSG,msg_table);
}
void login_do_final_msg(void){
	_do_final_msg(LOGIN_MAX_MSG,msg_table);
}
