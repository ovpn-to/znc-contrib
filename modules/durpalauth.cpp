/**
 * Copyright (C) 2008 Ben Ford <binford2k@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation.
 *
 * @class CDrupalAuthMod
 * @author Ben Ford <binford2k@gmail.com>
 * @brief Drupal authentication module for znc.
 *
 * The module expects these space separated arguments, in this order
 *
 * <DB user> <DB password> <DB host> <DB name> <IRC server> <Channel name> [Authentication Order]
 * * DB user:		the username for your Drupal database
 * * DB password:	the password for your Drupal database
 * * DB host:		the hostname of the server running your Drupal database
 * * DB name:		the database name of your Drupal database
 * * IRC server:	the IRC server to connect imported Drupal users to
 * * Channel name:	the default channel imported users should join
 * * Auth order:	the order the module should use to authenticate:
 *						valid parameters are "local" and "drupal", separated 
 *						by a comma and no space. Defaults to local only.
 */

#include "znc.h"
#include "User.h"
#include "Modules.h"
#include "Chan.h"

#include <mysql/mysql.h>

enum authType { NONE, LOCAL, DRUPAL };

class CDrupalAuthMod : public CGlobalModule {
public:
	GLOBALMODCONSTRUCTOR(CDrupalAuthMod) {
		m_Cache.SetTTL(60000/*ms*/);
	}
	virtual ~CDrupalAuthMod() {}
	
	virtual bool OnBoot() {
		return true;
	}
	
	virtual bool OnLoad(const CString& sArgs, CString& sMessage) {
		sUserDB		= sArgs.Token(0);
		sPassDB		= sArgs.Token(1);
		sHost		= sArgs.Token(2);
		sDatabase	= sArgs.Token(3);
		sIRCServer	= sArgs.Token(4);
		sChan		= sArgs.Token(5);
		sAuthOrder	= sArgs.Token(6);

		if(sAuthOrder.Token(0, false, ",").AsLower() == "drupal") {
			authFirst = DRUPAL;
			DEBUG("=== authFirst: Drupal");
		}
		else {
			authFirst = LOCAL;
			DEBUG("=== authFirst: Local");
		}

		if(sAuthOrder.Token(1, false, ",").AsLower() == "local") {
			authSecond = LOCAL;
			DEBUG("=== authSecond: Local");
		}
		else if(sAuthOrder.Token(1, false, ",").AsLower() == "drupal") {
			authSecond = DRUPAL;
			DEBUG("=== authSecond: Drupal");
		}
		else {
			authSecond = NONE;
			DEBUG("authSecond: None");
		}


		return true;
	}
	
	virtual EModRet OnLoginAttempt(CSmartPtr<CAuthBase> Auth) {
		CString const user(Auth->GetUsername());
		CString const pass(Auth->GetPassword());
		CUser* pUser(CZNC::Get().FindUser(user));
		CString sDrupalLogin = GetNV(user); // this should only be set if the user was imported from Drupal

		if(sDrupalLogin.empty() && pUser && authFirst == LOCAL) {
			DEBUG("=== Punting to local account");
			return CONTINUE;
		}
		
		if(authFirst == DRUPAL || authSecond == DRUPAL) {
			CString const key(CString(user + ":" + pass).MD5());
			if (m_Cache.HasItem(key)) {
				Auth->AcceptLogin(*pUser);
				DEBUG("+++ Found in cache");
			}
			else if (DrupalAuthValidate(user, pass)) {
				DEBUG("+++ Successful Drupal password check");
				
				if (!pUser) {
					DEBUG("+++ Importing Drupal user on first login");
					
					// create user
					CUser* pNewUser = new CUser(user);
					CString sSalt = CUtils::GetSalt();
					pNewUser->SetPass(CUser::SaltedHash(pass, sSalt), CUser::HASH_DEFAULT, sSalt);
					pNewUser->AddServer(sIRCServer);
					pNewUser->AddChan(sChan, true); // Save channel into config file
					pNewUser->SetUseClientIP(true);
				
					CString sErr;
					if (!CZNC::Get().AddUser(pNewUser, sErr)) {
						delete pNewUser;
						DEBUG("Error: User not added! [" + sErr + "]");
						Auth->RefuseLogin("Error importing Drupal user");
					}

					// indicates both that this user is imported from Drupal and the last login time
					SetNV(user, CString::ToTimeStr(time(NULL)));
					pUser = CZNC::Get().FindUser(user);
				}
				
				Auth->AcceptLogin(*pUser);
				m_Cache.AddItem(key);
			}
			else if(sDrupalLogin.empty() && authSecond == LOCAL) {
				DEBUG("=== Falling through to local account");
				return CONTINUE;
			}
			else {
				Auth->RefuseLogin("Drupal Authentication failed");
				DEBUG("--- FAILED Drupal password check");
			}
		}
		
		return HALT;
	}
	
private:
	TCacheMap<CString>	m_Cache;
	
	CString		sUserDB;
	CString		sPassDB;
	CString		sHost;
	CString		sDatabase;
	CString		sIRCServer;
	CString		sChan;
	CString		sAuthOrder;
	authType	authFirst;
	authType	authSecond;
	
	bool DrupalAuthValidate(CString sUser, CString sPassword) {
		MYSQL		*conn;		/* pointer to connection handler */
		MYSQL_RES	*res_set;	/* Result set, for counting results from the database */

		bool retval = false;

		conn = mysql_init(NULL);
		if(conn){
			int uLen = sizeof(char)*strlen(sUser.c_str());
			int pLen = sizeof(char)*strlen(sPassword.c_str());
			char *user = (char*) malloc(2*uLen+1);
			char *password = (char*) malloc(2*pLen+1);
			char *query = (char*) malloc(2*(uLen+pLen)+70);
			
			mysql_real_escape_string(conn, user, sUser.c_str(), uLen);
			mysql_real_escape_string(conn, password, sPassword.c_str(), pLen);				 
			sprintf(query, "SELECT name FROM users WHERE name='%s' AND pass=MD5('%s') AND status=1", user, password);
				
			if(!mysql_real_connect(conn, sHost.c_str(), sUserDB.c_str(), sPassDB.c_str(), sDatabase.c_str(), 0, NULL, 0))
			{
				CString err	= mysql_error(conn);
				DEBUG("--- Database login failed: "+err);
			}
			else if(mysql_query(conn, query))
			{
				CString err	= mysql_error(conn);
				DEBUG("--- Query failed: "+err);
			}
			else
			{
				if((res_set = mysql_store_result(conn)))
				{
					// if this is a valid login, we should have exactly one row returned
					retval = (mysql_num_rows(res_set) == 1);
					mysql_free_result(res_set);
				}
			}
			free(user);
			free(password);
			free(query);
			mysql_close(conn);
		}
		else {
			DEBUG("--- MySQL init failed.  WTF?  OOM?");
		}
		return retval;
	}
};

GLOBALMODULEDEFS(CDrupalAuthMod, "Allow users to authenticate via Drupal database.")