/*
 * Copyright (C) 2004-2012  See the AUTHORS file for details.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation.
 */

#include "Chan.h"
#include "User.h"
#include "Client.h"
#include "IRCSock.h"
#include "Modules.h"
#include "znc.h"
#include "DCCBounce.h"

class CIdMsgMod : public CGlobalModule {
public:
	GLOBALMODCONSTRUCTOR(CIdMsgMod) {}

	virtual bool OnLoad(const CString& sArgs, CString& sMessage) {
		return true;
	}

	virtual ~CIdMsgMod() {}

	virtual bool OnServerCapAvailable(const CString& sCap) {
		return sCap == "identify-msg";
	}

	virtual void OnClientCapLs(SCString& ssCaps) {
		ssCaps.insert("identify-msg");
	}

	virtual bool IsClientCapSupported(const CString& sCap, bool bState) {
		return sCap == "identify-msg";
	}

	virtual EModRet OnPrivMsg(CNick& Nick, CString& sMessage) {
		if (GetUser()->GetIRCSock()->IsCapAccepted("identify-msg")) {
			char cSign = GetSign(sMessage);
			if (IsCTCP(sMessage)) {
				return HandlePrivCTCP(Nick, sMessage, cSign, true);
			} else {
				return HandlePrivMsg(Nick, sMessage, cSign, true);
			}
		} else {
			return HandlePrivMsg(Nick, sMessage, '-', false);
		}
	}

	virtual EModRet OnChanMsg(CNick& Nick, CChan& Channel, CString& sMessage) {
		if (GetUser()->GetIRCSock()->IsCapAccepted("identify-msg")) {
			char cSign = GetSign(sMessage);
			if (IsCTCP(sMessage)) {
				return HandleChanCTCP(Nick, Channel, sMessage, cSign, true);
			} else {
				return HandleChanMsg(Nick, Channel, sMessage, cSign, true);
			}
		} else {
			return HandleChanMsg(Nick, Channel, sMessage, '-', false);
		}
	}

	virtual EModRet OnPrivNotice(CNick& Nick, CString& sMessage) {
		if (GetUser()->GetIRCSock()->IsCapAccepted("identify-msg")) {
			char cSign = GetSign(sMessage);
			if (IsCTCP(sMessage)) {
				return HandleCTCPReply(Nick, sMessage, cSign, true);
			} else {
				return HandlePrivNotice(Nick, sMessage, cSign, true);
			}
		} else {
			return HandlePrivNotice(Nick, sMessage, '-', false);
		}
	}

	virtual EModRet OnChanNotice(CNick& Nick, CChan& Channel, CString& sMessage) {
		if (GetUser()->GetIRCSock()->IsCapAccepted("identify-msg")) {
			char cSign = GetSign(sMessage);
			return HandleChanNotice(Nick, Channel, sMessage, cSign, true);
		} else {
			return HandleChanNotice(Nick, Channel, sMessage, '-', false);
		}
	}

	// These calls are possible only for non-identify-msg server
	virtual EModRet OnCTCPReply(CNick& Nick, CString& sMessage) {
		return HandleCTCPReply(Nick, sMessage, '-', false);
	}

	virtual EModRet OnPrivCTCP(CNick& Nick, CString& sMessage) {
		return HandlePrivCTCP(Nick, sMessage, '-', false);
	}

	virtual EModRet OnChanCTCP(CNick& Nick, CChan& Channel, CString& sMessage) {
		return HandleChanCTCP(Nick, Channel, sMessage, '-', false);
	}

private:

	char GetSign(CString& sMessage) {
		char cSign = '-';
		if (sMessage.length() > 0) {
			cSign = sMessage[0];
			sMessage.LeftChomp();
		}
		return cSign;
	}

	bool IsCTCP(CString& sMessage) {
		if (sMessage.WildCmp("\001*\001")) {
			sMessage.LeftChomp();
			sMessage.RightChomp();
			return true;
		} else {
			return false;
		}
	}

//TODO call the rest of global modules too
#define CALLMODS(func) do {\
	if (bUseSign) {\
		sMessage = cSign + sMessage;\
	}\
	if (GetUser()->GetModules().func) {\
		/* User module halted. Do not forward message to clients */\
		return HALT;\
	}\
	if (bUseSign) {\
		sMessage.LeftChomp();\
	}\
} while (0)

	void Put(const CString& sPrefix, const CString& sMessage, char cSign) {
		for (unsigned int a = 0; a < GetUser()->GetClients().size(); ++a) {
			CClient* Client = GetUser()->GetClients()[a];
			if (Client->IsCapEnabled("identify-msg")) {
				Client->PutClient(sPrefix + cSign + sMessage);
			} else {
				Client->PutClient(sPrefix + sMessage);
			}
		}
	}

	EModRet HandlePrivMsg(CNick& Nick, CString& sMessage, char cSign, bool bUseSign) {
		CALLMODS(OnPrivMsg(Nick, sMessage));
		Put(":" + Nick.GetNickMask() + " PRIVMSG " + GetUser()->GetCurNick() + " :", sMessage, cSign);
		if (!GetUser()->IsUserAttached()) {
			// If the user is detached, add to the buffer
			GetUser()->AddQueryBuffer(":" + Nick.GetNickMask() + " PRIVMSG ",
					" :" + GetUser()->AddTimestamp(bUseSign ? cSign + sMessage : sMessage));
		}
		return HALT;
	}

	EModRet HandleChanMsg(CNick& Nick, CChan& Channel, CString& sMessage, char cSign, bool bUseSign) {
		CALLMODS(OnChanMsg(Nick, Channel, sMessage));
		if (!Channel.IsDetached()) {
			Put(":" + Nick.GetNickMask() + " PRIVMSG " + Channel.GetName() + " :", sMessage, cSign);
		}
		if (Channel.KeepBuffer() || !GetUser()->IsUserAttached() || Channel.IsDetached()) {
			Channel.AddBuffer(":" + Nick.GetNickMask() + " PRIVMSG " + Channel.GetName() +
					" :" + GetUser()->AddTimestamp(bUseSign ? cSign + sMessage : sMessage));
		}
		return HALT;
	}

	EModRet HandlePrivNotice(CNick& Nick, CString& sMessage, char cSign, bool bUseSign) {
		CALLMODS(OnPrivNotice(Nick, sMessage));
		Put(":" + Nick.GetNickMask() + " NOTICE " + GetUser()->GetCurNick() + " :", sMessage, cSign);
		if (!GetUser()->IsUserAttached()) {
			// If the user is detached, add to the buffer
			GetUser()->AddQueryBuffer(":" + Nick.GetNickMask() + " NOTICE ",
					" :" + GetUser()->AddTimestamp(bUseSign ? cSign + sMessage : sMessage));
		}
		return HALT;
	}

	EModRet HandleChanNotice(CNick& Nick, CChan& Channel, CString& sMessage, char cSign, bool bUseSign) {
		CALLMODS(OnChanNotice(Nick, Channel, sMessage));
		if (!Channel.IsDetached()) {
			Put(":" + Nick.GetNickMask() + " NOTICE " + Channel.GetName() + " :", sMessage, cSign);
		}
		if (Channel.KeepBuffer() || !GetUser()->IsUserAttached() || Channel.IsDetached()) {
			Channel.AddBuffer(":" + Nick.GetNickMask() + " NOTICE " + Channel.GetName() +
					" :" + GetUser()->AddTimestamp(bUseSign ? cSign + sMessage : sMessage));
		}
		return HALT;
	}

	EModRet HandleCTCPReply(CNick& Nick, CString& sMessage, char cSign, bool bUseSign) {
		CALLMODS(OnCTCPReply(Nick, sMessage));
		Put(":" + Nick.GetNickMask() + " NOTICE " + GetUser()->GetCurNick() + " :", "\001" + sMessage + "\001", cSign);
		return HALT;
	}

	EModRet HandlePrivCTCP(CNick& Nick, CString& sMessage, char cSign, bool bUseSign) {
		CALLMODS(OnPrivCTCP(Nick, sMessage));
		if (sMessage.TrimPrefix("ACTION ")) {
			//TODO prefix sMessage with cSign temporarily for MODULECALL?
			MODULECALL(OnPrivAction(Nick, sMessage), m_pUser, NULL, return HALT);

			if (!m_pUser->IsUserAttached()) {
				// If the user is detached, add to the buffer
				m_pUser->AddQueryBuffer(":" + Nick.GetNickMask() + " PRIVMSG ",
						" :\001ACTION " + m_pUser->AddTimestamp(bUseSign ? cSign + sMessage : sMessage) + "\001");
			}

			sMessage = "ACTION " + sMessage;
		}
		if (sMessage.Equals("DCC ", false, 4) && m_pUser && m_pUser->BounceDCCs() && m_pUser->IsUserAttached()) {
			// DCC CHAT chat 2453612361 44592
			CString sType = sMessage.Token(1);
			CString sFile = sMessage.Token(2);
			unsigned long uLongIP = sMessage.Token(3).ToULong();
			unsigned short uPort = sMessage.Token(4).ToUShort();
			unsigned long uFileSize = sMessage.Token(5).ToULong();

			if (sType.Equals("CHAT")) {
				CNick FromNick(Nick.GetNickMask());
				unsigned short uBNCPort = CDCCBounce::DCCRequest(FromNick.GetNick(), uLongIP, uPort, "", true, m_pUser, CUtils::GetIP(uLongIP));
				if (uBNCPort) {
					CString sIP = m_pUser->GetLocalDCCIP();
					Put(":" + Nick.GetNickMask() + " PRIVMSG " + GetUser()->GetCurNick() + " :",
							"\001DCC CHAT chat " + CString(CUtils::GetLongIP(sIP)) + " " + CString(uBNCPort) + "\001", cSign);
				}
			} else if (sType.Equals("SEND")) {
				// DCC SEND readme.txt 403120438 5550 1104
				unsigned short uBNCPort = CDCCBounce::DCCRequest(Nick.GetNick(), uLongIP, uPort, sFile, false, m_pUser, CUtils::GetIP(uLongIP));
				if (uBNCPort) {
					CString sIP = m_pUser->GetLocalDCCIP();
					Put(":" + Nick.GetNickMask() + " PRIVMSG " + GetUser()->GetCurNick() + " :",
							"\001DCC SEND " + sFile + " " + CString(CUtils::GetLongIP(sIP)) + " " + CString(uBNCPort) + " " + CString(uFileSize) + "\001", cSign);
				}
			} else if (sType.Equals("RESUME")) {
				// Need to lookup the connection by port, filter the port, and forward to the user
				CDCCBounce* pSock = (CDCCBounce*) CZNC::Get().GetManager().FindSockByLocalPort(sMessage.Token(3).ToUShort());

				if (pSock && pSock->GetSockName().Equals("DCC::", false, 5)) {
					Put(":" + Nick.GetNickMask() + " PRIVMSG " + GetUser()->GetCurNick() + " :",
							"\001DCC " + sType + " " + sFile + " " + CString(pSock->GetUserPort()) + " " + sMessage.Token(4) + "\001", cSign);
				}
			} else if (sType.Equals("ACCEPT")) {
				// Need to lookup the connection by port, filter the port, and forward to the user
				CSockManager& Manager = CZNC::Get().GetManager();

				for (unsigned int a = 0; a < Manager.size(); a++) {
					CDCCBounce* pSock = (CDCCBounce*) Manager[a];

					if (pSock && pSock->GetSockName().Equals("DCC::", false, 5)) {
						if (pSock->GetUserPort() == sMessage.Token(3).ToUShort()) {
							Put(":" + Nick.GetNickMask() + " PRIVMSG " + GetUser()->GetCurNick() + " :",
									"\001DCC " + sType + " " + sFile + " " + CString(pSock->GetLocalPort()) + " " + sMessage.Token(4) + "\001", cSign);
						}
					}
				}
			}

			return HALT;
		}

		// This handles everything which wasn't handled yet
		if (GetUser()->GetIRCSock()->OnGeneralCTCP(Nick, sMessage)) {
			return HALT;
		}

		Put(":" + Nick.GetNickMask() + " PRIVMSG " + GetUser()->GetCurNick() + " :",
				"\001" + sMessage + "\001", cSign);
		return HALT;
	}

	EModRet HandleChanCTCP(CNick& Nick, CChan& Channel, CString& sMessage, char cSign, bool bUseSign) {
		CALLMODS(OnChanCTCP(Nick, Channel, sMessage));
		if (sMessage.TrimPrefix("ACTION ")) {
			// prefix message with sign?
			MODULECALL(OnChanAction(Nick, Channel, sMessage), m_pUser, NULL, return HALT);
			if (Channel.KeepBuffer() || !m_pUser->IsUserAttached() || Channel.IsDetached()) {
				Channel.AddBuffer(":" + Nick.GetNickMask() + " PRIVMSG " + Channel.GetName() + " :\001ACTION "
						+ m_pUser->AddTimestamp(bUseSign ? cSign + sMessage : sMessage) + "\001");
			}
			sMessage = "ACTION " + sMessage;
		}

		// This handles everything which wasn't handled yet
		if (GetUser()->GetIRCSock()->OnGeneralCTCP(Nick, sMessage)) {
			return HALT;
		}

		if (!Channel.IsDetached()) {
			Put(":" + Nick.GetNickMask() + " PRIVMSG " + Channel.GetName() + " :",
					"\001" + sMessage + "\001", cSign);
		}
		return HALT;
	}

};

GLOBALMODULEDEFS(CIdMsgMod, "Adds support for identify-msg capability")

