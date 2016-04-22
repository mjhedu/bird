/*
 * br_irc_proto.h
 *
 *  Created on: Apr 9, 2016
 *      Author: reboot
 */

#ifndef PROTO_BGP_BR_IRC_PROTO_H_
#define PROTO_BGP_BR_IRC_PROTO_H_

struct proto_irc_u_config
{
  char *net_name;
  char *true_name;
  char *username;
  char *real_name;
  char *ident;
  char *hostname;
};

#define MIN_CH_NAME_LEN	1
#define MAX_CH_NAME_LEN	15
#define MAX_CL_NAME_LEN	31

#define MAX_NAME_LEN	31

#include <stdint.h>

#include "br_hasht.h"
#include "lib/ip.h"

#include "brc_memory.h"

typedef struct proto_irc_chan
{
  char name[MAX_CH_NAME_LEN + 1];
  uint8_t flags;
  mda sockref;
} proto_irc_chan;

#define IRC_STATUS_HAS_NAME	(uint32_t) 1 << 10
#define IRC_STATUS_AUTHED	(uint32_t) 1 << 11
#define IRC_STATUS_HAS_DNS	(uint32_t) 1 << 12
#define IRC_STATUS_HAS_IDENT	(uint32_t) 1 << 13
#define IRC_STATUS_HAS_PONG	(uint32_t) 1 << 14

#define IRC_STATUS_LOGGED_IN	(IRC_STATUS_HAS_NAME|IRC_STATUS_AUTHED|IRC_STATUS_HAS_PONG)

struct proto_irc_req
{
  char *cmd;
  mda cmd_params;
  char *trailer;
  unsigned char request[];
};

struct proto_irc_resp
{
  char *prefix;
  char *cmd;
  mda cmd_params;
  char *trailer;
};

#pragma pack(push, 4)

#define F_CHAN_VOICE	(uint8_t)1
#define F_CHAN_OPER	(uint8_t)1 << 1

struct payload_chan
{
  char name[MAX_CH_NAME_LEN + 1];
  uint8_t flags;
};

#define F_IRC_USER_SECURE	(uint32_t) 1 << 4


#define F_IRC_UPDATE		(F_IRC_UPDATE_AUTH|F_IRC_UPDATE_NAME|F_IRC_UPDATE_CHAN)

#define PAYLOAD_CR_SIZE		35

#define MAX_IRC_MSGLEN		512-2
#define IRC_MSGBUFLEN		512+1

#define MAX_IRC_USERNAME	19
#define MAX_IRC_REALNAME	47

struct proto_irc_rlmsg
{
  char code[15];
  char hostname[100];
  char args[100];
  char message[MAX_IRC_MSGLEN];
};

typedef struct irc_ea_payload
{
  char net_name[MAX_CL_NAME_LEN + 1];
  char true_name[MAX_CL_NAME_LEN + 1];
  char user_name[MAX_IRC_USERNAME + 1];
  char real_name[MAX_IRC_REALNAME + 1];
  uint8_t pnode_pxlen;
  uint32_t flags;
  struct payload_chan joined[PAYLOAD_CR_SIZE];
} irc_ea_payload;

#pragma pack(pop)

/* Error Replies.  */
#define ERR_NOSUCHNICK            401
#define ERR_NOSUCHNICK_TEXT       "%s :No such nick/channel."

#define ERR_NOSUCHSERVER          402
#define ERR_NOSUCHSERVER_TEXT     "%s :No such server"

#define ERR_NOSUCHCHANNEL         403
#define ERR_NOSUCHCHANNEL_TEXT    "%s :No such channel."

#define ERR_CANNOTSENDTOCHAN      404
#define ERR_CANNOTSENDTOCHAN_TEXT "%s :Cannot send to channel."

#define ERR_TOOMANYCHANNELS       405
#define ERR_TOOMANYCHANNELS_TEXT  "%s :You have joined too many channels"

#define ERR_WASNOSUCHNICK         406
#define ERR_WASNOSUCHNICK_TEXT    "%s :There was no such nickname"

#define ERR_TOOMANYTARGETS        407

#define ERR_NOORIGIN              409
#define ERR_NOORIGIN_TEXT         ":No origin specified"

#define ERR_NORECIPIENT           411

#define ERR_NOTEXTTOSEND          412
#define ERR_NOTEXTTOSEND_TEXT     ":No text to send"

#define ERR_NOTOPLEVEL            413
#define ERR_WILDTOPLEVEL          414

#define ERR_UNKNOWNCOMMAND        421
#define ERR_UNKNOWNCOMMAND_TEXT   "%s :Unknown command"

#define ERR_NOMOTD                422
#define ERR_NOMOTD_TEXT           ":MOTD File is missing"

#define ERR_NOADMININFO           423
#define ERR_FILEERROR             424
#define ERR_FILEERROR_TEXT        ":File error doing %s on %s"

#define ERR_NONICKNAMEGIVEN       431
#define ERR_NONICKNAMEGIVEN_TEXT  ":No nickname given"

#define ERR_ERRONEUSNICKNAME      432
#define ERR_ERRONEUSNICKNAME_TEXT "Erroneus nickname"

#define ERR_NICKNAMEINUSE         433
#define ERR_NICKNAMEINUSE_TEXT    "Nickname is already in use"

#define ERR_NICKCOLLISION         436
#define ERR_NICKCOLLISION_TEXT    "%s :Nickname collision KILL"
#define ERR_USERNOTINCHANNEL      441
#define ERR_USERNOTINCHANNEL_TEXT "%s %s :They aren't on that channel"

#define ERR_NOTONCHANNEL          442
#define ERR_NOTONCHANNEL_TEXT     "%s :You're not on that channel."

#define ERR_USERONCHANNEL         443
#define ERR_USERONCHANNEL_TEXT    "%s %s :is already on channel."

#define ERR_NOLOGIN               444
#define ERR_NOLOGIN_TEXT          "%s :User not logged in"
#define ERR_SUMMONDISABLED        445
#define ERR_SUMMONDISABLED_TEXT   ":SUMMON has been disabled"
#define ERR_USERSDISABLED         446
#define ERR_USERSDISABLED_TEXT    ":USERS has been disabled"
#define ERR_NOTREGISTERED         451
#define ERR_NOTREGISTERED_TEXT    ":You have not registered"

#define ERR_NEEDMOREPARAMS        461
#define ERR_NEEDMOREPARAMS_TEXT   "%s :Not enough parameters."

#define ERR_ALREADYREGISTRED      462
#define ERR_ALREADYREGISTRED_TEXT "You may not reregister"

#define ERR_NOPERMFORHOST         463
#define ERR_PASSWDMISMATCH        464
#define ERR_PASSWDMISMATCH_TEXT   ":Password incorrect"
#define ERR_YOUREBANNEDCREEP      465
#define ERR_YOUREBANNEDCREEP_TEXT ":You are banned from this server"

#define ERR_KEYSET                467
#define ERR_KEYSET_TEXT           "%s :Channel key already set."

#define ERR_CHANNELISFULL         471
#define ERR_CHANNELISFULL_TEXT    "%s :Cannot join channel (+l)"

#define ERR_UNKNOWNMODE           472
#define ERR_UNKNOWNMODE_TEXT      "%c :is unknown mode char to me."

#define ERR_INVITEONLYCHAN        473
#define ERR_INVITEONLYCHAN_TEXT   "%s :Cannot join channel (+i)"

#define ERR_BANNEDFROMCHAN        474
#define ERR_BANNEDFROMCHAN_TEXT   "%s :Cannot join channel (+b)"

#define ERR_BADCHANNELKEY         475
#define ERR_BADCHANNELKEY_TEXT    "%s :Cannot join channel (+k)"

#define ERR_NOPRIVILEGES          481
#define ERR_NOPRIVILEGES_TEXT     "Permission Denied- " \
                                  "You're not an IRC operator"

#define ERR_CHANOPRIVSNEEDED      482
#define ERR_CHANOPRIVSNEEDED_TEXT "%s :You're not channel operator."

#define ERR_CANTKILLSERVER        483

#define ERR_NOOPERHOST            491
#define ERR_NOOPERHOST_TEXT       ":No O-lines for your host"

#define ERR_UMODEUNKNOWNFLAG      501

#define ERR_USERSDONTMATCH        502
#define ERR_USERSDONTMATCH_TEXT   ":Cant change mode for other users"

#define RPL_USERHOST              302
#define RPL_CHANNELMODEIS_TEXT    "%s %s"
#define RPL_CHANNELMODEIS         324
#define RPL_CHANCREATED           329

#define LINK_CLOSE_TEXT		"ERROR :Closing Link: %s[%s] (%s)\r\n"

#define IRC_MESSAGE_DLMT	"\xD\xA"

#endif /* PROTO_BGP_BR_IRC_PROTO_H_ */
