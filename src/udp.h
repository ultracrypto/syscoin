// Copyright (c) 2013 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_UDP_H
#define BITCOIN_UDP_H

#include <string>
#include "net.h"
#include "serialize.h"

void ThreadUDPServer();

bool SendUDPMessage(CNode *pfrom, string strCommand, vector<CInv> &vInv);

#endif // BITCOIN_UDP_H
