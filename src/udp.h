// Copyright (c) 2013 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef SYSCOIN_UDP_H
#define SYSCOIN_UDP_H

#include <string>
#include "net.h"
#include "serialize.h"

void ThreadUDPServer();
bool SendUDPMessage(const CNode *pfrom, const std::string &strCommand, const std::vector<CInv> &vInv);

#endif // SYSCOIN_UDP_H
