// Copyright (c) 2013 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "protocol.h"
#include "udp.h"
#include "net.h"
#include "netbase.h"
#include "serialize.h"
#include "init.h"
#include <boost/bind.hpp>
#include <boost/asio.hpp>
#include "chainparams.h"
using namespace std;
using namespace boost;

using boost::asio::ip::udp;


class server
{
private:
	CConnman* connman;
public:
  server(CConnman* connmanIn, boost::asio::io_service& io_service, short port)
    : connman(connmanIn),io_service_(io_service),
      socket_(io_service, udp::endpoint(udp::v4(), port))
  {
    socket_.async_receive_from(
        boost::asio::buffer(data_, max_length), sender_endpoint_,
        boost::bind(&server::handle_receive_from, this,
          boost::asio::placeholders::error,
          boost::asio::placeholders::bytes_transferred));
  }

  void handle_receive_from(const boost::system::error_code& error,
      size_t bytes_recvd)
  {
    // if we don't know the node via TCP, ignore message
    CNetAddr remote_addr;
    LookupHost(sender_endpoint_.address().to_string(), remote_addr, false);

    CNode *pfrom = connman->FindNode(remote_addr);   // FIXME need ref?

    if (pfrom && !error && bytes_recvd > 0)
    {
		connman->ProcessReceivedBytes(pfrom, data_, bytes_recvd);
    }

    // fall through:
    // wait for next UDP message
    socket_.async_receive_from(
        boost::asio::buffer(data_, max_length), sender_endpoint_,
        boost::bind(&server::handle_receive_from, this,
          boost::asio::placeholders::error,
          boost::asio::placeholders::bytes_transferred));
  }

  void handle_send_to(const boost::system::error_code& /*error*/,
      size_t /*bytes_sent*/)
  {
    // wait for next UDP message
    socket_.async_receive_from(
        boost::asio::buffer(data_, max_length), sender_endpoint_,
        boost::bind(&server::handle_receive_from, this,
          boost::asio::placeholders::error,
          boost::asio::placeholders::bytes_transferred));
  }

  void sendmsg(udp::endpoint &remote_endpoint,
               const char *data, unsigned int data_len)
  {
        socket_.async_send_to(
            boost::asio::buffer(data, data_len), remote_endpoint,
            boost::bind(&server::handle_send_to, this,
              boost::asio::placeholders::error,
              boost::asio::placeholders::bytes_transferred));
  }

  void sendmsg(std::string ipAddr, std::string strPort,
               char *data, unsigned int data_len)
  {
      udp::resolver resolver(io_service_);
      udp::resolver::query query(udp::v4(), ipAddr, strPort);
      udp::endpoint receiver_endpoint = *resolver.resolve(query);
      sendmsg(receiver_endpoint, data, data_len);
  }

private:
  boost::asio::io_service& io_service_;
  udp::socket socket_;
  udp::endpoint sender_endpoint_;
  enum { max_length = 100 * 1024 };
  char data_[max_length];
};

static class server *cur_server = NULL;

bool SendUDPMessage(CNode *pfrom, string strCommand, vector<CInv> &vInv)
{
    CDataStream vSend(SER_NETWORK, PROTOCOL_VERSION);
    unsigned int nHeaderStart = vSend.size();
    vSend << CMessageHeader(Params().MessageStart(), strCommand.c_str(), 0);
    unsigned int nMessageStart = vSend.size();

    vSend << vInv;

    // Set the size
    unsigned int nSize = vSend.size() - nMessageStart;
    memcpy((char*)&vSend[nHeaderStart] + CMessageHeader::MESSAGE_SIZE_OFFSET, &nSize, sizeof(nSize));

    // Set the checksum
    uint256 hash = Hash(vSend.begin() + nMessageStart, vSend.end());
    unsigned int nChecksum = 0;
    memcpy(&nChecksum, &hash, sizeof(nChecksum));
    assert(nMessageStart - nHeaderStart >= CMessageHeader::CHECKSUM_OFFSET + sizeof(nChecksum));
    memcpy((char*)&vSend[nHeaderStart] + CMessageHeader::CHECKSUM_OFFSET, &nChecksum, sizeof(nChecksum));

    if (cur_server) {
        cur_server->sendmsg(pfrom->addr.ToString(), pfrom->addr.ToStringPort(),
                            &vSend[0], (unsigned int) vSend.size());
        
        return true;
    }

    return false;
}

void ThreadUDPServer2()
{
    printf("ThreadUDPServer started\n");

    try
    {
      boost::asio::io_service io_service;
  
      server s(&g_connman, io_service, GetListenPort());

      cur_server = &s;
  
      while (!fRequestShutdown)
          io_service.run_one();

      cur_server = NULL;

    }
    catch (std::exception& e)
    {
		LogPrintf("ThreadUDPServer2 %s\n", e.what());
		printf("ThreadUDPServer2 %s\n", e.what());
    }

}

void ThreadUDPServer()
{
    // Make this thread recognisable as the UDP server thread
    RenameThread("syscoin-udp");

    try
    {
        ThreadUDPServer2();
    }
    catch (std::exception& e) {
        LogPrintf("ThreadUDPServer %s\n", e.what());
		printf("ThreadUDPServer %s\n", e.what());
    }
	printf("ThreadUDPServer exited\n");
}

