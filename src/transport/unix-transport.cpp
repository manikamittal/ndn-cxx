/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2013 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

#include <stdexcept>
#include <stdlib.h>

#include <ndn-cpp/face.hpp>
#include <ndn-cpp/transport/unix-transport.hpp>
#include <ndn-cpp/c/util/ndn_memory.h>

#include <boost/asio.hpp>
#include <boost/bind.hpp>

using namespace std;
typedef boost::asio::local::stream_protocol protocol;

namespace ndn {

const size_t MAX_LENGTH = 9000;

class UnixTransport::Impl
{
public:
  Impl(UnixTransport &transport)
    : transport_(transport)
    , socket_(*transport_.ioService_)
    , partialDataSize_(0)
    , connectionInProgress_(false)
  {
  }

  void
  connectHandler(const boost::system::error_code& error)
  {
    connectionInProgress_ = false;

    if (!error)
      {
        partialDataSize_ = 0;
        socket_.async_receive(boost::asio::buffer(inputBuffer_, MAX_LENGTH), 0,
                              boost::bind(&Impl::handle_async_receive, this, _1, _2));

        transport_.isConnected_ = true;

        for (std::list<Block>::iterator i = sendQueue_.begin(); i != sendQueue_.end(); ++i)
          socket_.async_send(boost::asio::buffer(i->wire(), i->size()),
                             boost::bind(&Impl::handle_async_send, this, _1, *i));

        sendQueue_.clear();
      }
    else
      {
        // may need to throw exception
        transport_.isConnected_ = false;
        throw Transport::Error(error, "error while connecting to the forwarder");
      }
  }
  
  void
  connect()
  {
    if (!connectionInProgress_) {
      connectionInProgress_ = true;
      socket_.open();
      socket_.async_connect(protocol::endpoint(transport_.unixSocket_),
                            func_lib::bind(&Impl::connectHandler, this, _1));
    }
  }

  void 
  close()
  {
    socket_.close();
    transport_.isConnected_ = false;
  }

  void 
  send(const Block &wire)
  {
    if (!transport_.isConnected_)
      sendQueue_.push_back(wire);
    else
      socket_.async_send(boost::asio::buffer(wire.wire(), wire.size()),
                         boost::bind(&Impl::handle_async_send, this, _1, wire));
  }

  inline void
  processAll(uint8_t *buffer, size_t &offset, size_t availableSize)
  {
    while(offset < availableSize)
      {
        Block element(buffer + offset, availableSize - offset);
        transport_.receive(element);

        offset += element.size();
      }
  }
  
  void
  handle_async_receive(const boost::system::error_code& error, std::size_t bytes_recvd)
  {
    /// @todo The socket is not datagram, so need to have internal buffer to handle partial data reception

    if (error)
      {
        socket_.close(); // closing at this point may not be that necessary
        transport_.isConnected_ = true;
        throw Transport::Error(error, "error while receiving data from socket");
      }
    
    if (!error && bytes_recvd > 0)
      {
        // inputBuffer_ has bytes_recvd received bytes of data
        if (partialDataSize_ > 0)
          {
            size_t newDataSize = std::min(bytes_recvd, MAX_LENGTH-partialDataSize_);
            ndn_memcpy(partialData_ + partialDataSize_, inputBuffer_, newDataSize);
            partialDataSize_ += newDataSize;
              
            size_t offset = 0;
            try
              {
                processAll(partialData_, offset, partialDataSize_);

                // no exceptions => processed the whole thing
                if (bytes_recvd - newDataSize > 0)
                  {
                    // there is a little bit more data available
                        
                    offset = 0;
                    partialDataSize_ = bytes_recvd - newDataSize;
                    ndn_memcpy(partialData_, inputBuffer_ + newDataSize, partialDataSize_);

                    processAll(partialData_, offset, partialDataSize_);

                    // no exceptions => processed the whole thing
                    partialDataSize_ = 0;
                  }
                else
                  {
                    // done processing
                    partialDataSize_ = 0;
                  }
              }
            catch(Tlv::Error &)
              {
                if (offset > 0)
                  {
                    partialDataSize_ -= offset;
                    ndn_memcpy(partialData_, partialData_ + offset, partialDataSize_);
                  }
                else if (offset == 0 && partialDataSize_ == MAX_LENGTH)
                  {
                    // very bad... should close connection
                    socket_.close();
                    transport_.isConnected_ = true;
                    throw Transport::Error(boost::system::error_code(), "input buffer full, but a valid TLV cannot be decoded");
                  }
              }
          }
        else
          {
            size_t offset = 0;
            try
              {
                processAll(inputBuffer_, offset, bytes_recvd);
              }
            catch(Tlv::Error &error)
              {
                if (offset > 0)
                  {
                    partialDataSize_ = bytes_recvd - offset;
                    ndn_memcpy(partialData_, inputBuffer_ + offset, partialDataSize_);
                  }
              }
          }
      }

    socket_.async_receive(boost::asio::buffer(inputBuffer_, MAX_LENGTH), 0,
                          boost::bind(&Impl::handle_async_receive, this, _1, _2));
  }

  void
  handle_async_send(const boost::system::error_code& error, const Block &wire)
  {
    // pass (needed to keep data block alive during the send)
  }
  
private:
  UnixTransport &transport_;
  
  protocol::socket socket_;
  uint8_t inputBuffer_[MAX_LENGTH];

  uint8_t partialData_[MAX_LENGTH];
  size_t partialDataSize_;

  std::list< Block > sendQueue_;
  bool connectionInProgress_;
};

UnixTransport::UnixTransport(const std::string &unixSocket/* = "/tmp/.ndnd.sock"*/) 
  : unixSocket_(unixSocket)
{
}

UnixTransport::~UnixTransport()
{
}

void 
UnixTransport::connect(boost::asio::io_service &ioService,
                       const ReceiveCallback &receiveCallback)
{
  Transport::connect(ioService, receiveCallback);
  
  impl_ = std::auto_ptr<UnixTransport::Impl> (new UnixTransport::Impl(*this));
  impl_->connect();
}

void 
UnixTransport::send(const Block &wire)
{
  impl_->send(wire);
}

void 
UnixTransport::close()
{
  impl_->close();
}

}