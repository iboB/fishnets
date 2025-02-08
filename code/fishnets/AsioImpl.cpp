// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#include "Context.hpp"
#include "WsSessionHandler.hpp"
#include "WsSessionOptions.hpp"
#include "EndpointInfo.hpp"

#define BOOST_BEAST_USE_STD_STRING_VIEW 1

#if defined(_MSC_VER)
#   pragma warning (disable: 4100)
#endif
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/asio/strand.hpp>

//#if !defined(FISHNETS_ENABLE_SSL)
//#   define FISHNETS_ENABLE_SSL 1
//#endif
//
//#if FISHNETS_ENABLE_SSL
//#include <boost/beast/ssl.hpp>
//#endif

namespace net = boost::asio;
namespace ssl = net::ssl;
namespace beast = boost::beast;
namespace ws = beast::websocket;
namespace http = beast::http;
using tcp = net::ip::tcp;

namespace fishnets {

} // namespace fishnets
