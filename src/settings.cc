#include <nexus/quic/settings.hpp>
#include <lsquic.h>

namespace nexus::quic {

namespace detail {

void read_settings(settings& out, const lsquic_engine_settings& in)
{
  const auto us = std::chrono::microseconds(in.es_handshake_to);
  out.handshake_timeout = std::chrono::duration_cast<std::chrono::seconds>(us);
  out.idle_timeout = std::chrono::seconds(in.es_idle_timeout);
  out.max_streams_per_connection =
      in.es_init_max_streams_bidi;
  out.connection_flow_control_window =
      in.es_init_max_data;
  out.incoming_stream_flow_control_window =
      in.es_init_max_stream_data_bidi_remote;
  out.outgoing_stream_flow_control_window =
      in.es_init_max_stream_data_bidi_local;
}

void write_settings(const settings& in, lsquic_engine_settings& out)
{
  out.es_handshake_to = std::chrono::duration_cast<std::chrono::microseconds>(
      in.handshake_timeout).count();
  out.es_idle_timeout = in.idle_timeout.count();
  out.es_init_max_streams_bidi =
      in.max_streams_per_connection;
  out.es_init_max_data =
      in.connection_flow_control_window;
  out.es_init_max_stream_data_bidi_remote =
      in.incoming_stream_flow_control_window;
  out.es_init_max_stream_data_bidi_local =
      in.outgoing_stream_flow_control_window;
}

bool check_settings(const lsquic_engine_settings& es, int flags,
                    std::string* message)
{
  char errbuf[256];
  int r = ::lsquic_engine_check_settings(&es, flags, errbuf, sizeof(errbuf));
  if (r == 0) {
    return true;
  }
  if (message) {
    message->assign(errbuf);
  }
  return false;
}

} // namespace detail

settings default_client_settings()
{
  lsquic_engine_settings es;
  ::lsquic_engine_init_settings(&es, 0);
  settings s;
  detail::read_settings(s, es);
  return s;
}

settings default_server_settings()
{
  lsquic_engine_settings es;
  ::lsquic_engine_init_settings(&es, LSENG_SERVER);
  settings s;
  detail::read_settings(s, es);
  return s;
}

bool check_client_settings(const settings& s, std::string* message)
{
  constexpr int flags = 0;
  lsquic_engine_settings es;
  ::lsquic_engine_init_settings(&es, flags);
  detail::write_settings(s, es);
  return detail::check_settings(es, flags, message);
}

bool check_server_settings(const settings& s, std::string* message)
{
  constexpr int flags = LSENG_SERVER;
  lsquic_engine_settings es;
  ::lsquic_engine_init_settings(&es, flags);
  detail::write_settings(s, es);
  return detail::check_settings(es, flags, message);
}

} // namespace nexus::quic
