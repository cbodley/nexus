#pragma once

#include <boost/asio/buffer.hpp>
#include <boost/asio/ssl.hpp>

namespace http2::detail::test {

inline void use_server_certificate(boost::asio::ssl::context& ctx)
{
  // openssl req -x509 -nodes -newkey rsa:4096 -keyout key.pem -days 36500 -out cert.pem -subj /CN=test_https_start
  ctx.use_private_key(boost::asio::buffer(R"(
-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCr6k6dMOFyrWi9
EvSed6m58QNypx6bLku4/HWtGK8bqBBF65lzqbA9uRpLIkYNRH8wo7ygBNFy82uz
OfI9uFm3kfKolf2teCSEW+MZSDBHPom5vphYojqqU7xlYp8aeaqRn5iyaNCKbG/i
xAzdoFvnHeDi2P8L5QGvghR9Un+dtpBc9ZcV8uKRWnHQZJEaClOJ6VTrTnUOtVRu
Z0dTk7aKWX3cdChl0GNoW9nxqVedKoguh09GC6EZ9CLmgPQi/CoMkGYijrKjsIbm
onqHO7kJFjfPTJBOMKJgsflcXDxNlaoYviM2O4ruLDKNgIDKD8GMnE/mnfUDdhCU
mWOg6KqRAgMBAAECggEAVreQBBZ+AjyakpUXM0AlKxf5p0HJXHmT1LH0IeZLneW+
n6Zh90fnEJtoOfIF5/dfOQe+w/DqPdOvxe461QtCpihGgOd32KK7uNAo073oLGfN
TRZo/nyGnxgx9eozW0V31pDsk0Hvv4NHRNmjq7+R3BjkMUlIDZXsrb0t3LFakhCK
7cVxW9XQSbwfhhh/u6m4iAegt4GnYyRpds/Su7tWPOPu/wfmOh8P42qEqSPL0MGh
4u8a+LTjyvJd2tbcoo13UWkA5IDB0WlsJMyi3/TkIPy2RRORXoId5dv/e0eD2ErR
E4dVurB7DIy/RmsuNLG5j7qNrkIyrd2pzTfGhu7MgQKBgQDeT1M9QzO7BrKSb1MW
IffVHxv457Gse3rvqhTQLwX/iXc0nlhoXv4NMgDcUpE5buICntk8TlWPWgcul4VJ
W5Hlv3l1NxaqTL3rn7VzkTtMNmN5LUBlt3bxg+ez+auRN9cSZVuwQlOgocn4UQ4r
oqq35oQAH6W/DCeD2yqA+w1aiQKBgQDF9+LhXRtWcUx/4P+X1lgAjHjCMddOMuUM
6Oz2BfrX0hP83Tl2Mg3Pcrlnj8HzfeVBLXqT1CLyFAIit22Zs0eu6ctDxMBzn4ul
b3edn3jvnpsVuSgiVUb/5cYgGJ5+BDzuuYe0CGkKReFeh+KBwpWTK52TCPbu+/89
FB5Fy86tyQKBgQDOMn9/nDx4Jb8uCankJn+MIv28AZOP6zxc3cHOUz9aBLQXjyNr
M2iq7o1TzhW7Uri5O4M8519+xj9RHONY5mFN2yqZ6Q3RybqCuTEBT1zT1MKxG6LW
dbQSUYlxKovS9xs6id7gfrS4kjgWZYAiQw/b4SjgQHpo2KoyJ++lkLaTGQKBgQCU
pKO+A2LbbQa7nf1LzK0W/GJPrYy0MpK5Nst1jtfh5OMNIi5bCQpFkSaVE+PVJ9pT
LgqzpLz4dv2Dg6bPmUVhmDn/EGRQbKM1/JQbzfnIMZbQoM35uX4t9iDlSJb4l8YI
mVXDX+0+wWmOyQjR1YDpl/4gwMJoft4OxmRUk8sDwQKBgQDBBArd1aFN/y9LvMhR
ljHw/DDs0x8vpLhS4qwl2AFOloDyDX44F6T0ml4/o9h++G5WBS3oGSwYmGeLa9Xu
5fxpk8/ivKvVrkNgqHjNFt1R0WT/B/DtLv3kAs3+j6bngrnxPamoiIzapL8YxDqn
h5rFG7fUNpt1BInXc2so9eR9/Q==
-----END PRIVATE KEY-----
)"),
                      boost::asio::ssl::context::pem);

  ctx.use_certificate_chain(boost::asio::buffer(R"(
-----BEGIN CERTIFICATE-----
MIIDGTCCAgGgAwIBAgIUdFcF0M/LNXfjYPbghxK4iW/F6wAwDQYJKoZIhvcNAQEL
BQAwGzEZMBcGA1UEAwwQdGVzdF9odHRwc19zdGFydDAgFw0xOTAzMDgyMzQ4MzNa
GA8yMTE5MDIxMjIzNDgzM1owGzEZMBcGA1UEAwwQdGVzdF9odHRwc19zdGFydDCC
ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKvqTp0w4XKtaL0S9J53qbnx
A3KnHpsuS7j8da0YrxuoEEXrmXOpsD25GksiRg1EfzCjvKAE0XLza7M58j24WbeR
8qiV/a14JIRb4xlIMEc+ibm+mFiiOqpTvGVinxp5qpGfmLJo0Ipsb+LEDN2gW+cd
4OLY/wvlAa+CFH1Sf522kFz1lxXy4pFacdBkkRoKU4npVOtOdQ61VG5nR1OTtopZ
fdx0KGXQY2hb2fGpV50qiC6HT0YLoRn0IuaA9CL8KgyQZiKOsqOwhuaieoc7uQkW
N89MkE4womCx+VxcPE2Vqhi+IzY7iu4sMo2AgMoPwYycT+ad9QN2EJSZY6DoqpEC
AwEAAaNTMFEwHQYDVR0OBBYEFBloU2liwTh1rlWiDpSORpSx+ggIMB8GA1UdIwQY
MBaAFBloU2liwTh1rlWiDpSORpSx+ggIMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZI
hvcNAQELBQADggEBAH5IknT9xf7INYVdzJddbHSJrm4ZhkSaqVPuVXYkmrgra1Ac
emX07CkVDq9iQA+J4hD5f6Md+9fafLJc0ofBfIxVVDou6mJZ+tXWv/N9y9v4CHx/
chpQ7U5ShaqNMTqhvmwgr3TByAHI0tB7T6xfeK8ZrN6QG1DwDuJQputaErUSBbv8
UbtC6+Mj5kcFMlj+lGiUyVuo0VfGS2RR1+sXs+zlR32IIpgX0PtCjSSG8LO1NMSI
hU2WNMA2vjoA8XIzBOqBiP3qTX5JW6gh0FGArMeP5ZAkT6Pdg1ti0UEuhQqTIWjB
jW1cAHWRuauMrbBR1d6+6KCM3/+pb4/WOWgppqE=
-----END CERTIFICATE-----
)"));
}

} // namespace http2::detail::test
