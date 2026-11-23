
#pragma once

#include "dnsrecords.hh"
#include "iputils.hh"
#include "logr.hh"

// ", TSIG error: BADKEY" when the answer carries a TSIG record with a
// non-zero error (RFC 8945 5.2), "" otherwise. The rcode alone is NOTAUTH
// for every TSIG failure; the cause is only in this field.
std::string tsigErrorSuffix(const MOADNSParser& mdp);

class TSIGTCPVerifier
{
public:
  TSIGTCPVerifier(Logr::log_t slog, const TSIGTriplet& tt, const ComboAddress& remote, TSIGRecordContent& trc): d_slog(slog), d_tt(tt), d_remote(remote), d_trc(trc)
  {
  }
  bool check(const string& data, const MOADNSParser& mdp);
private:
  Logr::log_t d_slog;
  const TSIGTriplet& d_tt;
  const ComboAddress& d_remote;
  TSIGRecordContent& d_trc;
  string d_prevMac; // RFC2845 4.4
  string d_signData;
  size_t d_tsigPos{0};
  uint8_t d_nonSignedMessages{0}; // RFC2845 4.4
};
