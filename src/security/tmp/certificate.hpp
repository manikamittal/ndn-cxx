/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2013-2015 Regents of the University of California.
 *
 * This file is part of ndn-cxx library (NDN C++ library with eXperimental eXtensions).
 *
 * ndn-cxx library is free software: you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later version.
 *
 * ndn-cxx library is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received copies of the GNU General Public License and GNU Lesser
 * General Public License along with ndn-cxx, e.g., in COPYING.md file.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * See AUTHORS.md for complete list of ndn-cxx authors and contributors.
 *
 * @author Zhiyi Zhang <dreamerbarrychang@gmail.com>
 * @author Yingdi Yu <http://irl.cs.ucla.edu/~yingdi/>
 */

#ifndef NDN_SECURITY_TMP_CERTIFICATE_HPP
#define NDN_SECURITY_TMP_CERTIFICATE_HPP

#include "../../data.hpp"

namespace ndn {
namespace security {
namespace tmp {

/// @brief The certificate following the certificate format naming convention
/// @see doc/specs/certificate-format.rst
class Certificate : public Data
{
public:
  Certificate();

  /**
   * @brief Construct certificate from a data object
   * @throw tlv::Error if data does not follow certificate format
   */
  explicit
  Certificate(Data&& data);

  /**
   * @brief Construct certificate from a wire encoding
   * @throw tlv::Error if wire encoding is invalid or does not follow certificate format
   */
  explicit
  Certificate(const Block& block);

  /**
   * @brief Get key name
   *
   * Key name is the prefix of certificate name up to and including the 'KEY' component.
   */
  Name
  getKeyName() const;

  /**
   * @brief Get identity name
   *
   * Identity name is the prefix of certificate name before the keyId component.
   */
  Name
  getIdentity() const;

  name::Component
  getKeyId() const;

  name::Component
  getIssuerId() const;

  /// @brief Get public key bits (in PKCS#8 format)
  const Buffer
  getPublicKey() const;

  /**
   * @return the signer name in KeyLocator
   * @throw tlv::Error when KeyLocator is not a name
   */
  const Name&
  getIssuerName() const;

  /// @brief Check if the certificate is valid at @p ts.
  bool
  isInValidityPeriod(const time::system_clock::TimePoint& ts = time::system_clock::now()) const;

  /// @brief Get extension with TLV @p type
  const Block&
  getExtension(uint32_t type) const;

public:
  static const ssize_t VERSION_OFFSET;
  static const ssize_t ISSUER_ID_OFFSET;
  static const ssize_t KEY_COMPONENT_OFFSET;
  static const ssize_t KEY_ID_OFFSET;
  static const size_t MIN_CERT_NAME_LENGTH;
  static const size_t MIN_KEY_NAME_LENGTH;
  static const name::Component KEY_COMPONENT;
};

} // namespace tmp

bool
isCertName(const Name& certName);

bool
isKeyName(const Name& keyName);

/**
 * @brief Extract key name from @p certName
 * @throw std::invalid_argument if @p certName does not follow certificate naming convention.
 */
Name
toKeyName(const Name& certName);

/**
 * @brief Extract identity name and keyId from @p keyName
 * @return (identity name, key Id)
 * @throw std::invalid_argument if @p keyName does not follow key naming convention.
 */
std::tuple<Name, name::Component>
parseKeyName(const Name& keyName);

} // namespace security
} // namespace ndn

#endif // NDN_SECURITY_TMP_CERTIFICATE_HPP
