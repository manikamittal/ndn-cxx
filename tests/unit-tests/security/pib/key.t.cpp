/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2013-2016 Regents of the University of California.
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
 */

#include "security/pib/key.hpp"
#include "security/pib/pib.hpp"
#include "security/pib/pib-memory.hpp"
#include "security/pib/detail/key-impl.hpp"
#include "pib-data-fixture.hpp"

#include "boost-test.hpp"

namespace ndn {
namespace security {
namespace pib {
namespace tests {

using tmp::Certificate;

BOOST_AUTO_TEST_SUITE(Security)
BOOST_AUTO_TEST_SUITE(Pib)
BOOST_AUTO_TEST_SUITE(TestKey)

using security::Pib;

BOOST_FIXTURE_TEST_CASE(ValidityChecking, PibDataFixture)
{
  using security::pib::detail::KeyImpl;

  // an empty key
  Key key;

  BOOST_CHECK_EQUAL(static_cast<bool>(key), false);
  BOOST_CHECK_EQUAL(!key, true);

  if (key)
    BOOST_CHECK(false);
  else
    BOOST_CHECK(true);

  // an initialized key
  auto pibImpl = make_shared<pib::PibMemory>();
  auto keyImpl = make_shared<KeyImpl>(id1Key1Name, id1Key1.buf(), id1Key1.size(), pibImpl);
  key = Key(keyImpl);

  BOOST_CHECK_EQUAL(static_cast<bool>(key), true);
  BOOST_CHECK_EQUAL(!key, false);

  if (key)
    BOOST_CHECK(true);
  else
    BOOST_CHECK(false);
}

/**
 * pib::Key is a wrapper of pib::detail::KeyImpl.  Since the functionalities of KeyImpl
 * have already been tested in detail/key-impl.t.cpp, we only test the shared property
 * of pib::Key in this test case.
 */

BOOST_FIXTURE_TEST_CASE(Share, PibDataFixture)
{
  using security::pib::detail::KeyImpl;

  auto pibImpl = make_shared<pib::PibMemory>();
  auto keyImpl = make_shared<KeyImpl>(id1Key1Name, id1Key1.buf(), id1Key1.size(), pibImpl);
  Key key1(keyImpl);
  Key key2(keyImpl);

  key1.addCertificate(id1Key1Cert1);
  BOOST_CHECK_NO_THROW(key2.getCertificate(id1Key1Cert1.getName()));
  key2.removeCertificate(id1Key1Cert1.getName());
  BOOST_CHECK_THROW(key1.getCertificate(id1Key1Cert1.getName()), Pib::Error);

  key1.setDefaultCertificate(id1Key1Cert1);
  BOOST_CHECK_NO_THROW(key2.getDefaultCertificate());
}

BOOST_AUTO_TEST_SUITE_END()
BOOST_AUTO_TEST_SUITE_END()
BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace pib
} // namespace security
} // namespace ndn
