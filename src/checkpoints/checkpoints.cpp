// Copyright (c) 2021, Private Pay - Reborn
// Copyright (c) 2014-2021, The Monero Project
// Copyright (c) 2017-2021, The Masari Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#include "include_base_utils.h"

using namespace epee;

#include "checkpoints.h"

#include "common/dns_utils.h"
#include "include_base_utils.h"
#include "string_tools.h"
#include "storages/portable_storage_template_helper.h" // epee json include
#include "serialization/keyvalue_serialization.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "checkpoints"

namespace cryptonote
{
  /**
   * @brief struct for loading a checkpoint from json
   */
  struct t_hashline
  {
    uint64_t height; //!< the height of the checkpoint
    std::string hash; //!< the hash for the checkpoint
        BEGIN_KV_SERIALIZE_MAP()
          KV_SERIALIZE(height)
          KV_SERIALIZE(hash)
        END_KV_SERIALIZE_MAP()
  };

  /**
   * @brief struct for loading many checkpoints from json
   */
  struct t_hash_json {
    std::vector<t_hashline> hashlines; //!< the checkpoint lines from the file
        BEGIN_KV_SERIALIZE_MAP()
          KV_SERIALIZE(hashlines)
        END_KV_SERIALIZE_MAP()
  };

  //---------------------------------------------------------------------------
  checkpoints::checkpoints()
  {
  }
  //---------------------------------------------------------------------------
  bool checkpoints::add_checkpoint(uint64_t height, const std::string& hash_str)
  {
    crypto::hash h = crypto::null_hash;
    bool r = epee::string_tools::parse_tpod_from_hex_string(hash_str, h);
    CHECK_AND_ASSERT_MES(r, false, "Failed to parse checkpoint hash string into binary representation!");

    // return false if adding at a height we already have AND the hash is different
    if (m_points.count(height))
    {
      CHECK_AND_ASSERT_MES(h == m_points[height], false, "Checkpoint at given height already exists, and hash for new checkpoint was different!");
    }
    m_points[height] = h;
    return true;
  }
  //---------------------------------------------------------------------------
  bool checkpoints::is_in_checkpoint_zone(uint64_t height) const
  {
    return !m_points.empty() && (height <= (--m_points.end())->first);
  }
  //---------------------------------------------------------------------------
  bool checkpoints::check_block(uint64_t height, const crypto::hash& h, bool& is_a_checkpoint) const
  {
    auto it = m_points.find(height);
    is_a_checkpoint = it != m_points.end();
    if(!is_a_checkpoint)
      return true;

    if(it->second == h)
    {
      MINFO("CHECKPOINT PASSED FOR HEIGHT " << height << " " << h);
      return true;
    }else
    {
      MWARNING("CHECKPOINT FAILED FOR HEIGHT " << height << ". EXPECTED HASH: " << it->second << ", FETCHED HASH: " << h);
      return false;
    }
  }
  //---------------------------------------------------------------------------
  bool checkpoints::check_block(uint64_t height, const crypto::hash& h) const
  {
    bool ignored;
    return check_block(height, h, ignored);
  }
  //---------------------------------------------------------------------------
  //FIXME: is this the desired behavior?
  bool checkpoints::is_alternative_block_allowed(uint64_t blockchain_height, uint64_t block_height) const
  {
    if (0 == block_height)
      return false;

    auto it = m_points.upper_bound(blockchain_height);
    // Is blockchain_height before the first checkpoint?
    if (it == m_points.begin())
      return true;

    --it;
    uint64_t checkpoint_height = it->first;
    return checkpoint_height < block_height;
  }
  //---------------------------------------------------------------------------
  uint64_t checkpoints::get_max_height() const
  {
    std::map< uint64_t, crypto::hash >::const_iterator highest = 
        std::max_element( m_points.begin(), m_points.end(),
                         ( boost::bind(&std::map< uint64_t, crypto::hash >::value_type::first, _1) < 
                           boost::bind(&std::map< uint64_t, crypto::hash >::value_type::first, _2 ) ) );
    return highest->first;
  }
  //---------------------------------------------------------------------------
  const std::map<uint64_t, crypto::hash>& checkpoints::get_points() const
  {
    return m_points;
  }

  bool checkpoints::check_for_conflicts(const checkpoints& other) const
  {
    for (auto& pt : other.get_points())
    {
      if (m_points.count(pt.first))
      {
        CHECK_AND_ASSERT_MES(pt.second == m_points.at(pt.first), false, "Checkpoint at given height already exists, and hash for new checkpoint was different!");
      }
    }
    return true;
  }

  bool checkpoints::init_default_checkpoints(network_type nettype)
  {
    if (nettype == TESTNET)
    {
  //    ADD_CHECKPOINT(0,     "96375dc8a8dd960c33f59190edf51a3f458d6e8d8a2c7bc7517c5dee26955174");

      return true;
    }
    if (nettype == STAGENET)
    {
      return true;
    }
    ADD_CHECKPOINT(1, "31c66763d4582a4de671222f2fa187969cacef1b5412628187d08beffc79516a");
	ADD_CHECKPOINT(10000, "a4bf8ae33e0ea6d5eead5e5b5416a1e9b56a0c2c3b29f705410c0e1c91f5a3a2");
	ADD_CHECKPOINT(25000, "567f1c20b0bb24b0909c3d8e185e59fae4637da0cbe3a040c675dc7490be7f79");
	ADD_CHECKPOINT(50000, "2e70fbf835e8aff6d530b34106261dcaf89612506a1c8d2433cb24a71d9a3cbd");
	ADD_CHECKPOINT(75000, "8cc7ff2e4564998add727d789f11dd98742df3e3b3a7eaf84af8d85d6445596a");
	ADD_CHECKPOINT(100000, "45924d7f9288d8def0876c1b1b046c86cc19a1b738e08ec5e21ce3f548a2ffeb");
	ADD_CHECKPOINT(125000, "4958a72d7cc088a28b7c8cd46d06f46737b8d93c7d737031de0a7030ec350484");
	ADD_CHECKPOINT(150000, "1ef692b6df1d255611ab479ec5feb2a18b10284bb02210d4d32ef7d92796dc50");
	ADD_CHECKPOINT(175000, "3c0bb4e13202699236f6de2a0b9ecfb13b18c89b855c9d47118c399c2e59b97f");
	ADD_CHECKPOINT(200000, "f78b56ed7996372faed59a3369ba925eca64c26273e7646e85efc41558c6828d");
	ADD_CHECKPOINT(225000, "9328d79e864442db23a68ab144ce23e79764628633f044e8b36fb9cdde5e7b15");
	ADD_CHECKPOINT(250000, "ac9af86500e4bf1bd5f19909d545ba1dc9dd5b1b31cf948bf6009c707868d8ae");
	ADD_CHECKPOINT(275000, "05411f5ce852b92645ae853dec72e0f797dfee417a6e3f84710bcb5b6b7c9e6e");
	ADD_CHECKPOINT(300000, "d586fed0205d968798f2b0ff2e2d8c9f95e9e33600676351113ed487d511e0db");
	ADD_CHECKPOINT(325000, "f12e9af6d9a426fd3a5f976428dd9834bd897a10da604330060fedb47266a071");
	ADD_CHECKPOINT(350000, "6f897fa2c195235ae7bdb7b4706b5dddff459f9ba24883ddd2fdcc9559c25e49");
	ADD_CHECKPOINT(375000, "53ce78a6129b6d42b45ac3525fafd414b83526269b246cadc5f9612c6aa3e82c");
	ADD_CHECKPOINT(400000, "b3e88b8cb76103435453a592b8d4f72422ca4385b691e3c5a156445792d09a35");
	ADD_CHECKPOINT(425000, "57b8a06d06f2539bd5b87fa86824444ad1bf04f7aac09b88f79071d7d352fae0");
	ADD_CHECKPOINT(450000, "38dc6b0e7f487bf0b0cadac6482db77f5aba55763fa1e05f962b3b6ad0411c88");
	ADD_CHECKPOINT(475000, "9e376c1d1875471f1c3f9d8632783cc18378336f952c07bd3ab94976cfce291d");
	ADD_CHECKPOINT(500000, "1c19b0d07289f837fa4758768375847493ae59055535b2b22c2dd3edc2282dae");
	ADD_CHECKPOINT(525000, "6fbfc94a0f54191d54516008d0c74d4150f0ff230221d3dd34eb715ce74a01b1");
	ADD_CHECKPOINT(550000, "2f121ddfe1886561d40f19e0baa445cb6f40cbe517d961f2d72249e857df0f37");

    return true;
  }

  bool checkpoints::load_checkpoints_from_json(const std::string &json_hashfile_fullpath)
  {
    boost::system::error_code errcode;
    if (! (boost::filesystem::exists(json_hashfile_fullpath, errcode)))
    {
      LOG_PRINT_L1("Blockchain checkpoints file not found");
      return true;
    }

    LOG_PRINT_L1("Adding checkpoints from blockchain hashfile");

    uint64_t prev_max_height = get_max_height();
    LOG_PRINT_L1("Hard-coded max checkpoint height is " << prev_max_height);
    t_hash_json hashes;
    if (!epee::serialization::load_t_from_json_file(hashes, json_hashfile_fullpath))
    {
      MERROR("Error loading checkpoints from " << json_hashfile_fullpath);
      return false;
    }
    for (std::vector<t_hashline>::const_iterator it = hashes.hashlines.begin(); it != hashes.hashlines.end(); )
    {
      uint64_t height;
      height = it->height;
      if (height <= prev_max_height) {
	LOG_PRINT_L1("ignoring checkpoint height " << height);
      } else {
	std::string blockhash = it->hash;
	LOG_PRINT_L1("Adding checkpoint height " << height << ", hash=" << blockhash);
	ADD_CHECKPOINT(height, blockhash);
      }
      ++it;
    }

    return true;
  }

  bool checkpoints::load_checkpoints_from_dns(network_type nettype)
  {
    std::vector<std::string> records;

    // All four MoneroPulse domains have DNSSEC on and valid
    static const std::vector<std::string> dns_urls = {	  "ck1.privatepay.online"
														, "ck2.privatepay.online"
														, "ck3.privatepay.online"
														};

    static const std::vector<std::string> testnet_dns_urls = {};

    static const std::vector<std::string> stagenet_dns_urls = {};

    if (!tools::dns_utils::load_txt_records_from_dns(records, nettype == TESTNET ? testnet_dns_urls : nettype == STAGENET ? stagenet_dns_urls : dns_urls))
      return true; // why true ?

    for (const auto& record : records)
    {
      auto pos = record.find(":");
      if (pos != std::string::npos)
      {
        uint64_t height;
        crypto::hash hash;

        // parse the first part as uint64_t,
        // if this fails move on to the next record
        std::stringstream ss(record.substr(0, pos));
        if (!(ss >> height))
        {
    continue;
        }

        // parse the second part as crypto::hash,
        // if this fails move on to the next record
        std::string hashStr = record.substr(pos + 1);
        if (!epee::string_tools::parse_tpod_from_hex_string(hashStr, hash))
        {
    continue;
        }

        ADD_CHECKPOINT(height, hashStr);
      }
    }
    return true;
  }

  bool checkpoints::load_new_checkpoints(const std::string &json_hashfile_fullpath, network_type nettype, bool dns)
  {
    bool result;

    result = load_checkpoints_from_json(json_hashfile_fullpath);
    if (dns)
    {
      result &= load_checkpoints_from_dns(nettype);
    }

    return result;
  }
}
