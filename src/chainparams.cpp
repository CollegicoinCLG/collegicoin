// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2017 The PIVX developers
// Copyright (c) 2019 The Collegicoin Developers
// Copyright (c) 2019 The Collegicoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "bignum.h"
#include "random.h"
#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

using namespace std;
using namespace boost::assign;

struct SeedSpec6 {
    uint8_t addr[16];
    uint16_t port;
};

#include "chainparamsseeds.h"

/*
---------------
algorithm: x16r
pzTimestamp: 20190208 CollegiCoin by ZioFabry
pubkey: 04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f
bits: 504365040
time: 1549580953
merkle root hash: 4c313fe4670bce96eacac6676ef6a674a1249b236efec6b469d118c971c3b1c1
Searching for genesis hash...
nonce: 1734805
genesis hash: 000008d58116c81fc01c28d5d741c1de9553ae90f35c6bf141b149946502b417
*/


/**
 * Main network
 */

//! Convert the pnSeeds6 array into usable address objects.
static void convertSeed6(std::vector<CAddress>& vSeedsOut, const SeedSpec6* data, unsigned int count)
{
    // It'll only connect to one or two seed nodes because once it connects,
    // it'll get a pile of addresses with newer timestamps.
    // Seed nodes are given a random 'last seen time' of between one and two
    // weeks ago.
    const int64_t nOneWeek = 7 * 24 * 60 * 60;
    for (unsigned int i = 0; i < count; i++) {
        struct in6_addr ip;
        memcpy(&ip, data[i].addr, sizeof(ip));
        CAddress addr(CService(ip, data[i].port));
        addr.nTime = GetTime() - GetRand(nOneWeek) - nOneWeek;
        vSeedsOut.push_back(addr);
    }
}

//   What makes a good checkpoint block?
// + Is surrounded by blocks with reasonable timestamps
//   (no blocks before with a timestamp after, none after with
//    timestamp before)
// + Contains no strange transactions
static Checkpoints::MapCheckpoints mapCheckpoints =
    boost::assign::map_list_of
    (0, uint256("0x000008d58116c81fc01c28d5d741c1de9553ae90f35c6bf141b149946502b417"));

static const Checkpoints::CCheckpointData data = {
    &mapCheckpoints,
    1549580953, // * UNIX timestamp of last checkpoint block
    0,          // * total number of transactions between genesis and last checkpoint (the tx=... number in the SetBestChain debug.log lines)
    1440        // * estimated number of transactions per day after checkpoint
};

static Checkpoints::MapCheckpoints mapCheckpointsTestnet =
    boost::assign::map_list_of(0, uint256("0x000008d58116c81fc01c28d5d741c1de9553ae90f35c6bf141b149946502b417"));

static const Checkpoints::CCheckpointData dataTestnet = {
    &mapCheckpointsTestnet,
    1549580953, // * UNIX timestamp of last checkpoint block
    0,          // * total number of transactions between genesis and last checkpoint (the tx=... number in the SetBestChain debug.log lines)
    1440        // * estimated number of transactions per day after checkpoint
};

static Checkpoints::MapCheckpoints mapCheckpointsRegtest =
    boost::assign::map_list_of(0, uint256("0x000008d58116c81fc01c28d5d741c1de9553ae90f35c6bf141b149946502b417"));
static const Checkpoints::CCheckpointData dataRegtest = {
    &mapCheckpointsRegtest,
    1549580953, // * UNIX timestamp of last checkpoint block
    0,          // * total number of transactions between genesis and last checkpoint (the tx=... number in the SetBestChain debug.log lines)
    1440        // * estimated number of transactions per day after checkpoint
};

class CMainParams : public CChainParams
{
public:
    CMainParams()
    {
        networkID                      = CBaseChainParams::MAIN;
        strNetworkID                   = "main";

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 4-byte int at any alignment.
         */
        pchMessageStart[0]             = 0x33;
        pchMessageStart[1]             = 0xdc;
        pchMessageStart[2]             = 0x21;
        pchMessageStart[3]             = 0xcb;
        vAlertPubKey                   = ParseHex("04307320ddf6bb1f1847ed4814515742bda9bb10415ce492f669a7ea7c4590e520b60febafd3a84b3c5528a303017bde0a88bbc7b78eee117ee6c4ba6f7c9e4a7a");
        nDefaultPort                   = 12034;
        nSubsidyHalvingInterval        = 1050000;
        nMaxReorganizationDepth        = 100;
        nEnforceBlockUpgradeMajority   = 750;
        nRejectBlockOutdatedMajority   = 950;
        nToCheckBlockUpgradeMajority   = 1000;
        nMinerThreads                  = 0;

        bnProofOfWorkLimit             = ~uint256(0) >> 20;
        nTargetTimespan                =  1 * 60; 
        nTargetSpacing                 =  1 * 60;  // Collegicoin: 1 minute blocks during POW (block 1-200)

        bnProofOfStakeLimit            = ~uint256(0) >> 20;
        nTargetTimespanPOS             = 40 * 60; 
        nTargetSpacingPOS              =  1 * 60;  // Collegicoin: 1 minute blocks during POS

        nMaturity                      = 5; // 6 block maturity (+1 elsewhere)
        nMasternodeCountDrift          = 20;
        nMaxMoneyOut                   = 12000000 * COIN; // 16 million max supply

        /** Height or Time Based Activations **/
        nLastPOWBlock                  = 1000;
        nModifierUpdateBlock           = 1;

        const char* pszTimestamp       = "20190208 CollegiCoin by ZioFabry";
        CMutableTransaction txNew;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].scriptSig         = CScript() << 486604799 << CScriptNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].nValue           = 0 * COIN;
        txNew.vout[0].scriptPubKey     = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock          = 0;
        genesis.hashMerkleRoot         = genesis.BuildMerkleTree();
        genesis.nVersion               = 1;
        genesis.nTime                  = 1549580953;
        genesis.nBits                  = 504365040;
        genesis.nNonce                 = 1734805;

        hashGenesisBlock               = genesis.GetHash();
        assert(hashGenesisBlock        == uint256("0x000008d58116c81fc01c28d5d741c1de9553ae90f35c6bf141b149946502b417"));
        assert(genesis.hashMerkleRoot  == uint256("0x4c313fe4670bce96eacac6676ef6a674a1249b236efec6b469d118c971c3b1c1"));
 
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,  28);  // Start with 'C' from https://en.bitcoin.it/wiki/List_of_address_prefixes
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,  63);  // Start with 'S' from https://en.bitcoin.it/wiki/List_of_address_prefixes
        base58Prefixes[SECRET_KEY]     = std::vector<unsigned char>(1, 193);  // from https://en.bitcoin.it/wiki/List_of_address_prefixes
        
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >(); // SecureCloud BIP32 pubkeys start with 'xpub' (Bitcoin defaults)
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >(); // SecureCloud BIP32 prvkeys start with 'xprv' (Bitcoin defaults)
        base58Prefixes[EXT_COIN_TYPE]  = boost::assign::list_of(0x80)(0x00)(0x92)(0xf1).convert_to_container<std::vector<unsigned char> >(); // BIP44 coin type is from https://github.com/satoshilabs/slips/blob/master/slip-0044.md 109 	0x800092f1

        vFixedSeeds.clear();
        vSeeds.clear();

        convertSeed6(vFixedSeeds, pnSeed6_main, ARRAYLEN(pnSeed6_main));

        vSeeds.push_back(CDNSSeedData("seed01.collegicoin.com", "seed01.collegicoin.com"));
        vSeeds.push_back(CDNSSeedData("seed02.collegicoin.com", "seed02.collegicoin.com"));
        vSeeds.push_back(CDNSSeedData("seed03.collegicoin.com", "seed03.collegicoin.com"));
        vSeeds.push_back(CDNSSeedData("seed04.collegicoin.com", "seed04.collegicoin.com"));
        vSeeds.push_back(CDNSSeedData("seed05.collegicoin.com", "seed05.collegicoin.com"));
        vSeeds.push_back(CDNSSeedData("seed06.collegicoin.com", "seed06.collegicoin.com"));
        vSeeds.push_back(CDNSSeedData("seed07.collegicoin.com", "seed07.collegicoin.com"));
        vSeeds.push_back(CDNSSeedData("seed08.collegicoin.com", "seed08.collegicoin.com"));
        vSeeds.push_back(CDNSSeedData("seed09.collegicoin.com", "seed09.collegicoin.com"));

        fMiningRequiresPeers           = true;
        fAllowMinDifficultyBlocks      = false;
        fDefaultConsistencyChecks      = false;
        fRequireStandard               = true;
        fMineBlocksOnDemand            = false;
        fSkipProofOfWorkCheck          = false;
        fTestnetToBeDeprecatedFieldRPC = false;
        fHeadersFirstSyncingActive     = false;

        nPoolMaxTransactions           = 3;
        strSporkKey                    = "04f9cb975c94dc0037ba350e19f09566239439b5c9ed1729a4dfb257e5d2b75759bb1fa2c72f4a5270c9cb9e4465c213cfeac65a2b83f2484ad297a3991cc7020a";
        strMasternodePoolDummyAddress  = "SYuYowBAuCLdgSUDEvFp9CGzK2isZXHN7r";
        nStartMasternodePayments       = 1525192183; 

        nBudget_Fee_Confirmations      = 6; // Number of confirmations for the finalization fee

        strTreasuryAddress             = "SeRhGrDny4xXFGt9dPwBHSYARNpb2dzCdh";
    }

    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return data;
    }
};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CMainParams
{
public:
    CTestNetParams()
    {
        networkID                      = CBaseChainParams::TESTNET;
        strNetworkID                   = "test";
        pchMessageStart[0]             = 0x4a;
        pchMessageStart[1]             = 0x2d;
        pchMessageStart[2]             = 0x32;
        pchMessageStart[3]             = 0xbc;
        vAlertPubKey                   = ParseHex("04abac66ae10ca99a58d2bf464ed97328c69a5c96ddaacae797c595990c86e01d4c9f16d490d047dac06a24c36e1575e6f6ee5e49f3677df12e85ae1ed9c37fa88");
        nDefaultPort                   = 13034;
        nEnforceBlockUpgradeMajority   = 51;
        nRejectBlockOutdatedMajority   = 75;
        nToCheckBlockUpgradeMajority   = 100;
        nMinerThreads                  = 0;

        bnProofOfWorkLimit             = ~uint256(0) >> 20;
        nTargetTimespan                =  1 * 60; 
        nTargetSpacing                 =  1 * 60;  // Collegicoin: 1 minute blocks during POW (block 1-200) on testnet

        bnProofOfStakeLimit            = ~uint256(0) >> 20;
        nTargetTimespanPOS             =  40 * 60; 
        nTargetSpacingPOS              =   1 * 60;  // Collegicoin: 1 minute blocks during POS on testnet

        nLastPOWBlock                  = 1000;
        nMaturity                      = 5;
        nMasternodeCountDrift          = 4;
        nModifierUpdateBlock           = 1;
        nMaxMoneyOut                   = 12000000 * COIN;

        //! Modify the testnet genesis block so the timestamp is valid for a later start.
        genesis.nTime                  = 1549580953;
        genesis.nNonce                 = 1734805;

        hashGenesisBlock               = genesis.GetHash();
        assert(hashGenesisBlock        == uint256("0x000008d58116c81fc01c28d5d741c1de9553ae90f35c6bf141b149946502b417"));
        assert(genesis.hashMerkleRoot  == uint256("0x4c313fe4670bce96eacac6676ef6a674a1249b236efec6b469d118c971c3b1c1"));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,  87);  // Start with 'c' from https://en.bitcoin.it/wiki/List_of_address_prefixes
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 125);  // Start with 's' from https://en.bitcoin.it/wiki/List_of_address_prefixes
        base58Prefixes[SECRET_KEY]     = std::vector<unsigned char>(1, 193);  // from https://en.bitcoin.it/wiki/List_of_address_prefixes

        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >(); // SecureCloud BIP32 pubkeys start with 'xpub' (Bitcoin defaults)
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >(); // SecureCloud BIP32 prvkeys start with 'xprv' (Bitcoin defaults)
        base58Prefixes[EXT_COIN_TYPE]  = boost::assign::list_of(0x80)(0x00)(0x00)(0x01).convert_to_container<std::vector<unsigned char> >();
        // Testnet Collegicoin BIP44 coin type is '1' (All coin's testnet default)
        
        convertSeed6(vFixedSeeds, pnSeed6_test, ARRAYLEN(pnSeed6_test));

        fMiningRequiresPeers           = true;
        fAllowMinDifficultyBlocks      = false;
        fDefaultConsistencyChecks      = false;
        fRequireStandard               = false;
        fMineBlocksOnDemand            = false;
        fTestnetToBeDeprecatedFieldRPC = true;

        nPoolMaxTransactions           = 2;
        strSporkKey                    = "04bb4cc355d8b119f89b3cf9353f2c9e50fbea04276cdd97f4d7a6a9eaeec929e232d4a45431e28a45df5ed5a96162ece24f3b398adfc03544239fd33465d5620f";
        strMasternodePoolDummyAddress  = "gbJ4Qad4xc77PpLzMx6rUegAs6aUPWkcUq";
        nStartMasternodePayments       = genesis.nTime + 86400; // 24 hours after genesis
        nBudget_Fee_Confirmations      = 3; // Number of confirmations for the finalization fee. We have to make this very short
                                       // here because we only have a 8 block finalization window on testnet

        strTreasuryAddress             = "sc3NySryJN1XpJ1MbNf3knBLXEKMbnqNyz";
    }
    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return dataTestnet;
    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CTestNetParams
{
public:
    CRegTestParams()
    {
        networkID = CBaseChainParams::REGTEST;
        strNetworkID = "regtest";
        strNetworkID = "regtest";
        pchMessageStart[0] = 0x20;
        pchMessageStart[1] = 0xee;
        pchMessageStart[2] = 0x32;
        pchMessageStart[3] = 0xbc;
        nSubsidyHalvingInterval = 150;
        nEnforceBlockUpgradeMajority = 750;
        nRejectBlockOutdatedMajority = 950;
        nToCheckBlockUpgradeMajority = 1000;
        nMinerThreads = 1;
        nTargetTimespan = 24 * 60 * 60; // Collegicoin: 1 day
        nTargetSpacing = 2 * 60;        // Collegicoin: 1 minutes
        bnProofOfWorkLimit = ~uint256(0) >> 1;
        genesis.nTime = 1516926684;
        genesis.nBits = 0x207fffff;
        genesis.nNonce = 20542300;

        hashGenesisBlock = genesis.GetHash();
        nDefaultPort = 14034;
       // assert(hashGenesisBlock == uint256("0x229874aa8a92df3347600978e226ba57bc994b9fa291ea50519afafca2d50ed3"));

        vFixedSeeds.clear(); //! Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //! Regtest mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fAllowMinDifficultyBlocks = true;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;
    }
    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return dataRegtest;
    }
};
static CRegTestParams regTestParams;

/**
 * Unit test
 */
class CUnitTestParams : public CMainParams, public CModifiableParams
{
public:
    CUnitTestParams()
    {
        networkID = CBaseChainParams::UNITTEST;
        strNetworkID = "unittest";
        nDefaultPort = 51478;
        vFixedSeeds.clear(); //! Unit test mode doesn't have any fixed seeds.
        vSeeds.clear();      //! Unit test mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fAllowMinDifficultyBlocks = false;
        fMineBlocksOnDemand = true;
    }

    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        // UnitTest share the same checkpoints as MAIN
        return data;
    }

    //! Published setters to allow changing values in unit test cases
    virtual void setSubsidyHalvingInterval(int anSubsidyHalvingInterval) { nSubsidyHalvingInterval = anSubsidyHalvingInterval; }
    virtual void setEnforceBlockUpgradeMajority(int anEnforceBlockUpgradeMajority) { nEnforceBlockUpgradeMajority = anEnforceBlockUpgradeMajority; }
    virtual void setRejectBlockOutdatedMajority(int anRejectBlockOutdatedMajority) { nRejectBlockOutdatedMajority = anRejectBlockOutdatedMajority; }
    virtual void setToCheckBlockUpgradeMajority(int anToCheckBlockUpgradeMajority) { nToCheckBlockUpgradeMajority = anToCheckBlockUpgradeMajority; }
    virtual void setDefaultConsistencyChecks(bool afDefaultConsistencyChecks) { fDefaultConsistencyChecks = afDefaultConsistencyChecks; }
    virtual void setAllowMinDifficultyBlocks(bool afAllowMinDifficultyBlocks) { fAllowMinDifficultyBlocks = afAllowMinDifficultyBlocks; }
    virtual void setSkipProofOfWorkCheck(bool afSkipProofOfWorkCheck) { fSkipProofOfWorkCheck = afSkipProofOfWorkCheck; }
};
static CUnitTestParams unitTestParams;


static CChainParams* pCurrentParams = 0;

CModifiableParams* ModifiableParams()
{
    assert(pCurrentParams);
    assert(pCurrentParams == &unitTestParams);
    return (CModifiableParams*)&unitTestParams;
}

const CChainParams& Params()
{
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams& Params(CBaseChainParams::Network network)
{
    switch (network) {
    case CBaseChainParams::MAIN:
        return mainParams;
    case CBaseChainParams::TESTNET:
        return testNetParams;
    case CBaseChainParams::REGTEST:
        return regTestParams;
    case CBaseChainParams::UNITTEST:
        return unitTestParams;
    default:
        assert(false && "Unimplemented network");
        return mainParams;
    }
}

void SelectParams(CBaseChainParams::Network network)
{
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}

bool SelectParamsFromCommandLine()
{
    CBaseChainParams::Network network = NetworkIdFromCommandLine();
    if (network == CBaseChainParams::MAX_NETWORK_TYPES)
        return false;

    SelectParams(network);
    return true;
}