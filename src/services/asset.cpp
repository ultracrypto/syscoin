﻿// Copyright (c) 2017-2018 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "services/asset.h"
#include "services/assetallocation.h"
#include "init.h"
#include "validation.h"
#include "util.h"
#include "core_io.h"
#include "wallet/wallet.h"
#include "wallet/rpcwallet.h"
#include "chainparams.h"
#include <boost/algorithm/string/classification.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/range/algorithm_ext/erase.hpp>
#include <chrono>
#include "wallet/coincontrol.h"
#include <rpc/util.h>
#include <key_io.h>
#include <policy/policy.h>
#include <consensus/validation.h>
#include <wallet/fees.h>
#include <outputtype.h>
#include <boost/thread.hpp>
#include <merkleblock.h>
extern AssetBalanceMap mempoolMapAssetBalances;
extern ArrivalTimesMapImpl arrivalTimesMap;
unsigned int MAX_UPDATES_PER_BLOCK = 2;
std::unique_ptr<CAssetDB> passetdb;
std::unique_ptr<CAssetAllocationDB> passetallocationdb;
std::unique_ptr<CAssetAllocationMempoolDB> passetallocationmempooldb;
std::unique_ptr<CEthereumTxRootsDB> pethereumtxrootsdb;
std::unique_ptr<CAssetIndexDB> passetindexdb;

// SYSCOIN service rpc functions
UniValue syscoinburn(const JSONRPCRequest& request);
UniValue syscoinmint(const JSONRPCRequest& request);
UniValue syscointxfund(const JSONRPCRequest& request);


UniValue syscoinlistreceivedbyaddress(const JSONRPCRequest& request);
extern UniValue sendrawtransaction(const JSONRPCRequest& request);
UniValue syscoindecoderawtransaction(const JSONRPCRequest& request);

UniValue assetnew(const JSONRPCRequest& request);
UniValue assetupdate(const JSONRPCRequest& request);
UniValue addressbalance(const JSONRPCRequest& request);
UniValue assettransfer(const JSONRPCRequest& request);
UniValue assetsend(const JSONRPCRequest& request);
UniValue assetsendmany(const JSONRPCRequest& request);
UniValue assetinfo(const JSONRPCRequest& request);
UniValue listassets(const JSONRPCRequest& request);
UniValue syscoinsetethstatus(const JSONRPCRequest& request);
UniValue syscoinsetethheaders(const JSONRPCRequest& request);
UniValue getblockhashbytxid(const JSONRPCRequest& request);
UniValue syscoingetspvproof(const JSONRPCRequest& request);
using namespace std::chrono;
using namespace std;

int GetSyscoinDataOutput(const CTransaction& tx) {
	for (unsigned int i = 0; i<tx.vout.size(); i++) {
		if (tx.vout[i].scriptPubKey.IsUnspendable())
			return i;
	}
	return -1;
}
CAmount getaddressbalance(const string& strAddress)
{
    UniValue paramsUTXO(UniValue::VARR);
    UniValue utxoParams(UniValue::VARR);
    utxoParams.push_back("addr(" + strAddress + ")");
    paramsUTXO.push_back("start");
    paramsUTXO.push_back(utxoParams);
    JSONRPCRequest request;
    request.params = paramsUTXO;
    UniValue resUTXOs = scantxoutset(request);
    return AmountFromValue(find_value(resUTXOs.get_obj(), "total_amount"));
}
string stringFromValue(const UniValue& value) {
	string strName = value.get_str();
	return strName;
}
vector<unsigned char> vchFromValue(const UniValue& value) {
	string strName = value.get_str();
	unsigned char *strbeg = (unsigned char*)strName.c_str();
	return vector<unsigned char>(strbeg, strbeg + strName.size());
}

std::vector<unsigned char> vchFromString(const std::string &str) {
	unsigned char *strbeg = (unsigned char*)str.c_str();
	return vector<unsigned char>(strbeg, strbeg + str.size());
}
string stringFromVch(const vector<unsigned char> &vch) {
	string res;
	vector<unsigned char>::const_iterator vi = vch.begin();
	while (vi != vch.end()) {
		res += (char)(*vi);
		vi++;
	}
	return res;
}
bool GetSyscoinData(const CTransaction &tx, vector<unsigned char> &vchData, int& nOut)
{
	nOut = GetSyscoinDataOutput(tx);
	if (nOut == -1)
		return false;

	const CScript &scriptPubKey = tx.vout[nOut].scriptPubKey;
	return GetSyscoinData(scriptPubKey, vchData);
}
bool GetSyscoinData(const CScript &scriptPubKey, vector<unsigned char> &vchData)
{
	CScript::const_iterator pc = scriptPubKey.begin();
	opcodetype opcode;
	if (!scriptPubKey.GetOp(pc, opcode))
		return false;
	if (opcode != OP_RETURN)
		return false;
	if (!scriptPubKey.GetOp(pc, opcode, vchData))
		return false;
	return true;
}
bool GetSyscoinBurnData(const CTransaction &tx, CAssetAllocation* theAssetAllocation)
{   
    if(!theAssetAllocation) 
        return false;  
    std::vector<unsigned char> vchEthAddress;
    uint32_t nAssetFromScript;
    CAmount nAmountFromScript;
    CWitnessAddress burnWitnessAddress;
    if(!GetSyscoinBurnData(tx, nAssetFromScript, burnWitnessAddress, nAmountFromScript, vchEthAddress)){
        return false;
    }
    theAssetAllocation->SetNull();
    theAssetAllocation->assetAllocationTuple.nAsset = nAssetFromScript;
    theAssetAllocation->assetAllocationTuple.witnessAddress = burnWitnessAddress;
    theAssetAllocation->listSendingAllocationAmounts.push_back(make_pair(CWitnessAddress(0, vchFromString("burn")), nAmountFromScript));
    return true;

} 
bool GetSyscoinBurnData(const CTransaction &tx, uint32_t& nAssetFromScript, CWitnessAddress& burnWitnessAddress, CAmount &nAmountFromScript, std::vector<unsigned char> &vchEthAddress)
{
    if(tx.nVersion != SYSCOIN_TX_VERSION_ASSET_ALLOCATION_BURN){
        LogPrint(BCLog::SYS, "GetSyscoinBurnData: Invalid transaction version\n");
        return false;
    }
    int nOut = GetSyscoinDataOutput(tx);
    if (nOut == -1){
        LogPrint(BCLog::SYS, "GetSyscoinBurnData: Data index must be positive\n");
        return false;
    }

    const CScript &scriptPubKey = tx.vout[nOut].scriptPubKey;
    std::vector<std::vector< unsigned char> > vvchArgs;
    if(!GetSyscoinBurnData(scriptPubKey, vvchArgs)){
        LogPrint(BCLog::SYS, "GetSyscoinBurnData: Cannot get burn data\n");
        return false;
    }
        
    if(vvchArgs.size() != 5){
        LogPrint(BCLog::SYS, "GetSyscoinBurnData: Wrong argument size %d\n", vvchArgs.size());
        return false;
    }
          
    if(vvchArgs[0].size() != 4){
        LogPrint(BCLog::SYS, "GetSyscoinBurnData: nAssetFromScript - Wrong argument size %d\n", vvchArgs[0].size());
        return false;
    }
        
    nAssetFromScript  = static_cast<uint32_t>(vvchArgs[0][3]);
    nAssetFromScript |= static_cast<uint32_t>(vvchArgs[0][2]) << 8;
    nAssetFromScript |= static_cast<uint32_t>(vvchArgs[0][1]) << 16;
    nAssetFromScript |= static_cast<uint32_t>(vvchArgs[0][0]) << 24;
            
    if(vvchArgs[1].size() != 8){
        LogPrint(BCLog::SYS, "GetSyscoinBurnData: nAmountFromScript - Wrong argument size %d\n", vvchArgs[1].size());
        return false; 
    }
    uint64_t result = static_cast<uint64_t>(vvchArgs[1][7]);
    result |= static_cast<uint64_t>(vvchArgs[1][6]) << 8;
    result |= static_cast<uint64_t>(vvchArgs[1][5]) << 16;
    result |= static_cast<uint64_t>(vvchArgs[1][4]) << 24; 
    result |= static_cast<uint64_t>(vvchArgs[1][3]) << 32;  
    result |= static_cast<uint64_t>(vvchArgs[1][2]) << 40;  
    result |= static_cast<uint64_t>(vvchArgs[1][1]) << 48;  
    result |= static_cast<uint64_t>(vvchArgs[1][0]) << 56;   
    nAmountFromScript = (CAmount)result;
    
    if(vvchArgs[2].empty()){
        LogPrint(BCLog::SYS, "GetSyscoinBurnData: Ethereum address empty\n");
        return false; 
    }
    vchEthAddress = vvchArgs[2]; 
    if(vvchArgs[3].size() != 1){
        LogPrint(BCLog::SYS, "GetSyscoinBurnData: Witness address version - Wrong argument size %d\n", vvchArgs[3].size());
        return false;
    }
    const unsigned char &nWitnessVersion = static_cast<unsigned char>(vvchArgs[3][0]);
    
    if(vvchArgs[4].empty()){
        LogPrint(BCLog::SYS, "GetSyscoinBurnData: Witness address empty\n");
        return false;
    }     
    

    burnWitnessAddress = CWitnessAddress(nWitnessVersion, vvchArgs[4]);   
    return true; 
}
bool GetSyscoinBurnData(const CScript &scriptPubKey, std::vector<std::vector<unsigned char> > &vchData)
{
    CScript::const_iterator pc = scriptPubKey.begin();
    opcodetype opcode;
    if (!scriptPubKey.GetOp(pc, opcode))
        return false;
    if (opcode != OP_RETURN)
        return false;
    vector<unsigned char> vchArg;
    if (!scriptPubKey.GetOp(pc, opcode, vchArg))
        return false;
    vchData.push_back(vchArg);
    vchArg.clear();
    if (!scriptPubKey.GetOp(pc, opcode, vchArg))
        return false;
    vchData.push_back(vchArg);
    vchArg.clear();       
    if (!scriptPubKey.GetOp(pc, opcode, vchArg))
        return false;
    vchData.push_back(vchArg);
    vchArg.clear();        
    if (!scriptPubKey.GetOp(pc, opcode, vchArg))
        return false;
    vchData.push_back(vchArg);
    vchArg.clear();   
    if (!scriptPubKey.GetOp(pc, opcode, vchArg))
        return false;
    vchData.push_back(vchArg);
    vchArg.clear();              
    return true;
}


string assetFromTx(const int &nVersion) {
    switch (nVersion) {
    case SYSCOIN_TX_VERSION_ASSET_ACTIVATE:
        return "assetactivate";
    case SYSCOIN_TX_VERSION_ASSET_UPDATE:
        return "assetupdate";
    case SYSCOIN_TX_VERSION_ASSET_TRANSFER:
        return "assettransfer";
	case SYSCOIN_TX_VERSION_ASSET_SEND:
		return "assetsend";
    default:
        return "<unknown asset op>";
    }
}
bool CAsset::UnserializeFromData(const vector<unsigned char> &vchData) {
    try {
		CDataStream dsAsset(vchData, SER_NETWORK, PROTOCOL_VERSION);
		dsAsset >> *this;
    } catch (std::exception &e) {
		SetNull();
        return false;
    }
	return true;
}
bool CMintSyscoin::UnserializeFromData(const vector<unsigned char> &vchData) {
    try {
        CDataStream dsMS(vchData, SER_NETWORK, PROTOCOL_VERSION);
        dsMS >> *this;
    } catch (std::exception &e) {
        SetNull();
        return false;
    }
    return true;
}
bool CAsset::UnserializeFromTx(const CTransaction &tx) {
	vector<unsigned char> vchData;
	int nOut;
	if (!IsAssetTx(tx.nVersion) || !GetSyscoinData(tx, vchData, nOut))
	{
		SetNull();
		return false;
	}
	if(!UnserializeFromData(vchData))
	{	
		return false;
	}
    return true;
}
bool CMintSyscoin::UnserializeFromTx(const CTransaction &tx) {
    vector<unsigned char> vchData;
    int nOut;
    if (!IsSyscoinMintTx(tx.nVersion) || !GetSyscoinData(tx, vchData, nOut))
    {
        SetNull();
        return false;
    }
    if(!UnserializeFromData(vchData))
    {   
        return false;
    }
    return true;
}
bool FlushSyscoinDBs() {
    bool ret = true;
	 {
        if (passetallocationmempooldb != nullptr)
        {
            ResyncAssetAllocationStates();
            {
                LOCK(cs_assetallocation);
                LogPrintf("Flushing Asset Allocation Mempool Balances...size %d\n", mempoolMapAssetBalances.size());
                passetallocationmempooldb->WriteAssetAllocationMempoolBalances(mempoolMapAssetBalances);
                mempoolMapAssetBalances.clear();
            }
            {
                LOCK(cs_assetallocationarrival);
                LogPrintf("Flushing Asset Allocation Arrival Times...size %d\n", arrivalTimesMap.size());
                passetallocationmempooldb->WriteAssetAllocationMempoolArrivalTimes(arrivalTimesMap);
                arrivalTimesMap.clear();
            }
            if (!passetallocationmempooldb->Flush()) {
                LogPrintf("Failed to write to asset allocation mempool database!");
                ret = false;
            }            
        }
	 }
     if (pethereumtxrootsdb != nullptr)
     {
        if(!pethereumtxrootsdb->PruneTxRoots())
        {
            LogPrintf("Failed to write to prune Ethereum TX Roots database!");
            ret = false;
        }
        if (!pethereumtxrootsdb->Flush()) {
            LogPrintf("Failed to write to ethereum tx root database!");
            ret = false;
        } 
     }
	return ret;
}
void CTxMemPool::removeExpiredMempoolBalances(setEntries& stage){ 
    vector<vector<unsigned char> > vvch;
    int count = 0;
    for (const txiter& it : stage) {
        const CTransaction& tx = it->GetTx();
        if(IsAssetAllocationTx(tx.nVersion)){
            CAssetAllocation allocation(tx);
            if(allocation.assetAllocationTuple.IsNull())
                continue;
            if(ResetAssetAllocation(allocation.assetAllocationTuple.ToString(), tx.GetHash())){
                count++;
            }
        }
    }
    if(count > 0)
         LogPrint(BCLog::SYS, "removeExpiredMempoolBalances removed %d expired asset allocation transactions from mempool balances\n", count);  
}

bool FindAssetOwnerInTx(const CCoinsViewCache &inputs, const CTransaction& tx, const CWitnessAddress &witnessAddressToMatch) {
	CTxDestination dest;
    int witnessversion;
    std::vector<unsigned char> witnessprogram;
	for (unsigned int i = 0; i < tx.vin.size(); i++) {
		const Coin& prevCoins = inputs.AccessCoin(tx.vin[i].prevout);
		if (prevCoins.IsSpent()) {
			continue;
		}
        if (prevCoins.out.scriptPubKey.IsWitnessProgram(witnessversion, witnessprogram) && witnessAddressToMatch.vchWitnessProgram == witnessprogram && witnessAddressToMatch.nVersion == (unsigned char)witnessversion)
            return true;
	}
	return false;
}
void CreateAssetRecipient(const CScript& scriptPubKey, CRecipient& recipient)
{
	CRecipient recp = { scriptPubKey, recipient.nAmount, false };
	recipient = recp;
	const CAmount &minFee = GetFee(3000);
	recipient.nAmount = minFee;
}
void CreateRecipient(const CScript& scriptPubKey, CRecipient& recipient)
{
	CRecipient recp = { scriptPubKey, recipient.nAmount, false };
	recipient = recp;
	CTxOut txout(recipient.nAmount, scriptPubKey);
	size_t nSize = GetSerializeSize(txout, SER_DISK, 0) + 148u;
	recipient.nAmount = GetFee(nSize);
}
void CreateFeeRecipient(CScript& scriptPubKey, CRecipient& recipient)
{
	CRecipient recp = { scriptPubKey, 0, false };
	recipient = recp;
}
UniValue SyscoinListReceived(const CWallet* pwallet, bool includeempty = true, bool includechange = false)
{
	map<string, int> mapAddress;
	UniValue ret(UniValue::VARR);
  
	const std::map<CKeyID, int64_t>& mapKeyPool = pwallet->GetAllReserveKeys();
	for (const std::pair<const CTxDestination, CAddressBookData>& item : pwallet->mapAddressBook) {

		const CTxDestination& dest = item.first;
		const string& strAccount = item.second.name;

		isminefilter filter = ISMINE_SPENDABLE;
		isminefilter mine = IsMine(*pwallet, dest);
		if (!(mine & filter))
			continue;

		const string& strAddress = EncodeDestination(dest);

        const CAmount& nBalance = getaddressbalance(strAddress);
		UniValue obj(UniValue::VOBJ);
		if (includeempty || (!includeempty && nBalance > 0)) {
			obj.pushKV("balance", ValueFromAmount(nBalance));
			obj.pushKV("label", strAccount);
			const CKeyID *keyID = boost::get<CKeyID>(&dest);
			if (keyID && !pwallet->mapAddressBook.count(dest) && !mapKeyPool.count(*keyID)) {
				if (!includechange)
					continue;
				obj.pushKV("change", true);
			}
			else
				obj.pushKV("change", false);
			ret.push_back(obj);
		}
		mapAddress[strAddress] = 1;
	}

	vector<COutput> vecOutputs;
	{
		LOCK(pwallet->cs_wallet);
		pwallet->AvailableCoins(vecOutputs, true, nullptr, 1, MAX_MONEY, MAX_MONEY, 0, 0, 9999999);
	}
	for(const COutput& out: vecOutputs) {
		CTxDestination address;
		if (!ExtractDestination(out.tx->tx->vout[out.i].scriptPubKey, address))
			continue;

		const string& strAddress = EncodeDestination(address);
		if (mapAddress.find(strAddress) != mapAddress.end())
			continue;

		UniValue paramsBalance(UniValue::VARR);
		UniValue balanceParams(UniValue::VARR);
		balanceParams.push_back("addr(" + strAddress + ")");
		paramsBalance.push_back("start");
		paramsBalance.push_back(balanceParams);
		JSONRPCRequest request;
		request.params = paramsBalance;
		UniValue resBalance = scantxoutset(request);
		UniValue obj(UniValue::VOBJ);
		obj.pushKV("address", strAddress);
		const CAmount& nBalance = AmountFromValue(find_value(resBalance.get_obj(), "total_amount"));
		if (includeempty || (!includeempty && nBalance > 0)) {
			obj.pushKV("balance", ValueFromAmount(nBalance));
			obj.pushKV("label", "");
			const CKeyID *keyID = boost::get<CKeyID>(&address);
			if (keyID && !pwallet->mapAddressBook.count(address) && !mapKeyPool.count(*keyID)) {
				if (!includechange)
					continue;
				obj.pushKV("change", true);
			}
			else
				obj.pushKV("change", false);
			ret.push_back(obj);
		}
		mapAddress[strAddress] = 1;

	}
	return ret;
}
UniValue syscointxfund_helper(const int &nVersion, const string &vchWitness, vector<CRecipient> &vecSend) {
	CMutableTransaction txNew;
	txNew.nVersion = nVersion;

	COutPoint witnessOutpoint;
	if (!vchWitness.empty() && vchWitness != "''")
	{
		string strWitnessAddress;
		strWitnessAddress = vchWitness;
		addressunspent(strWitnessAddress, witnessOutpoint);
		if (witnessOutpoint.IsNull())
		{
			throw runtime_error("SYSCOIN_RPC_ERROR ERRCODE: 9000 - " + _("This transaction requires a witness but not enough outputs found for witness address: ") + strWitnessAddress + _(". Please make sure the address is funded with a small output to cover fees, current fee rate: ") + ValueFromAmount(GetFee(3000)).write() + " SYS");
		}
		Coin pcoinW;
		if (GetUTXOCoin(witnessOutpoint, pcoinW))
			txNew.vin.push_back(CTxIn(witnessOutpoint, pcoinW.out.scriptPubKey));
	}

	// vouts to the payees
	for (const auto& recipient : vecSend)
	{
		CTxOut txout(recipient.nAmount, recipient.scriptPubKey);
		if (!IsDust(txout, dustRelayFee))
		{
			txNew.vout.push_back(txout);
		}
	}   

	UniValue paramsFund(UniValue::VARR);
	paramsFund.push_back(EncodeHexTx(txNew));
	return paramsFund;
}


class CCountSigsVisitor : public boost::static_visitor<void> {
private:
	const CKeyStore &keystore;
	int &nNumSigs;

public:
	CCountSigsVisitor(const CKeyStore &keystoreIn, int &numSigs) : keystore(keystoreIn), nNumSigs(numSigs) {}

	void Process(const CScript &script) {
		txnouttype type;
		std::vector<CTxDestination> vDest;
		int nRequired;
		if (ExtractDestinations(script, type, vDest, nRequired)) {
			for(const CTxDestination &dest: vDest)
				boost::apply_visitor(*this, dest);
		}
	}
	void operator()(const CKeyID &keyId) {
		nNumSigs++;
	}

	void operator()(const CScriptID &scriptId) {
		CScript script;
		if (keystore.GetCScript(scriptId, script))
			Process(script);
	}
	void operator()(const WitnessV0ScriptHash& scriptID)
	{
		CScriptID id;
		CRIPEMD160().Write(scriptID.begin(), 32).Finalize(id.begin());
		CScript script;
		if (keystore.GetCScript(id, script)) {
			Process(script);
		}
	}

	void operator()(const WitnessV0KeyHash& keyid) {
		nNumSigs++;
	}

	template<typename X>
	void operator()(const X &none) {}
};
UniValue syscointxfund(const JSONRPCRequest& request) {
	std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
	CWallet* const pwallet = wallet.get();
	const UniValue &params = request.params;
	if (request.fHelp || 1 > params.size() || 3 < params.size())
		throw runtime_error(
			"syscointxfund \"hexstring\" \"address\" ( \"output_index\" )\n"
			"\nFunds a new syscoin transaction with inputs used from wallet or an array of addresses specified. Note that any inputs to the transaction added prior to calling this will not be accounted and new outputs will be added everytime you call this function.\n"
			"\nArguments:\n"
			"1.  \"hexstring\"    (string, required) The raw syscoin transaction output given from rpc (ie: assetnew, assetupdate)\n"
			"2.  \"address\"      (string, required) Address belonging to this asset transaction. \n"
			"3.  \"output_index\" (number, optional) Output index from available UTXOs in address. Defaults to selecting all that are needed to fund the transaction. \n"
            "\nResult:\n"
            "[\n"
            "  \"hexstring\"       (string) the unsigned funded transaction hexstring. \n"
            "]\n"
			"\nExamples:\n"
			+ HelpExampleCli("syscointxfund", "<hexstring> \"sys1qtyf33aa2tl62xhrzhralpytka0krxvt0a4e8ee\"")
			+ HelpExampleRpc("syscointxfund", "<hexstring> \"sys1qtyf33aa2tl62xhrzhralpytka0krxvt0a4e8ee\" 0")
			+ HelpRequiringPassphrase(pwallet));

	const string &hexstring = params[0].get_str();
    const string &strAddress = params[1].get_str();
	CMutableTransaction tx;
    // decode as non-witness
	if (!DecodeHexTx(tx, hexstring, true, false))
		throw runtime_error("SYSCOIN_ASSET_RPC_ERROR: ERRCODE: 5500 - " + _("Could not send raw transaction: Cannot decode transaction from hex string: ") + hexstring);

	UniValue addressArray(UniValue::VARR);	
	int output_index = -1;
    if (params.size() > 2) {
        output_index = params[2].get_int();
    }
 
    CRecipient addressRecipient;
    CScript scriptPubKeyFromOrig = GetScriptForDestination(DecodeDestination(strAddress));
    CreateAssetRecipient(scriptPubKeyFromOrig, addressRecipient);  
    addressArray.push_back("addr(" + strAddress + ")"); 
    
    
    CTransaction txIn_t(tx);    
 
    
    // add total output amount of transaction to desired amount
    CAmount nDesiredAmount = txIn_t.GetValueOut();
    CAmount nCurrentAmount = 0;

    LOCK(cs_main);

    // # vin (with IX)*FEE + # vout*FEE + (10 + # vin)*FEE + 34*FEE (for change output)
    CAmount nFees = GetFee(10 + 34);

    for (auto& vin : tx.vin) {
        Coin coin;
        if (!GetUTXOCoin(vin.prevout, coin))
            continue;
        int numSigs = 0;
        CCountSigsVisitor(*pwallet, numSigs).Process(coin.out.scriptPubKey);
        nFees += GetFee(numSigs * 200);
    }
    for (auto& vout : tx.vout) {
        const unsigned int nBytes = ::GetSerializeSize(vout, SER_NETWORK, PROTOCOL_VERSION);
        nFees += GetFee(nBytes);
    }
    
    
	UniValue paramsBalance(UniValue::VARR);
	paramsBalance.push_back("start");
	paramsBalance.push_back(addressArray);
	JSONRPCRequest request1;
	request1.params = paramsBalance;

	UniValue resUTXOs = scantxoutset(request1);
	UniValue utxoArray(UniValue::VARR);
	if (resUTXOs.isObject()) {
		const UniValue& resUtxoUnspents = find_value(resUTXOs.get_obj(), "unspents");
		if (!resUtxoUnspents.isArray())
			throw runtime_error("SYSCOIN_ASSET_RPC_ERROR: ERRCODE: 5501 - " + _("No unspent outputs found in addresses provided"));
		utxoArray = resUtxoUnspents.get_array();
	}
	else
		throw runtime_error("SYSCOIN_ASSET_RPC_ERROR: ERRCODE: 5501 - " + _("No funds found in addresses provided"));

    const CAmount &minFee = GetFee(3000);
    if (nCurrentAmount < (nDesiredAmount + nFees)) {
        // only look for small inputs if addresses were passed in, if looking through wallet we do not want to fund via small inputs as we may end up spending small inputs inadvertently
        if (IsSyscoinTx(tx.nVersion) && params.size() > 1) {
            LOCK(mempool.cs);
            int countInputs = 0;
            // fund with small inputs first
            for (int i = 0; i < (int)utxoArray.size(); i++)
            {
                const UniValue& utxoObj = utxoArray[i].get_obj();
                const string &strTxid = find_value(utxoObj, "txid").get_str();
                const uint256& txid = uint256S(strTxid);
                const int& nOut = find_value(utxoObj, "vout").get_int();
                const std::vector<unsigned char> &data(ParseHex(find_value(utxoObj, "scriptPubKey").get_str()));
                const CScript& scriptPubKey = CScript(data.begin(), data.end());
                const CAmount &nValue = AmountFromValue(find_value(utxoObj, "amount"));
                const CTxIn txIn(txid, nOut, scriptPubKey);
                const COutPoint outPoint(txid, nOut);
                if (std::find(tx.vin.begin(), tx.vin.end(), txIn) != tx.vin.end())
                    continue;
                // look for small inputs only, if not selecting all
                if (nValue <= minFee || (output_index >= 0 && output_index == i)) {

                    if (mempool.mapNextTx.find(outPoint) != mempool.mapNextTx.end())
                        continue;
                    {
                        LOCK(pwallet->cs_wallet);
                        if (pwallet->IsLockedCoin(txid, nOut))
                            continue;
                    }
                    if (!IsOutpointMature(outPoint))
                        continue;
                    int numSigs = 0;
                    CCountSigsVisitor(*pwallet, numSigs).Process(scriptPubKey);
                    // add fees to account for every input added to this transaction
                    nFees += GetFee(numSigs * 200);
                    tx.vin.push_back(txIn);
                    countInputs++;
                    nCurrentAmount += nValue;
                    if (nCurrentAmount >= (nDesiredAmount + nFees) || (output_index >= 0 && output_index == i)) {
                        break;
                    }
                }
            }
            if (countInputs <= 0 && !fTPSTestEnabled && !IsSyscoinMintTx(tx.nVersion))
            {
                for (unsigned int i = 0; i < MAX_UPDATES_PER_BLOCK; i++){
                    nDesiredAmount += addressRecipient.nAmount;
                    CTxOut out(addressRecipient.nAmount, addressRecipient.scriptPubKey);
                    const unsigned int nBytes = ::GetSerializeSize(out, SER_NETWORK, PROTOCOL_VERSION);
                    nFees += GetFee(nBytes);
                    tx.vout.push_back(out);
                }
            }
        }   
		if (nCurrentAmount < (nDesiredAmount + nFees)) {

			LOCK(mempool.cs);
			for (unsigned int i = 0; i < utxoArray.size(); i++)
			{
				const UniValue& utxoObj = utxoArray[i].get_obj();
				const string &strTxid = find_value(utxoObj, "txid").get_str();
				const uint256& txid = uint256S(strTxid);
				const int& nOut = find_value(utxoObj, "vout").get_int();
				const std::vector<unsigned char> &data(ParseHex(find_value(utxoObj, "scriptPubKey").get_str()));
				const CScript& scriptPubKey = CScript(data.begin(), data.end());
				const CAmount &nValue = AmountFromValue(find_value(utxoObj, "amount"));
				const CTxIn txIn(txid, nOut, scriptPubKey);
				const COutPoint outPoint(txid, nOut);
				if (std::find(tx.vin.begin(), tx.vin.end(), txIn) != tx.vin.end())
					continue;
                // look for bigger inputs
                if (nValue <= minFee)
                    continue;
				if (mempool.mapNextTx.find(outPoint) != mempool.mapNextTx.end())
					continue;
				{
					LOCK(pwallet->cs_wallet);
					if (pwallet->IsLockedCoin(txid, nOut))
						continue;
				}
				if (!IsOutpointMature(outPoint))
					continue;
				int numSigs = 0;
				CCountSigsVisitor(*pwallet, numSigs).Process(scriptPubKey);
				// add fees to account for every input added to this transaction
				nFees += GetFee(numSigs * 200);
				tx.vin.push_back(txIn);
				nCurrentAmount += nValue;
				if (nCurrentAmount >= (nDesiredAmount + nFees)) {
					break;
				}
			}
		}
	}
    
  
	const CAmount &nChange = nCurrentAmount - nDesiredAmount - nFees;
	if (nChange < 0)
		throw runtime_error("SYSCOIN_ASSET_RPC_ERROR: ERRCODE: 5502 - " + _("Insufficient funds"));
        
    // change back to funding address
	const CTxDestination & dest = DecodeDestination(strAddress);
	if (!IsValidDestination(dest))
		throw runtime_error("Change address is not valid");
	CTxOut changeOut(nChange, GetScriptForDestination(dest));
	if (!IsDust(changeOut, dustRelayFee))
		tx.vout.push_back(changeOut);
	
    
	// pass back new raw transaction
	UniValue res(UniValue::VARR);
	res.push_back(EncodeHexTx(tx));
	return res;
}
UniValue syscoinburn(const JSONRPCRequest& request) {
	const UniValue &params = request.params;
	if (request.fHelp || 3 != params.size())
		throw runtime_error(
			"syscoinburn <amount> <burn_to_sysx> <ethereum_destination_address>\n"
            "\nArguments:\n"
			"1. <amount>         (numeric, required) Amount of SYS to burn. Note that fees are applied on top. It is not inclusive of fees.\n"
			"2. <burn_to_sysx>   (boolean, required) Set to true if you are provably burning SYS to go to SYSX. False if you are provably burning SYS forever.\n"
            "\nResult:\n"
            "[\n"
            "  \"txid\":        (string) The transaction ID\n"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("syscoinburn", "\"amount\" \"true\" \"ethaddress\"")
            + HelpExampleRpc("syscoinburn", "\"amount\" \"true\" \"ethaddress\"")
            );
    
            
	CAmount nAmount = AmountFromValue(params[0]);
	bool bBurnToSYSX = params[1].get_bool();
    string ethAddress = params[2].get_str();
    boost::erase_all(ethAddress, "0x");  // strip 0x if exist

   
	vector<CRecipient> vecSend;
	CScript scriptData;
	scriptData << OP_RETURN;
	if (bBurnToSYSX){
		scriptData << ParseHex(ethAddress);
    }

	CMutableTransaction txNew;
    if(bBurnToSYSX)
        txNew.nVersion = SYSCOIN_TX_VERSION_BURN;
	CTxOut txout(nAmount, scriptData);
	txNew.vout.push_back(txout);
       

	UniValue paramsFund(UniValue::VARR);
	paramsFund.push_back(EncodeHexTx(txNew));
	return paramsFund;
}
UniValue syscoinmint(const JSONRPCRequest& request) {
	const UniValue &params = request.params;
	if (request.fHelp || 8 != params.size())
		throw runtime_error(
			"syscoinmint <address> <amount> <blocknumber> <tx_hex> <txroot_hex> <txmerkleproof_hex> <txmerkleroofpath_hex> <witness>\n"
            "\nArguments:\n"
			"1. <address>               (string, required) Mint to this address.\n"
			"2. <amount>                (numeric, required) Amount of SYS to mint. Note that fees are applied on top. It is not inclusive of fees.\n"
            "3. <blocknumber>           (numeric, required) Block number of the block that included the burn transaction on Ethereum.\n"
            "4. <tx_hex>                (string, required) Raw transaction hex of the burn transaction on Ethereum.\n"
            "5. <txroot_hex>            (string, required) The transaction merkle root that commits this transaction to the block header.\n"
            "6. <txmerkleproof_hex>     (string, required) The list of parent nodes of the Merkle Patricia Tree for SPV proof.\n"
            "7. <txmerkleroofpath_hex>  (string, requird) The merkle path to walk through the tree to recreate the merkle root.\n"
            "8. <witness>               (string, optional) Witness address that will sign for web-of-trust notarization of this transaction.\n"
            "\nResult:\n"
            "[\n"
            "  \"txid\"                 (string) The transaction ID"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("syscoinmint","\"address\" \"amount\" \"blocknumber\" \"tx_hex\" \"txroot_hex\" \"txmerkleproof\" \"txmerkleproofpath\" \"\"")
            + HelpExampleRpc("syscoinmint","\"address\" \"amount\" \"blocknumber\" \"tx_hex\" \"txroot_hex\" \"txmerkleproof\" \"txmerkleproofpath\" \"\"")
            );

	string vchAddress = params[0].get_str();
	CAmount nAmount = AmountFromValue(params[1]);
    uint32_t nBlockNumber = (uint32_t)params[2].get_int();
    string vchValue = params[3].get_str();
    boost::erase_all(vchValue, "'");
    string vchTxRoot = params[4].get_str();
    boost::erase_all(vchTxRoot, "'");
    string vchParentNodes = params[5].get_str();
    boost::erase_all(vchParentNodes, "'");
    string vchPath = params[6].get_str();
    boost::erase_all(vchPath, "'");
    string strWitnessAddress = params[7].get_str();
    
	vector<CRecipient> vecSend;
	const CTxDestination &dest = DecodeDestination(vchAddress);
    
	CScript scriptPubKeyFromOrig = GetScriptForDestination(dest);

	CMutableTransaction txNew;
	txNew.nVersion = SYSCOIN_TX_VERSION_MINT;
	txNew.vout.push_back(CTxOut(nAmount, scriptPubKeyFromOrig));
    
    CMintSyscoin mintSyscoin;
    mintSyscoin.vchValue = ParseHex(vchValue);
    mintSyscoin.vchTxRoot = ParseHex(vchTxRoot);
    mintSyscoin.nBlockNumber = nBlockNumber;
    mintSyscoin.vchParentNodes = ParseHex(vchParentNodes);
    mintSyscoin.vchPath = ParseHex(vchPath);
    
    vector<unsigned char> data;
    mintSyscoin.Serialize(data);
    
    CScript scriptData;
    scriptData << OP_RETURN << data;
    
    CTxOut txout(0, scriptData);
    txNew.vout.push_back(txout);
 
    COutPoint witnessOutpoint;
    if (!strWitnessAddress.empty() && strWitnessAddress != "''")
    {
        addressunspent(strWitnessAddress, witnessOutpoint);
        if (witnessOutpoint.IsNull())
        {
            throw runtime_error("SYSCOIN_RPC_ERROR ERRCODE: 9000 - " + _("This transaction requires a witness but not enough outputs found for witness address: ") + strWitnessAddress + _(". Please make sure the address is funded with a small output to cover fees, current fee rate: ") + ValueFromAmount(GetFee(3000)).write() + " SYS");
        }
        Coin pcoinW;
        if (GetUTXOCoin(witnessOutpoint, pcoinW))
            txNew.vin.push_back(CTxIn(witnessOutpoint, pcoinW.out.scriptPubKey));
    }    
    
	UniValue res(UniValue::VARR);
	res.push_back(EncodeHexTx(txNew));
	return res;
}
UniValue syscoindecoderawtransaction(const JSONRPCRequest& request) {
	const UniValue &params = request.params;
	if (request.fHelp || 1 != params.size())
		throw runtime_error(
            "syscoindecoderawtransaction <hexstring>\n"
			"\nDecode raw syscoin transaction (serialized, hex-encoded) and display information pertaining to the service that is included in the transactiion data output(OP_RETURN)\n"
            "\nArguments:\n"
			"1. <hexstring>     (string, required) The transaction hex string.\n"
            "\nResult:\n"
            "\nExamples:\n"
            + HelpExampleCli("syscoindecoderawtransaction", "\"hexstring\"")
            + HelpExampleRpc("syscoindecoderawtransaction", "\"hexstring\"")
            );

	string hexstring = params[0].get_str();
	CMutableTransaction tx;
	if(!DecodeHexTx(tx, hexstring, false, true))
        DecodeHexTx(tx, hexstring, true, true);
	CTransaction rawTx(tx);
	if (rawTx.IsNull())
		throw runtime_error("SYSCOIN_RPC_ERROR: ERRCODE: 5512 - " + _("Could not decode transaction"));
	
    UniValue output(UniValue::VOBJ);
    if(!DecodeSyscoinRawtransaction(rawTx, output))
        throw runtime_error("SYSCOIN_RPC_ERROR: ERRCODE: 5512 - " + _("Not a Syscoin transaction"));
	return output;
}
bool IsSyscoinMintTx(const int &nVersion){
    return nVersion == SYSCOIN_TX_VERSION_ASSET_ALLOCATION_MINT || nVersion == SYSCOIN_TX_VERSION_MINT;
}
bool IsAssetTx(const int &nVersion){
    return nVersion == SYSCOIN_TX_VERSION_ASSET_ACTIVATE || nVersion == SYSCOIN_TX_VERSION_ASSET_UPDATE || nVersion == SYSCOIN_TX_VERSION_ASSET_TRANSFER || nVersion == SYSCOIN_TX_VERSION_ASSET_SEND;
}
bool IsAssetAllocationTx(const int &nVersion){
    return nVersion == SYSCOIN_TX_VERSION_ASSET_ALLOCATION_MINT || nVersion == SYSCOIN_TX_VERSION_ASSET_ALLOCATION_BURN || 
        nVersion == SYSCOIN_TX_VERSION_ASSET_ALLOCATION_SEND ;
}
bool IsSyscoinTx(const int &nVersion){
    return IsAssetTx(nVersion) || IsAssetAllocationTx(nVersion) || IsSyscoinMintTx(nVersion);
}
bool DecodeSyscoinRawtransaction(const CTransaction& rawTx, UniValue& output){
    vector<vector<unsigned char> > vvch;
    bool found = false;
    if(IsSyscoinMintTx(rawTx.nVersion)){
        found = AssetMintTxToJson(rawTx, output);
    }
    else if (IsAssetTx(rawTx.nVersion) || IsAssetAllocationTx(rawTx.nVersion)){
        found = SysTxToJSON(rawTx, output);
    }
    
    return found;
}
bool SysTxToJSON(const CTransaction& tx, UniValue& output)
{
    bool found = false;
	if (IsAssetTx(tx.nVersion) && tx.nVersion != SYSCOIN_TX_VERSION_ASSET_SEND)
		found = AssetTxToJSON(tx, output);
    else if(tx.nVersion == SYSCOIN_TX_VERSION_BURN)
        found = SysBurnTxToJSON(tx, output);        
	else if (IsAssetAllocationTx(tx.nVersion) || tx.nVersion == SYSCOIN_TX_VERSION_ASSET_SEND)
		found = AssetAllocationTxToJSON(tx, output);
    return found;
}
bool SysBurnTxToJSON(const CTransaction &tx, UniValue &entry)
{
    int nHeight = 0;
    uint256 hash_block;
    CBlockIndex* blockindex = nullptr;
    CTransactionRef txRef;
    if (GetTransaction(tx.GetHash(), txRef, Params().GetConsensus(), hash_block, true, blockindex) && blockindex)
        nHeight = blockindex->nHeight; 
    entry.pushKV("txtype", "syscoinburn");
    entry.pushKV("_id", tx.GetHash().GetHex());
    entry.pushKV("txid", tx.GetHash().GetHex());
    entry.pushKV("height", nHeight);
    UniValue oOutputArray(UniValue::VARR);
    for (const auto& txout : tx.vout){
        CTxDestination address;
        if (!ExtractDestination(txout.scriptPubKey, address))
            continue;
        UniValue oOutputObj(UniValue::VOBJ);
        const string& strAddress = EncodeDestination(address);
        oOutputObj.pushKV("address", strAddress);
        oOutputObj.pushKV("amount", ValueFromAmount(txout.nValue));   
        oOutputArray.push_back(oOutputObj);
    }
    
    entry.pushKV("outputs", oOutputArray);
    entry.pushKV("total", ValueFromAmount(tx.GetValueOut()));
    entry.pushKV("confirmed", nHeight > 0);  
    return true;
}
int GenerateSyscoinGuid()
{
    int rand = 0;
    while(rand <= SYSCOIN_TX_VERSION_MINT)
	    rand = GetRand(std::numeric_limits<int>::max());
    return rand;
}
unsigned int addressunspent(const string& strAddressFrom, COutPoint& outpoint)
{
	UniValue paramsUTXO(UniValue::VARR);
	UniValue utxoParams(UniValue::VARR);
	utxoParams.push_back("addr(" + strAddressFrom + ")");
	paramsUTXO.push_back("start");
	paramsUTXO.push_back(utxoParams);
	JSONRPCRequest request;
	request.params = paramsUTXO;
	UniValue resUTXOs = scantxoutset(request);
	UniValue utxoArray(UniValue::VARR);
    if (resUTXOs.isObject()) {
        const UniValue& resUtxoUnspents = find_value(resUTXOs.get_obj(), "unspents");
        if (!resUtxoUnspents.isArray())
            throw runtime_error("SYSCOIN_ASSET_RPC_ERROR: ERRCODE: 5501 - " + _("No unspent outputs found in addresses provided"));
        utxoArray = resUtxoUnspents.get_array();
    }   
    else
        throw runtime_error("SYSCOIN_ASSET_RPC_ERROR: ERRCODE: 5501 - " + _("No unspent outputs found in addresses provided"));
        
	unsigned int count = 0;
	{
		LOCK(mempool.cs);
		const CAmount &minFee = GetFee(3000);
		for (unsigned int i = 0; i < utxoArray.size(); i++)
		{
			const UniValue& utxoObj = utxoArray[i].get_obj();
			const uint256& txid = uint256S(find_value(utxoObj, "txid").get_str());
			const int& nOut = find_value(utxoObj, "vout").get_int();
			const CAmount &nValue = AmountFromValue(find_value(utxoObj, "amount"));
			if (nValue > minFee)
				continue;
			const COutPoint &outPointToCheck = COutPoint(txid, nOut);

			if (mempool.mapNextTx.find(outPointToCheck) != mempool.mapNextTx.end())
				continue;
			if (outpoint.IsNull())
				outpoint = outPointToCheck;
			count++;
		}
	}
	return count;
}

UniValue syscoinlistreceivedbyaddress(const JSONRPCRequest& request)
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwallet = wallet.get();
	const UniValue &params = request.params;
	if (request.fHelp || params.size() != 0)
		throw runtime_error(
			"syscoinlistreceivedbyaddress\n"
			"\nList balances by receiving address.\n"
			"\nResult:\n"
			"[\n"
			"  {\n"
			"    \"address\" : \"receivingaddress\",    (string) The receiving address\n"
			"    \"amount\" : x.xxx,                 	(numeric) The total amount in " + CURRENCY_UNIT + " received by the address\n"
			"    \"label\" : \"label\"                  (string) A comment for the address/transaction, if any\n"
			"  }\n"
			"  ,...\n"
			"]\n"
			"\nExamples:\n"
			+ HelpExampleCli("syscoinlistreceivedbyaddress", "")
			+ HelpExampleRpc("syscoinlistreceivedbyaddress", "")
		);

	return SyscoinListReceived(pwallet, true, false);
}

bool IsOutpointMature(const COutPoint& outpoint)
{
	Coin coin;
	GetUTXOCoin(outpoint, coin);
	if (coin.IsSpent())
		return false;
	int numConfirmationsNeeded = 0;
	if (coin.IsCoinBase())
		numConfirmationsNeeded = COINBASE_MATURITY - 1;

	if (coin.nHeight > -1 && chainActive.Tip())
		return (chainActive.Height() - coin.nHeight) >= numConfirmationsNeeded;

	// don't have chainActive or coin height is neg 1 or less
	return false;

}
void CAsset::Serialize( vector<unsigned char> &vchData) {
    CDataStream dsAsset(SER_NETWORK, PROTOCOL_VERSION);
    dsAsset << *this;
	vchData = vector<unsigned char>(dsAsset.begin(), dsAsset.end());

}
void CMintSyscoin::Serialize( vector<unsigned char> &vchData) {
    CDataStream dsMint(SER_NETWORK, PROTOCOL_VERSION);
    dsMint << *this;
    vchData = vector<unsigned char>(dsMint.begin(), dsMint.end());

}
void WriteAssetIndexTXID(const uint32_t& nAsset, const uint256& txid){
    int64_t page;
    if(!passetindexdb->ReadAssetPage(page)){
        page = 0;
        if(!passetindexdb->WriteAssetPage(page))
           LogPrint(BCLog::SYS, "Failed to write asset page\n");                  
    }
    std::vector<uint256> TXIDS;
    passetindexdb->ReadIndexTXIDs(nAsset, page, TXIDS);
    // new page needed
    if(((int)TXIDS.size()) >= fAssetIndexPageSize){
        TXIDS.clear();
        page++;
        if(!passetindexdb->WriteAssetPage(page))
            LogPrint(BCLog::SYS, "Failed to write asset page\n");
    }
    TXIDS.push_back(txid);
    if(!passetindexdb->WriteIndexTXIDs(nAsset, page, TXIDS))
        LogPrint(BCLog::SYS, "Failed to write asset index txids\n");
}
void CAssetDB::WriteAssetIndex(const CTransaction& tx, const CAsset& dbAsset, const int& nHeight) {
	if (fZMQAsset || fAssetIndex) {
		UniValue oName(UniValue::VOBJ);
        // assetsends write allocation indexes
        if(tx.nVersion != SYSCOIN_TX_VERSION_ASSET_SEND && AssetTxToJSON(tx, dbAsset, nHeight, oName)){
            if(fZMQAsset)
                GetMainSignals().NotifySyscoinUpdate(oName.write().c_str(), "assetrecord");
            if(fAssetIndex)
            {
                if(!fAssetIndexGuids.empty() && std::find(fAssetIndexGuids.begin(),fAssetIndexGuids.end(),dbAsset.nAsset) == fAssetIndexGuids.end()){
                    LogPrint(BCLog::SYS, "Asset cannot be indexed because it is not set in -assetindexguids list\n");
                    return;
                }
                const uint256& txid = tx.GetHash();
                WriteAssetIndexTXID(dbAsset.nAsset, txid);
                if(!passetindexdb->WritePayload(txid, oName))
                    LogPrint(BCLog::SYS, "Failed to write asset index payload\n");
            }
        }
	}
}
bool GetAsset(const int &nAsset,
        CAsset& txPos) {
    if (passetdb == nullptr || !passetdb->ReadAsset(nAsset, txPos))
        return false;
    return true;
}


bool DisconnectAssetSend(const CTransaction &tx, AssetMap &mapAssets, AssetAllocationMap &mapAssetAllocations){
    const uint256 &txid = tx.GetHash();
    CAsset dbAsset;
    CAssetAllocation theAssetAllocation(tx);
    if(theAssetAllocation.assetAllocationTuple.IsNull()){
        LogPrint(BCLog::SYS,"DisconnectSyscoinTransaction: Could not decode asset allocation in asset send\n");
        return false;
    } 
    auto result  = mapAssets.try_emplace(theAssetAllocation.assetAllocationTuple.nAsset, std::move(emptyAsset));
    auto mapAsset = result.first;
    const bool& mapAssetNotFound = result.second;
    if(mapAssetNotFound){
        if (!GetAsset(theAssetAllocation.assetAllocationTuple.nAsset, dbAsset)) {
            LogPrint(BCLog::SYS,"DisconnectSyscoinTransaction: Could not get asset %d\n",theAssetAllocation.assetAllocationTuple.nAsset);
            return false;               
        } 
        mapAsset->second = std::move(dbAsset);                   
    }
    CAsset& storedSenderRef = mapAsset->second;
               
               
    for(const auto& amountTuple:theAssetAllocation.listSendingAllocationAmounts){
        const CAssetAllocationTuple receiverAllocationTuple(theAssetAllocation.assetAllocationTuple.nAsset, amountTuple.first);
        const std::string &receiverTupleStr = receiverAllocationTuple.ToString();
        CAssetAllocation receiverAllocation;
        auto result = mapAssetAllocations.try_emplace(std::move(receiverTupleStr), std::move(emptyAllocation));
        auto mapAssetAllocation = result.first;
        const bool &mapAssetAllocationNotFound = result.second;
        if(mapAssetAllocationNotFound){
            GetAssetAllocation(receiverAllocationTuple, receiverAllocation);
            if (receiverAllocation.assetAllocationTuple.IsNull()) {
                receiverAllocation.assetAllocationTuple.nAsset = std::move(receiverAllocationTuple.nAsset);
                receiverAllocation.assetAllocationTuple.witnessAddress = std::move(receiverAllocationTuple.witnessAddress);
            } 
            mapAssetAllocation->second = std::move(receiverAllocation);                 
        }
        CAssetAllocation& storedReceiverAllocationRef = mapAssetAllocation->second;
                    

        // reverse allocation
        if(storedReceiverAllocationRef.nBalance >= amountTuple.second){
            storedReceiverAllocationRef.nBalance -= amountTuple.second;
            storedSenderRef.nBalance += amountTuple.second;
        } 
        if(storedReceiverAllocationRef.nBalance == 0){
            storedReceiverAllocationRef.SetNull();       
        }
        if(fAssetIndex){
            if(!passetindexdb->EraseIndexTXID(receiverAllocationTuple, txid)){
                 LogPrint(BCLog::SYS,"DisconnectSyscoinTransaction: Could not erase receiver allocation from asset allocation index\n");
            }
            if(!passetindexdb->EraseIndexTXID(receiverAllocationTuple.nAsset, txid)){
                 LogPrint(BCLog::SYS,"DisconnectSyscoinTransaction: Could not erase receiver allocation from asset index\n");
            } 
        }                                             
    }     
    if(fAssetIndex){
        if(!passetindexdb->EraseIndexTXID(theAssetAllocation.assetAllocationTuple, txid)){
             LogPrint(BCLog::SYS,"DisconnectSyscoinTransaction: Could not erase sender allocation from asset allocation index\n");
        }
        if(!passetindexdb->EraseIndexTXID(theAssetAllocation.assetAllocationTuple.nAsset, txid)){
             LogPrint(BCLog::SYS,"DisconnectSyscoinTransaction: Could not erase sender allocation from asset index\n");
        }       
    }          
    return true;  
}
bool DisconnectAssetUpdate(const CTransaction &tx, AssetMap &mapAssets){
    
    CAsset dbAsset;
    CAsset theAsset(tx);
    if(theAsset.IsNull()){
        LogPrint(BCLog::SYS,"DisconnectSyscoinTransaction: Could not decode asset\n");
        return false;
    }
    auto result = mapAssets.try_emplace(theAsset.nAsset, std::move(emptyAsset));
    auto mapAsset = result.first;
    const bool &mapAssetNotFound = result.second;
    if(mapAssetNotFound){
        if (!GetAsset(theAsset.nAsset, dbAsset)) {
            LogPrint(BCLog::SYS,"DisconnectSyscoinTransaction: Could not get asset %d\n",theAsset.nAsset);
            return false;               
        } 
        mapAsset->second = std::move(dbAsset);                   
    }
    CAsset& storedSenderRef = mapAsset->second;   
           
    if(theAsset.nBalance > 0){
        // reverse asset minting by the issuer
        storedSenderRef.nBalance -= theAsset.nBalance;
        storedSenderRef.nTotalSupply -= theAsset.nBalance;
        if(storedSenderRef.nBalance < 0 || storedSenderRef.nTotalSupply < 0) {
            LogPrint(BCLog::SYS,"DisconnectSyscoinTransaction: Asset cannot be negative: Balance %lld, Supply: %lld\n",storedSenderRef.nBalance, storedSenderRef.nTotalSupply);
            return false;
        }                                          
    } 
    if(fAssetIndex){
        const uint256 &txid = tx.GetHash();
        if(!passetindexdb->EraseIndexTXID(theAsset.nAsset, txid)){
             LogPrint(BCLog::SYS,"DisconnectSyscoinTransaction: Could not erase asset update from asset index\n");
        }
    }         
    return true;  
}
bool DisconnectAssetActivate(const CTransaction &tx, AssetMap &mapAssets){
    
    CAsset theAsset(tx);
    
    if(theAsset.IsNull()){
        LogPrint(BCLog::SYS,"DisconnectSyscoinTransaction: Could not decode asset in asset activate\n");
        return false;
    }
    auto result = mapAssets.try_emplace(theAsset.nAsset, std::move(emptyAsset));
    auto mapAsset = result.first;
    const bool &mapAssetNotFound = result.second;
    if(mapAssetNotFound){
        CAsset dbAsset;
        if (!GetAsset(theAsset.nAsset, dbAsset)) {
            LogPrint(BCLog::SYS,"DisconnectSyscoinTransaction: Could not get asset %d\n",theAsset.nAsset);
            return false;               
        } 
        mapAsset->second = std::move(dbAsset);                   
    }
    mapAsset->second.SetNull();  
    if(fAssetIndex){
        const uint256 &txid = tx.GetHash();
        if(!passetindexdb->EraseIndexTXID(theAsset.nAsset, txid)){
             LogPrint(BCLog::SYS,"DisconnectSyscoinTransaction: Could not erase asset activate from asset index\n");
        }       
    }       
    return true;  
}
bool CheckAssetInputs(const CTransaction &tx, const CCoinsViewCache &inputs,
        bool fJustCheck, int nHeight, AssetMap& mapAssets, AssetAllocationMap &mapAssetAllocations, string &errorMessage, bool bSanityCheck) {
	if (passetdb == nullptr)
		return false;
	const uint256& txHash = tx.GetHash();
	if (!bSanityCheck)
		LogPrint(BCLog::SYS, "*** ASSET %d %d %s %s\n", nHeight,
			chainActive.Tip()->nHeight, txHash.ToString().c_str(),
			fJustCheck ? "JUSTCHECK" : "BLOCK");

	// unserialize asset from txn, check for valid
	CAsset theAsset;
	CAssetAllocation theAssetAllocation;
	vector<unsigned char> vchData;

	int nDataOut;
	if(!GetSyscoinData(tx, vchData, nDataOut) || (tx.nVersion != SYSCOIN_TX_VERSION_ASSET_SEND && !theAsset.UnserializeFromData(vchData)) || (tx.nVersion == SYSCOIN_TX_VERSION_ASSET_SEND && !theAssetAllocation.UnserializeFromData(vchData)))
	{
		errorMessage = "SYSCOIN_ASSET_CONSENSUS_ERROR ERRCODE: 2000 - " + _("Cannot unserialize data inside of this transaction relating to an asset");
		return error(errorMessage.c_str());
	}
    

	if(fJustCheck)
	{
		if (tx.nVersion != SYSCOIN_TX_VERSION_ASSET_SEND) {
			if (theAsset.vchPubData.size() > MAX_VALUE_LENGTH)
			{
				errorMessage = "SYSCOIN_ASSET_CONSENSUS_ERROR: ERRCODE: 2004 - " + _("Asset public data too big");
		        return error(errorMessage.c_str());
			}
		}
		switch (tx.nVersion) {
		case SYSCOIN_TX_VERSION_ASSET_ACTIVATE:
			if (theAsset.nAsset <= SYSCOIN_TX_VERSION_MINT)
			{
				errorMessage = "SYSCOIN_ASSET_CONSENSUS_ERROR: ERRCODE: 2005 - " + _("asset guid invalid");
				return error(errorMessage.c_str());
			}
            if (!theAsset.vchContract.empty() && theAsset.vchContract.size() != MAX_GUID_LENGTH)
            {
                errorMessage = "SYSCOIN_ASSET_CONSENSUS_ERROR: ERRCODE: 2005 - " + _("Contract address not proper size");
                return error(errorMessage.c_str());
            }  
			if (theAsset.nPrecision > 8)
			{
				errorMessage = "SYSCOIN_ASSET_CONSENSUS_ERROR: ERRCODE: 2005 - " + _("Precision must be between 0 and 8");
				return error(errorMessage.c_str());
			}
			if (theAsset.nMaxSupply != -1 && !AssetRange(theAsset.nMaxSupply, theAsset.nPrecision))
			{
				errorMessage = "SYSCOIN_ASSET_CONSENSUS_ERROR: ERRCODE: 2014 - " + _("Max supply out of money range");
				return error(errorMessage.c_str());
			}
			if (theAsset.nBalance > theAsset.nMaxSupply)
			{
				errorMessage = "SYSCOIN_ASSET_CONSENSUS_ERROR: ERRCODE: 2015 - " + _("Total supply cannot exceed maximum supply");
				return error(errorMessage.c_str());
			}
            if (!theAsset.witnessAddress.IsValid())
            {
                errorMessage = "SYSCOIN_ASSET_CONSENSUS_ERROR: ERRCODE: 2015 - " + _("Address specified is invalid");
                return error(errorMessage.c_str());
            }
            if(theAsset.nUpdateFlags > ASSET_UPDATE_ALL){
                errorMessage = "SYSCOIN_ASSET_CONSENSUS_ERROR: ERRCODE: 2026 - " + _("Invalid update flags");
                return error(errorMessage.c_str());
            }          
			break;

		case SYSCOIN_TX_VERSION_ASSET_UPDATE:
			if (theAsset.nBalance < 0){
				errorMessage = "SYSCOIN_ASSET_CONSENSUS_ERROR: ERRCODE: 2017 - " + _("Balance must be greater than or equal to 0");
				return error(errorMessage.c_str());
			}
            if (!theAssetAllocation.assetAllocationTuple.IsNull())
            {
                errorMessage = "SYSCOIN_ASSET_CONSENSUS_ERROR: ERRCODE: 2019 - " + _("Cannot update allocations");
                return error(errorMessage.c_str());
            }
            if (!theAsset.vchContract.empty() && theAsset.vchContract.size() != MAX_GUID_LENGTH)
            {
                errorMessage = "SYSCOIN_ASSET_CONSENSUS_ERROR: ERRCODE: 2005 - " + _("Contract address not proper size");
                return error(errorMessage.c_str());
            }  
            if(theAsset.nUpdateFlags > ASSET_UPDATE_ALL){
                errorMessage = "SYSCOIN_ASSET_CONSENSUS_ERROR: ERRCODE: 2026 - " + _("Invalid update flags");
                return error(errorMessage.c_str());
            }           
			break;
            
		case SYSCOIN_TX_VERSION_ASSET_SEND:
			if (theAssetAllocation.listSendingAllocationAmounts.empty())
			{
				errorMessage = "SYSCOIN_ASSET_CONSENSUS_ERROR: ERRCODE: 2020 - " + _("Asset send must send an input or transfer balance");
				return error(errorMessage.c_str());
			}
			if (theAssetAllocation.listSendingAllocationAmounts.size() > 250)
			{
				errorMessage = "SYSCOIN_ASSET_CONSENSUS_ERROR: ERRCODE: 2021 - " + _("Too many receivers in one allocation send, maximum of 250 is allowed at once");
				return error(errorMessage.c_str());
			}
			break;
        case SYSCOIN_TX_VERSION_ASSET_TRANSFER:
            break;
		    errorMessage = "SYSCOIN_ASSET_CONSENSUS_ERROR: ERRCODE: 2023 - " + _("Asset transaction has unknown op");
			return error(errorMessage.c_str());
		}
	}

	CAsset dbAsset;
    const uint32_t &nAsset = tx.nVersion == SYSCOIN_TX_VERSION_ASSET_SEND ? theAssetAllocation.assetAllocationTuple.nAsset : theAsset.nAsset;
    auto result = mapAssets.try_emplace(nAsset, std::move(emptyAsset));
    auto mapAsset = result.first;
    const bool & mapAssetNotFound = result.second; 
	if (mapAssetNotFound)
	{
        if(!GetAsset(nAsset, dbAsset)){
			if (tx.nVersion != SYSCOIN_TX_VERSION_ASSET_ACTIVATE) {
				errorMessage = "SYSCOIN_ASSET_CONSENSUS_ERROR: ERRCODE: 2024 - " + _("Failed to read from asset DB");
				return error(errorMessage.c_str());
			}
            else
                 mapAsset->second = std::move(theAsset); 
	    }
        else{
            if(tx.nVersion == SYSCOIN_TX_VERSION_ASSET_ACTIVATE){
                errorMessage =  "SYSCOIN_ASSET_CONSENSUS_ERROR: ERRCODE: 2041 - " + _("Asset already exists");
                return error(errorMessage.c_str());
            }
            mapAsset->second = std::move(dbAsset); 
        }
    }
    CAsset &storedSenderAssetRef = mapAsset->second;
	if (tx.nVersion == SYSCOIN_TX_VERSION_ASSET_TRANSFER) {
	
        if (!FindAssetOwnerInTx(inputs, tx, storedSenderAssetRef.witnessAddress))
        {
            errorMessage = "SYSCOIN_ASSET_CONSENSUS_ERROR: ERRCODE: 1015 - " + _("Cannot transfer this asset. Asset owner must sign off on this change");
            return error(errorMessage.c_str());
        }           
	}

	if (tx.nVersion == SYSCOIN_TX_VERSION_ASSET_UPDATE) {
		if (!FindAssetOwnerInTx(inputs, tx, storedSenderAssetRef.witnessAddress))
		{
			errorMessage = "SYSCOIN_ASSET_CONSENSUS_ERROR: ERRCODE: 1015 - " + _("Cannot update this asset. Asset owner must sign off on this change");
			return error(errorMessage.c_str());
		}

		if (theAsset.nBalance > 0 && !(storedSenderAssetRef.nUpdateFlags & ASSET_UPDATE_SUPPLY))
		{
			errorMessage = "SYSCOIN_ASSET_CONSENSUS_ERROR: ERRCODE: 2026 - " + _("Insufficient privileges to update supply");
			return error(errorMessage.c_str());
		}          
        // increase total supply
        storedSenderAssetRef.nTotalSupply += theAsset.nBalance;
		storedSenderAssetRef.nBalance += theAsset.nBalance;

		if (!AssetRange(storedSenderAssetRef.nTotalSupply, storedSenderAssetRef.nPrecision))
		{
			errorMessage = "SYSCOIN_ASSET_CONSENSUS_ERROR: ERRCODE: 2029 - " + _("Total supply out of money range");
			return error(errorMessage.c_str());
		}
		if (storedSenderAssetRef.nTotalSupply > storedSenderAssetRef.nMaxSupply)
		{
			errorMessage = "SYSCOIN_ASSET_CONSENSUS_ERROR: ERRCODE: 2030 - " + _("Total supply cannot exceed maximum supply");
			return error(errorMessage.c_str());
		}

	}      
	if (tx.nVersion == SYSCOIN_TX_VERSION_ASSET_SEND) {
		if (storedSenderAssetRef.witnessAddress != theAssetAllocation.assetAllocationTuple.witnessAddress || !FindAssetOwnerInTx(inputs, tx, storedSenderAssetRef.witnessAddress))
		{
			errorMessage = "SYSCOIN_ASSET_CONSENSUS_ERROR: ERRCODE: 1015 - " + _("Cannot send this asset. Asset owner must sign off on this change");
			return error(errorMessage.c_str());
		}

		// check balance is sufficient on sender
		CAmount nTotal = 0;
		for (const auto& amountTuple : theAssetAllocation.listSendingAllocationAmounts) {
			nTotal += amountTuple.second;
			if (amountTuple.second <= 0)
			{
				errorMessage = "SYSCOIN_ASSET_CONSENSUS_ERROR: ERRCODE: 2032 - " + _("Receiving amount must be positive");
				return error(errorMessage.c_str());
			}
		}
		if (storedSenderAssetRef.nBalance < nTotal) {
			errorMessage = "SYSCOIN_ASSET_CONSENSUS_ERROR: ERRCODE: 2033 - " + _("Sender balance is insufficient");
			return error(errorMessage.c_str());
		}
		for (const auto& amountTuple : theAssetAllocation.listSendingAllocationAmounts) {
			if (!bSanityCheck) {
				CAssetAllocation receiverAllocation;
				const CAssetAllocationTuple receiverAllocationTuple(theAssetAllocation.assetAllocationTuple.nAsset, amountTuple.first);
                const string& receiverTupleStr = receiverAllocationTuple.ToString();
                auto result = mapAssetAllocations.try_emplace(std::move(receiverTupleStr), std::move(emptyAllocation));
                auto mapAssetAllocation = result.first;
                const bool& mapAssetAllocationNotFound = result.second;
               
                if(mapAssetAllocationNotFound){
                    GetAssetAllocation(receiverAllocationTuple, receiverAllocation);
                    if (receiverAllocation.assetAllocationTuple.IsNull()) {
                        receiverAllocation.assetAllocationTuple.nAsset = std::move(receiverAllocationTuple.nAsset);
                        receiverAllocation.assetAllocationTuple.witnessAddress = std::move(receiverAllocationTuple.witnessAddress);
                        if(fAssetIndex && !fJustCheck){
                            std::vector<uint32_t> assetGuids;
                            passetindexdb->ReadAssetsByAddress(receiverAllocation.assetAllocationTuple.witnessAddress, assetGuids);
                            if(std::find(assetGuids.begin(), assetGuids.end(), receiverAllocation.assetAllocationTuple.nAsset) == assetGuids.end())
                                assetGuids.push_back(receiverAllocation.assetAllocationTuple.nAsset);
                            
                            passetindexdb->WriteAssetsByAddress(receiverAllocation.assetAllocationTuple.witnessAddress, assetGuids);
                        }                        
                    } 
                    mapAssetAllocation->second = std::move(receiverAllocation);                
                }
                
                CAssetAllocation& storedReceiverAllocationRef = mapAssetAllocation->second;
                
                storedReceiverAllocationRef.nBalance += amountTuple.second;
                                        
				// adjust sender balance
				storedSenderAssetRef.nBalance -= amountTuple.second;                              
			}
		}
        if (!bSanityCheck && !fJustCheck)
            passetallocationdb->WriteAssetAllocationIndex(tx, storedSenderAssetRef, true, nHeight);  
	}
	else if (tx.nVersion != SYSCOIN_TX_VERSION_ASSET_ACTIVATE)
	{         
		if (!theAsset.witnessAddress.IsNull())
			storedSenderAssetRef.witnessAddress = theAsset.witnessAddress;
		if (!theAsset.vchPubData.empty())
			storedSenderAssetRef.vchPubData = theAsset.vchPubData;
		else if (!(storedSenderAssetRef.nUpdateFlags & ASSET_UPDATE_DATA))
		{
			errorMessage = "SYSCOIN_ASSET_CONSENSUS_ERROR: ERRCODE: 2026 - " + _("Insufficient privileges to update public data");
			return error(errorMessage.c_str());
		}
                 			
		if (!(storedSenderAssetRef.nUpdateFlags & ASSET_UPDATE_CONTRACT))
		{
			errorMessage = "SYSCOIN_ASSET_CONSENSUS_ERROR: ERRCODE: 2026 - " + _("Insufficient privileges to update smart contract burn method signature");
			return error(errorMessage.c_str());
		}
        
        if (!theAsset.vchContract.empty() && tx.nVersion != SYSCOIN_TX_VERSION_ASSET_TRANSFER)
            storedSenderAssetRef.vchContract = theAsset.vchContract;             
        else if (!(storedSenderAssetRef.nUpdateFlags & ASSET_UPDATE_CONTRACT))
        {
            errorMessage = "SYSCOIN_ASSET_CONSENSUS_ERROR: ERRCODE: 2026 - " + _("Insufficient privileges to update smart contract");
            return error(errorMessage.c_str());
        }    
              
		if (theAsset.nUpdateFlags != storedSenderAssetRef.nUpdateFlags && (!(storedSenderAssetRef.nUpdateFlags & (ASSET_UPDATE_FLAGS | ASSET_UPDATE_ADMIN)))) {
			errorMessage = "SYSCOIN_ASSET_CONSENSUS_ERROR: ERRCODE: 2040 - " + _("Insufficient privileges to update flags");
			return error(errorMessage.c_str());
		}
        storedSenderAssetRef.nUpdateFlags = theAsset.nUpdateFlags;


	}
	if (tx.nVersion == SYSCOIN_TX_VERSION_ASSET_ACTIVATE)
	{
        if (!FindAssetOwnerInTx(inputs, tx, storedSenderAssetRef.witnessAddress))
        {
            errorMessage = "SYSCOIN_ASSET_CONSENSUS_ERROR: ERRCODE: 1015 - " + _("Cannot create this asset. Asset owner must sign off on this change");
            return error(errorMessage.c_str());
        }          
		// starting supply is the supplied balance upon init
		storedSenderAssetRef.nTotalSupply = storedSenderAssetRef.nBalance;
	}
	// set the asset's txn-dependent values
    storedSenderAssetRef.nHeight = nHeight;
	storedSenderAssetRef.txHash = txHash;
	// write asset, if asset send, only write on pow since asset -> asset allocation is not 0-conf compatible
	if (!bSanityCheck && !fJustCheck) {
        passetdb->WriteAssetIndex(tx, storedSenderAssetRef, nHeight);
		LogPrint(BCLog::SYS,"CONNECTED ASSET: tx=%s symbol=%d hash=%s height=%d fJustCheck=%d\n",
				assetFromTx(tx.nVersion).c_str(),
				nAsset,
				txHash.ToString().c_str(),
				nHeight,
				fJustCheck ? 1 : 0);
	}
	
    return true;
}

UniValue assetnew(const JSONRPCRequest& request) {
	const UniValue &params = request.params;
    if (request.fHelp || params.size() != 8)
        throw runtime_error(
			"assetnew <address> <public value> <contract> <precision=8> <supply> <max_supply> <update_flags> <witness>\n"
            "\nCreate a new asset\n"
            "\nArguments:\n"
			"1. <address> An address that you own.\n"
            "2. <public value> public data, 256 characters max.\n"
            "3. <contract> Ethereum token contract for SyscoinX bridge. Must be in hex and not include the '0x' format tag. For example contract '0xb060ddb93707d2bc2f8bcc39451a5a28852f8d1d' should be set as 'b060ddb93707d2bc2f8bcc39451a5a28852f8d1d'. Leave empty for no smart contract bridge.\n" 
			"4. <precision> Precision of balances. Must be between 0 and 8. The lower it is the higher possible max_supply is available since the supply is represented as a 64 bit integer. With a precision of 8 the max supply is 10 billion.\n"
			"5. <supply> Initial supply of asset. Can mint more supply up to total_supply amount or if total_supply is -1 then minting is uncapped.\n"
			"6. <max_supply> Maximum supply of this asset. Set to -1 for uncapped. Depends on the precision value that is set, the lower the precision the higher max_supply can be.\n"
			"7. <update_flags> Ability to update certain fields. Must be decimal value which is a bitmask for certain rights to update. The bitmask represents 0x01(1) to give admin status (needed to update flags), 0x10(2) for updating public data field, 0x100(4) for updating the smart contract/burn method signature fields, 0x1000(8) for updating supply, 0x10000(16) for being able to update flags (need admin access to update flags as well). 0x11111(31) for all.\n"
			"8. <witness> Witness address that will sign for web-of-trust notarization of this transaction.\n"
            "\nResult:\n"
            "[                       (array of strings)\n"
            "  \"rawtransaction\"           (string) The unfunded and unsigned raw transaction of the new asset creation transaction\n"
            "  \"assetguid\"                (string) The guid of asset to be created\n"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("assetnew", "\"myaddress\" \"publicvalue\" \"contractaddr\" 8 100 1000 31")
            + HelpExampleRpc("assetnew", "\"myaddress\" \"publicvalue\" \"contractaddr\" 8 100 1000 31")
            );
	string vchAddress = params[0].get_str();
	vector<unsigned char> vchPubData = vchFromString(params[1].get_str());
    string strContract = params[2].get_str();
    if(!strContract.empty())
         boost::erase_all(strContract, "0x");  // strip 0x in hex str if exist
   
	int precision = params[3].get_int();
	string vchWitness;
	UniValue param4 = params[4];
	UniValue param5 = params[5];
	CAmount nBalance = AssetAmountFromValue(param4, precision);
	CAmount nMaxSupply = AssetAmountFromValue(param5, precision);
	int nUpdateFlags = params[6].get_int();
	vchWitness = params[7].get_str();

	string strAddressFrom;
	string strAddress = vchAddress;
	const CTxDestination address = DecodeDestination(strAddress);

    UniValue detail = DescribeAddress(address);
    if(find_value(detail.get_obj(), "iswitness").get_bool() == false)
        throw runtime_error("SYSCOIN_ASSET_RPC_ERROR: ERRCODE: 2501 - " + _("Address must be a segwit based address"));
    string witnessProgramHex = find_value(detail.get_obj(), "witness_program").get_str();
    unsigned char witnessVersion = (unsigned char)find_value(detail.get_obj(), "witness_version").get_int();   


	// calculate net
    // build asset object
    CAsset newAsset;
	newAsset.nAsset = GenerateSyscoinGuid();
	newAsset.vchPubData = vchPubData;
    newAsset.vchContract = ParseHex(strContract);
	newAsset.witnessAddress = CWitnessAddress(witnessVersion, ParseHex(witnessProgramHex));
	newAsset.nBalance = nBalance;
	newAsset.nMaxSupply = nMaxSupply;
	newAsset.nPrecision = precision;
	newAsset.nUpdateFlags = nUpdateFlags;
	vector<unsigned char> data;
	newAsset.Serialize(data);
    

	// use the script pub key to create the vecsend which sendmoney takes and puts it into vout
	vector<CRecipient> vecSend;



	CScript scriptData;
	scriptData << OP_RETURN << data;
	CRecipient fee;
	CreateFeeRecipient(scriptData, fee);
	vecSend.push_back(fee);
	UniValue res = syscointxfund_helper(SYSCOIN_TX_VERSION_ASSET_ACTIVATE, vchWitness, vecSend);
	res.push_back((int)newAsset.nAsset);
	return res;
}
UniValue addressbalance(const JSONRPCRequest& request) {
    const UniValue &params = request.params;
    if (request.fHelp || params.size() != 1)
        throw runtime_error(
            "addressbalance [address]\n");
    string address = params[0].get_str();
    UniValue res(UniValue::VARR);
    res.push_back(ValueFromAmount(getaddressbalance(address)));
    return res;
}

UniValue assetupdate(const JSONRPCRequest& request) {
	const UniValue &params = request.params;
    if (request.fHelp || params.size() != 6)
        throw runtime_error(
			"assetupdate <asset> <public value> <contract> <supply> <update_flags> <witness>\n"
			"\nPerform an update on an asset you control.\n"
            "\nArguments:\n"
			"1. <asset>             (numeric, required) Asset guid.\n"
            "2. <public value>      (string, required) Public data, 256 characters max.\n"
            "3. <contract>          (string, required) Ethereum token contract for SyscoinX bridge. Leave empty for no smart contract bridge.\n"             
		    "4. <supply>            (numeric, required) New supply of asset. Can mint more supply up to total_supply amount or if max_supply is -1 then minting is uncapped. If greator than zero, minting is assumed otherwise set to 0 to not mint any additional tokens.\n"
            "5. <update_flags>      (string, required) Ability to update certain fields. Must be decimal value which is a bitmask for certain rights to update. The bitmask represents 0x01(1) to give admin status (needed to update flags), 0x10(2) for updating public data field, 0x100(4) for updating the smart contract/burn method signature fields, 0x1000(8) for updating supply, 0x10000(16) for being able to update flags (need admin access to update flags as well). 0x11111(31) for all.\n"
            "6. <witness>           (string, optional) Witness address that will sign for web-of-trust notarization of this transaction.\n"
            "\nResult:\n"
            "\nExamples:\n"
            + HelpExampleCli("assetupdate", "\"assetguid\" \"publicvalue\" \"contractaddress\" \"supply\" \" update_flags\" \"\"")
            + HelpExampleRpc("assetupdate", "\"assetguid\" \"publicvalue\" \"contractaddress\" \"supply\" \" update_flags\" \"\"")
            );
	const int &nAsset = params[0].get_int();
	string strData = "";
	string strPubData = "";
	string strCategory = "";
	strPubData = params[1].get_str();
    string strContract = params[2].get_str();
    if(!strContract.empty())
        boost::erase_all(strContract, "0x");  // strip 0x if exist
    vector<unsigned char> vchContract = ParseHex(strContract);

	int nUpdateFlags = params[4].get_int();
	string vchWitness;
	vchWitness = params[5].get_str();
    
	CAsset theAsset;

    if (!GetAsset( nAsset, theAsset))
        throw runtime_error("SYSCOIN_ASSET_RPC_ERROR: ERRCODE: 2501 - " + _("Could not find a asset with this key"));
        
    const CWitnessAddress &copyWitness = theAsset.witnessAddress;
    theAsset.ClearAsset();
    theAsset.witnessAddress = copyWitness;
    
	UniValue param3 = params[3];
	CAmount nBalance = 0;
	if(param3.get_str() != "0")
		nBalance = AssetAmountFromValue(param3, theAsset.nPrecision);
	
	if(strPubData != stringFromVch(theAsset.vchPubData))
		theAsset.vchPubData = vchFromString(strPubData);
    else
        theAsset.vchPubData.clear();
    if(vchContract != theAsset.vchContract)
        theAsset.vchContract = vchContract;
    else
        theAsset.vchContract.clear();

	theAsset.nBalance = nBalance;
	theAsset.nUpdateFlags = nUpdateFlags;

	vector<unsigned char> data;
	theAsset.Serialize(data);
    

	vector<CRecipient> vecSend;


	CScript scriptData;
	scriptData << OP_RETURN << data;
	CRecipient fee;
	CreateFeeRecipient(scriptData, fee);
	vecSend.push_back(fee);
	return syscointxfund_helper(SYSCOIN_TX_VERSION_ASSET_UPDATE, vchWitness, vecSend);
}

UniValue assettransfer(const JSONRPCRequest& request) {
	const UniValue &params = request.params;
    if (request.fHelp || params.size() != 3)
        throw runtime_error(
			"assettransfer [asset] [address] [witness]\n"
			"\nTransfer an asset you own to another address.\n"
            "\nArguments:\n"
			"1. <asset>      (numeric, required) Asset guid.\n"
			"2. <address>    (string, required) Address to transfer to.\n"
			"3. <witness>    (string, optional) Witness address that will sign for web-of-trust notarization of this transaction.\n"
            "\nResult:\n"
            "[\n"
            "  \"hexstring\"    (string) Unfunded and unsigned transaction hexstring\n"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("assettransfer", "\"asset\" \"address\" \"\"")
            + HelpExampleRpc("assettransfer", "\"asset\" \"address\" \"\"")
            );

    // gather & validate inputs
	const int &nAsset = params[0].get_int();
	string vchAddressTo = params[1].get_str();
	string vchWitness;
	vchWitness = params[2].get_str();

    CScript scriptPubKeyOrig, scriptPubKeyFromOrig;
	CAsset theAsset;
    if (!GetAsset( nAsset, theAsset))
        throw runtime_error("SYSCOIN_ASSET_RPC_ERROR: ERRCODE: 2505 - " + _("Could not find a asset with this key"));
	


	const CTxDestination addressTo = DecodeDestination(vchAddressTo);


    UniValue detail = DescribeAddress(addressTo);
    if(find_value(detail.get_obj(), "iswitness").get_bool() == false)
        throw runtime_error("SYSCOIN_ASSET_RPC_ERROR: ERRCODE: 2501 - " + _("Address must be a segwit based address"));
    string witnessProgramHex = find_value(detail.get_obj(), "witness_program").get_str();
    unsigned char witnessVersion = (unsigned char)find_value(detail.get_obj(), "witness_version").get_int();   

    
	theAsset.ClearAsset();
    CScript scriptPubKey;
	theAsset.witnessAddress = CWitnessAddress(witnessVersion, ParseHex(witnessProgramHex));

	vector<unsigned char> data;
	theAsset.Serialize(data);


	vector<CRecipient> vecSend;
    

	CScript scriptData;
	scriptData << OP_RETURN << data;
	CRecipient fee;
	CreateFeeRecipient(scriptData, fee);
	vecSend.push_back(fee);
	return syscointxfund_helper(SYSCOIN_TX_VERSION_ASSET_TRANSFER, vchWitness, vecSend);
}
UniValue assetsend(const JSONRPCRequest& request) {
    const UniValue &params = request.params;
    if (request.fHelp || params.size() != 3)
        throw runtime_error(
            "assetsend <asset> <addressTo> <amount>\n"
            "\nSend an asset you own to another address.\n"
            "\nArguments:\n"
            "1. \"asset\":        (numeric, required) The asset GUID\n"
            "2. \"addressto\":    (string, required) The address to send the asset (creates an asset allocation)\n"
            "3. \"amount\":       (numeric, required) the quantity of asset to send\n"
            "\nResult:\n"
            "[\n"
            "  \"hexstring\":    (string) the unsigned and unfunded transaction hexstring.\n"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("assetsend", "\"assetguid\" \"addressto\" \"amount\"")
            + HelpExampleRpc("assetsend", "\"assetguid\" \"addressto\" \"amount\"")
            );

    UniValue output(UniValue::VARR);
    UniValue outputObj(UniValue::VOBJ);
    outputObj.pushKV("address", params[1]);
    outputObj.pushKV("amount", params[2]);
    output.push_back(outputObj);
    UniValue paramsFund(UniValue::VARR);
    paramsFund.push_back(params[0]);
    paramsFund.push_back(output);
    paramsFund.push_back("");
    JSONRPCRequest requestMany;
    requestMany.params = paramsFund;
    return assetsendmany(requestMany);          
}
UniValue assetsendmany(const JSONRPCRequest& request) {
	const UniValue &params = request.params;
	if (request.fHelp || params.size() != 3)
		throw runtime_error(
			"assetsendmany \"asset\" \'[{\"address\":\"address\",\"amount\":amount},...]\' [witness]\n"
			"\nSend an asset you own to another address/address as an asset allocation. Maximimum recipients is 250.\n"
            "\nArguments:\n"
            "1. \"asset\":         (numeric, required) The asset GUID\n"
            "2. \"amounts\":       (string, required) a json array of json objects\n"
            "   [\n"
            "     {\n"
            "       \"address\":\"addressto\"  (string, required) The address to send the assetallocation to\n"
            "       ,\n"
            "       \"amount\":\"amount\"      (numeric, required) The amount of allocation to send\n"
            "     }\n"
            "    ,...\n"
            "   ]\n"
            "3. \"witness\":       (string, optional) THe list of witnesses\n"
            "\nResult:\n"
            "[\n"
            "  \"hexstring\":      (string) the unsigned and unfunded transaction hexstring.\n"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("assetsendmany", "\"assetguid\" '[{\"address\":\"sysaddress1\",\"amount\":100},{\"address\":\"sysaddress2\",\"amount\":200}]\' \"\"")
            + HelpExampleCli("assetsendmany", "\"assetguid\" \"[{\\\"address\\\":\\\"sysaddress1\\\",\\\"amount\\\":100},{\\\"address\\\":\\\"sysaddress2\\\",\\\"amount\\\":200}]\" \"\"")
            + HelpExampleRpc("assetsendmany", "\"assetguid\" \'[{\"address\":\"sysaddress1\",\"amount\":100},{\"address\":\"sysaddress2\",\"amount\":200}]\' \"\"")
            + HelpExampleRpc("assetsendmany", "\"assetguid\" \"[{\\\"address\\\":\\\"sysaddress1\\\",\\\"amount\\\":100},{\\\"address\\\":\\\"sysaddress2\\\",\\\"amount\\\":200}]\" \"\"")
            );
	// gather & validate inputs
	const int &nAsset = params[0].get_int();
	UniValue valueTo = params[1];
	string vchWitness = params[2].get_str();
	if (!valueTo.isArray())
		throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Array of receivers not found");

	CAsset theAsset;
	if (!GetAsset(nAsset, theAsset))
		throw runtime_error("SYSCOIN_ASSET_RPC_ERROR: ERRCODE: 2507 - " + _("Could not find a asset with this key"));



	CAssetAllocation theAssetAllocation;
	theAssetAllocation.assetAllocationTuple = CAssetAllocationTuple(nAsset, theAsset.witnessAddress);

	UniValue receivers = valueTo.get_array();
	for (unsigned int idx = 0; idx < receivers.size(); idx++) {
		const UniValue& receiver = receivers[idx];
		if (!receiver.isObject())
			throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "expected object with {\"address'\", or \"amount\"}");

		UniValue receiverObj = receiver.get_obj();
		string toStr = find_value(receiverObj, "address").get_str();
        CTxDestination dest = DecodeDestination(toStr);
		if(!IsValidDestination(dest))
			throw runtime_error("SYSCOIN_ASSET_RPC_ERROR: ERRCODE: 2509 - " + _("Asset must be sent to a valid syscoin address"));

        UniValue detail = DescribeAddress(dest);
        if(find_value(detail.get_obj(), "iswitness").get_bool() == false)
            throw runtime_error("SYSCOIN_ASSET_RPC_ERROR: ERRCODE: 2501 - " + _("Address must be a segwit based address"));
        string witnessProgramHex = find_value(detail.get_obj(), "witness_program").get_str();
        unsigned char witnessVersion = (unsigned char)find_value(detail.get_obj(), "witness_version").get_int();    
                		
		UniValue amountObj = find_value(receiverObj, "amount");
		if (amountObj.isNum() || amountObj.isStr()) {
			const CAmount &amount = AssetAmountFromValue(amountObj, theAsset.nPrecision);
			if (amount <= 0)
				throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "amount must be positive");
			theAssetAllocation.listSendingAllocationAmounts.push_back(make_pair(CWitnessAddress(witnessVersion,ParseHex(witnessProgramHex)), amount));
		}
		else
			throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "expected amount as number in receiver array");

	}

	CScript scriptPubKey;

    vector<unsigned char> data;
    theAssetAllocation.Serialize(data);
    
	vector<CRecipient> vecSend;

	CScript scriptData;
	scriptData << OP_RETURN << data;
	CRecipient fee;
	CreateFeeRecipient(scriptData, fee);
	vecSend.push_back(fee);

	return syscointxfund_helper(SYSCOIN_TX_VERSION_ASSET_SEND, vchWitness, vecSend);
}

UniValue assetinfo(const JSONRPCRequest& request) {
	const UniValue &params = request.params;
    if (request.fHelp || 1 != params.size())
        throw runtime_error("assetinfo <asset>\n"
                "\nShow stored values of a single asset and its.\n"
                "\nArguments:\n"
                "1. \"asset\":       (numeric, required) The asset guid"
                "\nResult:\n"
                "{\n"
                "  \"_id\":          (numeric) The asset guid\n"
                "  \"txid\":         (string) The transaction id that created this asset\n"
                "  \"publicvalue\":  (string) The public value attached to this asset\n"
                "  \"address\":      (string) The address that controls this address\n"
                "  \"contract\":     (string) The ethereum contract address\n"
                "  \"balance\":      (numeric) The current balance\n"
                "  \"total_supply\": (numeric) The total supply of this asset\n"
                "  \"max_supply\":   (numeric) The maximum supply of this asset\n"
                "  \"update_flag\":  (numeric) The flag in decimal \n"
                "  \"precision\":    (numeric) The precision of this asset \n"   
                "}\n"
                "\nExamples:\n"
                + HelpExampleCli("assetinfo", "\"assetguid\"")
                + HelpExampleRpc("assetinfo", "\"assetguid\"")
                );

    const int &nAsset = params[0].get_int();
	UniValue oAsset(UniValue::VOBJ);

	CAsset txPos;
	if (passetdb == nullptr || !passetdb->ReadAsset(nAsset, txPos))
		throw runtime_error("SYSCOIN_ASSET_RPC_ERROR: ERRCODE: 2511 - " + _("Failed to read from asset DB"));

	if(!BuildAssetJson(txPos, oAsset))
		oAsset.clear();
    return oAsset;
}
bool BuildAssetJson(const CAsset& asset, UniValue& oAsset)
{
    oAsset.pushKV("_id", (int)asset.nAsset);
    oAsset.pushKV("txid", asset.txHash.GetHex());
	oAsset.pushKV("publicvalue", stringFromVch(asset.vchPubData));
	oAsset.pushKV("address", asset.witnessAddress.ToString());
    oAsset.pushKV("contract", asset.vchContract.empty()? "" : "0x"+HexStr(asset.vchContract));
	oAsset.pushKV("balance", ValueFromAssetAmount(asset.nBalance, asset.nPrecision));
	oAsset.pushKV("total_supply", ValueFromAssetAmount(asset.nTotalSupply, asset.nPrecision));
	oAsset.pushKV("max_supply", ValueFromAssetAmount(asset.nMaxSupply, asset.nPrecision));
	oAsset.pushKV("update_flags", asset.nUpdateFlags);
	oAsset.pushKV("precision", (int)asset.nPrecision);
	return true;
}
bool AssetTxToJSON(const CTransaction& tx, UniValue &entry)
{
	CAsset asset(tx);
	if(asset.IsNull())
		return false;

	CAsset dbAsset;
	GetAsset(asset.nAsset, dbAsset);
    
    int nHeight = 0;
    uint256 hash_block;
    CBlockIndex* blockindex = nullptr;
    CTransactionRef txRef;
    if (GetTransaction(tx.GetHash(), txRef, Params().GetConsensus(), hash_block, true, blockindex) && blockindex)
        nHeight = blockindex->nHeight; 
        	

	entry.pushKV("txtype", assetFromTx(tx.nVersion));
	entry.pushKV("_id", (int)asset.nAsset);
    entry.pushKV("txid", tx.GetHash().GetHex());
    entry.pushKV("height", nHeight);
    
	if(tx.nVersion == SYSCOIN_TX_VERSION_ASSET_ACTIVATE || (!asset.vchPubData.empty() && dbAsset.vchPubData != asset.vchPubData))
		entry.pushKV("publicvalue", stringFromVch(asset.vchPubData));
        
    if(tx.nVersion == SYSCOIN_TX_VERSION_ASSET_ACTIVATE || (!asset.vchContract.empty() && dbAsset.vchContract != asset.vchContract))
        entry.pushKV("contract", "0x"+HexStr(asset.vchContract));
        
	if (tx.nVersion == SYSCOIN_TX_VERSION_ASSET_ACTIVATE || (!asset.witnessAddress.IsNull() && dbAsset.witnessAddress != asset.witnessAddress))
		entry.pushKV("address", asset.witnessAddress.ToString());

	if (tx.nVersion == SYSCOIN_TX_VERSION_ASSET_ACTIVATE || asset.nUpdateFlags != dbAsset.nUpdateFlags)
		entry.pushKV("update_flags", asset.nUpdateFlags);
              
	if (tx.nVersion == SYSCOIN_TX_VERSION_ASSET_ACTIVATE || asset.nBalance != dbAsset.nBalance)
		entry.pushKV("balance", ValueFromAssetAmount(asset.nBalance, dbAsset.nPrecision));
    if (tx.nVersion == SYSCOIN_TX_VERSION_ASSET_ACTIVATE){
        entry.pushKV("total_supply", ValueFromAssetAmount(asset.nTotalSupply, dbAsset.nPrecision)); 
        entry.pushKV("precision", asset.nPrecision);  
    }         
     return true;
}
bool AssetTxToJSON(const CTransaction& tx, const CAsset& dbAsset, const int& nHeight, UniValue &entry)
{
    CAsset asset(tx);
    if(asset.IsNull() || dbAsset.IsNull())
        return false;

    entry.pushKV("txtype", assetFromTx(tx.nVersion));
    entry.pushKV("_id", (int)asset.nAsset);
    entry.pushKV("txid", tx.GetHash().GetHex());
    entry.pushKV("height", nHeight);

    if(tx.nVersion == SYSCOIN_TX_VERSION_ASSET_ACTIVATE || (!asset.vchPubData.empty() && dbAsset.vchPubData != asset.vchPubData))
        entry.pushKV("publicvalue", stringFromVch(asset.vchPubData));
        
    if(tx.nVersion == SYSCOIN_TX_VERSION_ASSET_ACTIVATE|| (!asset.vchContract.empty() && dbAsset.vchContract != asset.vchContract))
        entry.pushKV("contract", "0x"+HexStr(asset.vchContract));
        
    if (tx.nVersion == SYSCOIN_TX_VERSION_ASSET_ACTIVATE || (!asset.witnessAddress.IsNull() && dbAsset.witnessAddress != asset.witnessAddress))
        entry.pushKV("address", asset.witnessAddress.ToString());

    if (tx.nVersion == SYSCOIN_TX_VERSION_ASSET_ACTIVATE || asset.nUpdateFlags != dbAsset.nUpdateFlags)
        entry.pushKV("update_flags", asset.nUpdateFlags);
              
    if (tx.nVersion == SYSCOIN_TX_VERSION_ASSET_ACTIVATE || asset.nBalance != dbAsset.nBalance)
        entry.pushKV("balance", ValueFromAssetAmount(asset.nBalance, dbAsset.nPrecision));
    if (tx.nVersion == SYSCOIN_TX_VERSION_ASSET_ACTIVATE){
        entry.pushKV("total_supply", ValueFromAssetAmount(asset.nTotalSupply, dbAsset.nPrecision)); 
        entry.pushKV("precision", asset.nPrecision);  
    }  
    return true;
}
UniValue ValueFromAssetAmount(const CAmount& amount,int precision)
{
	if (precision < 0 || precision > 8)
		throw JSONRPCError(RPC_TYPE_ERROR, "Precision must be between 0 and 8");
	bool sign = amount < 0;
	int64_t n_abs = (sign ? -amount : amount);
	int64_t quotient = n_abs;
	int64_t divByAmount = 1;
	int64_t remainder = 0;
	string strPrecision = "0";
	if (precision > 0) {
		divByAmount = pow(10, precision);
		quotient = n_abs / divByAmount;
		remainder = n_abs % divByAmount;
		strPrecision = boost::lexical_cast<string>(precision);
	}

	return UniValue(UniValue::VSTR,
		strprintf("%s%d.%0" + strPrecision + "d", sign ? "-" : "", quotient, remainder));
}
CAmount AssetAmountFromValue(UniValue& value, int precision)
{
	if(precision < 0 || precision > 8)
		throw JSONRPCError(RPC_TYPE_ERROR, "Precision must be between 0 and 8");
	if (!value.isNum() && !value.isStr())
		throw JSONRPCError(RPC_TYPE_ERROR, "Amount is not a number or string");
	if (value.isStr() && value.get_str() == "-1") {
		value.setInt((int64_t)(MAX_ASSET / ((int)pow(10, precision))));
	}
	CAmount amount;
	if (!ParseFixedPoint(value.getValStr(), precision, &amount))
		throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount");
	if (!AssetRange(amount))
		throw JSONRPCError(RPC_TYPE_ERROR, "Amount out of range");
	return amount;
}
CAmount AssetAmountFromValueNonNeg(const UniValue& value, int precision)
{
	if (precision < 0 || precision > 8)
		throw JSONRPCError(RPC_TYPE_ERROR, "Precision must be between 0 and 8");
	if (!value.isNum() && !value.isStr())
		throw JSONRPCError(RPC_TYPE_ERROR, "Amount is not a number or string");
	CAmount amount;
	if (!ParseFixedPoint(value.getValStr(), precision, &amount))
		throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount");
	if (!AssetRange(amount))
		throw JSONRPCError(RPC_TYPE_ERROR, "Amount out of range");
	return amount;
}
bool AssetRange(const CAmount& amount, int precision)
{

	if (precision < 0 || precision > 8)
		throw JSONRPCError(RPC_TYPE_ERROR, "Precision must be between 0 and 8");
	bool sign = amount < 0;
	int64_t n_abs = (sign ? -amount : amount);
	int64_t quotient = n_abs;
	if (precision > 0) {
		int64_t divByAmount = pow(10, precision);
		quotient = n_abs / divByAmount;
	}
	if (!AssetRange(quotient))
		return false;
	return true;
}
bool CAssetDB::Flush(const AssetMap &mapAssets){
    if(mapAssets.empty())
        return true;
    CDBBatch batch(*this);
    for (const auto &key : mapAssets) {
        if(key.second.IsNull())
            batch.Erase(key.first);
        else
            batch.Write(key.first, key.second);
    }
    LogPrint(BCLog::SYS, "Flushing %d assets\n", mapAssets.size());
    return WriteBatch(batch);
}
bool CAssetDB::ScanAssets(const int count, const int from, const UniValue& oOptions, UniValue& oRes) {
	string strTxid = "";
	vector<CWitnessAddress > vecWitnessAddresses;
    uint32_t nAsset = 0;
	if (!oOptions.isNull()) {
		const UniValue &txid = find_value(oOptions, "txid");
		if (txid.isStr()) {
			strTxid = txid.get_str();
		}
		const UniValue &assetObj = find_value(oOptions, "asset");
		if (assetObj.isNum()) {
			nAsset = boost::lexical_cast<uint32_t>(assetObj.get_int());
		}

		const UniValue &owners = find_value(oOptions, "addresses");
		if (owners.isArray()) {
			const UniValue &ownersArray = owners.get_array();
			for (unsigned int i = 0; i < ownersArray.size(); i++) {
				const UniValue &owner = ownersArray[i].get_obj();
                const CTxDestination &dest = DecodeDestination(owner.get_str());
                UniValue detail = DescribeAddress(dest);
                if(find_value(detail.get_obj(), "iswitness").get_bool() == false)
                    throw runtime_error("SYSCOIN_ASSET_RPC_ERROR: ERRCODE: 2501 - " + _("Address must be a segwit based address"));
                string witnessProgramHex = find_value(detail.get_obj(), "witness_program").get_str();
                unsigned char witnessVersion = (unsigned char)find_value(detail.get_obj(), "witness_version").get_int();   
				const UniValue &ownerStr = find_value(owner, "address");
				if (ownerStr.isStr()) 
					vecWitnessAddresses.push_back(CWitnessAddress(witnessVersion, ParseHex(witnessProgramHex)));
			}
		}
	}
	boost::scoped_ptr<CDBIterator> pcursor(NewIterator());
	pcursor->SeekToFirst();
	CAsset txPos;
	uint32_t key;
	int index = 0;
	while (pcursor->Valid()) {
		boost::this_thread::interruption_point();
		try {
			if (pcursor->GetKey(key) && (nAsset == 0 || nAsset != key)) {
				pcursor->GetValue(txPos);
				if (!strTxid.empty() && strTxid != txPos.txHash.GetHex())
				{
					pcursor->Next();
					continue;
				}
				if (!vecWitnessAddresses.empty() && std::find(vecWitnessAddresses.begin(), vecWitnessAddresses.end(), txPos.witnessAddress) == vecWitnessAddresses.end())
				{
					pcursor->Next();
					continue;
				}
				UniValue oAsset(UniValue::VOBJ);
				if (!BuildAssetJson(txPos, oAsset))
				{
					pcursor->Next();
					continue;
				}
				index += 1;
				if (index <= from) {
					pcursor->Next();
					continue;
				}
				oRes.push_back(oAsset);
				if (index >= count + from)
					break;
			}
			pcursor->Next();
		}
		catch (std::exception &e) {
			return error("%s() : deserialize error", __PRETTY_FUNCTION__);
		}
	}
	return true;
}
UniValue listassets(const JSONRPCRequest& request) {
	const UniValue &params = request.params;
	if (request.fHelp || 3 < params.size())
		throw runtime_error(
            "listassets (count) (from) ([{options}])\n"
			"\nScan through all assets.\n"
            "\nArguments:\n"
			"1. <count>          (numeric, optional, default=10) The number of results to return.\n"
			"2. <from>           (numeric, optional, default=0) The number of results to skip.\n"
			"3. <options>        (object, optional) A json object with options to filter results\n"
			"    {\n"
			"      \"txid\":txid					(string) Transaction ID to filter results for\n"
			"	   \"asset\":guid					(numeric) Asset GUID to filter.\n"
			"	   \"addresses\"			        (array) a json array with owners\n"
			"		[\n"
			"			{\n"
			"				\"address\":string		(string) Address to filter.\n"
			"			} \n"
			"			,...\n"
			"		]\n"
			"    }\n"
            "\nResult:\n"
            "\nExampels:\n"
			+ HelpExampleCli("listassets", "0")
			+ HelpExampleCli("listassets", "10 10")
			+ HelpExampleCli("listassets", "0 0 '{\"addresses\":[{\"address\":\"sys1qw40fdue7g7r5ugw0epzk7xy24tywncm26hu4a7\"},{\"address\":\"sys1qw40fdue7g7r5ugw0epzk7xy24tywncm26hu4a7\"}]}'")
			+ HelpExampleCli("listassets", "0 0 '{\"asset\":3473733}'")
			+ HelpExampleRpc("listassets", "0 0 '{\"addresses\":[{\"address\":\"sys1qw40fdue7g7r5ugw0epzk7xy24tywncm26hu4a7\"},{\"address\":\"sys1qw40fdue7g7r5ugw0epzk7xy24tywncm26hu4a7\"}]}'")
			+ HelpExampleRpc("listassets", "0 0 '{\"asset\":3473733}'")
		);
	UniValue options;
	int count = 10;
	int from = 0;
	if (params.size() > 0) {
		count = params[0].get_int();
		if (count == 0) {
			count = 10;
		} else
		if (count < 0) {
			throw runtime_error("SYSCOIN_ASSET_RPC_ERROR: ERRCODE: 2512 - " + _("'count' must be 0 or greater"));
		}
	}
	if (params.size() > 1) {
		from = params[1].get_int();
		if (from < 0) {
			throw runtime_error("SYSCOIN_ASSET_RPC_ERROR: ERRCODE: 2512 - " + _("'from' must be 0 or greater"));
		}
	}
	if (params.size() > 2) {
		options = params[2];
	}

	UniValue oRes(UniValue::VARR);
	if (!passetdb->ScanAssets(count, from, options, oRes))
		throw runtime_error("SYSCOIN_ASSET_RPC_ERROR: ERRCODE: 2512 - " + _("Scan failed"));
	return oRes;
}
bool CAssetIndexDB::ScanAssetIndex(int64_t page, const UniValue& oOptions, UniValue& oRes) {
    CAssetAllocationTuple assetTuple;
    uint32_t nAsset = 0;
    if (!oOptions.isNull()) {
        const UniValue &assetObj = find_value(oOptions, "asset");
        if (assetObj.isNum()) {
            nAsset = boost::lexical_cast<uint32_t>(assetObj.get_int());
        }
        else
            return false;

        const UniValue &addressObj = find_value(oOptions, "address");
        if (addressObj.isStr()) {
            const CTxDestination &dest = DecodeDestination(addressObj.get_str());
            UniValue detail = DescribeAddress(dest);
            if(find_value(detail.get_obj(), "iswitness").get_bool() == false)
                throw runtime_error("SYSCOIN_ASSET_RPC_ERROR: ERRCODE: 2501 - " + _("Address must be a segwit based address"));
            string witnessProgramHex = find_value(detail.get_obj(), "witness_program").get_str();
            unsigned char witnessVersion = (unsigned char)find_value(detail.get_obj(), "witness_version").get_int();   
            assetTuple = CAssetAllocationTuple(nAsset, CWitnessAddress(witnessVersion, ParseHex(witnessProgramHex)));
        }
    }
    else
        return false;
    vector<uint256> vecTX;
    int64_t pageFound;
    bool scanAllocation = !assetTuple.IsNull();
    if(scanAllocation){
        if(!ReadAssetAllocationPage(pageFound))
            return true;
    }
    else{
        if(!ReadAssetPage(pageFound))
            return true;
    }
    if(pageFound < page)
        return false;
    // order by highest page first
    page = pageFound - page;
    if(scanAllocation){
        if(!ReadIndexTXIDs(assetTuple, page, vecTX))
            return false;
    }
    else{
        if(!ReadIndexTXIDs(nAsset, page, vecTX))
            return false;
    }
    // reverse order LIFO
    std::reverse(vecTX.begin(), vecTX.end());
    uint256 block_hash;
    for(const uint256& txid: vecTX){
        UniValue oObj(UniValue::VOBJ);
        if(!ReadPayload(txid, oObj))
            continue;
        if(ReadBlockHash(txid, block_hash)){
            oObj.pushKV("block_hash", block_hash.GetHex());        
        }
        else
            oObj.pushKV("block_hash", "");
           
        oRes.push_back(oObj);
    }
    
    return true;
}
UniValue getblockhashbytxid(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "getblockhash txid\n"
            "\nReturns hash of block in best-block-chain at txid provided. Requires -blockindex configuration flag.\n"
            "\nArguments:\n"
            "1. txid         (string, required) A transaction that is in the block\n"
            "\nResult:\n"
            "\"hash\"         (string) The block hash\n"
            "\nExamples:\n"
            + HelpExampleCli("getblockhashbytxid", "dfc7eac24fa89b0226c64885f7bedaf132fc38e8980b5d446d76707027254490")
            + HelpExampleRpc("getblockhashbytxid", "dfc7eac24fa89b0226c64885f7bedaf132fc38e8980b5d446d76707027254490")
        );
    if(!fBlockIndex)
        throw runtime_error("SYSCOIN_ASSET_RPC_ERROR: ERRCODE: 1510 - " + _("You must reindex syscoin with -blockindex enabled"));
    LOCK(cs_main);

    uint256 hash = ParseHashV(request.params[0], "parameter 1");

    uint256 blockhash;
    if(!passetindexdb->ReadBlockHash(hash, blockhash))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block hash not found in asset index");

    const CBlockIndex* pblockindex = LookupBlockIndex(blockhash);
    if (!pblockindex) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
    }

    return pblockindex->GetBlockHash().GetHex();
}
UniValue syscoingetspvproof(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw std::runtime_error(
            "syscoingetspvproof txid (blockhash) \n"
            "\nReturns SPV proof for use with inter-chain transfers. Requires -blockindex configuration flag if you omit the blockhash parameter.\n"
            "\nArguments:\n"
            "1. txid         (string, required) A transaction that is in the block\n"
            "1. blockhash    (string, not-required) Block containing txid\n"
            "\nResult:\n"
        "\"proof\"         (string) JSON representation of merkl/ nj   nk ne proof (transaction index, siblings and block header and some other information useful for moving coins/assets to another chain)\n"
            "\nExamples:\n"
            + HelpExampleCli("syscoingetspvproof", "dfc7eac24fa89b0226c64885f7bedaf132fc38e8980b5d446d76707027254490")
            + HelpExampleRpc("syscoingetspvproof", "dfc7eac24fa89b0226c64885f7bedaf132fc38e8980b5d446d76707027254490")
        );
    LOCK(cs_main);
    UniValue res(UniValue::VOBJ);
    uint256 txhash = ParseHashV(request.params[0], "parameter 1");
    uint256 blockhash;
    if(request.params.size() > 1)
        blockhash = ParseHashV(request.params[1], "parameter 2");
    if(fBlockIndex){
        if(!passetindexdb->ReadBlockHash(txhash, blockhash))
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block hash not found in asset index");
    }
    CBlockIndex* pblockindex = LookupBlockIndex(blockhash);
    if (!pblockindex) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
    }
    CTransactionRef tx;
    uint256 hash_block;
    if (!GetTransaction(txhash, tx, Params().GetConsensus(), hash_block, true, pblockindex))   
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Transaction not found"); 

    CBlock block;
    if (IsBlockPruned(pblockindex)) {
        throw JSONRPCError(RPC_MISC_ERROR, "Block not available (pruned data)");
    }

    if (!ReadBlockFromDisk(block, pblockindex, Params().GetConsensus())) {
        // Block not found on disk. This could be because we have the block
        // header in our index but don't have the block (for example if a
        // non-whitelisted node sends us an unrequested long chain of valid
        // blocks, we add the headers to our index, but don't accept the
        // block).
        throw JSONRPCError(RPC_MISC_ERROR, "Block not found on disk");
    }   
    CDataStream ssBlock(SER_NETWORK, PROTOCOL_VERSION);
    ssBlock << pblockindex->GetBlockHeader(Params().GetConsensus());
    const std::string &rawTx = EncodeHexTx(*tx, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS);
    res.pushKV("transaction",rawTx);
    // get first 80 bytes of header (non auxpow part)
    res.pushKV("header", HexStr(ssBlock.begin(), ssBlock.begin()+80));
    UniValue siblings(UniValue::VARR);
    // store the index of the transaction we are looking for within the block
    int nIndex = 0;
    for (unsigned int i = 0;i < block.vtx.size();i++) {
        const uint256 &txHashFromBlock = block.vtx[i]->GetHash();
        if(txhash == txHashFromBlock)
            nIndex = i;
        siblings.push_back(txHashFromBlock.GetHex());
    }
    res.pushKV("siblings", siblings);
    res.pushKV("index", nIndex);
    UniValue assetVal;
    try{
        UniValue paramsDecode(UniValue::VARR);
        paramsDecode.push_back(rawTx);   
        JSONRPCRequest requestDecodeRPC;
        requestDecodeRPC.params = paramsDecode;
        UniValue resDecode = syscoindecoderawtransaction(requestDecodeRPC);
        assetVal = find_value(resDecode.get_obj(), "asset"); 
    }
    catch(const runtime_error& e){
    }
    if(!assetVal.isNull()) {
        CAsset asset;
        if(!GetAsset(assetVal.get_int(), asset))
             throw runtime_error("SYSCOIN_ASSET_RPC_ERROR: ERRCODE: 1510 - " + _("Asset not found"));
        if(asset.vchContract.empty())
            throw runtime_error("SYSCOIN_ASSET_RPC_ERROR: ERRCODE: 1510 - " + _("Asset contract is empty"));
         res.pushKV("contract", HexStr(asset.vchContract));    
                   
    }
    else{
        res.pushKV("contract", HexStr(Params().GetConsensus().vchSYSXContract));
    }
    return res;
}
UniValue listassetindex(const JSONRPCRequest& request) {
    const UniValue &params = request.params;
    if (request.fHelp || 2 != params.size())
        throw runtime_error(
            "listassetindex <page> <options>\n"
            "\nScan through all asset index and return paged results based on page number passed in. Requires assetindex config parameter enabled and optional assetindexpagesize which is 25 by default.\n"
            "\nArguments:\n"
            "1. <page>           (numeric, default=0) Return specific page number of transactions. Lower page number means more recent transactions.\n"
            "2. <options>        (array, required) A json object with options to filter results\n"
            "    {\n"
            "      \"asset\":guid                   (numeric) Asset GUID to filter.\n"
            "      \"address\":string               (string, optional) Address to filter. Leave empty to scan globally through asset.\n"
            "    }\n"
            + HelpExampleCli("listassetindex", "0 '{\"asset\":92922}'")
            + HelpExampleCli("listassetindex", "2 '{\"asset\":92922, \"address\":\"sys1qw40fdue7g7r5ugw0epzk7xy24tywncm26hu4a7\"}'")
            + HelpExampleRpc("listassetindex", "0 '{\"asset\":92922}'")
            + HelpExampleRpc("listassetindex", "2 '{\"asset\":92922, \"address\":\"sys1qw40fdue7g7r5ugw0epzk7xy24tywncm26hu4a7\"}'")
        );
    if(!fAssetIndex){
        throw runtime_error("SYSCOIN_ASSET_RPC_ERROR: ERRCODE: 1510 - " + _("You must start syscoin with -assetindex enabled"));
    }
    UniValue options;
    int64_t page = params[0].get_int64();
   
    if (page < 0) {
        throw runtime_error("SYSCOIN_ASSET_RPC_ERROR: ERRCODE: 1510 - " + _("'page' must be 0 or greater"));
    }

    options = params[1];
    
    UniValue oRes(UniValue::VARR);
    if (!passetindexdb->ScanAssetIndex(page, options, oRes))
        throw runtime_error("SYSCOIN_ASSET_RPC_ERROR: ERRCODE: 1510 - " + _("Scan failed"));
    return oRes;
}
UniValue listassetindexassets(const JSONRPCRequest& request) {
    const UniValue &params = request.params;
    if (request.fHelp || 1 != params.size())
        throw runtime_error(
            "listassetindexassets <address>\n"
            "\nReturn a list of assets an address is associated with.\n"
            "\nArguments:\n"
            "1. <asset>          (numeric, required) Address to find assets associated with.\n"
            "\nResult:\n"
            "\nExamples:\n"
            + HelpExampleCli("listassetindex", "sys1qw40fdue7g7r5ugw0epzk7xy24tywncm26hu4a7")
            + HelpExampleRpc("listassetindex", "sys1qw40fdue7g7r5ugw0epzk7xy24tywncm26hu4a7")
        );
    if(!fAssetIndex){
        throw runtime_error("SYSCOIN_ASSET_RPC_ERROR: ERRCODE: 1510 - " + _("You must start syscoin with -assetindex enabled"));
    }       
    const CTxDestination &dest = DecodeDestination(params[0].get_str());
    UniValue detail = DescribeAddress(dest);
    if(find_value(detail.get_obj(), "iswitness").get_bool() == false)
        throw runtime_error("SYSCOIN_ASSET_RPC_ERROR: ERRCODE: 2501 - " + _("Address must be a segwit based address"));
    string witnessProgramHex = find_value(detail.get_obj(), "witness_program").get_str();
    unsigned char witnessVersion = (unsigned char)find_value(detail.get_obj(), "witness_version").get_int();   
 
    UniValue oRes(UniValue::VARR);
    std::vector<uint32_t> assetGuids;
    if (!passetindexdb->ReadAssetsByAddress(CWitnessAddress(witnessVersion, ParseHex(witnessProgramHex)), assetGuids))
        throw runtime_error("SYSCOIN_ASSET_RPC_ERROR: ERRCODE: 1510 - " + _("Lookup failed"));
        
    for(const uint32_t& guid: assetGuids){
        UniValue oObj(UniValue::VOBJ);
        oObj.pushKV("asset", (int)guid);
        oRes.push_back(oObj);
    }
    return oRes;
}
UniValue syscoinstopgeth(const JSONRPCRequest& request) {
    const UniValue &params = request.params;
    if (request.fHelp || 0 != params.size())
        throw runtime_error(
            "syscoinstopgeth\n"
            "\nStops Geth and the relayer from running.\n"
            );
    if(!StopRelayerNode(relayerPID))
        throw runtime_error("SYSCOIN_ASSET_RPC_ERROR: ERRCODE: 2512 - " + _("Could not stop relayer"));
    if(!StopGethNode(gethPID))
        throw runtime_error("SYSCOIN_ASSET_RPC_ERROR: ERRCODE: 2512 - " + _("Could not stop Geth"));
    UniValue ret(UniValue::VOBJ);
    ret.pushKV("status", "success");
    return ret;
}
UniValue syscoinstartgeth(const JSONRPCRequest& request) {
    const UniValue &params = request.params;
    if (request.fHelp || 0 != params.size())
        throw runtime_error(
            "syscoinstartgeth\n"
            "\nStarts Geth and the relayer.\n"
            );
    
    StopRelayerNode(relayerPID);
    StopGethNode(gethPID);
    int wsport = gArgs.GetArg("-gethwebsocketport", 8546);
    bool bGethTestnet = gArgs.GetBoolArg("-gethtestnet", false);
    if(!StartGethNode(gethPID, bGethTestnet, wsport))
        throw runtime_error("SYSCOIN_ASSET_RPC_ERROR: ERRCODE: 2512 - " + _("Could not start Geth"));
    int rpcport = gArgs.GetArg("-rpcport", BaseParams().RPCPort());
    const std::string& rpcuser = gArgs.GetArg("-rpcuser", "u");
    const std::string& rpcpassword = gArgs.GetArg("-rpcpassword", "p");
    if(!StartRelayerNode(relayerPID, rpcport, rpcuser, rpcpassword, wsport))
        throw runtime_error("SYSCOIN_ASSET_RPC_ERROR: ERRCODE: 2512 - " + _("Could not stop relayer"));
    
    UniValue ret(UniValue::VOBJ);
    ret.pushKV("status", "success");
    return ret;
}
UniValue syscoinsetethstatus(const JSONRPCRequest& request) {
    const UniValue &params = request.params;
    if (request.fHelp || 2 != params.size())
        throw runtime_error(
            "syscoinsetethstatus <syncing_status> <highestBlock>\n"
            "\nSets ethereum syncing and network status for indication status of network sync.\n"
            "\nArguments:\n"
            "1. <syncing_status>    (string, required)  Syncing status either 'syncing' or 'synced'.\n"
            "2. <highestBlock>      (numeric, require)  What the highest block height on Ethereum is found to be. Usually coupled with syncing_status of 'syncing'. Set to 0 if syncing_status is 'synced'.\n" 
            "\nResult:\n"
            "\nExamples:\n"
            + HelpExampleCli("syscoinsetethstatus", "syncing 7000000")
            + HelpExampleCli("syscoinsetethstatus", "synced 0")
            + HelpExampleRpc("syscoinsetethstatus", "syncing 7000000")
            + HelpExampleRpc("syscoinsetethstatus", "synced 0")
            );
    string status = params[0].get_str();
    int highestBlock = params[1].get_int();
    
    if(highestBlock > 0){
        LOCK(cs_ethsyncheight);
        fGethSyncHeight = highestBlock;
    }
    fGethSyncStatus = status; 
    if(!fGethSynced && fGethCurrentHeight >= fGethSyncHeight)       
        fGethSynced = fGethSyncStatus == "synced";

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("status", "success");
    return ret;
}
UniValue syscoinsetethheaders(const JSONRPCRequest& request) {
    const UniValue &params = request.params;
    if (request.fHelp || 1 != params.size())
        throw runtime_error(
            "syscoinsetethheaders <headers>\n"
            "\nSets Ethereum headers in Syscoin to validate transactions through the SYSX bridge.\n"
            "\nArguments:\n"
            "1. <headers>      (string, required)   A JSON objects representing an array of arrays (block number, tx root) from Ethereum blockchain.\n"
            "\nResult:\n"
            "\nExamples:\n"
            + HelpExampleCli("syscoinsetethheaders", "\"[[7043888,\\\"0xd8ac75c7b4084c85a89d6e28219ff162661efb8b794d4b66e6e9ea52b4139b10\\\"],...]\"")
            + HelpExampleRpc("syscoinsetethheaders", "\"[[7043888,\\\"0xd8ac75c7b4084c85a89d6e28219ff162661efb8b794d4b66e6e9ea52b4139b10\\\"],...]\"")
            );  

    EthereumTxRootMap txRootMap;       
    const UniValue &headerArray = params[0].get_array();
    for(size_t i =0;i<headerArray.size();i++){
        const UniValue &tupleArray = headerArray[i].get_array();
        if(tupleArray.size() != 2)
            throw runtime_error("SYSCOIN_ASSET_RPC_ERROR: ERRCODE: 2512 - " + _("Invalid size in a blocknumber/txroot tuple, should be size of 2"));
        uint32_t nHeight = (uint32_t)tupleArray[0].get_int();
        {
            LOCK(cs_ethsyncheight);
            if(nHeight > fGethSyncHeight)
                fGethSyncHeight = nHeight;
        }
        if(nHeight > fGethCurrentHeight)
            fGethCurrentHeight = nHeight;
        string txRoot = tupleArray[1].get_str();
        boost::erase_all(txRoot, "0x");  // strip 0x
        const vector<unsigned char> &vchTxRoot = ParseHex(txRoot);
        txRootMap.try_emplace(nHeight, vchTxRoot);
    } 
    bool res = pethereumtxrootsdb->FlushWrite(txRootMap) && pethereumtxrootsdb->PruneTxRoots();
    UniValue ret(UniValue::VOBJ);
    ret.pushKV("status", res? "success": "fail");
    return ret;
}
bool CEthereumTxRootsDB::PruneTxRoots() {
    EthereumTxRootMap mapEraseTxRoots;
    boost::scoped_ptr<CDBIterator> pcursor(NewIterator());
    pcursor->SeekToFirst();
    vector<uint32_t> vecHeightKeys;
    uint32_t key;
    int32_t cutoffHeight;
    {
        LOCK(cs_ethsyncheight);
        // cutoff is ~1 week of blocks is about 40k blocks
        cutoffHeight = fGethSyncHeight - MAX_ETHEREUM_TX_ROOTS;
        if(cutoffHeight < 0){
            LogPrint(BCLog::SYS, "Nothing to prune fGethSyncHeight = %d\n", fGethSyncHeight);
            return true;
        }
    }
    std::vector<unsigned char> txPos;
    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        try {
            if (pcursor->GetKey(key) && key < (uint32_t)cutoffHeight) {
                vecHeightKeys.emplace_back(std::move(key));
            }
            pcursor->Next();
        }
        catch (std::exception &e) {
            return error("%s() : deserialize error", __PRETTY_FUNCTION__);
        }
    }
    {
        LOCK(cs_ethsyncheight);
        WriteHighestHeight(fGethSyncHeight);
    }
    
    WriteCurrentHeight(fGethCurrentHeight);      
    FlushErase(vecHeightKeys);
    return true;
}
bool CEthereumTxRootsDB::Init(){
    bool highestHeight = false;
    {
        LOCK(cs_ethsyncheight);
        highestHeight = ReadHighestHeight(fGethSyncHeight);
    }
    return highestHeight && ReadCurrentHeight(fGethCurrentHeight);
    
}
bool CAssetIndexDB::FlushErase(const std::vector<uint256> &vecTXIDs){
    if(vecTXIDs.empty() || !fAssetIndex)
        return true;

    CDBBatch batch(*this);
    for (const uint256 &txid : vecTXIDs) {
        // erase payload
        batch.Erase(txid);
        // erase blockhash
        batch.Erase(std::make_pair(bh, txid));
    }
    LogPrint(BCLog::SYS, "Flushing %d asset index removals\n", vecTXIDs.size());
    return WriteBatch(batch);
}
bool CEthereumTxRootsDB::FlushErase(const std::vector<uint32_t> &vecHeightKeys){
    if(vecHeightKeys.empty())
        return true;
    CDBBatch batch(*this);
    for (const auto &key : vecHeightKeys) {
        batch.Erase(key);
    }
    LogPrint(BCLog::SYS, "Flushing, erasing %d ethereum tx roots\n", vecHeightKeys.size());
    return WriteBatch(batch);
}
bool CEthereumTxRootsDB::FlushWrite(const EthereumTxRootMap &mapTxRoots){
    if(mapTxRoots.empty())
        return true;
    CDBBatch batch(*this);
    for (const auto &key : mapTxRoots) {
        batch.Write(key.first, key.second);
    }
    LogPrint(BCLog::SYS, "Flushing, writing %d ethereum tx roots\n", mapTxRoots.size());
    return WriteBatch(batch);
}
