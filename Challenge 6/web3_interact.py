# run with:
# uv run --with web3,py-evm,eth_tester web3_interact.py

from web3 import Web3
from web3.providers.eth_tester import EthereumTesterProvider
from Crypto.Util.number import getPrime, bytes_to_long
import platform, hashlib

w3 = Web3(EthereumTesterProvider())
acct = w3.eth.accounts[0]

xor = lambda a, b : bytes(x^y for x, y in zip(a, b))

def setup_contract(bytecode, abi):
    tx_hash = w3.eth.contract(abi=abi, bytecode=bytecode).constructor().transact({"from": acct})
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    contract = w3.eth.contract(address=receipt.contractAddress, abi=abi)
    return contract

class LCGOracle:
    def __init__(self, m, c, n, seed):
        self.m = m
        self.c = c
        self.n = n
        self.state = seed

    def get_next(self):
        self.state = (self.m * self.state + self.c) % self.n
        return self.state

class LCGOracleContract:
    def __init__(self, m, c, n, seed):
        self.m = m
        self.c = c
        self.n = n
        self.state = seed
        self.contract_bytes = '6080604052348015600e575f5ffd5b506102e28061001c5f395ff3fe608060405234801561000f575f5ffd5b5060043610610029575f3560e01c8063115218341461002d575b5f5ffd5b6100476004803603810190610042919061010c565b61005d565b6040516100549190610192565b60405180910390f35b5f5f848061006e5761006d6101ab565b5b86868061007e5761007d6101ab565b5b8987090890505f5f8411610092575f610095565b60015b60ff16905081816100a69190610205565b858260016100b49190610246565b6100be9190610205565b6100c89190610279565b9250505095945050505050565b5f5ffd5b5f819050919050565b6100eb816100d9565b81146100f5575f5ffd5b50565b5f81359050610106816100e2565b92915050565b5f5f5f5f5f60a08688031215610125576101246100d5565b5b5f610132888289016100f8565b9550506020610143888289016100f8565b9450506040610154888289016100f8565b9350506060610165888289016100f8565b9250506080610176888289016100f8565b9150509295509295909350565b61018c816100d9565b82525050565b5f6020820190506101a55f830184610183565b92915050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601260045260245ffd5b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601160045260245ffd5b5f61020f826100d9565b915061021a836100d9565b9250828202610228816100d9565b9150828204841483151761023f5761023e6101d8565b5b5092915050565b5f610250826100d9565b915061025b836100d9565b9250828203905081811115610273576102726101d8565b5b92915050565b5f610283826100d9565b915061028e836100d9565b92508282019050808211156102a6576102a56101d8565b5b9291505056fea2646970667358221220c7e885c1633ad951a2d8168f80d36858af279d8b5fe2e19cf79eac15ecb9fdd364736f6c634300081e0033'
        self.contract_abi = [{'inputs':[{'internalType':'uint256','name':'LCG_MULTIPLIER','type':'uint256'},{'internalType':'uint256','name':'LCG_INCREMENT','type':'uint256'},{'internalType':'uint256','name':'LCG_MODULUS','type':'uint256'},{'internalType':'uint256','name':'_currentState','type':'uint256'},{'internalType':'uint256','name':'_counter','type':'uint256'}],'name':'nextVal','outputs':[{'internalType':'uint256','name':'','type':'uint256'}],'stateMutability':'pure','type':'function'}]
        self.contract = setup_contract(self.contract_bytes, self.contract_abi)
    
    def get_next(self, ctr):
        self.state = self.contract.functions.nextVal(self.m, self.c, self.n, self.state, ctr).call()
        return self.state

class TripleXOR:
    def __init__(self):
        self.contract_bytes = '61030f61004d600b8282823980515f1a6073146041577f4e487b71000000000000000000000000000000000000000000000000000000005f525f60045260245ffd5b305f52607381538281f3fe7300000000000000000000000000000000000000003014608060405260043610610034575f3560e01c80636230075614610038575b5f5ffd5b610052600480360381019061004d919061023c565b610068565b60405161005f91906102c0565b60405180910390f35b5f5f845f1b90505f845f1b90505f61007f85610092565b9050818382181893505050509392505050565b5f5f8290506020815111156100ae5780515f525f5191506100b6565b602081015191505b50919050565b5f604051905090565b5f5ffd5b5f5ffd5b5f819050919050565b6100df816100cd565b81146100e9575f5ffd5b50565b5f813590506100fa816100d6565b92915050565b5f5ffd5b5f5ffd5b5f601f19601f8301169050919050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52604160045260245ffd5b61014e82610108565b810181811067ffffffffffffffff8211171561016d5761016c610118565b5b80604052505050565b5f61017f6100bc565b905061018b8282610145565b919050565b5f67ffffffffffffffff8211156101aa576101a9610118565b5b6101b382610108565b9050602081019050919050565b828183375f83830152505050565b5f6101e06101db84610190565b610176565b9050828152602081018484840111156101fc576101fb610104565b5b6102078482856101c0565b509392505050565b5f82601f83011261022357610222610100565b5b81356102338482602086016101ce565b91505092915050565b5f5f5f60608486031215610253576102526100c5565b5b5f610260868287016100ec565b9350506020610271868287016100ec565b925050604084013567ffffffffffffffff811115610292576102916100c9565b5b61029e8682870161020f565b9150509250925092565b5f819050919050565b6102ba816102a8565b82525050565b5f6020820190506102d35f8301846102b1565b9291505056fea26469706673582212203fc7e6cc4bf6a86689f458c2d70c565e7c776de95b401008e58ca499ace9ecb864736f6c634300081e0033'
        self.contract_abi = [{'inputs': [{'internalType': 'uint256', 'name': '_primeFromLcg', 'type': 'uint256'}, {'internalType': 'uint256', 'name': '_conversationTime', 'type': 'uint256'}, {'internalType': 'string', 'name': '_plaintext', 'type': 'string'}], 'name': 'encrypt', 'outputs': [{'internalType': 'bytes32', 'name': '', 'type': 'bytes32'}], 'stateMutability': 'pure', 'type': 'function'}]
        self.contract = setup_contract(self.contract_bytes, self.contract_abi)

    def encrypt(self, prime_from_lcg, conversation_time, plaintext_bytes):
        ciphertext = self.contract.functions.encrypt(prime_from_lcg, conversation_time, plaintext_bytes).call()
        return ciphertext

m, c, n, seed = [getPrime(256) for _ in range(4)]
lcgOracleContract = LCGOracleContract(m, c, n, seed)
lcgOracle = LCGOracle(m, c, n, seed)

# when ctr == 0, the seed is returned
assert seed == lcgOracleContract.get_next(0)

for i in range(10):
    assert lcgOracleContract.get_next(i+1) == lcgOracle.get_next()

tripleXORContract = TripleXOR()
pt = 'SubscribeToPliromatics!:)'
conv_time = 1337
prm = lcgOracle.get_next()
ct = tripleXORContract.encrypt(prm, conv_time, pt)

conv_time = int.to_bytes(conv_time, length=32, byteorder='big')
pt = pt.encode() + b'\x00'*(32-len(pt))

assert prm == bytes_to_long(xor(xor(ct, conv_time), pt))