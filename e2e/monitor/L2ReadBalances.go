// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package main

import (
	"errors"
	"math/big"
	"strings"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
)

// Reference imports to suppress errors if they are not otherwise used.
var (
	_ = errors.New
	_ = big.NewInt
	_ = strings.NewReader
	_ = ethereum.NotFound
	_ = bind.Bind
	_ = common.Big1
	_ = types.BloomLookup
	_ = event.NewSubscription
	_ = abi.ConvertType
)

// L2ReadBalancesMetaData contains all meta data concerning the L2ReadBalances contract.
var L2ReadBalancesMetaData = &bind.MetaData{
	ABI: "[{\"inputs\":[{\"internalType\":\"string\",\"name\":\"btcAddress\",\"type\":\"string\"}],\"name\":\"getBitcoinAddressBalance\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"balance\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getBitcoinLastHeader\",\"outputs\":[{\"internalType\":\"bytes\",\"name\":\"result\",\"type\":\"bytes\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"l1ReadBalancesAddress\",\"type\":\"address\"},{\"internalType\":\"string\",\"name\":\"btcAddress\",\"type\":\"string\"}],\"name\":\"sendBitcoinAddressBalanceToL1\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]",
	Bin: "0x6080604052348015600e575f80fd5b50610a108061001c5f395ff3fe608060405234801561000f575f80fd5b506004361061003f575f3560e01c80636d030e3714610043578063a39272a11461005f578063f4cdc2891461008f575b5f80fd5b61005d60048036038101906100589190610475565b6100ad565b005b610079600480360381019061007491906104d2565b6101ec565b6040516100869190610535565b60405180910390f35b610097610300565b6040516100a491906105d8565b60405180910390f35b5f6100b883836101ec565b90505f73420000000000000000000000000000000000000790505f620f42409050620f42405a101561011f576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161011690610652565b60405180910390fd5b8173ffffffffffffffffffffffffffffffffffffffff16633dbb202b878787874360405160240161015394939291906106aa565b604051602081830303815290604052631a1a1a3b60e01b6020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff8381831617835250505050846040518463ffffffff1660e01b81526004016101b793929190610715565b5f604051808303815f87803b1580156101ce575f80fd5b505af11580156101e0573d5f803e3d5ffd5b50505050505050505050565b5f8083838080601f0160208091040260200160405190810160405280939291908181526020018383808284375f81840152601f19601f8201169050808301925050505050505090505f80604073ffffffffffffffffffffffffffffffffffffffff168360405161025c919061078b565b5f60405180830381855afa9150503d805f8114610294576040519150601f19603f3d011682016040523d82523d5f602084013e610299565b606091505b5091509150816102de576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016102d590610811565b60405180910390fd5b806102e890610889565b60c01c67ffffffffffffffff16935050505092915050565b60605f80604473ffffffffffffffffffffffffffffffffffffffff1660405161032890610912565b5f60405180830381855afa9150503d805f8114610360576040519150601f19603f3d011682016040523d82523d5f602084013e610365565b606091505b5091509150816103aa576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016103a190610996565b60405180910390fd5b809250505090565b5f80fd5b5f80fd5b5f73ffffffffffffffffffffffffffffffffffffffff82169050919050565b5f6103e3826103ba565b9050919050565b6103f3816103d9565b81146103fd575f80fd5b50565b5f8135905061040e816103ea565b92915050565b5f80fd5b5f80fd5b5f80fd5b5f8083601f84011261043557610434610414565b5b8235905067ffffffffffffffff81111561045257610451610418565b5b60208301915083600182028301111561046e5761046d61041c565b5b9250929050565b5f805f6040848603121561048c5761048b6103b2565b5b5f61049986828701610400565b935050602084013567ffffffffffffffff8111156104ba576104b96103b6565b5b6104c686828701610420565b92509250509250925092565b5f80602083850312156104e8576104e76103b2565b5b5f83013567ffffffffffffffff811115610505576105046103b6565b5b61051185828601610420565b92509250509250929050565b5f819050919050565b61052f8161051d565b82525050565b5f6020820190506105485f830184610526565b92915050565b5f81519050919050565b5f82825260208201905092915050565b5f5b8381101561058557808201518184015260208101905061056a565b5f8484015250505050565b5f601f19601f8301169050919050565b5f6105aa8261054e565b6105b48185610558565b93506105c4818560208601610568565b6105cd81610590565b840191505092915050565b5f6020820190508181035f8301526105f081846105a0565b905092915050565b5f82825260208201905092915050565b7f6e6f7420656e6f75676820676173206c656674000000000000000000000000005f82015250565b5f61063c6013836105f8565b915061064782610608565b602082019050919050565b5f6020820190508181035f83015261066981610630565b9050919050565b828183375f83830152505050565b5f61068983856105f8565b9350610696838584610670565b61069f83610590565b840190509392505050565b5f6060820190508181035f8301526106c381868861067e565b90506106d26020830185610526565b6106df6040830184610526565b95945050505050565b6106f1816103d9565b82525050565b5f63ffffffff82169050919050565b61070f816106f7565b82525050565b5f6060820190506107285f8301866106e8565b818103602083015261073a81856105a0565b90506107496040830184610706565b949350505050565b5f81905092915050565b5f6107658261054e565b61076f8185610751565b935061077f818560208601610568565b80840191505092915050565b5f610796828461075b565b915081905092915050565b7f5374617469632063616c6c20746f2062746342616c4164647220707265636f6d5f8201527f70696c652028307834302920636f6e7472616374206661696c65640000000000602082015250565b5f6107fb603b836105f8565b9150610806826107a1565b604082019050919050565b5f6020820190508181035f830152610828816107ef565b9050919050565b5f819050602082019050919050565b5f7fffffffffffffffff00000000000000000000000000000000000000000000000082169050919050565b5f610874825161083e565b80915050919050565b5f82821b905092915050565b5f6108938261054e565b8261089d8461082f565b90506108a881610869565b925060088210156108e8576108e37fffffffffffffffff0000000000000000000000000000000000000000000000008360080360080261087d565b831692505b5050919050565b50565b5f6108fd5f83610751565b9150610908826108ef565b5f82019050919050565b5f61091c826108f2565b9150819050919050565b7f5374617469632063616c6c20746f206274634c617374486561646572207072655f8201527f636f6d70696c652028307834342920636f6e7472616374206661696c65640000602082015250565b5f610980603e836105f8565b915061098b82610926565b604082019050919050565b5f6020820190508181035f8301526109ad81610974565b905091905056fea2646970667358221220570bc93ee3871c4c74890d0679fc702d311e68406ed5389e381af865736d1abe64736f6c637828302e382e32352d646576656c6f702e323032342e322e32342b636f6d6d69742e64626137353465630059",
}

// L2ReadBalancesABI is the input ABI used to generate the binding from.
// Deprecated: Use L2ReadBalancesMetaData.ABI instead.
var L2ReadBalancesABI = L2ReadBalancesMetaData.ABI

// L2ReadBalancesBin is the compiled bytecode used for deploying new contracts.
// Deprecated: Use L2ReadBalancesMetaData.Bin instead.
var L2ReadBalancesBin = L2ReadBalancesMetaData.Bin

// DeployL2ReadBalances deploys a new Ethereum contract, binding an instance of L2ReadBalances to it.
func DeployL2ReadBalances(auth *bind.TransactOpts, backend bind.ContractBackend) (common.Address, *types.Transaction, *L2ReadBalances, error) {
	parsed, err := L2ReadBalancesMetaData.GetAbi()
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	if parsed == nil {
		return common.Address{}, nil, nil, errors.New("GetABI returned nil")
	}

	address, tx, contract, err := bind.DeployContract(auth, *parsed, common.FromHex(L2ReadBalancesBin), backend)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	return address, tx, &L2ReadBalances{L2ReadBalancesCaller: L2ReadBalancesCaller{contract: contract}, L2ReadBalancesTransactor: L2ReadBalancesTransactor{contract: contract}, L2ReadBalancesFilterer: L2ReadBalancesFilterer{contract: contract}}, nil
}

// L2ReadBalances is an auto generated Go binding around an Ethereum contract.
type L2ReadBalances struct {
	L2ReadBalancesCaller     // Read-only binding to the contract
	L2ReadBalancesTransactor // Write-only binding to the contract
	L2ReadBalancesFilterer   // Log filterer for contract events
}

// L2ReadBalancesCaller is an auto generated read-only Go binding around an Ethereum contract.
type L2ReadBalancesCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// L2ReadBalancesTransactor is an auto generated write-only Go binding around an Ethereum contract.
type L2ReadBalancesTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// L2ReadBalancesFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type L2ReadBalancesFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// L2ReadBalancesSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type L2ReadBalancesSession struct {
	Contract     *L2ReadBalances             // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// L2ReadBalancesCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type L2ReadBalancesCallerSession struct {
	Contract *L2ReadBalancesCaller   // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts // Call options to use throughout this session
}

// L2ReadBalancesTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type L2ReadBalancesTransactorSession struct {
	Contract     *L2ReadBalancesTransactor   // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// L2ReadBalancesRaw is an auto generated low-level Go binding around an Ethereum contract.
type L2ReadBalancesRaw struct {
	Contract *L2ReadBalances // Generic contract binding to access the raw methods on
}

// L2ReadBalancesCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type L2ReadBalancesCallerRaw struct {
	Contract *L2ReadBalancesCaller // Generic read-only contract binding to access the raw methods on
}

// L2ReadBalancesTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type L2ReadBalancesTransactorRaw struct {
	Contract *L2ReadBalancesTransactor // Generic write-only contract binding to access the raw methods on
}

// NewL2ReadBalances creates a new instance of L2ReadBalances, bound to a specific deployed contract.
func NewL2ReadBalances(address common.Address, backend bind.ContractBackend) (*L2ReadBalances, error) {
	contract, err := bindL2ReadBalances(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &L2ReadBalances{L2ReadBalancesCaller: L2ReadBalancesCaller{contract: contract}, L2ReadBalancesTransactor: L2ReadBalancesTransactor{contract: contract}, L2ReadBalancesFilterer: L2ReadBalancesFilterer{contract: contract}}, nil
}

// NewL2ReadBalancesCaller creates a new read-only instance of L2ReadBalances, bound to a specific deployed contract.
func NewL2ReadBalancesCaller(address common.Address, caller bind.ContractCaller) (*L2ReadBalancesCaller, error) {
	contract, err := bindL2ReadBalances(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &L2ReadBalancesCaller{contract: contract}, nil
}

// NewL2ReadBalancesTransactor creates a new write-only instance of L2ReadBalances, bound to a specific deployed contract.
func NewL2ReadBalancesTransactor(address common.Address, transactor bind.ContractTransactor) (*L2ReadBalancesTransactor, error) {
	contract, err := bindL2ReadBalances(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &L2ReadBalancesTransactor{contract: contract}, nil
}

// NewL2ReadBalancesFilterer creates a new log filterer instance of L2ReadBalances, bound to a specific deployed contract.
func NewL2ReadBalancesFilterer(address common.Address, filterer bind.ContractFilterer) (*L2ReadBalancesFilterer, error) {
	contract, err := bindL2ReadBalances(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &L2ReadBalancesFilterer{contract: contract}, nil
}

// bindL2ReadBalances binds a generic wrapper to an already deployed contract.
func bindL2ReadBalances(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := L2ReadBalancesMetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, *parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_L2ReadBalances *L2ReadBalancesRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _L2ReadBalances.Contract.L2ReadBalancesCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_L2ReadBalances *L2ReadBalancesRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _L2ReadBalances.Contract.L2ReadBalancesTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_L2ReadBalances *L2ReadBalancesRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _L2ReadBalances.Contract.L2ReadBalancesTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_L2ReadBalances *L2ReadBalancesCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _L2ReadBalances.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_L2ReadBalances *L2ReadBalancesTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _L2ReadBalances.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_L2ReadBalances *L2ReadBalancesTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _L2ReadBalances.Contract.contract.Transact(opts, method, params...)
}

// GetBitcoinAddressBalance is a free data retrieval call binding the contract method 0xa39272a1.
//
// Solidity: function getBitcoinAddressBalance(string btcAddress) view returns(uint256 balance)
func (_L2ReadBalances *L2ReadBalancesCaller) GetBitcoinAddressBalance(opts *bind.CallOpts, btcAddress string) (*big.Int, error) {
	var out []interface{}
	err := _L2ReadBalances.contract.Call(opts, &out, "getBitcoinAddressBalance", btcAddress)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// GetBitcoinAddressBalance is a free data retrieval call binding the contract method 0xa39272a1.
//
// Solidity: function getBitcoinAddressBalance(string btcAddress) view returns(uint256 balance)
func (_L2ReadBalances *L2ReadBalancesSession) GetBitcoinAddressBalance(btcAddress string) (*big.Int, error) {
	return _L2ReadBalances.Contract.GetBitcoinAddressBalance(&_L2ReadBalances.CallOpts, btcAddress)
}

// GetBitcoinAddressBalance is a free data retrieval call binding the contract method 0xa39272a1.
//
// Solidity: function getBitcoinAddressBalance(string btcAddress) view returns(uint256 balance)
func (_L2ReadBalances *L2ReadBalancesCallerSession) GetBitcoinAddressBalance(btcAddress string) (*big.Int, error) {
	return _L2ReadBalances.Contract.GetBitcoinAddressBalance(&_L2ReadBalances.CallOpts, btcAddress)
}

// GetBitcoinLastHeader is a free data retrieval call binding the contract method 0xf4cdc289.
//
// Solidity: function getBitcoinLastHeader() view returns(bytes result)
func (_L2ReadBalances *L2ReadBalancesCaller) GetBitcoinLastHeader(opts *bind.CallOpts) ([]byte, error) {
	var out []interface{}
	err := _L2ReadBalances.contract.Call(opts, &out, "getBitcoinLastHeader")

	if err != nil {
		return *new([]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([]byte)).(*[]byte)

	return out0, err

}

// GetBitcoinLastHeader is a free data retrieval call binding the contract method 0xf4cdc289.
//
// Solidity: function getBitcoinLastHeader() view returns(bytes result)
func (_L2ReadBalances *L2ReadBalancesSession) GetBitcoinLastHeader() ([]byte, error) {
	return _L2ReadBalances.Contract.GetBitcoinLastHeader(&_L2ReadBalances.CallOpts)
}

// GetBitcoinLastHeader is a free data retrieval call binding the contract method 0xf4cdc289.
//
// Solidity: function getBitcoinLastHeader() view returns(bytes result)
func (_L2ReadBalances *L2ReadBalancesCallerSession) GetBitcoinLastHeader() ([]byte, error) {
	return _L2ReadBalances.Contract.GetBitcoinLastHeader(&_L2ReadBalances.CallOpts)
}

// SendBitcoinAddressBalanceToL1 is a paid mutator transaction binding the contract method 0x6d030e37.
//
// Solidity: function sendBitcoinAddressBalanceToL1(address l1ReadBalancesAddress, string btcAddress) returns()
func (_L2ReadBalances *L2ReadBalancesTransactor) SendBitcoinAddressBalanceToL1(opts *bind.TransactOpts, l1ReadBalancesAddress common.Address, btcAddress string) (*types.Transaction, error) {
	return _L2ReadBalances.contract.Transact(opts, "sendBitcoinAddressBalanceToL1", l1ReadBalancesAddress, btcAddress)
}

// SendBitcoinAddressBalanceToL1 is a paid mutator transaction binding the contract method 0x6d030e37.
//
// Solidity: function sendBitcoinAddressBalanceToL1(address l1ReadBalancesAddress, string btcAddress) returns()
func (_L2ReadBalances *L2ReadBalancesSession) SendBitcoinAddressBalanceToL1(l1ReadBalancesAddress common.Address, btcAddress string) (*types.Transaction, error) {
	return _L2ReadBalances.Contract.SendBitcoinAddressBalanceToL1(&_L2ReadBalances.TransactOpts, l1ReadBalancesAddress, btcAddress)
}

// SendBitcoinAddressBalanceToL1 is a paid mutator transaction binding the contract method 0x6d030e37.
//
// Solidity: function sendBitcoinAddressBalanceToL1(address l1ReadBalancesAddress, string btcAddress) returns()
func (_L2ReadBalances *L2ReadBalancesTransactorSession) SendBitcoinAddressBalanceToL1(l1ReadBalancesAddress common.Address, btcAddress string) (*types.Transaction, error) {
	return _L2ReadBalances.Contract.SendBitcoinAddressBalanceToL1(&_L2ReadBalances.TransactOpts, l1ReadBalancesAddress, btcAddress)
}
