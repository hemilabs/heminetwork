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

// TesttokenMetaData contains all meta data concerning the Testtoken contract.
var TesttokenMetaData = &bind.MetaData{
	ABI: "[{\"inputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"constructor\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"spender\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"allowance\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"needed\",\"type\":\"uint256\"}],\"name\":\"ERC20InsufficientAllowance\",\"type\":\"error\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"sender\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"balance\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"needed\",\"type\":\"uint256\"}],\"name\":\"ERC20InsufficientBalance\",\"type\":\"error\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"approver\",\"type\":\"address\"}],\"name\":\"ERC20InvalidApprover\",\"type\":\"error\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"receiver\",\"type\":\"address\"}],\"name\":\"ERC20InvalidReceiver\",\"type\":\"error\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"sender\",\"type\":\"address\"}],\"name\":\"ERC20InvalidSender\",\"type\":\"error\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"spender\",\"type\":\"address\"}],\"name\":\"ERC20InvalidSpender\",\"type\":\"error\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"owner\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"spender\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"value\",\"type\":\"uint256\"}],\"name\":\"Approval\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"from\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"to\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"value\",\"type\":\"uint256\"}],\"name\":\"Transfer\",\"type\":\"event\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"owner\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"spender\",\"type\":\"address\"}],\"name\":\"allowance\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"spender\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"value\",\"type\":\"uint256\"}],\"name\":\"approve\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"account\",\"type\":\"address\"}],\"name\":\"balanceOf\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"decimals\",\"outputs\":[{\"internalType\":\"uint8\",\"name\":\"\",\"type\":\"uint8\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"name\",\"outputs\":[{\"internalType\":\"string\",\"name\":\"\",\"type\":\"string\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"symbol\",\"outputs\":[{\"internalType\":\"string\",\"name\":\"\",\"type\":\"string\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"totalSupply\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"to\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"value\",\"type\":\"uint256\"}],\"name\":\"transfer\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"from\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"to\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"value\",\"type\":\"uint256\"}],\"name\":\"transferFrom\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]",
	Bin: "0x608060405234801561000f575f80fd5b506040518060400160405280600781526020017f4d79546f6b656e000000000000000000000000000000000000000000000000008152506040518060400160405280600281526020017f4d54000000000000000000000000000000000000000000000000000000000000815250816003908161008b91906105bd565b50806004908161009b91906105bd565b5050506100d8336100b06100dd60201b60201c565b60ff16600a6100bf91906107e8565b620f42406100cd9190610832565b6100e560201b60201c565b61095b565b5f6012905090565b5f73ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff1603610155575f6040517fec442f0500000000000000000000000000000000000000000000000000000000815260040161014c91906108b2565b60405180910390fd5b6101665f838361016a60201b60201c565b5050565b5f73ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff16036101ba578060025f8282546101ae91906108cb565b92505081905550610288565b5f805f8573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f2054905081811015610243578381836040517fe450d38c00000000000000000000000000000000000000000000000000000000815260040161023a9392919061090d565b60405180910390fd5b8181035f808673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f2081905550505b5f73ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff16036102cf578060025f8282540392505081905550610319565b805f808473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205f82825401925050819055505b8173ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef836040516103769190610942565b60405180910390a3505050565b5f81519050919050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52604160045260245ffd5b7f4e487b71000000000000000000000000000000000000000000000000000000005f52602260045260245ffd5b5f60028204905060018216806103fe57607f821691505b602082108103610411576104106103ba565b5b50919050565b5f819050815f5260205f209050919050565b5f6020601f8301049050919050565b5f82821b905092915050565b5f600883026104737fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff82610438565b61047d8683610438565b95508019841693508086168417925050509392505050565b5f819050919050565b5f819050919050565b5f6104c16104bc6104b784610495565b61049e565b610495565b9050919050565b5f819050919050565b6104da836104a7565b6104ee6104e6826104c8565b848454610444565b825550505050565b5f90565b6105026104f6565b61050d8184846104d1565b505050565b5b81811015610530576105255f826104fa565b600181019050610513565b5050565b601f8211156105755761054681610417565b61054f84610429565b8101602085101561055e578190505b61057261056a85610429565b830182610512565b50505b505050565b5f82821c905092915050565b5f6105955f198460080261057a565b1980831691505092915050565b5f6105ad8383610586565b9150826002028217905092915050565b6105c682610383565b67ffffffffffffffff8111156105df576105de61038d565b5b6105e982546103e7565b6105f4828285610534565b5f60209050601f831160018114610625575f8415610613578287015190505b61061d85826105a2565b865550610684565b601f19841661063386610417565b5f5b8281101561065a57848901518255600182019150602085019450602081019050610635565b868310156106775784890151610673601f891682610586565b8355505b6001600288020188555050505b505050505050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601160045260245ffd5b5f8160011c9050919050565b5f808291508390505b600185111561070e578086048111156106ea576106e961068c565b5b60018516156106f95780820291505b8081029050610707856106b9565b94506106ce565b94509492505050565b5f8261072657600190506107e1565b81610733575f90506107e1565b8160018114610749576002811461075357610782565b60019150506107e1565b60ff8411156107655761076461068c565b5b8360020a91508482111561077c5761077b61068c565b5b506107e1565b5060208310610133831016604e8410600b84101617156107b75782820a9050838111156107b2576107b161068c565b5b6107e1565b6107c484848460016106c5565b925090508184048111156107db576107da61068c565b5b81810290505b9392505050565b5f6107f282610495565b91506107fd83610495565b925061082a7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8484610717565b905092915050565b5f61083c82610495565b915061084783610495565b925082820261085581610495565b9150828204841483151761086c5761086b61068c565b5b5092915050565b5f73ffffffffffffffffffffffffffffffffffffffff82169050919050565b5f61089c82610873565b9050919050565b6108ac81610892565b82525050565b5f6020820190506108c55f8301846108a3565b92915050565b5f6108d582610495565b91506108e083610495565b92508282019050808211156108f8576108f761068c565b5b92915050565b61090781610495565b82525050565b5f6060820190506109205f8301866108a3565b61092d60208301856108fe565b61093a60408301846108fe565b949350505050565b5f6020820190506109555f8301846108fe565b92915050565b610e22806109685f395ff3fe608060405234801561000f575f80fd5b5060043610610091575f3560e01c8063313ce56711610064578063313ce5671461013157806370a082311461014f57806395d89b411461017f578063a9059cbb1461019d578063dd62ed3e146101cd57610091565b806306fdde0314610095578063095ea7b3146100b357806318160ddd146100e357806323b872dd14610101575b5f80fd5b61009d6101fd565b6040516100aa9190610a75565b60405180910390f35b6100cd60048036038101906100c89190610b26565b61028d565b6040516100da9190610b7e565b60405180910390f35b6100eb6102af565b6040516100f89190610ba6565b60405180910390f35b61011b60048036038101906101169190610bbf565b6102b8565b6040516101289190610b7e565b60405180910390f35b6101396102e6565b6040516101469190610c2a565b60405180910390f35b61016960048036038101906101649190610c43565b6102ee565b6040516101769190610ba6565b60405180910390f35b610187610333565b6040516101949190610a75565b60405180910390f35b6101b760048036038101906101b29190610b26565b6103c3565b6040516101c49190610b7e565b60405180910390f35b6101e760048036038101906101e29190610c6e565b6103e5565b6040516101f49190610ba6565b60405180910390f35b60606003805461020c90610cd9565b80601f016020809104026020016040519081016040528092919081815260200182805461023890610cd9565b80156102835780601f1061025a57610100808354040283529160200191610283565b820191905f5260205f20905b81548152906001019060200180831161026657829003601f168201915b5050505050905090565b5f80610297610467565b90506102a481858561046e565b600191505092915050565b5f600254905090565b5f806102c2610467565b90506102cf858285610480565b6102da858585610513565b60019150509392505050565b5f6012905090565b5f805f8373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f20549050919050565b60606004805461034290610cd9565b80601f016020809104026020016040519081016040528092919081815260200182805461036e90610cd9565b80156103b95780601f10610390576101008083540402835291602001916103b9565b820191905f5260205f20905b81548152906001019060200180831161039c57829003601f168201915b5050505050905090565b5f806103cd610467565b90506103da818585610513565b600191505092915050565b5f60015f8473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205f8373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f2054905092915050565b5f33905090565b61047b8383836001610603565b505050565b5f61048b84846103e5565b90507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff81101561050d57818110156104fe578281836040517ffb8f41b20000000000000000000000000000000000000000000000000000000081526004016104f593929190610d18565b60405180910390fd5b61050c84848484035f610603565b5b50505050565b5f73ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff1603610583575f6040517f96c6fd1e00000000000000000000000000000000000000000000000000000000815260040161057a9190610d4d565b60405180910390fd5b5f73ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff16036105f3575f6040517fec442f050000000000000000000000000000000000000000000000000000000081526004016105ea9190610d4d565b60405180910390fd5b6105fe8383836107d2565b505050565b5f73ffffffffffffffffffffffffffffffffffffffff168473ffffffffffffffffffffffffffffffffffffffff1603610673575f6040517fe602df0500000000000000000000000000000000000000000000000000000000815260040161066a9190610d4d565b60405180910390fd5b5f73ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff16036106e3575f6040517f94280d620000000000000000000000000000000000000000000000000000000081526004016106da9190610d4d565b60405180910390fd5b8160015f8673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205f8573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f208190555080156107cc578273ffffffffffffffffffffffffffffffffffffffff168473ffffffffffffffffffffffffffffffffffffffff167f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925846040516107c39190610ba6565b60405180910390a35b50505050565b5f73ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff1603610822578060025f8282546108169190610d93565b925050819055506108f0565b5f805f8573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f20549050818110156108ab578381836040517fe450d38c0000000000000000000000000000000000000000000000000000000081526004016108a293929190610d18565b60405180910390fd5b8181035f808673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f2081905550505b5f73ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff1603610937578060025f8282540392505081905550610981565b805f808473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205f82825401925050819055505b8173ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef836040516109de9190610ba6565b60405180910390a3505050565b5f81519050919050565b5f82825260208201905092915050565b5f5b83811015610a22578082015181840152602081019050610a07565b5f8484015250505050565b5f601f19601f8301169050919050565b5f610a47826109eb565b610a5181856109f5565b9350610a61818560208601610a05565b610a6a81610a2d565b840191505092915050565b5f6020820190508181035f830152610a8d8184610a3d565b905092915050565b5f80fd5b5f73ffffffffffffffffffffffffffffffffffffffff82169050919050565b5f610ac282610a99565b9050919050565b610ad281610ab8565b8114610adc575f80fd5b50565b5f81359050610aed81610ac9565b92915050565b5f819050919050565b610b0581610af3565b8114610b0f575f80fd5b50565b5f81359050610b2081610afc565b92915050565b5f8060408385031215610b3c57610b3b610a95565b5b5f610b4985828601610adf565b9250506020610b5a85828601610b12565b9150509250929050565b5f8115159050919050565b610b7881610b64565b82525050565b5f602082019050610b915f830184610b6f565b92915050565b610ba081610af3565b82525050565b5f602082019050610bb95f830184610b97565b92915050565b5f805f60608486031215610bd657610bd5610a95565b5b5f610be386828701610adf565b9350506020610bf486828701610adf565b9250506040610c0586828701610b12565b9150509250925092565b5f60ff82169050919050565b610c2481610c0f565b82525050565b5f602082019050610c3d5f830184610c1b565b92915050565b5f60208284031215610c5857610c57610a95565b5b5f610c6584828501610adf565b91505092915050565b5f8060408385031215610c8457610c83610a95565b5b5f610c9185828601610adf565b9250506020610ca285828601610adf565b9150509250929050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52602260045260245ffd5b5f6002820490506001821680610cf057607f821691505b602082108103610d0357610d02610cac565b5b50919050565b610d1281610ab8565b82525050565b5f606082019050610d2b5f830186610d09565b610d386020830185610b97565b610d456040830184610b97565b949350505050565b5f602082019050610d605f830184610d09565b92915050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601160045260245ffd5b5f610d9d82610af3565b9150610da883610af3565b9250828201905080821115610dc057610dbf610d66565b5b9291505056fea2646970667358221220c46b44a3aefa7c256713865cdff1f0f7427263866a94c53881685435da7a2bce64736f6c637828302e382e32352d646576656c6f702e323032342e322e32342b636f6d6d69742e64626137353465630059",
}

// TesttokenABI is the input ABI used to generate the binding from.
// Deprecated: Use TesttokenMetaData.ABI instead.
var TesttokenABI = TesttokenMetaData.ABI

// TesttokenBin is the compiled bytecode used for deploying new contracts.
// Deprecated: Use TesttokenMetaData.Bin instead.
var TesttokenBin = TesttokenMetaData.Bin

// DeployTesttoken deploys a new Ethereum contract, binding an instance of Testtoken to it.
func DeployTesttoken(auth *bind.TransactOpts, backend bind.ContractBackend) (common.Address, *types.Transaction, *Testtoken, error) {
	parsed, err := TesttokenMetaData.GetAbi()
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	if parsed == nil {
		return common.Address{}, nil, nil, errors.New("GetABI returned nil")
	}

	address, tx, contract, err := bind.DeployContract(auth, *parsed, common.FromHex(TesttokenBin), backend)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	return address, tx, &Testtoken{TesttokenCaller: TesttokenCaller{contract: contract}, TesttokenTransactor: TesttokenTransactor{contract: contract}, TesttokenFilterer: TesttokenFilterer{contract: contract}}, nil
}

// Testtoken is an auto generated Go binding around an Ethereum contract.
type Testtoken struct {
	TesttokenCaller     // Read-only binding to the contract
	TesttokenTransactor // Write-only binding to the contract
	TesttokenFilterer   // Log filterer for contract events
}

// TesttokenCaller is an auto generated read-only Go binding around an Ethereum contract.
type TesttokenCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// TesttokenTransactor is an auto generated write-only Go binding around an Ethereum contract.
type TesttokenTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// TesttokenFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type TesttokenFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// TesttokenSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type TesttokenSession struct {
	Contract     *Testtoken        // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// TesttokenCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type TesttokenCallerSession struct {
	Contract *TesttokenCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts    // Call options to use throughout this session
}

// TesttokenTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type TesttokenTransactorSession struct {
	Contract     *TesttokenTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts    // Transaction auth options to use throughout this session
}

// TesttokenRaw is an auto generated low-level Go binding around an Ethereum contract.
type TesttokenRaw struct {
	Contract *Testtoken // Generic contract binding to access the raw methods on
}

// TesttokenCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type TesttokenCallerRaw struct {
	Contract *TesttokenCaller // Generic read-only contract binding to access the raw methods on
}

// TesttokenTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type TesttokenTransactorRaw struct {
	Contract *TesttokenTransactor // Generic write-only contract binding to access the raw methods on
}

// NewTesttoken creates a new instance of Testtoken, bound to a specific deployed contract.
func NewTesttoken(address common.Address, backend bind.ContractBackend) (*Testtoken, error) {
	contract, err := bindTesttoken(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &Testtoken{TesttokenCaller: TesttokenCaller{contract: contract}, TesttokenTransactor: TesttokenTransactor{contract: contract}, TesttokenFilterer: TesttokenFilterer{contract: contract}}, nil
}

// NewTesttokenCaller creates a new read-only instance of Testtoken, bound to a specific deployed contract.
func NewTesttokenCaller(address common.Address, caller bind.ContractCaller) (*TesttokenCaller, error) {
	contract, err := bindTesttoken(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &TesttokenCaller{contract: contract}, nil
}

// NewTesttokenTransactor creates a new write-only instance of Testtoken, bound to a specific deployed contract.
func NewTesttokenTransactor(address common.Address, transactor bind.ContractTransactor) (*TesttokenTransactor, error) {
	contract, err := bindTesttoken(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &TesttokenTransactor{contract: contract}, nil
}

// NewTesttokenFilterer creates a new log filterer instance of Testtoken, bound to a specific deployed contract.
func NewTesttokenFilterer(address common.Address, filterer bind.ContractFilterer) (*TesttokenFilterer, error) {
	contract, err := bindTesttoken(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &TesttokenFilterer{contract: contract}, nil
}

// bindTesttoken binds a generic wrapper to an already deployed contract.
func bindTesttoken(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := TesttokenMetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, *parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Testtoken *TesttokenRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _Testtoken.Contract.TesttokenCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Testtoken *TesttokenRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Testtoken.Contract.TesttokenTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Testtoken *TesttokenRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Testtoken.Contract.TesttokenTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Testtoken *TesttokenCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _Testtoken.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Testtoken *TesttokenTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Testtoken.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Testtoken *TesttokenTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Testtoken.Contract.contract.Transact(opts, method, params...)
}

// Allowance is a free data retrieval call binding the contract method 0xdd62ed3e.
//
// Solidity: function allowance(address owner, address spender) view returns(uint256)
func (_Testtoken *TesttokenCaller) Allowance(opts *bind.CallOpts, owner common.Address, spender common.Address) (*big.Int, error) {
	var out []interface{}
	err := _Testtoken.contract.Call(opts, &out, "allowance", owner, spender)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// Allowance is a free data retrieval call binding the contract method 0xdd62ed3e.
//
// Solidity: function allowance(address owner, address spender) view returns(uint256)
func (_Testtoken *TesttokenSession) Allowance(owner common.Address, spender common.Address) (*big.Int, error) {
	return _Testtoken.Contract.Allowance(&_Testtoken.CallOpts, owner, spender)
}

// Allowance is a free data retrieval call binding the contract method 0xdd62ed3e.
//
// Solidity: function allowance(address owner, address spender) view returns(uint256)
func (_Testtoken *TesttokenCallerSession) Allowance(owner common.Address, spender common.Address) (*big.Int, error) {
	return _Testtoken.Contract.Allowance(&_Testtoken.CallOpts, owner, spender)
}

// BalanceOf is a free data retrieval call binding the contract method 0x70a08231.
//
// Solidity: function balanceOf(address account) view returns(uint256)
func (_Testtoken *TesttokenCaller) BalanceOf(opts *bind.CallOpts, account common.Address) (*big.Int, error) {
	var out []interface{}
	err := _Testtoken.contract.Call(opts, &out, "balanceOf", account)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// BalanceOf is a free data retrieval call binding the contract method 0x70a08231.
//
// Solidity: function balanceOf(address account) view returns(uint256)
func (_Testtoken *TesttokenSession) BalanceOf(account common.Address) (*big.Int, error) {
	return _Testtoken.Contract.BalanceOf(&_Testtoken.CallOpts, account)
}

// BalanceOf is a free data retrieval call binding the contract method 0x70a08231.
//
// Solidity: function balanceOf(address account) view returns(uint256)
func (_Testtoken *TesttokenCallerSession) BalanceOf(account common.Address) (*big.Int, error) {
	return _Testtoken.Contract.BalanceOf(&_Testtoken.CallOpts, account)
}

// Decimals is a free data retrieval call binding the contract method 0x313ce567.
//
// Solidity: function decimals() view returns(uint8)
func (_Testtoken *TesttokenCaller) Decimals(opts *bind.CallOpts) (uint8, error) {
	var out []interface{}
	err := _Testtoken.contract.Call(opts, &out, "decimals")

	if err != nil {
		return *new(uint8), err
	}

	out0 := *abi.ConvertType(out[0], new(uint8)).(*uint8)

	return out0, err

}

// Decimals is a free data retrieval call binding the contract method 0x313ce567.
//
// Solidity: function decimals() view returns(uint8)
func (_Testtoken *TesttokenSession) Decimals() (uint8, error) {
	return _Testtoken.Contract.Decimals(&_Testtoken.CallOpts)
}

// Decimals is a free data retrieval call binding the contract method 0x313ce567.
//
// Solidity: function decimals() view returns(uint8)
func (_Testtoken *TesttokenCallerSession) Decimals() (uint8, error) {
	return _Testtoken.Contract.Decimals(&_Testtoken.CallOpts)
}

// Name is a free data retrieval call binding the contract method 0x06fdde03.
//
// Solidity: function name() view returns(string)
func (_Testtoken *TesttokenCaller) Name(opts *bind.CallOpts) (string, error) {
	var out []interface{}
	err := _Testtoken.contract.Call(opts, &out, "name")

	if err != nil {
		return *new(string), err
	}

	out0 := *abi.ConvertType(out[0], new(string)).(*string)

	return out0, err

}

// Name is a free data retrieval call binding the contract method 0x06fdde03.
//
// Solidity: function name() view returns(string)
func (_Testtoken *TesttokenSession) Name() (string, error) {
	return _Testtoken.Contract.Name(&_Testtoken.CallOpts)
}

// Name is a free data retrieval call binding the contract method 0x06fdde03.
//
// Solidity: function name() view returns(string)
func (_Testtoken *TesttokenCallerSession) Name() (string, error) {
	return _Testtoken.Contract.Name(&_Testtoken.CallOpts)
}

// Symbol is a free data retrieval call binding the contract method 0x95d89b41.
//
// Solidity: function symbol() view returns(string)
func (_Testtoken *TesttokenCaller) Symbol(opts *bind.CallOpts) (string, error) {
	var out []interface{}
	err := _Testtoken.contract.Call(opts, &out, "symbol")

	if err != nil {
		return *new(string), err
	}

	out0 := *abi.ConvertType(out[0], new(string)).(*string)

	return out0, err

}

// Symbol is a free data retrieval call binding the contract method 0x95d89b41.
//
// Solidity: function symbol() view returns(string)
func (_Testtoken *TesttokenSession) Symbol() (string, error) {
	return _Testtoken.Contract.Symbol(&_Testtoken.CallOpts)
}

// Symbol is a free data retrieval call binding the contract method 0x95d89b41.
//
// Solidity: function symbol() view returns(string)
func (_Testtoken *TesttokenCallerSession) Symbol() (string, error) {
	return _Testtoken.Contract.Symbol(&_Testtoken.CallOpts)
}

// TotalSupply is a free data retrieval call binding the contract method 0x18160ddd.
//
// Solidity: function totalSupply() view returns(uint256)
func (_Testtoken *TesttokenCaller) TotalSupply(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _Testtoken.contract.Call(opts, &out, "totalSupply")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// TotalSupply is a free data retrieval call binding the contract method 0x18160ddd.
//
// Solidity: function totalSupply() view returns(uint256)
func (_Testtoken *TesttokenSession) TotalSupply() (*big.Int, error) {
	return _Testtoken.Contract.TotalSupply(&_Testtoken.CallOpts)
}

// TotalSupply is a free data retrieval call binding the contract method 0x18160ddd.
//
// Solidity: function totalSupply() view returns(uint256)
func (_Testtoken *TesttokenCallerSession) TotalSupply() (*big.Int, error) {
	return _Testtoken.Contract.TotalSupply(&_Testtoken.CallOpts)
}

// Approve is a paid mutator transaction binding the contract method 0x095ea7b3.
//
// Solidity: function approve(address spender, uint256 value) returns(bool)
func (_Testtoken *TesttokenTransactor) Approve(opts *bind.TransactOpts, spender common.Address, value *big.Int) (*types.Transaction, error) {
	return _Testtoken.contract.Transact(opts, "approve", spender, value)
}

// Approve is a paid mutator transaction binding the contract method 0x095ea7b3.
//
// Solidity: function approve(address spender, uint256 value) returns(bool)
func (_Testtoken *TesttokenSession) Approve(spender common.Address, value *big.Int) (*types.Transaction, error) {
	return _Testtoken.Contract.Approve(&_Testtoken.TransactOpts, spender, value)
}

// Approve is a paid mutator transaction binding the contract method 0x095ea7b3.
//
// Solidity: function approve(address spender, uint256 value) returns(bool)
func (_Testtoken *TesttokenTransactorSession) Approve(spender common.Address, value *big.Int) (*types.Transaction, error) {
	return _Testtoken.Contract.Approve(&_Testtoken.TransactOpts, spender, value)
}

// Transfer is a paid mutator transaction binding the contract method 0xa9059cbb.
//
// Solidity: function transfer(address to, uint256 value) returns(bool)
func (_Testtoken *TesttokenTransactor) Transfer(opts *bind.TransactOpts, to common.Address, value *big.Int) (*types.Transaction, error) {
	return _Testtoken.contract.Transact(opts, "transfer", to, value)
}

// Transfer is a paid mutator transaction binding the contract method 0xa9059cbb.
//
// Solidity: function transfer(address to, uint256 value) returns(bool)
func (_Testtoken *TesttokenSession) Transfer(to common.Address, value *big.Int) (*types.Transaction, error) {
	return _Testtoken.Contract.Transfer(&_Testtoken.TransactOpts, to, value)
}

// Transfer is a paid mutator transaction binding the contract method 0xa9059cbb.
//
// Solidity: function transfer(address to, uint256 value) returns(bool)
func (_Testtoken *TesttokenTransactorSession) Transfer(to common.Address, value *big.Int) (*types.Transaction, error) {
	return _Testtoken.Contract.Transfer(&_Testtoken.TransactOpts, to, value)
}

// TransferFrom is a paid mutator transaction binding the contract method 0x23b872dd.
//
// Solidity: function transferFrom(address from, address to, uint256 value) returns(bool)
func (_Testtoken *TesttokenTransactor) TransferFrom(opts *bind.TransactOpts, from common.Address, to common.Address, value *big.Int) (*types.Transaction, error) {
	return _Testtoken.contract.Transact(opts, "transferFrom", from, to, value)
}

// TransferFrom is a paid mutator transaction binding the contract method 0x23b872dd.
//
// Solidity: function transferFrom(address from, address to, uint256 value) returns(bool)
func (_Testtoken *TesttokenSession) TransferFrom(from common.Address, to common.Address, value *big.Int) (*types.Transaction, error) {
	return _Testtoken.Contract.TransferFrom(&_Testtoken.TransactOpts, from, to, value)
}

// TransferFrom is a paid mutator transaction binding the contract method 0x23b872dd.
//
// Solidity: function transferFrom(address from, address to, uint256 value) returns(bool)
func (_Testtoken *TesttokenTransactorSession) TransferFrom(from common.Address, to common.Address, value *big.Int) (*types.Transaction, error) {
	return _Testtoken.Contract.TransferFrom(&_Testtoken.TransactOpts, from, to, value)
}

// TesttokenApprovalIterator is returned from FilterApproval and is used to iterate over the raw logs and unpacked data for Approval events raised by the Testtoken contract.
type TesttokenApprovalIterator struct {
	Event *TesttokenApproval // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *TesttokenApprovalIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(TesttokenApproval)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(TesttokenApproval)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *TesttokenApprovalIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *TesttokenApprovalIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// TesttokenApproval represents a Approval event raised by the Testtoken contract.
type TesttokenApproval struct {
	Owner   common.Address
	Spender common.Address
	Value   *big.Int
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterApproval is a free log retrieval operation binding the contract event 0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925.
//
// Solidity: event Approval(address indexed owner, address indexed spender, uint256 value)
func (_Testtoken *TesttokenFilterer) FilterApproval(opts *bind.FilterOpts, owner []common.Address, spender []common.Address) (*TesttokenApprovalIterator, error) {

	var ownerRule []interface{}
	for _, ownerItem := range owner {
		ownerRule = append(ownerRule, ownerItem)
	}
	var spenderRule []interface{}
	for _, spenderItem := range spender {
		spenderRule = append(spenderRule, spenderItem)
	}

	logs, sub, err := _Testtoken.contract.FilterLogs(opts, "Approval", ownerRule, spenderRule)
	if err != nil {
		return nil, err
	}
	return &TesttokenApprovalIterator{contract: _Testtoken.contract, event: "Approval", logs: logs, sub: sub}, nil
}

// WatchApproval is a free log subscription operation binding the contract event 0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925.
//
// Solidity: event Approval(address indexed owner, address indexed spender, uint256 value)
func (_Testtoken *TesttokenFilterer) WatchApproval(opts *bind.WatchOpts, sink chan<- *TesttokenApproval, owner []common.Address, spender []common.Address) (event.Subscription, error) {

	var ownerRule []interface{}
	for _, ownerItem := range owner {
		ownerRule = append(ownerRule, ownerItem)
	}
	var spenderRule []interface{}
	for _, spenderItem := range spender {
		spenderRule = append(spenderRule, spenderItem)
	}

	logs, sub, err := _Testtoken.contract.WatchLogs(opts, "Approval", ownerRule, spenderRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(TesttokenApproval)
				if err := _Testtoken.contract.UnpackLog(event, "Approval", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseApproval is a log parse operation binding the contract event 0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925.
//
// Solidity: event Approval(address indexed owner, address indexed spender, uint256 value)
func (_Testtoken *TesttokenFilterer) ParseApproval(log types.Log) (*TesttokenApproval, error) {
	event := new(TesttokenApproval)
	if err := _Testtoken.contract.UnpackLog(event, "Approval", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// TesttokenTransferIterator is returned from FilterTransfer and is used to iterate over the raw logs and unpacked data for Transfer events raised by the Testtoken contract.
type TesttokenTransferIterator struct {
	Event *TesttokenTransfer // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *TesttokenTransferIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(TesttokenTransfer)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(TesttokenTransfer)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *TesttokenTransferIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *TesttokenTransferIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// TesttokenTransfer represents a Transfer event raised by the Testtoken contract.
type TesttokenTransfer struct {
	From  common.Address
	To    common.Address
	Value *big.Int
	Raw   types.Log // Blockchain specific contextual infos
}

// FilterTransfer is a free log retrieval operation binding the contract event 0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef.
//
// Solidity: event Transfer(address indexed from, address indexed to, uint256 value)
func (_Testtoken *TesttokenFilterer) FilterTransfer(opts *bind.FilterOpts, from []common.Address, to []common.Address) (*TesttokenTransferIterator, error) {

	var fromRule []interface{}
	for _, fromItem := range from {
		fromRule = append(fromRule, fromItem)
	}
	var toRule []interface{}
	for _, toItem := range to {
		toRule = append(toRule, toItem)
	}

	logs, sub, err := _Testtoken.contract.FilterLogs(opts, "Transfer", fromRule, toRule)
	if err != nil {
		return nil, err
	}
	return &TesttokenTransferIterator{contract: _Testtoken.contract, event: "Transfer", logs: logs, sub: sub}, nil
}

// WatchTransfer is a free log subscription operation binding the contract event 0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef.
//
// Solidity: event Transfer(address indexed from, address indexed to, uint256 value)
func (_Testtoken *TesttokenFilterer) WatchTransfer(opts *bind.WatchOpts, sink chan<- *TesttokenTransfer, from []common.Address, to []common.Address) (event.Subscription, error) {

	var fromRule []interface{}
	for _, fromItem := range from {
		fromRule = append(fromRule, fromItem)
	}
	var toRule []interface{}
	for _, toItem := range to {
		toRule = append(toRule, toItem)
	}

	logs, sub, err := _Testtoken.contract.WatchLogs(opts, "Transfer", fromRule, toRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(TesttokenTransfer)
				if err := _Testtoken.contract.UnpackLog(event, "Transfer", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseTransfer is a log parse operation binding the contract event 0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef.
//
// Solidity: event Transfer(address indexed from, address indexed to, uint256 value)
func (_Testtoken *TesttokenFilterer) ParseTransfer(log types.Log) (*TesttokenTransfer, error) {
	event := new(TesttokenTransfer)
	if err := _Testtoken.contract.UnpackLog(event, "Transfer", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}
