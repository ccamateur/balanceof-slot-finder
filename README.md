# balanceof-slot-finder

Small CLI tool to find the storage slot of the *'mapping (address => uint256) balanceOf'* variable  in a Solidity or Vyper smart contract. It can also compute the storage slot of *'balanceOf[<USER_ADDRESS>]'* providing a user address.

By default, RPC address is *http://localhost:8545*. <br>
Add your provider address with **--rpc**. 

The option **--bentobox** will calculate *'balanceOf[<TOKEN_ADDRESS>][<USER_ADDRESS>]'* for the BentoBox/DegenBox smart contract. 

Check for **--help** to see the full list of options. 

## Usage

```bash
# command 1)
#compute storage slot of balanceOf(0xdBdb4d16EdA451D0503b854CF79D55697F90c8DF). add --vyper if the contract is written in Vyper
#if balanceOf mapping variable is the slot 1 of the contract's storage
./balanceof-slot-finder --slot 1 0xdBdb4d16EdA451D0503b854CF79D55697F90c8DF

Storage slot for 'balanceOf(0xdbdb4d16eda451d0503b854cf79d55697f90c8df)' = 69554892544234123856217080638365649477632321735092257560885072347495956232176

#command 2)
#find the storage slot of the balanceOf mapping variable for the provided ERC20 contract. 
./balanceof-slot-finder --rpc https://eth-mainnet.alchemyapi.io/v2/<YOUR_KEY> 0xdBdb4d16EdA451D0503b854CF79D55697F90c8DF

0x00000000003b3cc22af3ae1eac0440bcee416b40 holds 16895417474608 ALCX # used to check if balance matches the storage slot value
  Searching for storage slot of 'balanceOf' mapping...
Storage slot of 'balanceOf' Solidity mapping found: 1

#command 3)
#providing two addresses will combine the two commands
./balanceof-slot-finder --rpc https://eth-mainnet.alchemyapi.io/v2/<YOUR_KEY> 0xdBdb4d16EdA451D0503b854CF79D55697F90c8DF 0x5a6A4D54456819380173272A5E8E9B9904BdF41B

0x56178a0d5f301baf6cf3e1cd53d9863437345bf9 holds 534149802135289119695 ALCX
  Searching for storage slot of 'balanceOf' mapping...
Storage slot of 'balanceOf' Solidity mapping found: 1
Calculating storage slot for balanceOf(0x5a6a4d54456819380173272a5e8e9b9904bdf41b)...
Storage slot for 'balanceOf(0x5a6a4d54456819380173272a5e8e9b9904bdf41b)' = 88268460590141927826542455104539624133371602486187028985383460166909506813562
