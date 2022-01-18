use std::sync::Arc;

use ethers::prelude::*;
use ethers::utils::keccak256;

use clap::{arg, App};

use indicatif::{ProgressBar, ProgressStyle};

mod erc20_token;
use erc20_token::ERC20Token;

const DEFAULT_LIMIT: u64 = 100;
const DEFAULT_BLOCK_BATCH: u64 = 25;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let command = App::new("balanceOf-slot-finder")
        .version("1.0")
        .about("Find the index of the storage slot of the balanceOf mapping of an ERC20 contract providing a contract's address. You can also compute the 'balanceOf(<USER_ADDRESS>)' storage slot providing a user's address.")
        .author("icyicy")
        .arg(
            arg!(rpc: --rpc <PROVIDER_ADDRESS>)
                .required(false)
                .help("Address of your Ethereum provider. Default = 'localhost'"),
        )
        .arg(
            arg!(limit: -l --limit <COUNT>)
                .required(false)
                .help("Max number of variables to check in the contract. Default = 50"),
        )
        .arg(
            arg!(batch: -b --batch <N_BLOCKS>)
                .required(false)
                .help("Search 'Transfer' Event Log in order to indentify a token holder in N_BLOCKS at once. Default = 25"),
        )
        .arg(arg!(slot: -s --slot <STORAGE_SLOT>).required(false).help("Storage slot which will be used to compute storage slot of 'balanceOf(<USER_ADDRESS>)'"))
        .arg(arg!(is_vyper: --vyper).required(false).help("Compute storage slot of <USER_ADDRESS> for a Vyper contract. Default = Solidity"))
        .arg(arg!(<TOKEN_ADDRESS>).required(false))
        .arg(arg!(<USER_ADDRESS>).required(false))
        .arg(arg!(holder: --holder <HOLDER_ADDRESS>).required(false).help("Address of a token holder. The program will match balances without searching for a token holder"))
        .get_matches();

    let mut rpc_addr = match command.value_of("rpc") {
        Some(addr) => String::from(addr),
        None => String::from("127.0.0.1"),
    };

    let limit = match command.value_of("limit") {
        Some(limit) => limit.parse::<u64>().unwrap(),
        None => DEFAULT_LIMIT,
    };

    let is_vyper = command.is_present("is_vyper");

    if !command.is_present("rpc") {
        rpc_addr = format!("http://{}:8545", rpc_addr);
    }
    let provider = Arc::new(Provider::try_from(rpc_addr)?);

    if let Some(slot) = command.value_of("slot") {
        let slot = U256::from_str_radix(slot, 10).expect("Slot is incorrect");
        let user_addr = command
            .value_of("TOKEN_ADDRESS")
            .expect("You need to provide a user address")
            .parse::<Address>()
            .expect("Address is not valid");

        let slot = get_storage_slot_for_addr(user_addr, slot, is_vyper);
        println!("Storage slot for 'balanceOf({:?})' = {}", user_addr, slot);
    } else {
        let token_addr = command
            .value_of("TOKEN_ADDRESS")
            .expect("You need to provide a token address")
            .parse::<Address>()
            .expect("Address is not valid");
        let token = ERC20Token::new(token_addr, Arc::clone(&provider));
        let token_symbol = match token.symbol().call().await {
            Ok(symbol) => symbol,
            Err(_) => String::from("UnknownToken"),
        };
        let (holder_addr, holder_balance) = match command.value_of("holder") {
            Some(holder_addr) => { 
                let holder_addr: Address = holder_addr.parse().expect("Address is not valid");
                (holder_addr, token.balance_of(holder_addr).call().await?)
            },
            None => find_token_holder(Arc::clone(&provider), &token).await?
        };
        println!("{:?} holds {} {}", holder_addr, holder_balance, token_symbol);
        if let Some((slot, is_vyper)) = find_storage_slot(Arc::clone(&provider), limit, token_addr, holder_addr, holder_balance).await? {
            if is_vyper {
                println!("Storage slot of 'balanceOf' Vyper mapping found: {}", slot);
            } else {
                println!("Storage slot of 'balanceOf' Solidity mapping found: {}", slot);
            }

            if let Some(user_addr) = command.value_of("USER_ADDRESS") {
                let user_addr = user_addr.parse::<Address>().expect("Address is not valid");
                println!("Calculating storage slot for balanceOf({:?})...", user_addr);
                let slot = get_storage_slot_for_addr(user_addr, slot, is_vyper);
                println!("Storage slot for 'balanceOf({:?})' = {}", user_addr, slot);
            }
        } else {
            println!("Storage slot not found. Try to increase 'limit'");
        }
    }
    
    Ok(())
}

async fn find_token_holder<M: Middleware + 'static>(provider: Arc<M>, token: &ERC20Token<M>) -> anyhow::Result<(Address, U256)> {
    let pb = ProgressBar::new_spinner();
    pb.enable_steady_tick(100);
    pb.set_message("Searching token holder...");

    let mut upper_block = provider.get_block_number().await?;
    let topic0: [u8; 32] = hex::decode("ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef")
        .unwrap()
        .try_into()
        .unwrap();
    loop {
        let filter = Filter::new().select(upper_block - DEFAULT_BLOCK_BATCH..upper_block).topic0(H256::from(topic0));
        let logs = provider.get_logs(&filter).await?;
        if !logs.is_empty() {
            for log in logs.iter() {
                let holder_addr = Address::from(log.topics[2]);
                let holder_balance = token.balance_of(holder_addr).call().await?;
                if holder_balance > U256::zero() {
                    return Ok((holder_addr, holder_balance));
                }
            }
        }
        upper_block = upper_block - DEFAULT_BLOCK_BATCH;
    }
}

fn get_storage_slot_for_addr(addr: Address, slot: U256, is_vyper: bool) -> U256 {
    let mut bytes_addr = [0; 32];
    let mut bytes_slot = [0; 32];
    U256::from(addr.as_ref()).to_big_endian(&mut bytes_addr);
    slot.to_big_endian(&mut bytes_slot);
    let slot = if is_vyper {
        U256::from_big_endian(&keccak256([bytes_addr, bytes_slot].concat()))
    } else {
        U256::from_big_endian(&keccak256([bytes_slot, bytes_addr].concat()))
    };
    return slot
    //println!("balanceOf({:?}) storage slot is: {:?}", addr, slot);
} 

async fn find_storage_slot<M: Middleware + 'static>(
    provider: Arc<M>, 
    limit: u64, 
    token_addr: Address, 
    holder_addr: Address, 
    holder_balance: U256
) -> anyhow::Result<Option<(U256, bool)>> {
    let pb = ProgressBar::new(limit as u64);
    pb.set_style(ProgressStyle::default_bar().template("{spinner:.green} {msg}"));
    pb.set_message(format!("Searching for storage slot of 'balanceOf' mapping..."));

    let mut bytes_i = [0; 32];
    let mut bytes_addr = [0; 32];
    U256::from(holder_addr.as_ref()).to_big_endian(&mut bytes_addr);
    for i in 0..limit {
        U256::from(i).to_big_endian(&mut bytes_i);
        let key_solidity = H256::from(keccak256([bytes_addr, bytes_i].concat()));
        let key_vyper = H256::from(keccak256([bytes_i, bytes_addr].concat()));

        let slot_solidity = provider.get_storage_at(token_addr, key_solidity, None).await?;
        if U256::from_big_endian(slot_solidity.as_bytes()) == holder_balance {
            pb.finish();
            return Ok(Some((U256::from(i), false)));
        }

        let slot_vyper = provider.get_storage_at(token_addr, key_vyper, None).await?;

        if U256::from_big_endian(slot_vyper.as_bytes()) == holder_balance {
            pb.finish();  
            return Ok(Some((U256::from(i), true)));
        }
        pb.inc(1);
    }
    
    Ok(None)
}
