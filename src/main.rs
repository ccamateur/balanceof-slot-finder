use std::sync::Arc;

use ethers::prelude::*;
use ethers::utils::keccak256;

use clap::{arg, App};

use indicatif::{ProgressBar, ProgressStyle};

mod erc20_token;
use erc20_token::ERC20Token;

const DEFAULT_LIMIT: u64 = 100;
//const BENTOBOX_ADDRESS: Address = H160([245, 188, 229, 7, 121, 8, 161, 183, 55, 11, 154, 224, 74, 220, 86, 94, 189, 100, 57, 102]);
//const DEGENBOX_ADDRESS: Address = H160([217, 111, 72, 102, 90, 20, 16, 192, 205, 102, 154, 136, 137, 142, 202, 54, 185, 252, 44, 206]);
const BENTOBOX_BALANCEOF_MAPPING_SLOT: u64 = 6;

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
        .arg(arg!(bentobox: --bentobox).required(false).help("Compute balanceOf[<TOKEN_ADDRESS>][<USER_ADDRESS>] storage slot for the BentoBox smart contract. Also works for DegenBox"))
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

    if command.is_present("bentobox") || command.is_present("degenbox") {
        let token_addr = command
            .value_of("TOKEN_ADDRESS")
            .expect("You need to provide a token address")
            .parse::<Address>()
            .expect("Token address is not valid");

        let user_addr = command
            .value_of("USER_ADDRESS")
            .expect("You need to provide a token address")
            .parse::<Address>()
            .expect("User address is not valid");

        let slot = get_storage_slot_for_addr_bentobox(token_addr, user_addr, H256::from_low_u64_be(BENTOBOX_BALANCEOF_MAPPING_SLOT));
        println!("Storage slot for 'balanceOf[{}][{}]' = {:?}", token_addr, user_addr, slot);
    } else if let Some(slot) = command.value_of("slot") {
        let slot = H256::from_low_u64_be(slot.parse::<u64>().expect("Slot is incorrect"));
        let user_addr = command
            .value_of("TOKEN_ADDRESS")
            .expect("You need to provide a user address")
            .parse::<Address>()
            .expect("Address is not valid");

        let slot = get_storage_slot_for_addr(user_addr, slot, is_vyper);
        println!("Storage slot for 'balanceOf[{:?}]' = {}", user_addr, slot);
    } else {
        let token_addr_str = command.value_of("TOKEN_ADDRESS").expect("You need to provide a token address");
        let token_addr = token_addr_str.parse::<Address>().expect("Address is not valid");
        let token = ERC20Token::new(token_addr, Arc::clone(&provider));
        let token_symbol = match token.symbol().call().await {
            Ok(symbol) => symbol,
            Err(_) => String::from("UnknownToken"),
        };
        let (holder_addr, holder_balance) = match command.value_of("holder") {
            Some(holder_addr) => {
                let holder_addr: Address = holder_addr.parse().expect("Address is not valid");
                (holder_addr, token.balance_of(holder_addr).call().await?)
            }
            None => find_token_holder_and_balance(token, token_addr_str).await,
        };
        println!("{:?} holds {} {}", holder_addr, holder_balance, token_symbol);
        if let Some((slot, is_vyper)) = find_mapping_storage_slot(Arc::clone(&provider), limit, token_addr, holder_addr, holder_balance).await {
            if is_vyper {
                println!("Storage slot of 'balanceOf' Vyper mapping found: {}", slot);
            } else {
                println!("Storage slot of 'balanceOf' Solidity mapping found: {}", slot);
            }

            if let Some(user_addr) = command.value_of("USER_ADDRESS") {
                let user_addr = user_addr.parse::<Address>().expect("Address is not valid");
                println!("Calculating storage slot for balanceOf({:?})...", user_addr);
                let slot = get_storage_slot_for_addr(user_addr, slot, is_vyper);
                println!("Storage slot for 'balanceOf[{}]' = {:?}", user_addr, slot);
            }
        } else {
            println!("Storage slot not found. Try to increase 'limit'");
        }
    }

    Ok(())
}

async fn find_token_holder_and_balance<M: Middleware>(token: ERC20Token<M>, token_addr: &str) -> (Address, U256) {
    let url = format!("https://etherscan.io/token/generic-tokenholders2?m=normal&a={}&p=1", token_addr);
    let response = reqwest::get(url).await.unwrap().text().await.unwrap();
    let document = scraper::Html::parse_document(response.as_str());
    let selector = scraper::Selector::parse("td > span").unwrap();
    let holder_addr = document
        .select(&selector)
        .flat_map(|x| x.text().collect::<Vec<_>>())
        .find_map(|x| x.parse::<Address>().ok())
        .unwrap();
    let holder_balance = token.balance_of(holder_addr).call().await.unwrap();
    return (holder_addr, holder_balance);
}

fn get_storage_slot_for_addr(addr: Address, mapping_slot: H256, is_vyper: bool) -> H256 {
    let mut bytes_addr = [0; 32];
    U256::from(addr.as_ref()).to_big_endian(&mut bytes_addr);
    if is_vyper {
        return H256::from(&keccak256([bytes_addr, mapping_slot.0].concat()));
    } else {
        return H256::from(&keccak256([mapping_slot.0, bytes_addr].concat()));
    }
}

fn get_storage_slot_for_addr_bentobox(token_addr: Address, user_addr: Address, mapping_slot: H256) -> H256 {
    let mut bytes_token_addr = [0; 32];
    let mut bytes_user_addr = [0; 32];
    U256::from(token_addr.as_ref()).to_big_endian(&mut bytes_token_addr);
    U256::from(user_addr.as_ref()).to_big_endian(&mut bytes_user_addr);
    return H256::from(keccak256([bytes_user_addr, keccak256([bytes_token_addr, mapping_slot.0].concat())].concat()));
}

/* async fn find_mapping_storage_slot_bentobox<M: Middleware + 'static>(
    bentobox: BentoBox<M>,
    limit: u64,
    token_addr: Address,
    holder_addr: Address,
    holder_balance: U256,
) -> Option<H256> {
    for i in 0..limit {
        let key_solidity = get_storage_slot_for_addr_bentobox(token_addr, holder_addr, H256::from_low_u64_be(i));
        let slot_value = bentobox.client().get_storage_at(bentobox.address(), key_solidity, None).await.unwrap();
        if U256::from_big_endian(slot_value.as_ref()) == holder_balance {
            return Some(H256::from_low_u64_be(i))
        }
    }
    return None
} */

async fn find_mapping_storage_slot<M: Middleware + 'static>(
    provider: Arc<M>,
    limit: u64,
    token_addr: Address,
    holder_addr: Address,
    holder_balance: U256,
) -> Option<(H256, bool)> {
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

        let slot_solidity = provider.get_storage_at(token_addr, key_solidity, None).await.unwrap();
        if U256::from_big_endian(slot_solidity.as_bytes()) == holder_balance {
            pb.finish();
            return Some((H256::from_low_u64_be(i), false));
        }

        let slot_vyper = provider.get_storage_at(token_addr, key_vyper, None).await.unwrap();
        if U256::from_big_endian(slot_vyper.as_bytes()) == holder_balance {
            pb.finish();
            return Some((H256::from_low_u64_be(i), true));
        }
        pb.inc(1);
    }

    return None;
}
