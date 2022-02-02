#![allow(clippy::not_unsafe_ptr_arg_deref)]
extern crate libc;
use arrayref::array_refs;
use digest::Digest;
use gateway::{
    instruction::{burn, initialize, mint},
    state::{Gateway, GATEWAY_STATE_CURRENT_SEED},
};
use renvm_sig::{RenVm, RenVmMsgBuilder};
use solana_client::{rpc_client::RpcClient, rpc_config::RpcSendTransactionConfig};
use solana_sdk::{
    commitment_config::CommitmentConfig,
    program_pack::Pack,
    pubkey::Pubkey,
    signature::{read_keypair_file, Signer},
    transaction::Transaction,
};
use spl_associated_token_account::{create_associated_token_account, get_associated_token_address};
use spl_math::uint::U256;
use spl_token::instruction::burn_checked;
use std::{
    ffi::{CStr, CString},
    process::exit,
    str::FromStr,
};

mod util;

const DEFAULT_DECIMALS: u8 = 8u8;

fn selector_to_program_id(selector: &str) -> Pubkey {
    match selector {
        "BTC/toSolana" => gateway::program_ids::bitcoin(),
        "BCH/toSolana" => gateway::program_ids::bitcoincash(),
        "DGB/toSolana" => gateway::program_ids::digibyte(),
        "DOGE/toSolana" => gateway::program_ids::dogecoin(),
        "FIL/toSolana" => gateway::program_ids::filecoin(),
        "LUNA/toSolana" => gateway::program_ids::terra(),
        "ZEC/toSolana" => gateway::program_ids::zcash(),
        "DAI/toSolana" => gateway::program_ids::dai(),
        _ => {
            eprintln!("unsupported selector: {}", selector);
            exit(1);
        }
    }
}

#[no_mangle]
pub extern "C" fn unique_pubkey() -> *const libc::c_char {
    let pubkey = Pubkey::new_unique();
    let pubkey = pubkey.to_string();
    CString::new(pubkey).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn program_derived_address(
    seeds_pointer: *const u8,
    seeds_size: libc::size_t,
    program: *const libc::c_char,
) -> *const libc::c_char {
    let seeds =
        unsafe { std::slice::from_raw_parts(seeds_pointer as *const u8, seeds_size as usize) };

    let buf_name = unsafe { CStr::from_ptr(program).to_bytes() };
    let program_str = String::from_utf8(buf_name.to_vec()).unwrap();
    let program_id = Pubkey::from_str(&program_str).unwrap();

    let (derived_address, _) = Pubkey::find_program_address(&[seeds], &program_id);

    CString::new(derived_address.to_string())
        .unwrap()
        .into_raw()
}

#[no_mangle]
pub extern "C" fn address(keypair_path: *const libc::c_char) -> *const libc::c_char {
    // Get the wallet address.
    let buf_name = unsafe { CStr::from_ptr(keypair_path).to_bytes() };
    let keypair_path = String::from_utf8(buf_name.to_vec()).unwrap();
    let wallet = read_keypair_file(&keypair_path).unwrap();

    CString::new(wallet.pubkey().to_string())
        .unwrap()
        .into_raw()
}

#[no_mangle]
pub extern "C" fn associated_token_account(
    wallet_address: *const libc::c_char,
    selector: *const libc::c_char,
) -> *const libc::c_char {
    let buf_name = unsafe { CStr::from_ptr(wallet_address).to_bytes() };
    let account_str = String::from_utf8(buf_name.to_vec()).unwrap();
    let account = Pubkey::from_str(&account_str).unwrap();

    // Get selector hash.
    let buf_name = unsafe { CStr::from_ptr(selector).to_bytes() };
    let selector = String::from_utf8(buf_name.to_vec()).unwrap();
    let mut hasher = sha3::Keccak256::new();
    hasher.update(selector.as_bytes());
    let selector_hash: [u8; 32] = hasher.finalize().into();

    // Derived address that will be the token mint.
    let (token_mint_id, _) =
        Pubkey::find_program_address(&[&selector_hash[..]], &gateway::program_ids::bitcoin());

    // Derive the associated token account.
    let recipient = get_associated_token_address(&account, &token_mint_id);

    CString::new(recipient.to_string()).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn gateway_initialize(
    keypair_path: *const libc::c_char,
    rpc_url: *const libc::c_char,
    authority_pointer: *const u8,
    selector: *const libc::c_char,
) -> *const libc::c_char {
    // Solana default signer and fee payer.
    let buf_name = unsafe { CStr::from_ptr(keypair_path).to_bytes() };
    let keypair_path = String::from_utf8(buf_name.to_vec()).unwrap();
    let payer = read_keypair_file(&keypair_path).unwrap();

    // Initialize client.
    let buf_name = unsafe { CStr::from_ptr(rpc_url).to_bytes() };
    let rpc_url = String::from_utf8(buf_name.to_vec()).unwrap();
    let rpc_client = RpcClient::new(rpc_url);
    let commitment_config = CommitmentConfig::confirmed();
    let (recent_blockhash, _, _) = rpc_client
        .get_recent_blockhash_with_commitment(commitment_config)
        .unwrap()
        .value;

    // Construct the RenVm authority 20-bytes Ethereum compatible address.
    let authority_slice =
        unsafe { std::slice::from_raw_parts(authority_pointer as *const u8, 20usize) };
    let mut authority = [0u8; 20usize];
    authority.copy_from_slice(authority_slice);

    // Get selector hash.
    let buf_name = unsafe { CStr::from_ptr(selector).to_bytes() };
    let selector = String::from_utf8(buf_name.to_vec()).unwrap();
    let mut hasher = sha3::Keccak256::new();
    hasher.update(selector.as_bytes());
    let selector_hash: [u8; 32] = hasher.finalize().into();

    let program_id = selector_to_program_id(&selector);

    // Find derived address that will hold Gateway's state.
    let (gateway_account_id, _) =
        Pubkey::find_program_address(&[GATEWAY_STATE_CURRENT_SEED.as_bytes()], &program_id);

    // Derived address that will be the token mint.
    let (token_mint_id, _) = Pubkey::find_program_address(&[&selector_hash[..]], &program_id);

    // Build and sign the initialize transaction.
    let mut tx = Transaction::new_with_payer(
        &[initialize(
            &program_id,
            &payer.pubkey(),
            &gateway_account_id,
            authority,
            &token_mint_id,
            &spl_token::id(),
            selector_hash,
            DEFAULT_DECIMALS,
            DEFAULT_DECIMALS,
        )
        .unwrap()],
        Some(&payer.pubkey()),
    );
    tx.sign(&[&payer], recent_blockhash);

    // Broadcast transaction.
    let signature = rpc_client
        .send_transaction_with_config(
            &tx,
            RpcSendTransactionConfig {
                preflight_commitment: Some(commitment_config.commitment),
                ..RpcSendTransactionConfig::default()
            },
        )
        .unwrap();

    CString::new(signature.to_string()).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn gateway_initialize_account(
    keypair_path: *const libc::c_char,
    rpc_url: *const libc::c_char,
    selector: *const libc::c_char,
) -> *const libc::c_char {
    // Solana default signer and fee payer.
    let buf_name = unsafe { CStr::from_ptr(keypair_path).to_bytes() };
    let keypair_path = String::from_utf8(buf_name.to_vec()).unwrap();
    let payer = read_keypair_file(&keypair_path).unwrap();

    // Initialize client.
    let buf_name = unsafe { CStr::from_ptr(rpc_url).to_bytes() };
    let rpc_url = String::from_utf8(buf_name.to_vec()).unwrap();
    let rpc_client = RpcClient::new(rpc_url);
    let commitment_config = CommitmentConfig::confirmed();
    let (recent_blockhash, _, _) = rpc_client
        .get_recent_blockhash_with_commitment(commitment_config)
        .unwrap()
        .value;

    // Get selector hash.
    let buf_name = unsafe { CStr::from_ptr(selector).to_bytes() };
    let selector = String::from_utf8(buf_name.to_vec()).unwrap();
    let mut hasher = sha3::Keccak256::new();
    hasher.update(selector.as_bytes());
    let selector_hash: [u8; 32] = hasher.finalize().into();

    let program_id = selector_to_program_id(&selector);

    // Derived address that will be the token mint.
    let (token_mint_id, _) = Pubkey::find_program_address(&[&selector_hash[..]], &program_id);

    // Build and sign transaction.
    let mut tx = Transaction::new_with_payer(
        &[create_associated_token_account(
            &payer.pubkey(),
            &payer.pubkey(),
            &token_mint_id,
        )],
        Some(&payer.pubkey()),
    );
    tx.sign(&[&payer], recent_blockhash);

    // Broadcast transaction.
    let signature = rpc_client
        .send_transaction_with_config(
            &tx,
            RpcSendTransactionConfig {
                preflight_commitment: Some(commitment_config.commitment),
                ..RpcSendTransactionConfig::default()
            },
        )
        .unwrap();

    CString::new(signature.to_string()).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn gateway_get_burn_count(
    rpc_url: *const libc::c_char,
    selector: *const libc::c_char,
) -> libc::c_ulonglong {
    // Initialize client.
    let buf_name = unsafe { CStr::from_ptr(rpc_url).to_bytes() };
    let rpc_url = String::from_utf8(buf_name.to_vec()).unwrap();
    let rpc_client = RpcClient::new(rpc_url);

    let buf_name = unsafe { CStr::from_ptr(selector).to_bytes() };
    let selector = String::from_utf8(buf_name.to_vec()).unwrap();
    let program_id = selector_to_program_id(&selector);

    // Fetch account data.
    let (gateway_account_id, _) =
        Pubkey::find_program_address(&[GATEWAY_STATE_CURRENT_SEED.as_bytes()], &program_id);
    let gateway_account_data = rpc_client.get_account_data(&gateway_account_id).unwrap();
    let gateway_state = Gateway::unpack_unchecked(&gateway_account_data).unwrap();

    gateway_state.burn_count + 1
}

#[no_mangle]
pub extern "C" fn gateway_mint(
    keypair_path: *const libc::c_char,
    rpc_url: *const libc::c_char,
    authority_secret: *const libc::c_char,
    selector: *const libc::c_char,
    amount: libc::c_ulonglong,
    nhash_pointer: *const u8,
    phash_pointer: *const u8,
) -> *const libc::c_char {
    // Solana default signer and fee payer.
    let buf_name = unsafe { CStr::from_ptr(keypair_path).to_bytes() };
    let keypair_path = String::from_utf8(buf_name.to_vec()).unwrap();
    let payer = read_keypair_file(&keypair_path).unwrap();

    // RenVm authority secret.
    let buf_name = unsafe { CStr::from_ptr(authority_secret).to_bytes() };
    let authority_secret = String::from_utf8(buf_name.to_vec()).unwrap();
    let renvm = RenVm::from_str(&authority_secret).unwrap();
    let renvm_authority = renvm.address();

    // Initialize client.
    let buf_name = unsafe { CStr::from_ptr(rpc_url).to_bytes() };
    let rpc_url = String::from_utf8(buf_name.to_vec()).unwrap();
    let rpc_client = RpcClient::new(rpc_url);
    let commitment_config = CommitmentConfig::confirmed();
    let (recent_blockhash, _, _) = rpc_client
        .get_recent_blockhash_with_commitment(commitment_config)
        .unwrap()
        .value;

    // Get selector hash.
    let buf_name = unsafe { CStr::from_ptr(selector).to_bytes() };
    let selector = String::from_utf8(buf_name.to_vec()).unwrap();
    let mut hasher = sha3::Keccak256::new();
    hasher.update(selector.as_bytes());
    let selector_hash: [u8; 32] = hasher.finalize().into();

    let program_id = selector_to_program_id(&selector);

    // Derived address that will be the token mint.
    let (gateway_account_id, _) =
        Pubkey::find_program_address(&[GATEWAY_STATE_CURRENT_SEED.as_bytes()], &program_id);
    let (token_mint_id, _) = Pubkey::find_program_address(&[&selector_hash[..]], &program_id);
    let (mint_authority_id, _) =
        Pubkey::find_program_address(&[&token_mint_id.to_bytes()], &program_id);
    let associated_token_account = get_associated_token_address(&payer.pubkey(), &token_mint_id);

    // Construct RenVm mint message and sign it.
    let phash_slice = unsafe { std::slice::from_raw_parts(phash_pointer as *const u8, 32) };
    let nhash_slice = unsafe { std::slice::from_raw_parts(nhash_pointer as *const u8, 32) };
    let mut phash = [0u8; 32usize];
    let mut nhash = [0u8; 32usize];
    phash[..32].clone_from_slice(phash_slice);
    nhash[..32].clone_from_slice(nhash_slice);

    let u256_amount = U256::from(amount);
    let mut amount_bytes = [0u8; 32];
    u256_amount.to_big_endian(&mut amount_bytes);
    let renvm_mint_msg = RenVmMsgBuilder::default()
        .amount(amount_bytes)
        .to(associated_token_account.to_bytes())
        .s_hash(selector_hash)
        .p_hash(phash)
        .n_hash(nhash)
        .build()
        .unwrap();
    let msg_hash = renvm_mint_msg.get_digest().unwrap();
    let renvm_sig = renvm.sign(&renvm_mint_msg).unwrap();
    let (sig_r, sig_s, sig_v) = array_refs![&renvm_sig, 32, 32, 1];
    let (mint_log_account_id, _) = Pubkey::find_program_address(&[&msg_hash[..]], &program_id);
    let mut tx = Transaction::new_with_payer(
        &[
            mint(
                &program_id,
                &payer.pubkey(),
                &gateway_account_id,
                &token_mint_id,
                &associated_token_account,
                &mint_log_account_id,
                &mint_authority_id,
                &spl_token::id(),
            )
            .unwrap(),
            util::mint_secp_instruction(
                sig_r,
                sig_s,
                u8::from_le_bytes(*sig_v),
                &util::encode_msg(
                    &renvm_mint_msg.amount,
                    &renvm_mint_msg.s_hash,
                    &renvm_mint_msg.to,
                    &renvm_mint_msg.p_hash,
                    &renvm_mint_msg.n_hash,
                ),
                renvm_authority[..].to_vec(),
            ),
        ],
        Some(&payer.pubkey()),
    );
    tx.sign(&[&payer], recent_blockhash);

    // Broadcast transaction.
    let signature = rpc_client
        .send_transaction_with_config(
            &tx,
            RpcSendTransactionConfig {
                preflight_commitment: Some(commitment_config.commitment),
                ..RpcSendTransactionConfig::default()
            },
        )
        .unwrap();

    CString::new(signature.to_string()).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn gateway_burn(
    keypair_path: *const libc::c_char,
    rpc_url: *const libc::c_char,
    selector: *const libc::c_char,
    burn_count: libc::c_ulonglong,
    burn_amount: libc::c_ulonglong,
    recipient_len: libc::size_t,
    recipient_pointer: *const u8,
) -> *const libc::c_char {
    // Solana default signer and fee payer.
    let buf_name = unsafe { CStr::from_ptr(keypair_path).to_bytes() };
    let keypair_path = String::from_utf8(buf_name.to_vec()).unwrap();
    let payer = read_keypair_file(&keypair_path).unwrap();

    // Initialize client.
    let buf_name = unsafe { CStr::from_ptr(rpc_url).to_bytes() };
    let rpc_url = String::from_utf8(buf_name.to_vec()).unwrap();
    let rpc_client = RpcClient::new(rpc_url);
    let commitment_config = CommitmentConfig::confirmed();
    let (recent_blockhash, _, _) = rpc_client
        .get_recent_blockhash_with_commitment(commitment_config)
        .unwrap()
        .value;

    // Get selector hash.
    let buf_name = unsafe { CStr::from_ptr(selector).to_bytes() };
    let selector = String::from_utf8(buf_name.to_vec()).unwrap();
    let mut hasher = sha3::Keccak256::new();
    hasher.update(selector.as_bytes());
    let selector_hash: [u8; 32] = hasher.finalize().into();

    let program_id = selector_to_program_id(&selector);

    // Derived address that will be the token mint.
    let (gateway_account_id, _) =
        Pubkey::find_program_address(&[GATEWAY_STATE_CURRENT_SEED.as_bytes()], &program_id);
    let (token_mint_id, _) = Pubkey::find_program_address(&[&selector_hash[..]], &program_id);
    let associated_token_account = get_associated_token_address(&payer.pubkey(), &token_mint_id);

    // Construct the 25-bytes address of release recipient of the underlying assets.
    let recipient_slice = unsafe {
        std::slice::from_raw_parts(recipient_pointer as *const u8, recipient_len as usize)
    };

    let (burn_log_account_id, _) =
        Pubkey::find_program_address(&[&burn_count.to_le_bytes()[..]], &program_id);
    let mut tx = Transaction::new_with_payer(
        &[
            burn_checked(
                &spl_token::id(),
                &associated_token_account,
                &token_mint_id,
                &payer.pubkey(),
                &[],
                burn_amount,
                DEFAULT_DECIMALS,
            )
            .unwrap(),
            burn(
                &program_id,
                &payer.pubkey(),
                &associated_token_account,
                &gateway_account_id,
                &token_mint_id,
                &burn_log_account_id,
                recipient_slice.to_vec(),
            )
            .unwrap(),
        ],
        Some(&payer.pubkey()),
    );
    tx.sign(&[&payer], recent_blockhash);

    // Broadcast transaction.
    let signature = rpc_client
        .send_transaction_with_config(
            &tx,
            RpcSendTransactionConfig {
                preflight_commitment: Some(commitment_config.commitment),
                ..RpcSendTransactionConfig::default()
            },
        )
        .unwrap();

    CString::new(signature.to_string()).unwrap().into_raw()
}
