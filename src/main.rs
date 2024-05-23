use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::anyhow;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use bdk::bitcoin::Network;
use bdk::blockchain::{AnyBlockchain, Blockchain, ElectrumBlockchain};
use bdk::database::SqliteDatabase;
use bdk::electrum_client::Client;
use bdk::keys::bip39::Mnemonic;
use bdk::keys::{DerivableKey, ExtendedKey};
use bdk::template::Bip84;
use bdk::wallet::AddressIndex::{New, Peek};
use bdk::{miniscript, FeeRate, KeychainKind, SignOptions, SyncOptions, Wallet};
use serde_json::json;
use tokio::net::TcpListener;
use tokio::sync::Mutex;

struct AppError(anyhow::Error);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Something went wrong: {}", self.0),
        )
            .into_response()
    }
}

impl From<bdk::Error> for AppError {
    fn from(error: bdk::Error) -> Self {
        AppError(anyhow::Error::new(error))
    }
}

impl From<rusqlite::Error> for AppError {
    fn from(error: rusqlite::Error) -> Self {
        AppError(anyhow::Error::new(error))
    }
}

struct AppState {
    wallet: Wallet<SqliteDatabase>,
    blockchain: AnyBlockchain,
}

type SharedAppState = Arc<Mutex<AppState>>;

fn main() -> anyhow::Result<()> {
    dotenv::from_filename(".env")?;
    dotenv::dotenv()?;

    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async {
        let (wallet, blockchain) = setup_bitcoin()?;

        let app_state = AppState { wallet, blockchain };

        setup_axum(app_state).await?;

        Ok::<(), anyhow::Error>(())
    })?;

    Ok(())
}

fn setup_bitcoin() -> anyhow::Result<(Wallet<SqliteDatabase>, AnyBlockchain)> {
    let network = Network::Testnet;
    let client = Client::new("ssl://electrum.blockstream.info:60002")?;
    let blockchain = ElectrumBlockchain::from(client);

    // let mnemonic: GeneratedKey<_, miniscript::Segwitv0> =
    //     Mnemonic::generate((WordCount::Words12, Language::English))?;
    // dbg!(mnemonic.to_string());

    let mnemonic_words = std::env::var("MNEMONIC_WORDS")?;
    let mnemonic = Mnemonic::parse(mnemonic_words)?;

    let xkey: ExtendedKey<miniscript::Segwitv0> = mnemonic.into_extended_key()?;
    let xprv = xkey
        .into_xprv(network)
        .ok_or(anyhow!("Failed to derive xprv."))?;

    let wallet = Wallet::new(
        Bip84(xprv, KeychainKind::External),
        Some(Bip84(xprv, KeychainKind::Internal)),
        network,
        SqliteDatabase::new("wallet.db"),
    )?;

    // let address = wallet.get_address(Peek(0))?;
    // dbg!(address.to_string());

    // let descriptor = wallet.get_descriptor_for_keychain(KeychainKind::External);
    // dbg!(&descriptor.to_string());

    wallet.sync(&blockchain, SyncOptions::default())?;
    // dbg!(wallet.get_balance()?);

    Ok((wallet, blockchain.into()))
}

async fn setup_axum(app_state: AppState) -> anyhow::Result<()> {
    let api_app = axum::Router::new()
        .route("/hi", axum::routing::get(hello_handler))
        .route("/new_address", axum::routing::get(new_address_handler))
        .route("/transactions", axum::routing::get(transactions_handler))
        .route("/balance", axum::routing::get(balance_handler))
        .route("/send", axum::routing::get(send_handler))
        .route("/sync", axum::routing::get(sync_handler))
        .route("/test_db", axum::routing::get(test_db_handler))
        .with_state(Arc::new(Mutex::new(app_state)));

    let api_addr = SocketAddr::from(([127, 0, 0, 1], 3001));
    let api_listener = TcpListener::bind(api_addr).await?;

    let _r = axum::serve(api_listener, api_app).await;

    Ok(())
}

async fn hello_handler() -> &'static str {
    "hello!"
}

#[axum::debug_handler]
async fn new_address_handler(
    State(state): State<SharedAppState>,
) -> Result<impl IntoResponse, AppError> {
    let address = state.lock().await.wallet.get_address(New)?;

    Ok(Json(json!({ "address": address.to_string() })))
}

#[axum::debug_handler]
async fn transactions_handler(
    State(state): State<SharedAppState>,
) -> Result<impl IntoResponse, AppError> {
    let transactions = state.lock().await.wallet.list_transactions(false)?;

    Ok(Json(transactions))
}

#[axum::debug_handler]
async fn balance_handler(
    State(state): State<SharedAppState>,
) -> Result<impl IntoResponse, AppError> {
    let balance = state.lock().await.wallet.get_balance()?;

    Ok(Json(balance))
}

#[axum::debug_handler]
async fn send_handler(State(state): State<SharedAppState>) -> Result<impl IntoResponse, AppError> {
    let state = state.lock().await;
    let wallet = &state.wallet;

    let send_to = wallet.get_address(New)?;

    let (mut psbt, details) = {
        let mut builder = wallet.build_tx();
        builder
            .add_recipient(send_to.script_pubkey(), 300)
            .enable_rbf()
            .do_not_spend_change()
            .fee_rate(FeeRate::from_sat_per_vb(5.0));

        builder.finish()?
    };

    let finalized = wallet.sign(&mut psbt, SignOptions::default())?;

    if !finalized {
        return Err(AppError(anyhow!("Failed to finalize transaction.")));
    }

    state.blockchain.broadcast(&psbt.extract_tx())?;

    Ok(Json(details))
}

#[axum::debug_handler]
async fn sync_handler(State(state): State<SharedAppState>) -> Result<impl IntoResponse, AppError> {
    let state = state.lock().await;
    state
        .wallet
        .sync(&state.blockchain, SyncOptions::default())?;

    Ok("ok")
}

#[axum::debug_handler]
async fn test_db_handler(
    State(_state): State<SharedAppState>,
) -> Result<impl IntoResponse, AppError> {
    let conn = open_db()?;

    let mut stmt = conn.prepare("SELECT id, name FROM persons")?;
    let persons: Vec<String> = stmt
        .query_map([], |row| {
            Ok(format!(
                "{}: {}",
                row.get::<_, i32>(0)?,
                row.get::<_, String>(1)?
            ))
        })?
        .filter_map(Result::ok)
        .collect();

    Ok(Json(persons))
}

fn open_db() -> Result<rusqlite::Connection, AppError> {
    let conn = rusqlite::Connection::open_with_flags(
        "test_db.db",
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
            | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
            | rusqlite::OpenFlags::SQLITE_OPEN_CREATE,
    )?;

    let user_version: i32 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if user_version == 0 {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS persons (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL
        )",
            (),
        )?;

        conn.execute(
            "INSERT INTO persons (name) VALUES (?1), (?2), (?3)",
            ["Steven", "John", "Alex"].map(|n| n.to_string()),
        )?;

        conn.pragma_update(None, "user_version", &1)?;
    }

    Ok(conn)
}
