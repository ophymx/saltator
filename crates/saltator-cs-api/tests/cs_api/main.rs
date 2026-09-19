//! The cs-api integration suite — one test binary, split by topic.
//! `harness` holds the Env fixture and every shared helper; each topic
//! module covers one surface. The end-to-end "two users register, chat,
//! and observe each other over the real HTTP router" case lives in
//! `client`.

mod account;
mod admin;
mod appservice;
mod client;
mod e2ee;
mod federation;
mod harness;
mod media;
mod push;
mod rooms;
mod sharding;
mod spaces;
