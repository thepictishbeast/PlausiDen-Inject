//! `inject-ios` -- iOS injection adapters for PlausiDen.
//!
//! Provides scaffolded adapters for iOS data stores including the Contacts
//! database (AddressBook.sqlitedb), Calendar (Calendar.sqlitedb), Photos
//! library (Photos.sqlite), and app sandbox injection.

pub mod calendar;
pub mod contacts;
pub mod photos;
pub mod sandbox;
